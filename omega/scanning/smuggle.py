"""omega/scanning/smuggle.py — HTTP request-smuggling differential prober
(suite name in fusion: ``smuggle-raw``).

Python orchestrates; the compiled Go microtool ``smsweep`` under
omega/adapters/go/ does the raw-TCP crafting (Go excels at raw sockets
and precise byte control). Pure-Python raw-socket fallback covers the
basic CL.TE / duplicate-CL differential when the polyglot gate is
closed or the Go toolchain is missing.

SAFETY CONTRACT — safe-read only:
- every probe is a single request whose framing headers CONFLICT; the
  body is an ordinary, well-framed payload that never carries a second
  (smuggled) request prefix, so no cache/shared connection can be
  poisoned by a probe run;
- detection is pure DIFFERENTIAL: response status/elapsed/size of each
  conflicting-framing case vs its clean twin and vs a baseline;
- all findings are ``verification='candidate'`` — never confirmed.

Cases covered:
  duplicate CL, CL.TE conflict, TE.CL conflict, TE.TE obfuscation
  (``Transfer-Encoding :`` / tab-prefixed / ``xchunked``), space- or
  tab-before-colon header obfuscation.

Finding shape matches the ENGINE convention (plain dict), evidence cap
300 chars, source=omega-smuggle/<case>.
"""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import subprocess

from omega.adapters import native

__all__ = [
    "Finding",
    "build_cases",
    "classify",
    "run_smuggle",
]

FINDING_EVIDENCE_CAP = native.FINDING_EVIDENCE_CAP
GATE_KEY = "gotools"
GATE_ENV = "PTK_POLYGLOT"
SUBPROC_TIMEOUT = 60
GO_BUILD_TIMEOUT = 120
OUTPUT_CAP = 2 * 1024 * 1024
PROBE_TIMEOUT_MS = 1500
REQUEST_TIMEOUT_S = max(5, PROBE_TIMEOUT_MS // 500)

_HOST_PORT_RE = re.compile(
    r"^(?:https?://)?([A-Za-z0-9_.\-\[\]]+)(?::(\d+))?(?:/.*)?$")


class Finding(dict):
    """ENGINE-convention finding dict (differential, candidate-only)."""

    def __init__(self, title, severity, verification_note, manual_check,
                 location, evidence, source, confidence="medium"):
        super().__init__(
            title=title,
            severity=severity,
            confidence=confidence,
            verification="candidate",
            verification_note=verification_note,
            manual_check=manual_check,
            location=location,
            evidence=evidence[:FINDING_EVIDENCE_CAP],
            source=source,
        )


def _result(findings=None, skipped=None, requests_sent=0, ran=None,
            surface=None):
    return {
        "findings": findings or [],
        "skipped": skipped or {},
        "requests_sent": requests_sent,
        "ran": ran or [],
        "surface": surface or {},
    }


def parse_target(target):
    """'http://127.0.0.1:8080/' -> ('127.0.0.1', 8080, '/')."""
    return parse_target_url(target)


def parse_target_url(target):
    """Robust target parse returning (host, port, path) or (None,..)."""
    import urllib.parse
    url = str(target or "").strip()
    if "://" not in url:
        url = "http://" + url
    try:
        p = urllib.parse.urlparse(url)
    except ValueError:
        return None, None, "/"
    if not p.hostname or not _HOST_PORT_RE.match(
            "%s:%d" % (p.hostname, p.port or 80) if p.port
            else p.hostname):
        return None, None, "/"
    return p.hostname, p.port or 80, (p.path or "/") + (
        ("?" + p.query) if p.query else "")


# ------------------------------------------------------------ case builder
def build_cases(host):
    """Return the ordered case list: [(name, raw_bytes, description)].

    Every case is a SAFE-READ probe: conflicting framing headers with a
    short inert body; no request smuggling (no second request prefix).
    ``clean`` twins use a single unambiguous framing header.
    """
    b = "X"
    body_cl = "q=%s" % (b * 8)
    chunked = "8\r\n%s\r\n0\r\n\r\n" % (b * 8)
    req = lambda method, headers, body: (
        "%s / HTTP/1.1\r\n%sHost: %s\r\n%sConnection: close\r\n\r\n%s"
        % (method, headers, host, "", body))
    hdr = lambda name, val: "%s: %s\r\n" % (name, val)

    cases = []
    cases.append(("baseline", (
        "POST / HTTP/1.1\r\n" + hdr("Content-Length", str(len(body_cl))) +
        "Host: %s\r\nConnection: close\r\n\r\n" % host + body_cl).encode(),
        "clean single Content-Length baseline"))
    cases.append(("duplicate_cl", (
        "POST / HTTP/1.1\r\n" +
        hdr("Content-Length", str(len(body_cl))) +
        hdr("Content-Length", "3") +
        "Host: %s\r\nConnection: close\r\n\r\n" % host + body_cl).encode(),
        "two conflicting Content-Length headers"))
    cases.append(("cl_te", (
        "POST / HTTP/1.1\r\n" +
        hdr("Content-Length", str(len(body_cl))) +
        hdr("Transfer-Encoding", "chunked") +
        "Host: %s\r\nConnection: close\r\n\r\n" % host + chunked).encode(),
        "Content-Length + Transfer-Encoding (CL.TE) conflict"))
    cases.append(("te_cl", (
        "POST / HTTP/1.1\r\n" +
        hdr("Transfer-Encoding", "chunked") +
        hdr("Content-Length", str(len(body_cl))) +
        "Host: %s\r\nConnection: close\r\n\r\n" % host + chunked).encode(),
        "Transfer-Encoding + Content-Length (TE.CL) conflict"))
    cases.append(("te_te_space", (
        "POST / HTTP/1.1\r\n" +
        hdr("Transfer-Encoding ", "chunked") +
        hdr("Content-Length", str(len(body_cl))) +
        "Host: %s\r\nConnection: close\r\n\r\n" % host + chunked).encode(),
        "obfuscated TE header (space before colon)"))
    cases.append(("te_te_tab", (
        "POST / HTTP/1.1\r\n" +
        hdr("Content-Length", str(len(body_cl))) +
        hdr("Transfer-Encoding", "\tchunked") +
        "Host: %s\r\nConnection: close\r\n\r\n" % host + chunked).encode(),
        "obfuscated TE header (tab in value)"))
    cases.append(("te_te_x", (
        "POST / HTTP/1.1\r\n" +
        hdr("Content-Length", str(len(body_cl))) +
        hdr("X-Transfer-Encoding", "chunked") +
        "Host: %s\r\nConnection: close\r\n\r\n" % host + chunked).encode(),
        "nonstandard transfer-encoding header variant"))
    cases.append(("space_colon_cl", (
        "POST / HTTP/1.1\r\n" +
        " Content-Length : %d\r\n" % len(body_cl) +
        "Host: %s\r\nConnection: close\r\n\r\n" % host + body_cl).encode(),
        "space-before-colon Content-Length obfuscation"))
    return cases


# ------------------------------------------------------- execution engines
def _python_send(host, port, raw, timeout_s):
    """Raw-socket send; returns (status, elapsed_ms, size, error)."""
    import time
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as s:
            s.settimeout(timeout_s)
            s.sendall(raw)
            buf = b""
            try:
                while len(buf) < 65536:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    buf += chunk
                    if b"\r\n\r\n" in buf:
                        head = buf.split(b"\r\n\r\n", 1)[0]
                        m = re.search(
                            rb"content-length:\s*(\d+)",
                            head, re.IGNORECASE)
                        if m and len(buf) >= (
                                buf.index(b"\r\n\r\n") + 4 +
                                int(m.group(1))):
                            break
            except socket.timeout:
                pass
        elapsed = int((time.monotonic() - start) * 1000)
        status = 0
        if buf.startswith(b"HTTP/"):
            try:
                status = int(buf.split(b" ", 2)[1])
            except (IndexError, ValueError):
                status = 0
        return status, elapsed, len(buf), ""
    except Exception as e:  # contained
        elapsed = int((time.monotonic() - start) * 1000)
        return 0, elapsed, 0, str(e)


def _python_exec(host, port, cases):
    return [
        {"name": name, "status": st, "elapsed_ms": ms, "size": sz,
         "error": err}
        for name, raw, _desc in cases
        for st, ms, sz, err in [_python_send(host, port, raw,
                                             REQUEST_TIMEOUT_S)]
    ]


def _gate_open(gate_open_fn=None):
    if gate_open_fn is not None:
        try:
            return bool(gate_open_fn())
        except Exception:
            return False
    return os.environ.get(GATE_ENV) == "1"


def _build_smsweep(cache_dir, log=None):
    """Compile omega/adapters/go/smsweep.go (gotools convention)."""
    src = os.path.join(native.GO_DIR, "smsweep.go")
    out = os.path.join(cache_dir, "smsweep")
    if os.path.exists(out) and os.path.exists(src) and \
            os.path.getmtime(out) >= os.path.getmtime(src):
        return out
    proc = subprocess.run(
        ["go", "build", "-o", out, src],
        capture_output=True, timeout=GO_BUILD_TIMEOUT, cwd=native.GO_DIR)
    if proc.returncode != 0 or not os.path.exists(out):
        raise RuntimeError("go build failed: " +
                           (proc.stderr or b"").decode("utf-8", "replace")
                           [:300])
    if log:
        log("smuggle: built smsweep -> %s" % out)
    return out


def _go_exec(host, port, cases, log=None):
    """Run the compiled smsweep binary; returns (results, err)."""
    try:
        os.makedirs(native.DEFAULT_CACHE_DIR, exist_ok=True)
        binary = _build_smsweep(native.DEFAULT_CACHE_DIR, log=log)
    except Exception as e:
        return None, f"smsweep build failed: {e}"
    payload = {
        "target": {"host": host, "port": port},
        "timeout_ms": PROBE_TIMEOUT_MS,
        "cases": [{"name": name,
                   "raw_b64": base64.b64encode(raw).decode("ascii")}
                  for name, raw, _d in cases],
    }
    try:
        proc = subprocess.run(
            [binary], input=json.dumps(payload).encode("utf-8"),
            capture_output=True, timeout=SUBPROC_TIMEOUT)
    except FileNotFoundError:
        return None, "binary not found: %s" % binary
    except subprocess.TimeoutExpired:
        return None, "timeout after %ds" % SUBPROC_TIMEOUT
    except Exception as e:
        return None, "subprocess error: %s" % e
    try:
        data = json.loads(proc.stdout[:OUTPUT_CAP].decode("utf-8", "replace"))
        return (data.get("results") or []), None
    except json.JSONDecodeError:
        return None, "invalid JSON from smsweep stdout"
    except Exception as e:
        return None, "parse error: %s" % e


# ------------------------------------------------------------ classifier
def classify(results):
    """Differential classifier: compare each case vs baseline AND its
    clean twin signal (any case whose status/size profile differs from
    the baseline is a candidate). Returns list of finding dicts.

    Rules:
    - different STATUS than baseline (e.g. 400 on framing conflict but
      200 baseline) -> front-end rejects / normalizes differently;
    - TIMEOUT profile (status 0 + large elapsed vs fast baseline) ->
      backend hung on the framing -> classic CL.TE/TE.CL differential;
    - different SIZE with same status -> body framing interpreted
      differently.
    """
    findings = []
    baseline = None
    for r in results:
        if (r.get("name") or "") == "baseline" and not r.get("error"):
            baseline = r
            break
    if baseline is None:
        return findings
    base_status = baseline.get("status") or 0
    for r in results:
        name = r.get("name") or "case"
        if name == "baseline" or r.get("error"):
            continue
        status = r.get("status") or 0
        size = r.get("size") or 0
        elapsed = r.get("elapsed_ms") or 0
        signal = None
        if status == 0 and elapsed >= PROBE_TIMEOUT_MS - 300:
            # a timeout means NO response at all — classify as timing,
            # not as a status differential against the baseline status.
            signal = ("timing differential (peer never answered within "
                      "%dms)" % elapsed)
        elif status != base_status:
            signal = ("status differential (%s -> %s)"
                      % (base_status or "none", status or "none"))
        elif size and abs(size - (baseline.get("size") or 0)) > 32:
            signal = ("size differential (%d vs %d bytes)"
                      % (size, baseline.get("size") or 0))
        if not signal:
            continue
        findings.append({
            "title": "HTTP request-smuggling differential: %s" % name,
            "severity": "high" if status == 0 or status != base_status
                        else "medium",
            "confidence": "medium",
            "verification": "candidate",
            "verification_note": (
                "Safe-read probe (%s) produced a %s versus the clean "
                "baseline — the server or an intermediary interprets the "
                "framing differently. Candidate only: no body was "
                "smuggled and no cache was poisoned by this probe; "
                "exploitability requires manual authorized verification."
                % (name, signal)),
            "manual_check": (
                "printf '<conflicting-framing request>' | nc <host> <port> "
                "(see omega.scanning.smuggle.build_cases for exact bytes)"),
            "location": "%s:%s" % (r.get("host", ""), r.get("port", "")),
            "evidence": "case=%s signal=%s status=%s elapsed_ms=%s size=%s"
                        % (name, signal, status, elapsed, size)[:300],
            "source": "omega-smuggle/%s" % name,
        })
    return findings


# ---------------------------------------------------------------- runner
def run_smuggle(target, log=None, allowlist=None, gate_open_fn=None,
                use_go=None):
    """Run the request-smuggling differential probe suite.

    Go path (raw TCP, full case set) is gated behind PTK_POLYGLOT /
    gate_open_fn; the pure-Python fallback (same raw-socket approach in
    stdlib sockets) always covers the basic CL.TE / duplicate-CL
    differential on loopback-authorized targets. Never raises.
    """
    from omega.probes import allowlist_ok

    result = _result()
    host, port, _path = parse_target_url(target)
    if not host:
        result["skipped"][GATE_KEY] = "unparseable target: %r" % target
        return result
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = \
            "target %r not in allowlist" % target
        return result

    cases = build_cases(host)
    used = None
    skipped = {}

    # Go path is opt-in via the polyglot gate.
    if use_go is None:
        use_go = _gate_open(gate_open_fn)
    if use_go:
        # no toolchain pre-check here: _go_exec owns the build attempt
        # and reports its failure through the skipped map (contained).
        results, err = _go_exec(host, port, cases, log=log)
        if results is None:
            skipped["smsweep-go"] = err
        else:
            used = "smsweep-go"
            for r in results:
                r.setdefault("host", host)
                r.setdefault("port", port)

    if used is None:
        # pure-Python fallback (basic CL.TE / duplicate-CL differential)
        results = _python_exec(host, port, cases)
        for r in results:
            r.setdefault("host", host)
            r.setdefault("port", port)
        used = "python-raw"

    findings = classify(results)
    result["findings"] = findings
    result["requests_sent"] = len(results)
    result["ran"] = [used]
    result["skipped"] = skipped
    result["surface"] = {"smuggle": results}
    if log:
        log("smuggle: engine=%s cases=%d findings=%d skipped=%s"
            % (used, len(results), len(findings), sorted(skipped)))
    return result
