"""omega/adapters/cpptools — Python runner for the C++ polyglot adapter.

Drives omega/adapters/cpp/hdrstruct.cpp (compiled with g++ -O2 on
demand into the shared cache ~/.cache/omega/bin, mirroring the
ctools.py convention). The C++ tool parses raw HTTP response heads,
classifies security-header presence and cookie-flag completeness, and
emits NDJSON. Everything is gated behind PTK_POLYGLOT=1 and never
raises outward: gate closed, missing toolchain, compile failures,
subprocess timeouts and malformed JSON all become contained entries
in result['skipped'].

FP guard: a well-configured fixture response (all security headers
present, cookies flagged HttpOnly+Secure, versionless Server banner)
produces ZERO findings. HTTPS-only signals (HSTS, Secure cookie) are
never raised against plain-HTTP targets.

Findings contract: title/severity/confidence('candidate')/
verification('candidate')/source/evidence(<=300)/location/manual_check
(real shell command against the real target).
"""
import json
import os
import shutil
import subprocess

from omega.adapters import native

OUTPUT_CAP = 2 * 1024 * 1024          # subprocess stdout cap (2 MB)
SUBPROC_TIMEOUT = 60                  # seconds per tool run
BUILD_TIMEOUT = 90                    # seconds per g++ compile
FINDING_EVIDENCE_CAP = native.FINDING_EVIDENCE_CAP

CPP_DIR = os.path.join(native.PACKAGE_DIR, "cpp")
HDRSTRUCT_SRC = os.path.join(CPP_DIR, "hdrstruct.cpp")
GATE_KEY = "cpptools"

# security headers whose ABSENCE is reported (with https-only gating)
HDR_FINDINGS = [
    # (flag, severity, note)
    ("has_csp", "MEDIUM", "content-security-policy"),
    ("has_xcto", "LOW", "x-content-type-options"),
    ("has_xfo", "LOW", "x-frame-options"),
    ("has_referrer_policy", "INFO", "referrer-policy"),
]


def _gate_open(gate_open_fn=None):
    if gate_open_fn is not None:
        try:
            return bool(gate_open_fn())
        except Exception:
            return False
    return os.environ.get("PTK_POLYGLOT") == "1"


def _result(findings=None, skipped=None, requests_sent=0, ran=None,
            surface=None):
    return {
        "findings": findings or [],
        "skipped": skipped or {},
        "requests_sent": requests_sent,
        "ran": ran or [],
        "surface": surface or {},
    }


def _finding(title, severity, source, evidence, location, manual_check,
             note=None):
    ev = str(evidence or "")
    if len(ev) > FINDING_EVIDENCE_CAP:
        ev = ev[:FINDING_EVIDENCE_CAP] + "…"
    return {
        "title": title,
        "severity": severity,
        "confidence": "candidate",
        "verification": "candidate",
        "verification_note": note or (
            "candidate from a compiled C++ adapter: header-shape signal "
            "only — verify manually before acting"),
        "source": source,
        "evidence": ev,
        "location": location,
        "manual_check": manual_check,
    }


def _find_gxx():
    """Return a usable C++ compiler name or None (g++ preferred)."""
    for cxx in ("g++", "c++", "clang++"):
        if shutil.which(cxx):
            return cxx
    return None


def _build_hdrstruct(cache_dir, log=None):
    """Compile hdrstruct.cpp into cache_dir/hdrstruct (stale-aware)."""
    cxx = _find_gxx()
    if not cxx:
        raise RuntimeError("no C++ compiler on PATH")
    out_path = os.path.join(cache_dir, "hdrstruct")
    if os.path.exists(out_path) and \
            os.path.exists(HDRSTRUCT_SRC) and \
            os.path.getmtime(out_path) >= os.path.getmtime(HDRSTRUCT_SRC):
        return out_path  # fresh binary — reuse
    os.makedirs(cache_dir, exist_ok=True)
    proc = subprocess.run(
        [cxx, "-O2", "-std=c++17", "-o", out_path, HDRSTRUCT_SRC],
        capture_output=True, timeout=BUILD_TIMEOUT, cwd=CPP_DIR)
    if proc.returncode != 0 or not os.path.exists(out_path):
        raise RuntimeError("g++ build failed: " +
                           (proc.stderr or b"").decode("utf-8", "replace")
                           [:300])
    if log:
        log(f"cpptools: built hdrstruct -> {out_path}")
    return out_path


def _run_hdrstruct_binary(binary, items):
    """Run the binary with NDJSON on stdin; return (list of dicts, err)."""
    stdin_data = "".join(
        json.dumps({"url": str(it.get("url") or ""),
                    "headers": str(it.get("headers") or "")}) + "\n"
        for it in items
    ).encode("utf-8")
    try:
        proc = subprocess.run(
            [binary], input=stdin_data, capture_output=True,
            timeout=SUBPROC_TIMEOUT)
    except FileNotFoundError:
        return None, f"binary not found: {binary}"
    except subprocess.TimeoutExpired:
        return None, f"timeout after {SUBPROC_TIMEOUT}s (process killed)"
    except Exception as e:
        return None, f"subprocess error: {e}"
    out = proc.stdout[:OUTPUT_CAP]  # hard 2 MB cap before parsing
    rows = []
    for line in out.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            return None, "invalid JSON from tool stdout"
        except Exception as e:
            return None, f"parse error: {e}"
    return rows, None


def _is_https(url):
    return str(url or "").lower().startswith("https://")


def _flag_findings(row):
    """Turn hdrstruct flags into findings (FP guard: clean -> none)."""
    flags = row.get("flags") or {}
    url = str(row.get("url") or "")
    https = _is_https(url)
    findings = []
    for flag, severity, header in HDR_FINDINGS:
        if not flags.get(flag):
            findings.append(_finding(
                f"Missing security response header: {header}",
                severity,
                f"cpp-hdrstruct/missing_{header.replace('-', '_')}",
                f"{url} — response omits {header}",
                url,
                f"curl -sD - -o /dev/null '{url}' | grep -i "
                f"'^{header}:'",
                note=f"header-absence candidate ({header}); confirm the "
                     f"header is genuinely absent and applicable before "
                     f"acting"))
    if https and not flags.get("has_hsts"):
        findings.append(_finding(
            "Missing HSTS header on HTTPS response",
            "MEDIUM",
            "cpp-hdrstruct/missing_hsts",
            f"{url} — HTTPS response omits strict-transport-security",
            url,
            f"curl -sD - -o /dev/null '{url}' | grep -i "
            f"'^strict-transport-security:'"))
    if flags.get("cookie_no_httponly"):
        findings.append(_finding(
            "Set-Cookie without HttpOnly flag",
            "MEDIUM",
            "cpp-hdrstruct/cookie_no_httponly",
            f"{url} — a Set-Cookie header lacks HttpOnly (script-"
            f"readable session cookie candidate)",
            url,
            f"curl -sD - -o /dev/null '{url}' | grep -i '^set-cookie'"))
    if https and flags.get("cookie_no_secure"):
        findings.append(_finding(
            "Set-Cookie without Secure flag on HTTPS response",
            "MEDIUM",
            "cpp-hdrstruct/cookie_no_secure",
            f"{url} — HTTPS Set-Cookie lacks the Secure attribute",
            url,
            f"curl -sD - -o /dev/null '{url}' | grep -i '^set-cookie'"))
    if flags.get("server_with_version"):
        findings.append(_finding(
            "Server banner discloses a version number",
            "INFO",
            "cpp-hdrstruct/server_banner",
            f"{url} — Server header contains a version digit",
            url,
            f"curl -sD - -o /dev/null '{url}' | grep -i '^server:'"))
    return findings


def run_hdrstruct(items, log=None, gate_open_fn=None):
    """Analyze raw HTTP response heads with the compiled hdrstruct
    binary. items: iterable of {"url": ..., "headers": ...} dicts.
    Never raises; gate/toolchain/compile/timeout/JSON errors are all
    contained into result['skipped'].
    """
    items = [it for it in (items or []) if isinstance(it, dict)]
    if not _gate_open(gate_open_fn):
        return _result(skipped={GATE_KEY:
                                "polyglot gate closed (PTK_POLYGLOT)"})
    if not _find_gxx():
        return _result(skipped={GATE_KEY: "C++ toolchain unavailable"})

    try:
        binary = _build_hdrstruct(native.DEFAULT_CACHE_DIR, log=log)
    except Exception as e:
        return _result(skipped={GATE_KEY: f"hdrstruct build failed: {e}"})

    rows, err = _run_hdrstruct_binary(binary, items)
    if rows is None:
        return _result(skipped={GATE_KEY: f"hdrstruct: {err}"})

    findings = []
    for row in rows:
        if row.get("error"):
            continue  # per-line errors are contained, not findings
        findings.extend(_flag_findings(row))

    if log:
        log(f"cpptools: hdrstruct items={len(items)} "
            f"findings={len(findings)}")
    return _result(findings=findings, requests_sent=len(items),
                   ran=["hdrstruct"],
                   surface={"hdrstruct": rows})


def _head_from_response(url, resp):
    """Build a raw response head (status line + header block) from a
    fetch-style response object (status/code + headers dict)."""
    status = getattr(resp, "status_code", None) or \
        getattr(resp, "status", None) or 200
    headers = getattr(resp, "headers", None) or {}
    lines = [f"HTTP/1.1 {status} STATUS"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    return "\n".join(lines)


def run_cpp_suite(target, fetch=None, log=None, gate_open_fn=None):
    """Convenience suite: fetch the target once and classify its
    response head with the C++ tool. Without a fetch callable the
    suite is contained-skipped (no network is attempted here)."""
    target = str(target or "")
    if not _gate_open(gate_open_fn):
        return _result(skipped={GATE_KEY:
                                "polyglot gate closed (PTK_POLYGLOT)"})
    if not target:
        return _result(skipped={GATE_KEY: "empty target"})
    if fetch is None:
        return _result(skipped={GATE_KEY: "no fetch callable available"})
    try:
        resp = fetch(target)
        head = _head_from_response(target, resp)
    except Exception as e:
        return _result(skipped={GATE_KEY: f"fetch failed: {e}"})
    return run_hdrstruct([{"url": target, "headers": head}],
                         log=log, gate_open_fn=gate_open_fn)
