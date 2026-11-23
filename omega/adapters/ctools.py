"""omega/adapters/ctools — Python runner for the C polyglot adapter.

Drives omega/adapters/c/urlinfo.c (compiled with `cc -O2`) via the same
compile-on-demand cache convention as omega.adapters.native
(DEFAULT_CACHE_DIR = ~/.cache/omega/bin). Everything is gated behind
PTK_POLYGLOT=1 and never raises outward: gate closed, missing toolchain,
compile failures, subprocess timeouts and malformed JSON all become
contained entries in result['skipped'].

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
CC_BUILD_TIMEOUT = 60                 # seconds per compile
FINDING_EVIDENCE_CAP = native.FINDING_EVIDENCE_CAP

C_DIR = os.path.join(native.PACKAGE_DIR, "c")
URLINFO_SRC = os.path.join(C_DIR, "urlinfo.c")
GATE_KEY = "ctools"


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
            "candidate from a compiled C adapter; static URL-shape signal "
            "only — verify manually before acting"),
        "source": source,
        "evidence": ev,
        "location": location,
        "manual_check": manual_check,
    }


def _find_cc():
    """Return a usable C compiler name or None (cc preferred, then gcc)."""
    for cc in ("cc", "gcc"):
        if shutil.which(cc):
            return cc
    return None


def _build_urlinfo(cache_dir, log=None):
    """Compile urlinfo.c into cache_dir/urlinfo (rebuild when stale).

    Returns the binary path; raises RuntimeError on failure (contained
    by the callers).
    """
    cc = _find_cc()
    if not cc:
        raise RuntimeError("no C compiler on PATH")
    out_path = os.path.join(cache_dir, "urlinfo")
    if os.path.exists(out_path) and \
            os.path.exists(URLINFO_SRC) and \
            os.path.getmtime(out_path) >= os.path.getmtime(URLINFO_SRC):
        return out_path  # fresh binary — reuse
    os.makedirs(cache_dir, exist_ok=True)
    proc = subprocess.run(
        [cc, "-O2", "-o", out_path, URLINFO_SRC],
        capture_output=True, timeout=CC_BUILD_TIMEOUT, cwd=C_DIR)
    if proc.returncode != 0 or not os.path.exists(out_path):
        raise RuntimeError("cc build failed: " +
                           (proc.stderr or b"").decode("utf-8", "replace")
                           [:300])
    if log:
        log(f"ctools: built urlinfo -> {out_path}")
    return out_path


def _run_urlinfo_binary(binary, urls):
    """Run the binary with NDJSON on stdin; return (list of dicts, err).

    Output is capped at OUTPUT_CAP before parsing; each output line is
    parsed independently so one malformed line cannot poison the batch.
    """
    stdin_data = "".join(
        json.dumps({"url": str(u)}) + "\n" for u in urls
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
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None, "invalid JSON from tool stdout"
        except Exception as e:
            return None, f"parse error: {e}"
        rows.append(obj)
    return rows, None


def _flag_findings(row):
    """Turn urlinfo flags into findings (FP guard: all-false -> none)."""
    flags = row.get("flags") or {}
    url = str(row.get("url") or "")
    findings = []
    if flags.get("userinfo_present"):
        findings.append(_finding(
            "URL userinfo trick present in link/redirect target",
            "HIGH",
            "c-urlinfo/userinfo_present",
            f"{url} — authority contains 'user@host' userinfo; classic "
            f"SSRF/redirect smuggling shape (auth confusion)",
            url,
            f"curl -sv --max-redirs 0 '{url}' 2>&1 | head -20"))
    if flags.get("long_path_gt200"):
        findings.append(_finding(
            "URL path longer than 200 characters",
            "INFO",
            "c-urlinfo/long_path_gt200",
            f"{url} — path exceeds 200 chars; parser/truncation "
            f"confusion possible downstream",
            url,
            f"curl -s -o /dev/null -w '%{{http_code}}' '{url}'"))
    if flags.get("nonstd_scheme"):
        findings.append(_finding(
            "URL uses a non-standard scheme",
            "LOW",
            "c-urlinfo/nonstd_scheme",
            f"{url} — scheme is not http/https (scheme confusion/"
            f"handler abuse candidate)",
            url,
            f"curl -s -o /dev/null -w '%{{http_code}}' '{url}'"))
    # default_port intentionally produces no finding (FP guard: the
    # flag marks benign port elision, not an issue).
    return findings


def run_urlinfo(urls, log=None, gate_open_fn=None):
    """Analyze URL strings with the compiled urlinfo binary.

    Never raises; gate/toolchain/compile/timeout/JSON errors are all
    contained into result['skipped'].
    """
    if urls is None:
        urls = []
    elif not isinstance(urls, (list, tuple, set)):
        urls = [urls]
    urls = [str(u) for u in urls if u is not None and str(u)]

    if not _gate_open(gate_open_fn):
        return _result(skipped={GATE_KEY:
                                "polyglot gate closed (PTK_POLYGLOT)"})
    if not _find_cc():
        return _result(skipped={GATE_KEY: "C toolchain unavailable"})

    try:
        binary = _build_urlinfo(native.DEFAULT_CACHE_DIR, log=log)
    except Exception as e:
        return _result(skipped={GATE_KEY: f"urlinfo build failed: {e}"})

    rows, err = _run_urlinfo_binary(binary, urls)
    if rows is None:
        return _result(skipped={GATE_KEY: f"urlinfo: {err}"})

    findings = []
    for row in rows:
        if row.get("error"):
            continue  # per-line errors are contained, not findings
        findings.extend(_flag_findings(row))

    if log:
        log(f"ctools: urlinfo urls={len(urls)} findings={len(findings)}")
    return _result(findings=findings, requests_sent=len(urls),
                   ran=["urlinfo"],
                   surface={"urlinfo": rows})


def build_suite_urls(target):
    """URL variants exercising the flags for a target host.

    target + common path variants including the userinfo trick,
    scheme-relative redirect and open-redirect parameter shapes.
    """
    target = str(target or "").rstrip("/")
    if not target:
        return []
    # host part for the userinfo variant
    rest = target.split("://", 1)[1] if "://" in target else target
    host = rest.split("/", 1)[0].split("?", 1)[0]
    return [
        target + "/",
        target + "/api",
        target + "/admin?next=http://evil.example",
        "//evil.example",
        "http://user@" + host + "/",
    ]


def run_c_suite(target, fetch=None, log=None, gate_open_fn=None):
    """Convenience suite: analyze target URL variants for flag quirks."""
    urls = build_suite_urls(target)
    if not urls:
        return _result(skipped={GATE_KEY: "empty target"})
    return run_urlinfo(urls, log=log, gate_open_fn=gate_open_fn)
