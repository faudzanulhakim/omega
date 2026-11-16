"""omega/adapters/gotools — Python runner for the Go dirscan/dnssweep tools.

Drives the compiled Go microtools under omega/adapters/go/ (dirscan.go,
dnssweep.go) via omega.adapters.native.ensure_native's compile-on-demand
convention. Everything is gated behind PTK_POLYGLOT=1 (or gate_open_fn)
and never raises outward: gate closed, missing Go toolchain, compile
failures, subprocess timeouts and malformed JSON all become contained
entries in result['skipped'].

Findings contract: title/severity/confidence('candidate')/
verification('candidate')/source/evidence(<=300)/location/manual_check
(real shell command against the real target).
"""
import json
import os
import re
import shutil
import subprocess

from omega.adapters import native

OUTPUT_CAP = 2 * 1024 * 1024          # subprocess stdout cap (2 MB)
SUBPROC_TIMEOUT = 60                  # seconds per tool run
GO_BUILD_TIMEOUT = 120                # seconds per go build
FINDING_EVIDENCE_CAP = native.FINDING_EVIDENCE_CAP

GATE_KEY = "gotools"

# path fragments that make an exposed path look sensitive (backup/env/git
# style artifacts) -> HIGH instead of LOW
_SENSITIVE_RE = re.compile(
    r"backup|\.sql($|\.)|\.env|\.git|\.bak($|\.)|\.svn|\.htaccess|"
    r"\.DS_Store|id_rsa|\.pem($|\.)|\.key($|\.)|dump|web\.config|"
    r"credentials|secret",
    re.IGNORECASE)


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


def _slug(path):
    """'/backup.sql' -> 'backup-sql' (non-alphanumerics collapsed to '-')."""
    s = re.sub(r"[^a-zA-Z0-9]+", "-", path.strip("/")).strip("-").lower()
    return s or "root"


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
            "candidate from a compiled Go adapter; differential signal "
            "only — verify manually before acting"),
        "source": source,
        "evidence": ev,
        "location": location,
        "manual_check": manual_check,
    }


def _build_tool(name, cache_dir, log=None):
    """Compile omega/adapters/go/<name>.go into cache_dir/<name>.

    Mirrors native.ensure_native's convention: rebuild when the binary is
    missing or older than its source. Returns the binary path or None
    (with the reason captured by the caller's exception handling).
    """
    src_path = os.path.join(native.GO_DIR, name + ".go")
    out_path = os.path.join(cache_dir, name)
    if os.path.exists(out_path) and \
            os.path.exists(src_path) and \
            os.path.getmtime(out_path) >= os.path.getmtime(src_path):
        return out_path  # fresh binary — reuse
    proc = subprocess.run(
        ["go", "build", "-o", out_path, src_path],
        capture_output=True, timeout=GO_BUILD_TIMEOUT, cwd=native.GO_DIR)
    if proc.returncode != 0 or not os.path.exists(out_path):
        raise RuntimeError("go build failed: " +
                           (proc.stderr or b"").decode("utf-8", "replace")
                           [:300])
    if log:
        log(f"gotools: built {name} -> {out_path}")
    return out_path


def _run_tool_json(binary, stdin_obj, log=None):
    """Run a Go tool with JSON on stdin; return (parsed dict|None, err)."""
    try:
        proc = subprocess.run(
            [binary],
            input=json.dumps(stdin_obj).encode("utf-8"),
            capture_output=True, timeout=SUBPROC_TIMEOUT)
    except FileNotFoundError:
        return None, f"binary not found: {binary}"
    except subprocess.TimeoutExpired:
        return None, f"timeout after {SUBPROC_TIMEOUT}s (process killed)"
    except Exception as e:
        return None, f"subprocess error: {e}"
    out = proc.stdout[:OUTPUT_CAP]  # hard 2 MB cap before parsing
    try:
        return json.loads(out.decode("utf-8", "replace")), None
    except json.JSONDecodeError:
        return None, "invalid JSON from tool stdout"
    except Exception as e:
        return None, f"parse error: {e}"


# ---------------------------------------------------------------- dirscan
def run_dirscan(target, paths, fetch=None, log=None, gate_open_fn=None):
    """Differential path scan via the compiled dirscan binary.

    The body-diff rule (200 + body differs from the probe baseline by
    > 40 chars => 'exists') is applied inside the Go binary; here we only
    translate its classification into findings. Never raises.
    """
    target = str(target or "")
    if paths is None:
        paths = []
    elif not isinstance(paths, (list, tuple, set)):
        paths = [paths]
    paths = [str(p) for p in paths if p is not None and str(p)]

    if not _gate_open(gate_open_fn):
        return _result(skipped={GATE_KEY:
                                "polyglot gate closed (PTK_POLYGLOT)"})
    if not shutil.which("go"):
        return _result(skipped={GATE_KEY: "go toolchain unavailable"},
                       requests_sent=0)

    try:
        ensure_res = native.ensure_native(native.DEFAULT_CACHE_DIR, log=log)
        if log:
            log(f"gotools: ensure_native built={ensure_res.get('built')}")
    except PermissionError:
        # gate was opened via gate_open_fn but env is closed; our own
        # execution path is already authorized above
        ensure_res = {"built": [], "skipped": []}
    except Exception as e:  # defensive: ensure_native itself never raises
        return _result(skipped={GATE_KEY: f"ensure_native error: {e}"})

    binary = None
    try:
        os.makedirs(native.DEFAULT_CACHE_DIR, exist_ok=True)
        binary = _build_tool("dirscan", native.DEFAULT_CACHE_DIR, log=log)
    except Exception as e:
        return _result(skipped={GATE_KEY: f"dirscan build failed: {e}"})

    probe = "/omega-" + os.urandom(8).hex()
    data, err = _run_tool_json(binary, {"target": target, "paths": paths,
                                        "probe": probe}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"dirscan: {err}"})

    findings = []
    for r in (data.get("results") or []):
        path = r.get("path") or ""
        klass = r.get("class") or ""
        status = r.get("status")
        url = target + path
        if klass == "exists":
            severity = "HIGH" if _SENSITIVE_RE.search(path) else "LOW"
            findings.append(_finding(
                f"directory/file exists: {path} (HTTP {status})",
                severity,
                f"go-dirscan/{_slug(path)}",
                f"GET {url} -> HTTP {status}, content-type "
                f"{r.get('ctype') or 'n/a'}, body differs from probe "
                f"baseline; snippet: {(r.get('snippet') or '')[:200]!r}",
                url,
                f"curl -s -o /dev/null -w '%{{http_code}}' {url}"))
        elif klass == "protected":
            findings.append(_finding(
                f"path exists but is protected (403): {path}",
                "INFO",
                f"go-dirscan/{_slug(path)}",
                f"GET {url} -> HTTP 403 (access denied) — resource likely "
                f"present but authorization required",
                url,
                f"curl -s -o /dev/null -w '%{{http_code}}' {url}"))
        # 'missing' / 'other' produce no findings (FP guard)

    if log:
        log(f"gotools: dirscan {target} paths={len(paths)} "
            f"findings={len(findings)}")
    return _result(findings=findings, requests_sent=len(paths),
                   ran=["dirscan"],
                   surface={"dirscan": data.get("results") or []})


# --------------------------------------------------------------- dnssweep
def _is_private_ip(ip):
    """True for loopback/RFC1918/link-local/IPv6 loopback/ULA addresses."""
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_loopback or a.is_link_local or a.is_private:
        return True
    if a.version == 6:
        return a in ipaddress.ip_network("fc00::/7")
    return False


def run_dnssweep(domain, names, log=None, gate_open_fn=None):
    """Concurrent DNS subdomain resolution via the compiled dnssweep binary.

    Alive hosts become INFO inventory findings; hosts resolving to
    private-range IPs become candidate LOW 'internal host resolvable'
    findings. Never raises.
    """
    domain = str(domain or "")
    if names is None:
        names = []
    elif not isinstance(names, (list, tuple, set)):
        names = [names]
    names = [str(n) for n in names if n is not None and str(n)]

    if not _gate_open(gate_open_fn):
        return _result(skipped={GATE_KEY:
                                "polyglot gate closed (PTK_POLYGLOT)"})
    if not shutil.which("go"):
        return _result(skipped={GATE_KEY: "go toolchain unavailable"})

    try:
        ensure_res = native.ensure_native(native.DEFAULT_CACHE_DIR, log=log)
        if log:
            log(f"gotools: ensure_native built={ensure_res.get('built')}")
    except PermissionError:
        ensure_res = {"built": [], "skipped": []}
    except Exception as e:
        return _result(skipped={GATE_KEY: f"ensure_native error: {e}"})

    binary = None
    try:
        os.makedirs(native.DEFAULT_CACHE_DIR, exist_ok=True)
        binary = _build_tool("dnssweep", native.DEFAULT_CACHE_DIR, log=log)
    except Exception as e:
        return _result(skipped={GATE_KEY: f"dnssweep build failed: {e}"})

    data, err = _run_tool_json(binary, {"domain": domain, "names": names},
                               log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"dnssweep: {err}"})

    findings = []
    for h in (data.get("alive") or []):
        fqdn = h.get("name") or ""
        ip = h.get("ip") or ""
        if _is_private_ip(ip):
            findings.append(_finding(
                f"internal host resolvable: {fqdn} -> {ip}",
                "LOW",
                "go-dnssweep/" + _slug(fqdn),
                f"DNS A query for {fqdn} returned private-range address "
                f"{ip} (internal namespace leak via public resolver)",
                fqdn,
                f"dig +short A {fqdn} @8.8.8.8"))
        else:
            findings.append(_finding(
                f"subdomain resolves: {fqdn} -> {ip}",
                "INFO",
                "go-dnssweep/" + _slug(fqdn),
                f"DNS A query for {fqdn} returned {ip}",
                fqdn,
                f"dig +short A {fqdn} @8.8.8.8"))

    if log:
        log(f"gotools: dnssweep {domain} names={len(names)} "
            f"alive={len(findings)} errors={data.get('errors')}")
    return _result(findings=findings, requests_sent=len(names),
                   ran=["dnssweep"],
                   surface={"dnssweep": {"alive": data.get("alive") or [],
                                         "errors": data.get("errors", 0)}})
