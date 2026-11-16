"""omega/native — compile-on-demand polyglot native adapter manager.

Manages compiled Go microtools and Node analysis scripts under
omega/adapters/.  Everything is gated behind env PTK_POLYGLOT=1 (or an
explicit allow=True) and is READ-ONLY recon: TCP connect + banner grab,
HTTP GET liveness, and offline JS regex analysis.  No function here ever
raises outward; failures become skipped-with-reason entries.

Binary cache: ensure_native() compiles each adapters/go/*.go with
`go build -o <cache_dir>/<name>`, skipping when the binary exists and is
newer than its source (rebuilt automatically after source edits).
"""
import json
import os
import shutil
import subprocess
import time

# --------------------------------------------------------------- constants
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
GO_DIR = os.path.join(PACKAGE_DIR, "go")
NODE_DIR = os.path.join(PACKAGE_DIR, "node")
DEFAULT_CACHE_DIR = os.path.expanduser("~/.cache/omega/bin")

OUTPUT_CAP = 2 * 1024 * 1024          # subprocess stdout cap
SUBPROC_TIMEOUT_DEFAULT = 30          # seconds
FINDING_EVIDENCE_CAP = 300
NODE_BIN = shutil.which("node") or "node"

# name -> (source filename, kind)
NATIVE_TOOLS = {
    "portspeed": ("portspeed.go", "go"),
    "htsweep": ("htsweep.go", "go"),
    "jsanalyze": ("jsanalyze.mjs", "node"),
}


# ---------------------------------------------------------------- gate
def _polyglot_allowed(allow=None):
    if allow is not None:
        return bool(allow)
    return os.environ.get("PTK_POLYGLOT") == "1"


def _require_gate(allow=None):
    """Raise PermissionError unless the polyglot gate is open."""
    if not _polyglot_allowed(allow):
        raise PermissionError(
            "polyglot native adapters disabled: set PTK_POLYGLOT=1 to allow "
            "compiled-tool execution (read-only recon only)")


# --------------------------------------------------------- compile manager
def ensure_native(cache_dir=DEFAULT_CACHE_DIR, log=None, allow=None):
    """Compile-on-demand each Go adapter.

    Returns {"built": [names], "skipped": [{"tool","reason"}]}.
    Build errors are contained as skipped entries; never raises.
    """
    _require_gate(allow)
    built, skipped = [], []
    try:
        os.makedirs(cache_dir, exist_ok=True)
    except Exception as e:
        return {"built": [], "skipped": [
            {"tool": "*", "reason": f"cache dir unusable: {e}"}]}
    for name, (src, kind) in NATIVE_TOOLS.items():
        src_path = os.path.join(GO_DIR, src)
        if kind != "go" or not os.path.exists(src_path):
            continue  # node scripts need no compilation
        out_path = os.path.join(cache_dir, name)
        try:
            if os.path.exists(out_path) and \
                    os.path.getmtime(out_path) >= os.path.getmtime(src_path):
                built.append(name)   # fresh binary — reuse
                continue
            proc = subprocess.run(
                ["go", "build", "-o", out_path, src_path],
                capture_output=True, timeout=120,
                cwd=GO_DIR,
                env={**os.environ, "GOFLAGS": os.environ.get("GOFLAGS", "")})
            if proc.returncode == 0 and os.path.exists(out_path):
                built.append(name)
                if log:
                    log(f"native: built {name} -> {out_path}")
            else:
                skipped.append({
                    "tool": name,
                    "reason": (proc.stderr or b"").decode("utf-8",
                                                          "replace")[:400]
                    or f"go build exited {proc.returncode}"})
        except FileNotFoundError:
            skipped.append({"tool": name,
                            "reason": "go toolchain not found on PATH"})
        except subprocess.TimeoutExpired:
            skipped.append({"tool": name, "reason": "go build timed out"})
        except Exception as e:
            skipped.append({"tool": name, "reason": f"build error: {e}"})
    return {"built": built, "skipped": skipped}


# ---------------------------------------------------------------- runners
def _run_json(cmd, timeout_s=SUBPROC_TIMEOUT_DEFAULT):
    """Run a subprocess, cap output, JSON-parse. Returns (dict|None, err)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True,
            timeout=max(1, int(timeout_s)))
        out = proc.stdout[:OUTPUT_CAP]
        return json.loads(out.decode("utf-8", "replace")), None
    except FileNotFoundError:
        return None, f"binary not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return None, f"timeout after {timeout_s}s"
    except json.JSONDecodeError:
        return None, "invalid JSON on stdout"
    except Exception as e:
        return None, f"error: {e}"


def run_portspeed(host, ports, timeout_s=SUBPROC_TIMEOUT_DEFAULT,
                  cache_dir=DEFAULT_CACHE_DIR, allow=None):
    """High-concurrency TCP port scan via the compiled portspeed binary.

    Returns {"open": [{"port", "banner"}], "error": None|str}; never raises.
    """
    _require_gate(allow)
    binary = os.path.join(cache_dir, "portspeed")
    if not os.path.exists(binary):
        res = ensure_native(cache_dir, allow=allow)
        if "portspeed" not in res.get("built", []):
            return {"open": [], "error": "portspeed binary unavailable"}
    data, err = _run_json(
        [binary, "-host", str(host), "-ports", str(ports)],
        timeout_s=timeout_s + 5)
    if data is None:
        return {"open": [], "error": err}
    return {"open": data.get("open") or [], "error": None}


def run_htsweep(urls, timeout_s=SUBPROC_TIMEOUT_DEFAULT,
                cache_dir=DEFAULT_CACHE_DIR, allow=None):
    """HTTP liveness sweep via the compiled htsweep binary.

    Returns {"alive": [{"url","status","title","server"}], "error": None|str}.
    """
    _require_gate(allow)
    binary = os.path.join(cache_dir, "htsweep")
    if not os.path.exists(binary):
        res = ensure_native(cache_dir, allow=allow)
        if "htsweep" not in res.get("built", []):
            return {"alive": [], "error": "htsweep binary unavailable"}
    targets_file = None
    try:
        import tempfile
        fd, targets_file = tempfile.mkstemp(prefix="omega-htsweep-",
                                            suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(str(u) for u in urls) + "\n")
        data, err = _run_json(
            [binary, "-targets-file", targets_file],
            timeout_s=timeout_s + 5)
    finally:
        if targets_file:
            try:
                os.unlink(targets_file)
            except Exception:
                pass
    if data is None:
        return {"alive": [], "error": err}
    return {"alive": data.get("alive") or [], "error": None}


def run_jsanalyze(path, timeout_s=SUBPROC_TIMEOUT_DEFAULT, allow=None):
    """Offline JS analysis via node jsanalyze.mjs. No network.

    Returns {"endpoints": [], "secrets": [], "api_routes": [],
             "error": None|str}.
    """
    _require_gate(allow)
    script = os.path.join(NODE_DIR, "jsanalyze.mjs")
    if not os.path.exists(script):
        return {"endpoints": [], "secrets": [], "api_routes": [],
                "error": "jsanalyze.mjs not found"}
    data, err = _run_json([NODE_BIN, script, str(path)], timeout_s=timeout_s)
    if data is None:
        return {"endpoints": [], "secrets": [], "api_routes": [],
                "error": err}
    return {"endpoints": data.get("endpoints") or [],
            "secrets": data.get("secrets") or [],
            "api_routes": data.get("api_routes") or [],
            "error": None}


# -------------------------------------------------------------- suite glue
def _finding(tool, title, severity, evidence, location="", param="",
             note=None):
    """engine-shaped finding produced by an omega native adapter."""
    ev = str(evidence or "")
    if len(ev) > FINDING_EVIDENCE_CAP:
        ev = ev[:FINDING_EVIDENCE_CAP] + "…"
    return {
        "title": title,
        "severity": severity,
        "confidence": "candidate",
        "verification": "signature",
        "verification_note": note or (
            f"signature from native adapter '{tool}'; requires manual "
            "verification before acting on it"),
        "manual_check": True,
        "location": location or "",
        "param": param or "",
        "evidence": ev,
        "source": f"omega-native/{tool}",
    }


def run_native_suite(target, kinds, budget=10, log=None, ports=None,
                     cache_dir=DEFAULT_CACHE_DIR, allow=None):
    """Run a selection of native adapters against a target.

    kinds: iterable subset of {"portspeed", "htsweep", "jsanalyze"}.
    budget: max number of adapters actually executed.
    Returns {"findings": [...], "surface": {...}, "ran": [...],
             "skipped": [{"tool","reason"}]} — never raises.
    """
    started = time.time()
    findings, surface = [], {}
    ran, skipped = [], []
    kinds = [k for k in (kinds or []) if k in NATIVE_TOOLS]

    # gate check up front (contained: report as universal skip)
    if not _polyglot_allowed(allow):
        return {"findings": [], "surface": {},
                "ran": [],
                "skipped": [{"tool": k,
                             "reason": "PTK_POLYGLOT not set; native "
                             "adapters disabled"} for k in kinds]}

    compile_res = ensure_native(cache_dir, log=log, allow=allow)
    skip_reasons = {s["tool"]: s["reason"] for s in compile_res["skipped"]}

    for kind in kinds:
        if len(ran) >= max(0, int(budget)):
            skipped.append({"tool": kind,
                            "reason": f"budget exhausted (budget={budget})"})
            continue
        if kind in skip_reasons:
            skipped.append({"tool": kind, "reason": skip_reasons[kind]})
            continue
        try:
            if kind == "portspeed":
                port_spec = ports or "21,22,80,443,3000,8000-8010"
                res = run_portspeed(target, port_spec,
                                    timeout_s=15, cache_dir=cache_dir,
                                    allow=allow)
                if res["error"]:
                    skipped.append({"tool": kind, "reason": res["error"]})
                    continue
                for p in res["open"][:100]:
                    banner = (p.get("banner") or "").strip()
                    findings.append(_finding(
                        "portspeed",
                        f"open TCP port: {target}:{p['port']}" +
                        (f" ({banner[:40]})" if banner else ""),
                        "INFO",
                        f"{target}:{p['port']} accepted connection" +
                        (f", banner: {banner}" if banner else ""),
                        location=f"{target}:{p['port']}"))
                surface["portspeed"] = {"open": res["open"][:100]}
                ran.append(kind)
            elif kind == "htsweep":
                urls = target if isinstance(target, (list, tuple)) else \
                    [target]
                res = run_htsweep(urls, timeout_s=15, cache_dir=cache_dir,
                                  allow=allow)
                if res["error"]:
                    skipped.append({"tool": kind, "reason": res["error"]})
                    continue
                for a in res["alive"][:100]:
                    findings.append(_finding(
                        "htsweep",
                        f"live HTTP endpoint: {a['url']} ({a['status']})",
                        "INFO",
                        f"{a['url']} -> HTTP {a['status']}" +
                        (f", server: {a['server']}" if a.get("server") else
                         "") +
                        (f", title: {a['title']!r}" if a.get("title") else
                         ""),
                        location=a["url"]))
                surface["htsweep"] = {"alive": res["alive"][:100]}
                ran.append(kind)
            elif kind == "jsanalyze":
                path = target if isinstance(target, str) else ""
                if not path or not os.path.exists(path):
                    skipped.append({"tool": kind,
                                    "reason": "no readable JS file path "
                                    "given"})
                    continue
                res = run_jsanalyze(path, allow=allow)
                if res["error"]:
                    skipped.append({"tool": kind, "reason": res["error"]})
                    continue
                for ep in res["endpoints"][:200]:
                    findings.append(_finding(
                        "jsanalyze", f"endpoint in JS: {ep}", "INFO",
                        f"endpoint {ep}", location=path))
                for route in res["api_routes"][:100]:
                    findings.append(_finding(
                        "jsanalyze", f"API route in JS: {route}", "INFO",
                        f"api route {route}", location=path))
                for sec in res["secrets"][:50]:
                    findings.append(_finding(
                        "jsanalyze",
                        "possible secret candidate in JS (high-entropy, "
                        ">=20 chars)", "LOW",
                        f"token candidate: {sec.get('value')}",
                        location=path,
                        note="high-entropy string candidate only "
                        "(length >= 20 and entropy >= 3.5); manual "
                        "verification required"))
                surface["jsanalyze"] = {
                    "endpoints": res["endpoints"][:200],
                    "api_routes": res["api_routes"][:100],
                    "secrets": res["secrets"][:50]}
                ran.append(kind)
        except Exception as e:  # absolute containment
            skipped.append({"tool": kind, "reason": f"internal error: {e}"})

    if log:
        log(f"native suite: ran={ran} skipped="
            f"{[s['tool'] for s in skipped]} "
            f"({time.time() - started:.2f}s)")
    return {"findings": findings, "surface": surface, "ran": ran,
            "skipped": skipped}
