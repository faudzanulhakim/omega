"""omega/adapters/rusttools — Python runner for the Rust polyglot adapter.

Drives omega/adapters/rust/pathscope.rs (compiled with `rustc -O` on
demand into the shared cache ~/.cache/omega/bin) — a pure-computation
path traversal normalizer / scope validator: candidate paths are
normalized (percent-decode, backslash-fold, dot-segment resolve) and
scored for traversal risk. NO network access.

Graceful degradation: when rustc is absent the bridge falls back to
an equivalent pure-Python normalizer with the identical JSON
contract (recorded as a fallback in the result surface), so callers
always work; rustc is only a fidelity upgrade. Everything is gated
behind PTK_POLYGLOT=1 and never raises outward.

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
BUILD_TIMEOUT = 120                   # seconds per rustc compile
FINDING_EVIDENCE_CAP = native.FINDING_EVIDENCE_CAP

RUST_DIR = os.path.join(native.PACKAGE_DIR, "rust")
PATHSCOPE_SRC = os.path.join(RUST_DIR, "pathscope.rs")
GATE_KEY = "rusttools"


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
            "normalization-shape candidate from a Rust adapter: the "
            "path merely normalizes outside the web root — verify "
            "manually before acting"),
        "source": source,
        "evidence": ev,
        "location": location,
        "manual_check": manual_check,
    }


# ------------------------------------------------------------ rust path
def _find_rustc():
    return shutil.which("rustc")


def _build_pathscope(cache_dir, log=None):
    """Compile pathscope.rs into cache_dir/pathscope (stale-aware)."""
    rustc = _find_rustc()
    if not rustc:
        raise RuntimeError("rustc not on PATH")
    out_path = os.path.join(cache_dir, "pathscope")
    if os.path.exists(out_path) and \
            os.path.exists(PATHSCOPE_SRC) and \
            os.path.getmtime(out_path) >= os.path.getmtime(PATHSCOPE_SRC):
        return out_path  # fresh binary — reuse
    os.makedirs(cache_dir, exist_ok=True)
    proc = subprocess.run(
        [rustc, "-O", "--edition", "2021", "-o", out_path, PATHSCOPE_SRC],
        capture_output=True, timeout=BUILD_TIMEOUT, cwd=RUST_DIR)
    if proc.returncode != 0 or not os.path.exists(out_path):
        raise RuntimeError("rustc build failed: " +
                           (proc.stderr or b"").decode("utf-8", "replace")
                           [:300])
    if log:
        log(f"rusttools: built pathscope -> {out_path}")
    return out_path


def _run_pathscope_binary(binary, paths):
    """Run the binary with one path per line; return (rows, err)."""
    stdin_data = "\n".join(str(p) for p in paths).encode("utf-8")
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
    out = proc.stdout[:OUTPUT_CAP]
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


# --------------------------------------------------- pure-python fallback
def _pct_decode(s):
    out = []
    i = 0
    b = s
    while i < len(b):
        if b[i] == "%" and i + 2 < len(b):
            try:
                out.append(chr(int(b[i + 1:i + 3], 16)))
                i += 3
                continue
            except ValueError:
                pass
        out.append(b[i])
        i += 1
    return "".join(out)


def _normalize_py(raw):
    """Pure-Python mirror of pathscope.rs normalization semantics."""
    encoded = ("%2e%2e" in raw.lower() or "..%2f" in raw.lower()
               or "%5c" in raw.lower() or "\\" in raw)
    cur = raw
    for _ in range(3):
        dec = _pct_decode(cur)
        if dec == cur:
            break
        cur = dec
    cur = cur.replace("\\", "/")
    collapsed = ""
    prev_slash = False
    for c in cur:
        if c == "/":
            if not prev_slash:
                collapsed += c
            prev_slash = True
        else:
            collapsed += c
            prev_slash = False
    parts = []
    escapes = 0
    for seg in collapsed.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            else:
                escapes += 1
        else:
            parts.append(seg)
    normalized = "../" * escapes + "/".join(parts)
    return (normalized, escapes > 0, encoded, escapes)


def _pathscope_fallback(paths):
    """Same NDJSON contract as the Rust binary (bridge still works)."""
    rows = []
    for raw in paths:
        raw = str(raw).strip()
        if not raw:
            continue
        normalized, escapes_root, encoded, escapes = _normalize_py(raw)
        score = min(100, escapes * 35 + (15 if encoded else 0))
        rows.append({"raw": raw, "normalized": normalized,
                     "traversal_risk": escapes_root,
                     "encoded": encoded, "score": score,
                     "escapes_root": escapes_root})
    return rows


# ---------------------------------------------------------------- runner
def run_pathscope(paths, log=None, gate_open_fn=None):
    """Score candidate paths for traversal risk with the compiled
    pathscope binary; falls back to the pure-Python normalizer when
    rustc is absent (bridge still works, result notes the fallback).
    Never raises."""
    paths = [str(p) for p in (paths or []) if str(p).strip()]
    if not _gate_open(gate_open_fn):
        return _result(skipped={GATE_KEY:
                                "polyglot gate closed (PTK_POLYGLOT)"})
    if not paths:
        return _result(skipped={GATE_KEY: "no paths given"})

    used_fallback = False
    rows = None
    err = None
    if _find_rustc():
        try:
            binary = _build_pathscope(native.DEFAULT_CACHE_DIR, log=log)
            rows, err = _run_pathscope_binary(binary, paths)
        except Exception as e:
            err = str(e)
            rows = None
    else:
        err = None  # rustc absent: fallback path below

    if rows is None:
        if err:
            # rust present but broken: still degrade to the fallback
            # instead of failing (bridge must always work)
            if log:
                log(f"rusttools: binary path failed ({err}); fallback")
        used_fallback = True
        rows = _pathscope_fallback(paths)

    findings = []
    for row in rows:
        if row.get("error") or not row.get("traversal_risk"):
            continue
        raw = str(row.get("raw") or "")
        normalized = str(row.get("normalized") or "")
        encoded = bool(row.get("encoded"))
        findings.append(_finding(
            "Path traversal normalization escapes web root",
            "HIGH" if int(row.get("score") or 0) >= 50 else "MEDIUM",
            "rust-pathscope/traversal",
            f"{raw} -> {normalized}"
            + (" (encoded traversal sequence)" if encoded else ""),
            raw,
            f"curl -s -o /dev/null -w '%{{http_code}}' "
            f"'<target>{raw}'",
            note="computed normalization only (no request was sent "
                 "from this adapter) — verify the endpoint accepts "
                 "the traversal before acting"))

    if log:
        log(f"rusttools: pathscope paths={len(paths)} "
            f"findings={len(findings)} fallback={used_fallback}")
    return _result(findings=findings, requests_sent=0,
                   ran=["pathscope"],
                   surface={"pathscope": rows,
                            "fallback": used_fallback})


def run_rust_suite(target, fetch=None, log=None, gate_open_fn=None):
    """Convenience suite: score a fixed set of candidate traversal
    shapes (pure computation; no requests against the target)."""
    paths = ["/admin", "/static/app.js", "/api/v1/users?id=3",
             "/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd",
             "/a/b/../../c", "/..%2f..%2fetc%2fpasswd"]
    return run_pathscope(paths, log=log, gate_open_fn=gate_open_fn)
