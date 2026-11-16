"""OMEGA regression gate — run before ANY release.

Usage (from repo root, with the engine venv interpreter):
    python3 lab/regress.py

What it does:
  1. Runs the hermetic test files tests/test_deepchecks.py and
     tests/test_fusion.py via pytest. If either fails: FAIL (exit 1).
  2. Starts the local ground-truth lab app (lab/vuln_app.py, 10 planted
     vulns + 3 clean FP traps) on an ephemeral 127.0.0.1 port.
  3. Runs the OMEGA fusion flow (same as lab/run_bench.py, budget via
     OMEGA_BENCH_BUDGET, default 400) against it.
  4. Asserts the gate:
       - detection: >= 9 of the 10 planted vulnerability classes produced
         at least one matching finding (token match on
         title/location/param/evidence);
       - precision: 0 HIGH/CRIT findings whose location targets one of the
         3 clean paths (/safe-param, /api/users, /health).
Verdict PASS (exit 0) or FAIL (exit 1). Never raises; unexpected errors
report FAIL with the reason instead of a traceback.

Exit codes: 0 = PASS, 1 = FAIL (regression or test failure).
"""
import os
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bench_ext import _finding_text, matches_hint, _is_high  # noqa: E402

CLEAN_PATHS = ("/safe-param", "/api/users", "/health")

# One hint list per planted vuln V1..V10 in lab/vuln_app.py.
PLANTED_CLASSES = [
    ("V1-sqli", ["sqli", "sql injection", "sql"]),
    ("V2-xss-reflected", ["xss", "reflected", "cross-site scripting"]),
    ("V3-path-traversal", ["traversal", "lfi", "../"]),
    ("V4-cmdi", ["command injection", "cmdi", "os command", "command"]),
    ("V5-ssti", ["ssti", "template injection", "template"]),
    ("V6-open-redirect", ["open redirect", "redirect"]),
    ("V7-env-exposure", [".env", "secret", "env exposure", "exposure"]),
    ("V8-insecure-cookie", ["cookie", "samesite", "httponly"]),
    ("V9-missing-headers", ["header", "csp", "hsts", "x-frame"]),
    ("V10-dir-listing", ["directory listing", "listing", "index of"]),
]

MIN_DETECTION = 9


def run_pytest_tests():
    """Run the two prerequisite test files; returns True on success."""
    cmd = [sys.executable, "-m", "pytest", "-q",
           os.path.join(REPO, "tests", "test_deepchecks.py"),
           os.path.join(REPO, "tests", "test_fusion.py")]
    try:
        proc = subprocess.run(cmd, cwd=REPO, capture_output=True,
                              text=True, timeout=600)
        tail = (proc.stdout or "").strip().splitlines()[-3:]
        print("[regress] pytest:\n  " + "\n  ".join(tail))
        return proc.returncode == 0
    except Exception as exc:
        print(f"[regress] pytest failed to run: {exc}")
        return False


def start_lab_server_real():
    """Import vuln_app from lab/ and serve on an ephemeral port."""
    from lab.vuln_app import Server, Handler  # noqa: E402
    srv = Server(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}", srv


def evaluate(findings, planted_classes=PLANTED_CLASSES,
             clean_paths=CLEAN_PATHS):
    """Pure verdict logic (unit-tested hermetically).

    Returns {"detected": [...], "detection_count": n,
             "clean_fps": [...], "pass": bool, "reason": str}
    """
    detected = []
    for name, hints in planted_classes:
        if any(matches_hint(f, hints) for f in findings):
            detected.append(name)
    clean_fps = []
    for f in findings:
        if not _is_high(f.get("severity")):
            continue
        loc = str(f.get("location") or "").lower()
        if any(p in loc for p in clean_paths):
            clean_fps.append(f)
    detection_count = len(detected)
    ok = detection_count >= MIN_DETECTION and not clean_fps
    reason = (f"detection {detection_count}/{len(planted_classes)} "
              f"(min {MIN_DETECTION}), clean-path HIGH/CRIT: {len(clean_fps)}")
    return {"detected": detected, "detection_count": detection_count,
            "clean_fps": clean_fps, "pass": ok, "reason": reason}


def main():
    if not run_pytest_tests():
        print("REGRESS VERDICT: FAIL — prerequisite tests failed")
        return 1
    url = None
    try:
        url, srv = start_lab_server_real()
        print(f"[regress] lab app at {url}")
        from omega.scanning.fusion import fuse
        budget = int(os.environ.get("OMEGA_BENCH_BUDGET", "400"))
        start = time.monotonic()
        result = fuse(url, budget=budget, allowlist=True)
        elapsed = time.monotonic() - start
        findings = result.get("findings") or []
        print(f"[regress] fusion ran {len(result.get('ran') or [])} suites "
              f"in {elapsed:.1f}s, {len(findings)} finding(s)")
        verdict = evaluate(findings)
        for name in verdict["detected"]:
            print(f"  [ok] {name}")
        missed = [n for n, _ in PLANTED_CLASSES
                  if n not in verdict["detected"]]
        for name in missed:
            print(f"  [MISS] {name}")
        for f in verdict["clean_fps"]:
            print(f"  [CLEAN-PATH FP] [{f.get('severity')}] "
                  f"{f.get('title')} @ {f.get('location')}")
        print("REGRESS VERDICT:", "PASS —" if verdict["pass"] else "FAIL —",
              verdict["reason"])
        return 0 if verdict["pass"] else 1
    except Exception as exc:
        print(f"REGRESS VERDICT: FAIL — fatal: "
              f"{type(exc).__name__}: {exc}")
        return 1
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
