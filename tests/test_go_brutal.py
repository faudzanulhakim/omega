"""Tests for batch-9 GO BRUTAL: hackwave + takeover Go tools, Python
runners, brain caps, gate enforcement, candidate-grade honesty."""
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

GO_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "omega", "adapters", "go")


# ---------------------------------------------------------------- Go tools
def test_go_tools_compile_and_run():
    hw = subprocess.run(["go", "build", "-o", "/tmp/t-hw", "hackwave.go"],
                        cwd=GO_DIR, capture_output=True, text=True)
    tk = subprocess.run(["go", "build", "-o", "/tmp/t-tk", "takeover.go"],
                        cwd=GO_DIR, capture_output=True, text=True)
    assert hw.returncode == 0, hw.stderr
    assert tk.returncode == 0, tk.stderr


def test_hackwave_reports_injection_candidate():
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(s, *a):
            pass

        def do_GET(s):
            if "'" in s.path or "passwd" in s.path or "7*7" in s.path:
                b = b"<html>SQL syntax near x</html>"
                code = 500
            else:
                b = b"<html>ok</html>"
                code = 200
            s.send_response(code)
            s.send_header("Content-Length", str(len(b)))
            s.end_headers()
            s.wfile.write(b)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        proc = subprocess.run(
            ["/tmp/t-hw"],
            input=json.dumps({"target": f"http://127.0.0.1:{port}/",
                              "params": ["q"], "concurrency": 20}),
            capture_output=True, text=True, timeout=60)
        data = json.loads(proc.stdout)
        assert data["results"], "expected at least one candidate"
        for r in data["results"]:
            assert r["class"] in ("reflected", "reflected+status-shift",
                                  "error-shape", "status-shift",
                                  "cmd-exec")
    finally:
        srv.shutdown()


def test_hackwave_clean_target_no_candidates():
    proc = subprocess.run(
        ["/tmp/t-hw"],
        input=json.dumps({"target": "http://127.0.0.1:1/", "params":
                          ["q"], "concurrency": 10}),
        capture_output=True, text=True, timeout=90)
    data = json.loads(proc.stdout)
    assert data["results"] == []  # conn refused -> nothing fabricated


def test_takeover_self_alias_skipped():
    proc = subprocess.run(
        ["/tmp/t-tk"],
        input=json.dumps({"hosts": ["nope.invalid"], "concurrency": 5}),
        capture_output=True, text=True, timeout=60)
    data = json.loads(proc.stdout)
    # a self-alias must NOT be reported as a candidate
    assert all(r["class"] != "takeover-candidate"
               for r in data["results"])


# ---------------------------------------------------------------- runners
def test_runners_gate_enforcement():
    from omega.adapters.gotools_offense import run_hackwave, run_takeover
    old = {k: os.environ.pop(k, None) for k in ("PTK_OFFENSE",
                                                "PTK_EXPLOIT")}
    try:
        out = run_hackwave("http://127.0.0.1:1/", ["q"])
        assert "offense gate closed" in str(out.get("skipped"))
        out2 = run_takeover(["x.example.com"])
        assert "exploit gate closed" in str(out2.get("skipped"))
    finally:
        os.environ.update({k: v for k, v in old.items() if v is not None})


def test_run_hackwave_finding_shape(tmp_path, monkeypatch):
    import http.server
    import threading
    from omega.adapters.gotools_offense import run_hackwave

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(s, *a):
            pass

        def do_GET(s):
            if "'" in s.path:
                b = b"<html>SQL syntax near</html>"
                code = 500
            else:
                b = b"<html>ok</html>"
                code = 200
            s.send_response(code)
            s.send_header("Content-Length", str(len(b)))
            s.end_headers()
            s.wfile.write(b)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    os.environ["PTK_OFFENSE"] = "1"
    try:
        out = run_hackwave(
            f"http://127.0.0.1:{srv.server_address[1]}/", ["q"],
            concurrency=10)
    finally:
        srv.shutdown()
        os.environ.pop("PTK_OFFENSE", None)
    for f in out.get("findings") or []:
        assert f["verification"] == "candidate"
        assert f.get("manual_check")
        assert f.get("cwe")
    if out.get("findings"):
        assert any(f["severity"] in ("HIGH", "MEDIUM")
                   for f in out["findings"])


# ---------------------------------------------------------------- brain
def test_brain_caps_197_and_registered():
    from omega.core.brain import DEFAULT_REGISTRY as reg
    assert len(reg.ids()) == 197
    assert reg.get("offense.hackwave") is not None
    assert reg.get("offense.takeover") is not None


def test_brain_caps_refuse_without_gates():
    from omega.core.brain import DEFAULT_REGISTRY as reg

    class S:
        target = "http://127.0.0.1:1/"
        surface = {}

    old = {k: os.environ.pop(k, None) for k in ("PTK_OFFENSE",
                                                "PTK_EXPLOIT")}
    try:
        out = reg.get("offense.hackwave").fn(S())
        assert "PTK_OFFENSE" in out.get("note", "")
        out2 = reg.get("offense.takeover").fn(S())
        assert "PTK_EXPLOIT" in out2.get("note", "")
    finally:
        os.environ.update({k: v for k, v in old.items() if v is not None})


def test_brutal_env_opens_hackwave_gate():
    """brutal mode sets PTK_* = 1, so the cap must then be allowed."""
    from omega.core.brain import DEFAULT_REGISTRY as reg

    class S:
        target = "http://127.0.0.1:1/"
        surface = {}
        log = None

    os.environ["PTK_OFFENSE"] = "1"
    try:
        out = reg.get("offense.hackwave").fn(S())
        note = str(out.get("note") or out.get("skipped") or "")
        assert "offense layer disabled" not in note
    finally:
        os.environ.pop("PTK_OFFENSE", None)


def test_native_registry_includes_new_tools():
    from omega.adapters import native
    assert native.NATIVE_TOOLS.get("hackwave") == ("hackwave.go", "go")
    assert native.NATIVE_TOOLS.get("takeover") == ("takeover.go", "go")


def test_findings_never_verified_from_go_layer():
    """Honesty: the offense layer can never emit verified/confirmed."""
    from omega.adapters.gotools_offense import run_hackwave
    os.environ["PTK_OFFENSE"] = "1"
    try:
        out = run_hackwave("http://127.0.0.1:1/", ["q"], concurrency=5)
    finally:
        os.environ.pop("PTK_OFFENSE", None)
    for f in out.get("findings") or []:
        assert f.get("verification") == "candidate"
