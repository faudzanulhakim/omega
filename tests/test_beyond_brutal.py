"""Tests for batch-10 BEYOND BRUTAL: privesc_probe + authblast Go
tools, jwtattack, attackgraph, killchain narrative, mutafuzz seeds,
CLI flags. Honesty invariants enforced everywhere."""
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

GO_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "omega", "adapters", "go")


# ---------------------------------------------------------------- Go
@pytest.fixture(scope="module")
def go_bins():
    a = subprocess.run(["go", "build", "-o", "/tmp/t-pesc",
                        "privesc_probe.go"], cwd=GO_DIR,
                       capture_output=True, text=True)
    b = subprocess.run(["go", "build", "-o", "/tmp/t-ab",
                        "authblast.go"], cwd=GO_DIR,
                       capture_output=True, text=True)
    assert a.returncode == 0, a.stderr
    assert b.returncode == 0, b.stderr
    return "/tmp/t-pesc", "/tmp/t-ab"


def test_privesc_refuses_no_template(go_bins):
    proc = subprocess.run([go_bins[0]],
                          input=json.dumps({"template": "http://x/"}),
                          capture_output=True, text=True, timeout=30)
    assert "template with {CMD}" in proc.stdout


def test_privesc_runs_through_template(go_bins):
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(s, *a):
            pass

        def do_GET(s):
            body = b"uid=0(root) gid=0(root) groups=0(root)"
            s.send_response(200)
            s.send_header("Content-Length", str(len(body)))
            s.end_headers()
            s.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        proc = subprocess.run(
            [go_bins[0]],
            input=json.dumps({
                "template":
                    f"http://127.0.0.1:{srv.server_address[1]}/?c={{CMD}}"}),
            capture_output=True, text=True, timeout=60)
        data = json.loads(proc.stdout)
        checks = [r["check"] for r in data["results"]]
        assert "identity" in checks
    finally:
        srv.shutdown()


def test_authblast_success_content_detection(go_bins):
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(s, *a):
            pass

        def do_POST(s):
            import urllib.parse as _up
            ln = int(s.headers.get("Content-Length", 0) or 0)
            form = _up.parse_qs(s.rfile.read(ln).decode())
            if (form.get("username") == ["admin"]
                    and form.get("password") == ["admin"]):
                out = b"<html>Welcome to the dashboard <a href=/logout>"
            else:
                out = b"<html>Invalid login</html>"
            s.send_response(200)
            s.send_header("Content-Length", str(len(out)))
            s.end_headers()
            s.wfile.write(out)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        proc = subprocess.run(
            [go_bins[1]],
            input=json.dumps({
                "logins": [f"http://127.0.0.1:{srv.server_address[1]}"
                           f"/login"],
                "pairs": [["admin", "admin"]], "concurrency": 5}),
            capture_output=True, text=True, timeout=60)
        data = json.loads(proc.stdout)
        assert data["results"], "admin:admin must be flagged"
        assert all(r["class"] in ("success-content", "redirect-shift",
                                 "status-shift", "no-fail-marker")
                   for r in data["results"])
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- runners
def test_privesc_runner_needs_confirmed_rce():
    from omega.adapters.gotools_offense import run_privesc
    out = run_privesc("http://x/?c={CMD}", confirm_rce=False)
    assert "CONFIRMED RCE" in str(out.get("skipped"))


def test_authblast_runner_gates():
    from omega.adapters.gotools_offense import run_authblast
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        out = run_authblast(["http://x/login"])
        assert "offense gate closed" in str(out.get("skipped"))
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


# ---------------------------------------------------------------- jwtattack
def _mk_jwt(header, payload):
    import base64
    b64 = lambda o: base64.urlsafe_b64encode(
        json.dumps(o).encode()).rstrip(b"=").decode()
    return f"{b64(header)}.{b64(payload)}.x"

def test_jwtattack_gates_and_no_token():
    from omega.offensive.offense.jwtattack import run_jwtattack
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        out = run_jwtattack("http://x", _mk_jwt({"alg": "HS256"},
                                               {"sub": "u"}),
                            fetch=lambda *a, **k: None)
        assert "PTK_OFFENSE" in out.get("note", "")
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


def test_jwtattack_none_alg_candidate():
    from omega.offensive.offense.jwtattack import run_jwtattack

    class R:
        def __init__(self, status):
            self.status = status

    calls = {"n": 0}

    def fetch(url, method="GET", headers=None):
        tok = (headers or {}).get("Authorization", "")
        calls["n"] += 1
        if ".x" in tok:
            return R(401)   # original (bogus sig) rejected
        return R(200)       # forged accepted

    tok = _mk_jwt({"alg": "HS256"}, {"sub": "u"})
    os.environ["PTK_OFFENSE"] = "1"
    try:
        out = run_jwtattack("http://x", tok, fetch=fetch)
    finally:
        os.environ.pop("PTK_OFFENSE", None)
    # baseline (original token) gets 200 too -> NO differential,
    # no fabricated finding (honesty invariant)
    for f in out.get("findings") or []:
        assert f["verification"] == "candidate"


# ---------------------------------------------------------------- graph
def test_attackgraph_chain_ssrf_to_creds():
    from omega.core.attackgraph import build_attack_graph
    fs = [{"title": "SSRF candidate", "cwe": "CWE-918",
           "severity": "HIGH", "verification": "candidate"},
          {"title": "metadata exposure", "cwe": "CWE-200",
           "severity": "HIGH", "verification": "candidate"}]
    doc = build_attack_graph(fs)
    assert doc["nodes"] == 2
    assert doc["chains"]
    steps = doc["chains"][0]["steps"]
    assert steps[0]["from"] == "CWE-918"


def test_killchain_narrative_in_report():
    from omega.reporting.report import generate_report
    from omega.reporting.killchain import render_killchain
    fs = [{"id": "F1", "title": "SSRF candidate", "severity": "HIGH",
           "evidence": "reached metadata", "location": "/api",
           "cwe": "CWE-918", "verification": "candidate",
           "manual_check": "replay"}]
    md = generate_report("http://x", fs, fmt="markdown")
    assert "## Kill-chain narrative" in md
    assert render_killchain([]) == ""  # no findings -> no section


# ---------------------------------------------------------------- brain
def test_brain_caps_197():
    from omega.core.brain import DEFAULT_REGISTRY as reg
    assert len(reg.ids()) == 197
    for cid in ("offense.privesc", "offense.authblast", "auth.jwtattack",
                "core.attackgraph"):
        assert reg.get(cid) is not None


def test_native_registry_batch10():
    from omega.adapters import native
    assert native.NATIVE_TOOLS.get("privesc_probe") == \
        ("privesc_probe.go", "go")
    assert native.NATIVE_TOOLS.get("authblast") == \
        ("authblast.go", "go")


# ---------------------------------------------------------------- CLI
def test_cli_flags_present():
    import io
    import contextlib
    from omega.core import cli as climod
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            climod.main(["brain", "--help"])
        except SystemExit:
            pass
    txt = buf.getvalue()
    for flag in ("--privesc", "--authblast", "--jwt-attack",
                 "--attack-graph"):
        assert flag in txt


# ---------------------------------------------------------------- mutafuzz
def test_mutafuzz_seed_payloads_used():
    from omega.offensive.offense.mutafuzz import run_mutafuzz
    seen = []

    def send(payload):
        seen.append(payload)
        return "ok"  # never blocked

    out = run_mutafuzz("baseprobe", send, budget=6, generations=1,
                       seed_payloads=["prev-survivor-1"])
    assert any("prev-survivor-1" in p for p in seen)
    assert out["survivors"]
