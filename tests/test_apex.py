"""Tests for batch-11 APEX: racehunter, techmem, exploitloop, pivot,
secondorder, bizfuzz, stackroute, brain caps, CLI flags."""
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


# ---------------------------------------------------------------- racehunter
@pytest.fixture(scope="module")
def race_bin():
    import subprocess
    go_dir = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "omega", "adapters", "go")
    r = subprocess.run(["go", "build", "-o", "/tmp/t-race",
                        "racehunter.go"], cwd=go_dir,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return "/tmp/t-race"


def test_racehunter_detects_double_success(race_bin):
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(s, *a):
            pass

        def do_POST(s):
            s.rfile.read(int(s.headers.get("Content-Length", 0) or 0))
            out = b"<html>payment success</html>"  # every copy "wins"
            s.send_response(200)
            s.send_header("Content-Length", str(len(out)))
            s.end_headers()
            s.wfile.write(out)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        proc = subprocess.run(
            [race_bin],
            input=json.dumps({
                "target": f"http://127.0.0.1:{srv.server_address[1]}/w",
                "method": "POST", "body": "acct=1&amt=1", "race_n": 10,
                "success_marker": "success"}),
            capture_output=True, text=True, timeout=60)
        data = json.loads(proc.stdout)
        assert data["success_count"] >= 5  # every copy hit the marker
    finally:
        srv.shutdown()


def test_racehunt_runner_gates():
    from omega.adapters.gotools_offense import run_racehunter
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        out = run_racehunter("http://x/w")
        assert "offense gate closed" in str(out.get("skipped"))
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


# ---------------------------------------------------------------- techmem
def test_techmem_roundtrip(tmp_path, monkeypatch):
    from omega.core import techmem
    monkeypatch.setenv("OMEGA_LESSONS_HOME", str(tmp_path / "lessons.json"))
    techmem.record_stack(["tomcat", "nginx"], "hackwave", "worked",
                         hint="double-encode passed")
    techmem.record_stack(["tomcat", "nginx"], "mutafuzz", "blocked",
                         hint="plain probe 403")
    doc = techmem.consult_stack(["tomcat", "nginx"])
    assert doc["stack"] == "nginx+tomcat"
    assert "double-encode passed" in doc["worked"]
    assert "plain probe 403" in doc["blocked"]
    assert "double-encode passed" not in doc["blocked"]


def test_techmem_stack_key_deterministic():
    from omega.core.techmem import stack_key
    assert stack_key(["Nginx", "TOMCAT"]) == stack_key(["tomcat",
                                                        "nginx"])


# ---------------------------------------------------------------- loop
def test_exploitloop_finds_winner():
    from omega.core.exploitloop import run_exploit_loop
    hs = [{"name": "ssti", "payloads": ["{{7*7}}"],
           "signals": ["49"]},
          {"name": "xss", "payloads": ["<b>x</b>"],
           "signals": ["<b>x</b>"]}]

    def probe(payload):
        if "{{7*7}}" in payload:
            return "computed: 49"  # ssti evidence
        return "plain"             # xss never confirmed

    out = run_exploit_loop(hs, probe, rounds=3, budget=20)
    assert out["winner"] == "ssti"
    assert out["posteriors"]["ssti"] > out["posteriors"]["xss"]


def test_exploitloop_budget_honored():
    from omega.core.exploitloop import run_exploit_loop
    hs = [{"name": f"h{i}", "payloads": [f"p{i}"], "signals": [f"s{i}"]}
          for i in range(5)]
    out = run_exploit_loop(hs, lambda p: "", rounds=3, budget=8)
    assert out["probes"] <= 8


# ---------------------------------------------------------------- pivot
def test_pivot_plan_plan_only_and_triggered():
    from omega.core.pivot import build_pivot_plan
    res = [{"check": "ssh-keys", "output": "id_rsa authorized_keys",
            "flag": "notable"},
           {"check": "identity", "output": "uid=1000", "flag": ""}]
    doc = build_pivot_plan(res, surface={"urls": ["http://x/a"]})
    assert doc["note"].startswith("PLAN-ONLY")
    trig = [p for p in doc["plan"] if p["triggered"]]
    assert all(not p["executed"] for p in doc["plan"])
    assert len(trig) == 1 and trig[0]["motive"].startswith("SSH")
    assert trig[0]["targets"] == ["http://x/a"]


def test_pivot_plan_no_findings_no_trigger():
    from omega.core.pivot import build_pivot_plan
    doc = build_pivot_plan([])
    assert doc["triggered"] == 0


# ---------------------------------------------------------------- secondorder
def test_secondorder_gates():
    from omega.offensive.offense.secondorder import run_second_order
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        out = run_second_order([{"url": "http://x/", "param": "q"}],
                               ["http://x/list"], fetch=lambda *a, **k: None)
        assert "PTK_OFFENSE" in out.get("note", "")
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


def test_secondorder_cross_page_marker():
    from omega.offensive.offense.secondorder import run_second_order
    planted = {}

    class R:
        def __init__(self, text):
            self.status = 200
            self.text = text

    def fetch(url, method="GET", body=None):
        if "plant" in url:
            mk = url.split("q=")[-1]
            planted["stored"] = mk
            return R("ok")
        return R(f"profile page: {planted.get('stored', '')}")  # replay

    os.environ["PTK_OFFENSE"] = "1"
    try:
        out = run_second_order(
            [{"url": "http://x/plant", "param": "q"}],
            ["http://x/profile"], fetch=fetch)
    finally:
        os.environ.pop("PTK_OFFENSE", None)
    assert out["findings"]
    for f in out["findings"]:
        assert f["verification"] == "candidate"
        assert f["cwe"] == "CWE-79"


# ---------------------------------------------------------------- bizfuzz
def test_bizfuzz_invalid_value_accepted():
    from omega.offensive.offense.bizfuzz import run_bizfuzz

    class R:
        def __init__(self, status, text):
            self.status = status
            self.text = text

    def fetch(url, method="POST", body=None):
        # baseline qty=1 accepted; qty=-1 ALSO accepted = flaw
        if "qty=-1" in str(body):
            return R(200, "order success added")
        return R(200, "order success added")

    os.environ["PTK_OFFENSE"] = "1"
    try:
        out = run_bizfuzz([{"url": "http://x/cart", "method": "POST",
                            "param": "qty", "value": "1"}],
                          fetch=fetch, budget=15)
    finally:
        os.environ.pop("PTK_OFFENSE", None)
    assert out["findings"]
    assert out["findings"][0]["verification"] == "candidate"
    assert out["findings"][0]["cwe"] == "CWE-840"


def test_bizfuzz_gates():
    from omega.offensive.offense.bizfuzz import run_bizfuzz
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        out = run_bizfuzz([{"url": "http://x"}], fetch=lambda *a, **k: None)
        assert "PTK_OFFENSE" in out.get("note", "")
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


# ---------------------------------------------------------------- stackroute
def test_stackroute_fingerprints():
    from omega.core.stackroute import route_stack, explain_route
    doc = route_stack(["Tomcat 9", "nginx"])
    assert "offense.authblast" in doc["route"]
    assert "tomcat" in doc["stack"]
    assert "nginx" in doc["stack"]
    doc2 = route_stack(["unknown-thing"])
    assert doc2["route"]  # generic brutal route
    txt = explain_route(["grafana"])
    assert "grafana" in txt and "authblast" in txt


# ---------------------------------------------------------------- brain/CLI
def test_brain_caps_197():
    from omega.core.brain import DEFAULT_REGISTRY as reg
    assert len(reg.ids()) == 197
    for cid in ("offense.racehunt", "offense.secondorder",
                "offense.bizfuzz", "core.exploitloop", "core.pivot",
                "core.stackroute"):
        assert reg.get(cid) is not None


def test_native_registry_racehunter():
    from omega.adapters import native
    assert native.NATIVE_TOOLS.get("racehunter") == \
        ("racehunter.go", "go")


def test_cli_flags_present():
    import contextlib
    import io
    from omega.core import cli as climod
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            climod.main(["brain", "--help"])
        except SystemExit:
            pass
    txt = buf.getvalue()
    for flag in ("--race-hunt", "--second-order", "--biz-fuzz",
                 "--exploit-loop", "--pivot-plan", "--stack-route"):
        assert flag in txt


def test_hackwave_records_techmem(tmp_path, monkeypatch):
    """Offense runs feed cross-target stack memory."""
    monkeypatch.setenv("OMEGA_LESSONS_HOME", str(tmp_path / "lessons.json"))
    from omega.core import techmem
    from omega.core.brain import DEFAULT_REGISTRY as reg

    class S:
        target = "http://127.0.0.1:1/"
        surface = {"techs": ["tomcat"], "params": ["q"]}
        log = None

    os.environ["PTK_OFFENSE"] = "1"
    try:
        reg.get("offense.hackwave").fn(S())
    finally:
        os.environ.pop("PTK_OFFENSE", None)
    doc = techmem.consult_stack(["tomcat"])
    assert doc["worked"] or doc["blocked"]  # outcome recorded either way
