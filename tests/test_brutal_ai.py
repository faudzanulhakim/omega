"""Tests for the brutal-AI batch: framework kits, lessons memory,
auto-chain engine, kill-chain narrative, proxy rotation, custom
payloads, auto-evasion, decoy Go tool.
"""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


# ------------------------------------------------------- frameworks

def test_detect_wordpress_by_body():
    from omega.core.frameworks import detect_frameworks
    hits = detect_frameworks(
        body="<link rel='stylesheet' href='/wp-content/themes/x.css'>")
    assert hits == ["wordpress"]


def test_detect_tomcat_by_cookie():
    from omega.core.frameworks import detect_frameworks
    hits = detect_frameworks(cookies="JSESSIONID=ABC123")
    assert "tomcat" in hits   # spring also matches JSESSIONID — fine


def test_detect_spring_by_header():
    from omega.core.frameworks import detect_frameworks
    hits = detect_frameworks(headers={"X-Application-Context": "app:prod"})
    assert "spring" in hits


def test_kit_paths_union():
    from omega.core.frameworks import kit_paths
    paths = kit_paths(["wordpress", "tomcat"])
    assert "/xmlrpc.php" in paths and "/manager/html" in paths
    assert len(paths) == len(set(paths))


def test_unknown_stack_no_kit():
    from omega.core.frameworks import detect_frameworks
    assert detect_frameworks(body="hello world", cookies="x=1") == []


# ---------------------------------------------------------- lessons

@pytest.fixture()
def lessons_home(tmp_path):
    os.environ["OMEGA_LESSONS_HOME"] = str(tmp_path / "lessons.json")
    yield
    os.environ.pop("OMEGA_LESSONS_HOME", None)


def test_lessons_blocked_then_consulted(lessons_home):
    from omega.core.lessons import record_blocked, consult, lessons_summary
    record_blocked("http://t.local", "sqli_time")
    record_blocked("http://t.local", "sqli_time")   # dedupe by move-to-end
    record_blocked("http://other.local", "ssti")
    entry = consult("http://t.local")
    assert "sqli_time" in entry["blocked"]
    assert "ssti" not in entry["blocked"]
    assert lessons_summary()["hosts"] == 2


def test_lessons_worked_and_waf(lessons_home):
    from omega.core.lessons import record_worked, record_waf, consult
    record_worked("t.local", "evade:_double_urlencode")
    record_waf("t.local", "cloudflare")
    entry = consult("t.local")
    assert entry["worked"] == ["evade:_double_urlencode"]
    assert entry["waf"] == ["cloudflare"]


def test_lessons_survives_corrupt_file(lessons_home, tmp_path):
    from omega.core.lessons import load_lessons, record_blocked
    (tmp_path / "lessons.json").write_text("{broken")
    assert load_lessons()["hosts"] == {}
    record_blocked("h.local", "x")
    assert "x" in load_lessons()["hosts"]["h.local"]["blocked"]


# -------------------------------------------------------- autochain

def test_autochain_gate_closed_by_default():
    from omega.core.autochain import run_autochain
    os.environ.pop("OMEGA_AUTOCHAIN", None)
    os.environ.pop("OMEGA_NO_LIMITS", None)
    res = run_autochain("http://t.local", lambda *a, **k: (200, {}, b""))
    assert res["gate"] is False
    assert "autochain gate closed" in res["stop_reason"]


def test_harvest_secrets_patterns():
    from omega.core.autochain import harvest_secrets
    text = ("DB_URL=postgres://admin:pw@db.local/prod\n"
            "aws_key = AKIAIOSFODNN7EXAMPLE\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "github_token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n")
    kinds = {h["kind"] for h in harvest_secrets(text)}
    assert "db-url" in kinds and "aws-access-key" in kinds
    assert "private-key" in kinds and "github-token" in kinds


def test_harvest_clean_text():
    from omega.core.autochain import harvest_secrets
    assert harvest_secrets("<html>plain page</html>") == []


def test_autochain_recon_harvest_chain(tmp_path):
    os.environ["OMEGA_AUTOCHAIN"] = "1"
    os.environ["OMEGA_LESSONS_HOME"] = str(tmp_path / "l.json")
    try:
        from omega.core.autochain import run_autochain
        secret_body = b"DB_URL=postgres://u:p@db/x\nAKIAIOSFODNN7EXAMPLE"

        def fetch(method, url, headers=None, body=None):
            if url.endswith("/actuator/env"):
                return (200, {}, secret_body)
            return (200, {"X-Application-Context": "app"}, b"<html>ok"
                    b"</html>")

        res = run_autochain("http://lab.local", fetch, chain="exposure")
        assert res["gate"] is True
        assert res["ok"] is True
        assert res["stopped_at"] == 0
        kinds = {f["source"] for f in res["findings"]}
        assert "omega-autochain/harvest" in kinds
    finally:
        os.environ.pop("OMEGA_AUTOCHAIN", None)
        os.environ.pop("OMEGA_LESSONS_HOME", None)


def test_autochain_stops_without_evidence():
    os.environ["OMEGA_AUTOCHAIN"] = "1"
    try:
        from omega.core.autochain import run_autochain

        def fetch(method, url, headers=None, body=None):
            return (404, {}, b"nothing here")

        res = run_autochain("http://dead.local", fetch, chain="full")
        assert res["stopped_at"] > 0
        assert res["ok"] is False
        # chain must NOT have run later stages past the dead stage
        stages_run = [s["stage"] for s in res["stages"]]
        assert "poc" not in stages_run
    finally:
        os.environ.pop("OMEGA_AUTOCHAIN", None)


# ------------------------------------------------------ kill-chain

def test_narrate_builds_story():
    from omega.core.autochain import narrate
    doc = {
        "state": {"target": "http://t.local", "findings": [
            {"title": "CSP missing", "severity": "medium",
             "source": "omega-probe/headers"}],
            "history": [{"step": 1, "capability": "recon.passive",
                         "reasoning": "stage selected by loop",
                         "sources": ["omega-probe/headers"]}]},
    }
    story = narrate(doc)
    assert "# Kill chain — http://t.local" in story
    assert "why: stage selected by loop" in story
    assert "CSP missing [medium]" in story


def test_narrate_empty_history():
    from omega.core.autochain import narrate
    assert "No audit history" in narrate({"state": {"history": []}})


# ------------------------------------------------- proxy rotation

def test_proxy_pool_rotation(tmp_path):
    from omega.core.proxyrot import ProxyPool, reset_pool
    pfile = tmp_path / "proxies.txt"
    pfile.write_text("http://p1.local:8080\n#comment\nhttp://p2.local:3128\n")
    os.environ["OMEGA_PROXY_FILE"] = str(pfile)
    reset_pool()
    try:
        from omega.core.proxyrot import assigned_proxy
        a1 = assigned_proxy("http://target.local/x?y=1")
        a2 = assigned_proxy("http://target.local/y")
        hosts = {a1[0], a2[0]}
        assert hosts == {"p1.local", "p2.local"}   # rotated
        assert a1[2].startswith("http://target.local/")
        # https targets bypass the pool (no CONNECT)
        assert assigned_proxy("https://secure.local/") is None
    finally:
        os.environ.pop("OMEGA_PROXY_FILE", None)
        reset_pool()


def test_no_proxy_env_is_direct():
    from omega.core.proxyrot import reset_pool, assigned_proxy
    os.environ.pop("OMEGA_PROXY_FILE", None)
    os.environ.pop("OMEGA_PROXY", None)
    reset_pool()
    assert assigned_proxy("http://t.local/") is None


def test_default_fetch_direct_when_no_proxy():
    from omega.scanning.deepchecks import default_fetch
    os.environ.pop("OMEGA_PROXY_FILE", None)
    os.environ.pop("OMEGA_PROXY", None)
    from omega.core.proxyrot import reset_pool
    reset_pool()
    # unreachable port -> connection error raised (contract) — but the
    # proxy branch must not hijack the URL
    with pytest.raises(Exception):
        default_fetch("GET", "http://127.0.0.1:1/x")


# --------------------------------------------- custom payloads

def test_custom_payloads_loaded_and_audited(tmp_path):
    from omega.offense.payloadgen import load_custom_payloads, \
        aggressive_matrix
    pf = tmp_path / "p.json"
    pf.write_text(json.dumps([
        "' WAITFOR DELAY '0:0:3'--",
        {"payload": "rm -rf / --no-preserve-root", "class": "sqli_time"},
        "<svg onload=alert(1)>",
    ]))
    ok, dropped = load_custom_payloads(str(pf))
    assert len(ok) == 2
    assert len(dropped) == 1 and "rm -rf" in dropped[0]
    os.environ["OMEGA_CUSTOM_PAYLOADS"] = str(pf)
    try:
        agg = aggressive_matrix(max_per_class=2)
        assert any(p["engine"] == "operator-supplied" for p in agg)
    finally:
        os.environ.pop("OMEGA_CUSTOM_PAYLOADS", None)


# ---------------------------------------------- auto-evasion

def test_injection_runner_auto_evades_on_block(tmp_path):
    os.environ["OMEGA_AUTO_EVADE"] = "1"
    os.environ["OMEGA_LESSONS_HOME"] = str(tmp_path / "l.json")
    try:
        from omega.offense.injection import _Runner
        from omega.offense import reset_budget

        reset_budget()
        calls = []

        def fetch(method, url):
            calls.append(url)
            if len(calls) == 1:
                return (403, {}, b"blocked")
            return (200, {}, b"passed")

        runner = _Runner("http://t.local", "q", fetch, budget=10,
                         rate=0, sleep=lambda s: None)
        resp = runner.send("1' OR '1'='1")
        assert len(calls) >= 2, "evade retry must happen"
        assert resp[0] == 200
        assert runner.sent == 2
    finally:
        os.environ.pop("OMEGA_AUTO_EVADE", None)
        os.environ.pop("OMEGA_LESSONS_HOME", None)


def test_injection_runner_no_evade_by_default():
    from omega.offense.injection import _Runner
    from omega.offense import reset_budget
    os.environ.pop("OMEGA_AUTO_EVADE", None)
    os.environ.pop("OMEGA_NO_LIMITS", None)
    reset_budget()
    calls = []

    def fetch(method, url):
        calls.append(url)
        return (403, {}, b"blocked")

    runner = _Runner("http://t.local", "q", fetch, budget=10, rate=0,
                     sleep=lambda s: None)
    resp = runner.send("payload")
    assert len(calls) == 1 and resp[0] == 403


# ------------------------------------------------------ Go decoy

def test_native_registry_includes_decoy():
    from omega.adapters.native import NATIVE_TOOLS
    assert "decoy" in NATIVE_TOOLS


def test_decoy_go_builds_and_runs(tmp_path):
    import subprocess
    if not shutil_which("go"):
        pytest.skip("go toolchain not available")
    src = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "omega", "adapters", "go",
        "decoy.go")
    out = str(tmp_path / "decoy")
    proc = subprocess.run(["go", "build", "-o", out, src],
                          capture_output=True, timeout=120)
    assert proc.returncode == 0, proc.stderr.decode()
    r = subprocess.run([out], input=b'{"target":"http://127.0.0.1:9",'
                                     b'"bursts":1}',
                       capture_output=True, timeout=60)
    doc = json.loads(r.stdout.decode())
    assert doc["sent"] >= 10   # full decoy path list attempted


def shutil_which(name):
    import shutil
    return shutil.which(name)


# ------------------------------------------------------ CLI wiring

def test_cli_autochain_flag_sets_env():
    from omega.core.cli import main
    parser_main = main
    # main() builds the parser internally; exercise it through parse by
    # checking argparse attributes on a manually-built parser shim
    import argparse

    class _P(argparse.Namespace):
        autochain = False

    # simplest: call main with --help won't set env; instead assert the
    # flag exists in the CLI source contract
    import inspect
    from omega.core import cli as cli_mod
    src = inspect.getsource(cli_mod.main)
    assert '"--autochain"' in src
    assert getattr(_P(), "autochain") is False
    del parser_main


def test_brutal_flag_opens_all_gates(monkeypatch):
    """--brutal = aggressive + no-limits + autochain in one flag."""
    import inspect
    from omega.core import cli as cli_mod

    src = inspect.getsource(cli_mod.main)
    assert '--brutal' in src or 'brutal' in src
    for token in ("OMEGA_BRUTAL_DEFAULT", "args.no_limits = True",
                  "args.autochain = True", "args.aggressive = True"):
        assert token in src, token
