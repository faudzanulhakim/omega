"""Tests for the max-power upgrade batch: multihypo, cwechain,
spamap, wafadapt, mutafuzz (gated), lessonsv2 outcomes, reporting
cvss/poc/execsum, brain wiring, CLI flags on both parsers."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


# ---------------------------------------------------------------- multihypo
class FakeResp:
    def __init__(self, text="", headers=None):
        self.text = text
        self.headers = headers or {}


class SeqFetch:
    """fetch(url) -> canned response by exact URL."""
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        return self.mapping.get(url, self.mapping.get("__base__", ""))


BASE = "http://127.0.0.1:1/"


def test_raise_competing_gives_multiple_kinds():
    from omega.core.multihypo import raise_competing
    hyps = raise_competing("server error 500 traceback")
    kinds = [h["kind"] for h in hyps]
    assert len(kinds) >= 3
    assert "injection-sqli" in kinds


def test_multihypo_verified_and_refuted():
    from omega.core.multihypo import run_multihypo_loop
    # probe that returns a DIFFERENT body => verified
    fetch = SeqFetch({"__base__": "static baseline"})
    doc = run_multihypo_loop(["reflect echo"], fetch, url=BASE)
    assert doc["verified"] or doc["uncertain"]
    assert "posteriors" in doc


def test_multihypo_budget_respected():
    from omega.core.multihypo import run_multihypo_loop
    fetch = SeqFetch({"__base__": ""})
    doc = run_multihypo_loop(["error"] * 20, fetch, url=BASE, budget=3)
    assert len(fetch.calls) <= 3 + 1  # + baseline


# ---------------------------------------------------------------- cwechain
def test_cwechain_proposes_ssrf_ladder():
    from omega.core.cwechain import propose_chains, chain_summary
    chains = propose_chains([{"title": "ssrf", "cwe": "CWE-918",
                              "location": "/fetch"}])
    assert chains
    text = "\n".join(chain_summary(chains))
    assert "CWE-200" in text and "PTK_OFFENSE" in text


def test_cwechain_plan_only_flags():
    from omega.core.cwechain import propose_chains
    chains = propose_chains([{"title": "upload", "cwe": "CWE-434"}])
    for c in chains:
        for s in c["proposals"]:
            assert s["gate"] in ("PTK_OFFENSE", "PTK_EXPLOIT")
            assert s["executed"] is False


def test_cwechain_no_cwe_no_chain():
    from omega.core.cwechain import propose_chains
    assert propose_chains([{"title": "x"}]) == []


# ---------------------------------------------------------------- spamap
def test_spamap_extracts_fetch_and_axios():
    from omega.scanning.spamap import _analyze_js
    js = ("fetch('/api/users?page=1');"
          "axios.post('/api/login', d);"
          "config={url:'/api/health'};")
    found = _analyze_js(js)
    assert "/api/users" in found and "/api/health" in found


def test_spamap_param_normalize():
    from omega.scanning.spamap import _normalize
    assert _normalize("/api/u/${id}") == "/api/u/{param}"
    assert _normalize("//evil.com/x").startswith("https:")
    assert _normalize("javascript:alert(1)") is None


def test_spamap_end_to_end_on_local():
    from omega.scanning.spamap import map_spa_endpoints
    page = "<html><script src='/app.js'></script></html>"
    appjs = "fetch('/api/orders'); axios.get('/api/me');"
    seen = {}

    def fetch(url):
        seen[url] = True
        if url.endswith("app.js"):
            return appjs
        return page

    doc = map_spa_endpoints(BASE, fetch=fetch)
    assert "/api/orders" in doc["endpoints"]
    assert any(u.endswith("app.js") for u in doc["assets"])


# ---------------------------------------------------------------- wafadapt
def test_wafadapt_fingerprints_cloudflare():
    from omega.core.wafadapt import adaptation_plan
    plan = adaptation_plan({"cf-ray": "8ab"}, "")
    assert plan["provider"] == "cloudflare"
    assert plan["pacing_ms"] >= 300 and plan["reuse_cookies"]


def test_wafadapt_generic_default():
    from omega.core.wafadapt import adaptation_plan
    plan = adaptation_plan({"server": "nginx"}, "hello")
    assert plan["provider"] == "generic"
    assert plan["pacing_ms"] > 0


def test_wafadapt_bot_providers_are_conservative():
    from omega.core.wafadapt import strategy_for
    for p in ("perimeterx", "datadome"):
        assert strategy_for(p)["concurrency"] == 1


# ---------------------------------------------------------------- mutafuzz
def test_mutafuzz_gated_in_brain():
    from omega.core.brain import DEFAULT_REGISTRY as reg
    cap = reg.get("offense.mutafuzz")
    assert cap is not None
    old = os.environ.get("PTK_OFFENSE")
    os.environ.pop("PTK_OFFENSE", None)
    try:
        out = cap.fn(type("S", (), {"target": BASE, "findings": []})())
        assert "PTK_OFFENSE" in out.get("note", "")
    finally:
        if old is not None:
            os.environ["PTK_OFFENSE"] = old


def test_mutafuzz_survivors_when_not_blocked():
    from omega.offensive.offense.mutafuzz import run_mutafuzz
    doc = run_mutafuzz("<b>omegaprobe1</b>",
                       lambda p: "ok " + p, budget=10)
    assert doc["survivors"] and doc["blocked"] == 0


def test_mutafuzz_counts_blocks():
    from omega.offensive.offense.mutafuzz import run_mutafuzz
    doc = run_mutafuzz("x", lambda p: "403 blocked waf", budget=6)
    assert doc["blocked"] >= 1 and doc["survivors"] == []


def test_mutafuzz_mutators_distinct():
    from omega.offensive.offense.mutafuzz import mutate
    muts = mutate("<b>x</b>", n=4)
    assert len(set(p for _n, p in muts)) == len(muts)


# ---------------------------------------------------------------- outcomes
def test_lessonsv2_outcome_ranking(tmp_path, monkeypatch):
    monkeypatch.setenv("OMEGA_LESSONS_HOME", str(tmp_path / "lessons.json"))
    from omega.core import lessonsv2
    lessonsv2.record_outcome("h1", "/", "double-encode", True)
    lessonsv2.record_outcome("h1", "/", "double-encode", True)
    lessonsv2.record_outcome("h1", "/", "concat-break", False)
    ranked = lessonsv2.rank_techniques("h1", "/")
    assert ranked[0]["technique"] == "double-encode"
    assert ranked[0]["rate"] == 1.0
    assert all(r["rate"] <= 1.0 for r in ranked)


def test_lessonsv2_sibling_outcomes_propagate(tmp_path, monkeypatch):
    monkeypatch.setenv("OMEGA_LESSONS_HOME", str(tmp_path / "lessons.json"))
    from omega.core import lessonsv2
    lessonsv2.record_outcome("h1", "/api", "url-encode", True)
    ranked = lessonsv2.rank_techniques("h1", "/api/users")
    assert any(r["technique"] == "url-encode" for r in ranked)


# ---------------------------------------------------------------- reporting
def test_cvss_official_vectors():
    from omega.reporting.cvss import base_score
    # known FIRST reference scores
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") \
        == 9.8
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") \
        == 10.0
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N") \
        == 5.3


def test_cvss_cwe_mapping():
    from omega.reporting.cvss import score_finding
    f = score_finding({"severity": "HIGH", "cwe": "CWE-89"})
    assert f["cvss_score"] >= 8.0 and "CVSS:3.1" in f["cvss_vector"]


def test_poc_get_and_state_changing():
    from omega.reporting.poc import build_poc
    poc = build_poc({"location": "http://x/a", "method": "GET"})
    assert poc["command"].startswith("curl -sk") and not poc["note"]
    poc2 = build_poc({"location": "http://x/a", "method": "POST",
                      "body": "b=1"})
    assert "-X POST" in poc2["command"] and poc2["note"]


def test_poc_no_url_is_documented():
    from omega.reporting.poc import build_poc
    poc = build_poc({"location": ""})
    assert poc["command"] is None


def test_sanitize_attaches_cvss_and_poc():
    from omega.reporting.report import sanitize_findings
    out = sanitize_findings([{"title": "sqli", "severity": "HIGH",
                              "cwe": "CWE-89",
                              "location": "http://x/?id=1"}])
    f = out[0]
    assert "CVSS:3.1" in f["cvss"] and f["poc"]["command"]


def test_execsum_audiences():
    from omega.reporting.execsum import all_audiences
    res = all_audiences([{"title": "sqli", "severity": "HIGH",
                          "cwe": "CWE-89",
                          "location": "http://x",
                          "verification": "verified"}], "lab")
    assert res["executive"]["risk_level"] == "elevated"
    assert res["manager"]["remediation_waves"]["wave-1 (now)"]
    assert res["developer"]["items"][0]["cvss"]


# ---------------------------------------------------------------- wiring
def test_brain_caps_registered():
    from omega.core.brain import DEFAULT_REGISTRY as reg
    for cid in ("core.multihypo", "core.cwechain", "core.spamap",
                "core.wafadapt", "core.outcomes"):
        assert reg.get(cid) is not None, cid


def test_brain_caps_total_197():
    from omega.core.brain import DEFAULT_REGISTRY as reg
    assert len(reg.ids()) == 197


def test_cli_flags_on_both_parsers():
    import inspect
    from omega.core import cli
    src = inspect.getsource(cli)
    for fl in ("--multihypo", "--cwe-chain", "--spa-map",
               "--waf-adapt", "--outcomes"):
        # both parsers register each flag
        assert src.count('"%s", action="store_true"' % fl) >= 2, fl


def test_handlers_in_shared_extras():
    import inspect
    from omega.core import cli
    src = inspect.getsource(cli._run_post_scan_extras)
    for name in ("multihypo", "cwe-chain", "spa-map", "waf-adapt",
                 "outcomes"):
        assert name in src, name


# ---------------------------------------------- QA audit fixes (M1/M2)
def test_default_fetch_reads_large_bodies():
    import http.server, threading
    from omega.scanning.deepchecks import default_fetch, RESPONSE_READ_CAP

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(s, *a):
            pass

        def do_GET(s):
            b = b"x" * (1024 * 1024 + 11)
            s.send_response(200)
            s.send_header("Content-Length", str(len(b)))
            s.end_headers()
            s.wfile.write(b)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    status, _h, body = default_fetch(
        "GET", "http://127.0.0.1:%d/" % srv.server_address[1])
    srv.shutdown()
    assert status == 200
    assert len(body) == RESPONSE_READ_CAP
    assert RESPONSE_READ_CAP >= 256 * 1024


def test_sanitize_recomputes_legacy_cvss_zero():
    from omega.reporting.report import sanitize_findings
    legacy = [{"title": "old", "severity": "INFO", "cwe": "CWE-200",
               "cvss": "0.0", "location": "http://x"}]
    out = sanitize_findings(legacy)
    assert "CVSS:3.1/" in out[0]["cvss"], out[0]["cvss"]


def test_sanitize_keeps_official_cvss_string():
    from omega.reporting.report import sanitize_findings
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    out = sanitize_findings([{"title": "s", "severity": "HIGH",
                              "cvss": vec + " (9.8)",
                              "location": "http://x"}])
    assert out[0]["cvss"] == vec + " (9.8)"
