"""Tests for batch-17 DEEPFROST: autodeep, fpkiller, sessionlife,
smartpace, evidencepack, multiorch, selftest, reporthtml."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


class R:
    def __init__(self, text="", status=200, headers=None):
        self.status = status
        self.text = text
        self.headers = headers or {}


class State:
    def __init__(self, target="http://t.local", surface=None,
                 findings=None):
        self.target = target
        self.surface = surface or {}
        self.findings = findings or []
        self.history = []
        self.log = None


def gate_env():
    os.environ["PTK_OFFENSE"] = "1"


def ungate():
    os.environ.pop("PTK_OFFENSE", None)


def test_sessionlife_gate():
    from omega.offensive.offense.sessionlife import run_sessionlife
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        out = run_sessionlife("http://x/", fetch=lambda *a, **k: R("x"))
        assert "PTK_OFFENSE" in out["note"]
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


# ------------------------------------------------------------ autodeep
def test_autodeep_skips_gated_when_gate_closed():
    from omega.core.autodeep import plan_engagement
    from omega.core.brain import DEFAULT_REGISTRY as reg
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        plan = plan_engagement(reg, surface={"gated": False})
        skips = [s for w in plan for s in w["skip"]]
        assert any(cap == "offense.jsmine" for cap, _ in skips)
        surface_wave = next(w for w in plan if w["wave"] == "surface")
        assert "core.jsmine" not in surface_wave["caps"]
        report_wave = next(w for w in plan if w["wave"] == "report")
        assert "core.pocgen" in report_wave["caps"]  # report always on
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


def test_autodeep_executes_report_wave_and_accumulates():
    from omega.core.autodeep import plan_engagement, execute_plan
    from omega.core.brain import DEFAULT_REGISTRY as reg
    state = State(findings=[{"title": "x", "severity": "HIGH",
                             "cwe": "CWE-79", "location": "/a"}])
    plan = plan_engagement(reg, surface={"gated": False},
                           max_waves=6)
    doc = execute_plan(reg, state, plan)
    assert doc["total_findings"] >= 1
    assert any(e["wave"] == "report" for e in doc["executed"])
    assert len(state.history) == len(doc["executed"])


# ------------------------------------------------------------ fpkiller
def test_fpkiller_strong_vs_weak():
    from omega.core.fpkiller import corroborate, render_corroboration
    strong = {"title": "marker X observed, identical response",
              "evidence": "raw", "location": "/a", "cwe": "CWE-79",
              "verification": "confirmed"}
    weak = {"title": "something", "evidence": "", "location": "",
            "verification": "candidate"}
    corr = corroborate([strong, weak])
    assert corr[0]["strength"] == "strong"
    assert corr[1]["strength"] == "weak"
    assert corr[1]["missing"]
    txt = render_corroboration(corr)
    assert "1 strong / 1 weak" in txt and "WEAK: something" in txt


# --------------------------------------------------------- sessionlife
def test_sessionlife_logout_not_invalidating():
    from omega.offensive.offense.sessionlife import run_sessionlife
    logged_out = {"done": False}

    def fetch(url, headers=None, method=None):
        if url.endswith("/logout"):
            logged_out["done"] = True
            return R("ok", 200)
        if url.endswith("/api/me"):
            # session stays valid even after logout = flaw
            return R('{"me":1}', 200)
        return R("", 404)

    gate_env()
    try:
        out = run_sessionlife("http://t.local", fetch=fetch,
                              auth_headers={"Cookie": "s=abc"})
    finally:
        ungate()
    assert any("does NOT invalidate" in f["title"]
               for f in out["findings"])
    assert logged_out["done"]


def test_sessionlife_reset_token_reuse():
    from omega.offensive.offense.sessionlife import run_sessionlife
    gate_env()
    try:
        out = run_sessionlife("http://t.local", fetch=lambda *a, **k: R(""),
                              reset_tokens=["abcdef123456",
                                            "abcdef123456"])
    finally:
        ungate()
    assert any("REUSED" in f["title"] for f in out["findings"])


# ------------------------------------------------------------ smartpace
def test_smartpace_recommendations():
    from omega.core.smartpace import measure_pace, recommend
    def fetch_429(url):
        return R("", 429)
    def fetch_healthy(url):
        return R("ok", 200)
    pace, why = recommend(measure_pace(fetch_429, "u", samples=2,
                                       gap_s=0))
    assert pace == 2.0 and "429" in why
    pace, why = recommend(measure_pace(fetch_healthy, "u", samples=3,
                                       gap_s=0))
    assert pace == 0.2 and "healthy" in why


# -------------------------------------------------------- evidencepack
def test_evidencepack_files_and_redaction(tmp_path, monkeypatch):
    from omega.reporting.evidencepack import pack_findings
    monkeypatch.setenv("OMEGA_EVIDENCE_HOME", str(tmp_path))
    findings = [{"title": "git exposed", "severity": "HIGH",
                 "cwe": "CWE-538", "location": "/.git/HEAD",
                 "evidence": "ref: refs/heads main password=hunter2",
                 "verification": "candidate"}]
    pack = pack_findings(findings, target="http://t.local")
    assert pack["count"] == 1
    raw = open(pack["files"][0]).read()
    assert "hunter2" not in raw
    assert "REDACTED" in raw
    idx = json.load(open(pack["index_file"]))
    assert idx["count"] == 1 and idx["items"][0]["n"] == 1


# ------------------------------------------------------------ multiorch
def test_multiorch_portfolio_ranked():
    from omega.core.multiorch import render_portfolio, run_portfolio
    from omega.core.brain import DEFAULT_REGISTRY as reg

    def make_state(t):
        f = ([{"title": "crit", "severity": "CRITICAL"}]
             if "bad" in t else [])
        return State(target=t, findings=f,
                     surface={"gated": False})

    doc = run_portfolio(reg, ["http://bad.local", "http://ok.local"],
                        make_state)
    assert doc["portfolio"][0]["target"] == "http://bad.local"
    txt = render_portfolio(doc)
    assert "ranked" in txt and "risk mass" in txt


# ------------------------------------------------------------- selftest
def test_selftest_mock_detection():
    from omega.core.selftest import run_selftests, render_selftests
    res = run_selftests()
    txt = render_selftests(res)
    assert "self-tests" in txt
    # every module must PROVE its detection path on the mock
    for m, r in res.items():
        assert r.get("ok"), f"{m} failed self-test: {r}"


# ----------------------------------------------------------- reporthtml
def test_reporthtml_dark_and_filter():
    from omega.reporting.reporthtml import render_html
    html_doc = render_html(
        [{"title": "git exposed", "severity": "HIGH", "cwe": "CWE-538",
          "location": "/.git/HEAD", "evidence": "ref:",
          "verification": "candidate"}],
        target="http://t.local")
    assert "<!doctype html>" in html_doc.lower()
    assert "0d1117" in html_doc  # dark theme
    assert "show('high')" in html_doc
    assert "git exposed" in html_doc


# -------------------------------------------------------- brain / CLI
def test_brain_caps_197():
    from omega.core.brain import DEFAULT_REGISTRY as reg
    assert len(reg.ids()) == 197
    for cid in ("core.autodeep", "core.fpkiller", "offense.sessionlife",
                "core.smartpace", "core.evidencepack", "core.multiorch",
                "core.selftest", "core.reporthtml"):
        assert reg.get(cid) is not None


def test_cli_deepfrost_flags():
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
    for flag in ("--auto-deep", "--fp-killer", "--session-life",
                 "--smart-pace", "--evidence-pack", "--portfolio",
                 "--self-test", "--html-report"):
        assert flag in txt
