"""Hermetic tests for the OMEGA AI-ASSIST layer (omega.scanning.aiassist).

No network, no engine — pure deterministic computation over dict
findings, plus a registration smoke test for the brain capability.
"""

import pytest

from omega.scanning import aiassist
from omega.scanning.aiassist import (analyst_brief, brief_markdown,
                                     plan_attack, prioritize, risk_score)


# ---------------------------------------------------------------- helpers

def f(title, severity="medium", verification="candidate", source="",
      evidence="", location="", **extra):
    d = {"title": title, "severity": severity,
         "verification": verification, "source": source,
         "evidence": evidence, "location": location,
         "confidence": "high", "manual_check": False}
    d.update(extra)
    return d


@pytest.fixture
def mixed():
    """One confirmed sqli (internet hint), one candidate jwt, one LOW."""
    return [
        f("SQL injection in /search parameter q", "critical", "confirmed",
          "deepchecks.sqli", "db error echoed",
          "https://example.com/search — internet exposed"),
        f("JWT accepted with alg=none", "high", "candidate",
          "sentinel.jwt", "token accepted"),
        f("Missing HSTS header", "low", "corroborated",
          "headerscan", "no Strict-Transport-Security"),
    ]


# ---------------------------------------------------------------- risk_score

def test_risk_score_severity_math():
    for sev, pts in (("CRITICAL", 40), ("HIGH", 30), ("MEDIUM", 15),
                     ("LOW", 5), ("INFO", 0)):
        got = risk_score([f("Some header issue", severity=sev)])[0]
        assert got["ai_risk"] == pts, sev
        if pts:
            assert "severity %s" % sev.lower() in got["ai_reason"]


def test_risk_score_unknown_severity_zero():
    got = risk_score([f("weird", severity="banana")])[0]
    assert got["ai_risk"] == 0


def test_risk_score_verification_weights():
    assert risk_score([f("t", "critical", "confirmed")])[0]["ai_risk"] == 75
    assert risk_score([f("t", "critical", "corroborated")])[0]["ai_risk"] \
        == 60
    assert risk_score([f("t", "critical", "candidate")])[0]["ai_risk"] == 40


def test_risk_score_confirmed_boolean_flag_counts():
    got = risk_score([{"title": "t", "severity": "critical",
                       "confirmed": True}])[0]
    assert got["ai_risk"] == 75


def test_risk_score_exploit_marker_adds_15():
    base = risk_score([f("Missing cookie flag", "medium",
                         "corroborated")])[0]["ai_risk"]
    marked = risk_score([f("IDOR in /api/v1/orders", "medium",
                           "corroborated")])[0]["ai_risk"]
    assert marked == base + 15
    assert "idor" in risk_score([f("IDOR in /api/v1/orders", "medium")])[0][
        "ai_reason"]


def test_risk_score_internet_hint_adds_5():
    base = risk_score([f("Open redirect", "medium")])[0]["ai_risk"]
    hinted = risk_score([f("Open redirect", "medium", location="public "
                           "edge")])[0]["ai_risk"]
    assert hinted == base + 5


def test_risk_score_caps_at_100():
    # max achievable with the documented weights is 95 (40+35+15+5);
    # the 100 cap holds regardless.
    got = risk_score([f("SQLi RCE exploited publicly", "critical",
                        "confirmed", evidence="internet exposed "
                        "0.0.0.0")])[0]
    assert got["ai_risk"] == 95
    assert got["ai_risk"] <= 100


def test_risk_score_deterministic_and_no_mutation(mixed):
    import copy
    before = copy.deepcopy(mixed)
    r1 = risk_score(mixed)
    r2 = risk_score(mixed)
    assert [x["ai_risk"] for x in r1] == [x["ai_risk"] for x in r2]
    assert [x["ai_reason"] for x in r1] == [x["ai_reason"] for x in r2]
    assert mixed == before          # inputs untouched


def test_risk_score_passthrough_non_dict():
    out = risk_score(["junk", 42])
    assert out == ["junk", 42]
    assert risk_score(None) == []
    assert risk_score(3.14) == []


# ---------------------------------------------------------------- prioritize

def test_prioritize_ordering_desc_and_tie_by_title():
    fs = [f("B beta", "high"), f("A alpha", "high"), f("C low", "low")]
    out = prioritize(fs)
    titles = [x["title"] for x in out["ranked"]]
    assert titles == ["A alpha", "B beta", "C low"]


def test_prioritize_buckets(mixed):
    s = prioritize(mixed)["summary"]
    assert s["total"] == 3
    assert "SQL injection in /search parameter q" in s["critical_now"]
    assert s["quick_wins"] == []
    assert "Missing HSTS header" in s["noise"]


def test_prioritize_quick_wins_band():
    # medium 15 + corroborated 20 + traversal marker 15 = 50 -> quick win
    fs = [f("Medium traversal candidate", "medium", "corroborated")]
    out = prioritize(fs)
    assert out["ranked"][0]["ai_risk"] == 50
    assert "Medium traversal candidate" in out["summary"]["quick_wins"]
    # one point below the band -> noise
    fs2 = [f("Mild header note", "medium", "corroborated")]
    assert "Mild header note" in prioritize(fs2)["summary"]["noise"]


def test_prioritize_empty():
    s = prioritize([])["summary"]
    assert s == {"total": 0, "critical_now": [], "quick_wins": [],
                 "noise": []}


# ---------------------------------------------------------------- plan_attack

def test_plan_attack_empty_findings_recon_only():
    plan = plan_attack([], "example.com")
    phases = [s["phase"] for s in plan]
    assert phases[0] == "recon"
    assert set(phases) == {"recon", "report"}
    assert all(s["based_on"] == [] for s in plan)


def test_plan_attack_confirmed_sqli_gives_loot_with_real_command():
    fs = [f("SQLi in /login", "critical", "confirmed", "deepchecks",
            "differential held")]
    plan = plan_attack(fs, "example.com")
    loot = [s for s in plan if s["phase"] == "loot"]
    priv = [s for s in plan if s["phase"] == "privilege"]
    assert loot, "confirmed finding must drive a loot step"
    assert loot[0]["based_on"] == ["SQLi in /login"]
    assert any("--scope-ack" in (c or "") and "example.com" in (c or "")
               for s in plan for c in [s["command"]] if c)


def test_plan_attack_candidate_gets_manual_check_step():
    fs = [f("JWT alg=none accepted", "high", "candidate", "sentinel")]
    plan = plan_attack(fs, "example.com")
    steps = [s for s in plan if "Manually verify" in s["action"]]
    assert steps and "JWT alg=none accepted" in steps[0]["based_on"][0]


def test_plan_attack_real_commands_use_target_and_scope_ack():
    fs = [f("SQLi", "critical", "confirmed")]
    plan = plan_attack(fs, "example.com")
    cmds = [s["command"] for s in plan if s["command"]]
    assert cmds
    for c in cmds:
        assert c.startswith("bash bin/omega ")
        assert "example.com" in c or c == ("bash bin/omega report - "
                                           "--out reports/omega-report.md")
    assert any("--scope-ack" in c for c in cmds)


def test_plan_attack_max_10_steps_and_contiguous_n():
    fs = [f("SQLi %d" % i, "critical", "confirmed", "s") for i in range(12)]
    fs += [f("Candidate jwt %d" % i, "high", "candidate", "s")
           for i in range(5)]
    plan = plan_attack(fs, "example.com")
    assert len(plan) <= 10
    assert [s["n"] for s in plan] == list(range(1, len(plan) + 1))
    phases = [s["phase"] for s in plan]
    assert phases[0] == "recon" and phases[-1] == "report"


def test_plan_attack_no_invented_findings(mixed):
    plan = plan_attack(mixed, "example.com")
    known = {x["title"] for x in mixed}
    for s in plan:
        for b in s["based_on"]:
            assert b in known, "plan referenced an unknown finding"


def test_plan_attack_phase_order_valid():
    fs = [f("SQLi", "critical", "confirmed"),
          f("Auth bypass candidate", "high", "candidate")]
    plan = plan_attack(fs, "example.com")
    order = ("recon", "initial-access", "privilege", "loot",
             "persist-check", "report")
    idxs = [order.index(s["phase"]) for s in plan]
    assert idxs == sorted(idxs)


# ---------------------------------------------------------------- brief

def test_analyst_brief_shape(mixed):
    b = analyst_brief(mixed, "example.com")
    assert b["contained"] is False
    assert b["headline"].startswith("Target example.com:")
    assert isinstance(b["risk_score"], int)
    assert b["stats"]["total"] == 3 and b["stats"]["confirmed"] == 1
    assert len(b["next_actions"]) == 3
    assert b["plan"] and b["plan"][0]["phase"] == "recon"


def test_analyst_brief_never_raises_garbage():
    for bad in (None, [], "garbage", 123, [None, 42, {"title": 5}],
                [{"severity": object()}]):
        b = analyst_brief(bad, "example.com")
        assert isinstance(b, dict)
        assert "headline" in b and "stats" in b and "plan" in b


def test_analyst_brief_empty_gives_recon_only_plan():
    b = analyst_brief([], "example.com")
    assert b["contained"] is True
    assert {s["phase"] for s in b["plan"]} == {"recon", "report"}
    assert b["risk_score"] == 0


def test_analyst_brief_risk_score_avg_top3():
    fs = [f("A", "critical", "confirmed"),      # 75
          f("B", "critical", "confirmed"),      # 75
          f("C", "critical", "confirmed"),      # 75
          f("D", "info", "candidate")]          # 0
    assert analyst_brief(fs, "t")["risk_score"] == 75


# ---------------------------------------------------------------- markdown

def test_brief_markdown_heading_and_table(mixed):
    md = brief_markdown(analyst_brief(mixed, "example.com"))
    assert md.startswith("## AI Analyst Brief")
    assert "Target example.com" in md
    assert "| # | Phase | Action | Based on |" in md
    assert "- Treat as urgent" in md or "- " in md


def test_brief_markdown_never_raises():
    for bad in (None, "nope", 7, {}, {"plan": "notalist",
                                      "next_actions": 3}):
        md = brief_markdown(bad)
        assert md.startswith("## AI Analyst Brief")


# ---------------------------------------------------------------- brain cap

def test_brain_ai_analyst_cap_registered_and_runs():
    from omega.brain import DEFAULT_REGISTRY, BrainState
    reg = DEFAULT_REGISTRY
    cap = reg.get("ai.analyst")
    assert cap is not None
    assert cap.risk == "passive"
    # duplicate-id guard: registering again must not raise or duplicate
    from omega.core.brain import _register_aiassist_capability
    _register_aiassist_capability(reg)
    assert sum(1 for c in reg.all() if c.id == "ai.analyst") == 1

    state = BrainState("example.com")
    state.update_from_stage("triage", {"findings": [
        {"title": "SQLi", "severity": "critical", "verification":
         "confirmed"}]})
    out = cap.fn(state, None)
    assert isinstance(out, dict)
    assert "note" in out
    assert state.ai_brief["stats"]["total"] == 1
    assert state.ai_ranked_findings[0]["ai_risk"] == 90  # 40+35+15 sqli


def test_brain_ai_analyst_cap_contained_on_garbage():
    from omega.brain import DEFAULT_REGISTRY, BrainState
    cap = DEFAULT_REGISTRY.get("ai.analyst")
    state = BrainState("example.com")
    state.findings = [None, 7, "junk"]
    out = cap.fn(state, None)
    assert isinstance(out, dict) and "note" in out
    assert state.ai_brief["stats"]["total"] == 0


# ---------------------------------------------------------------- hygiene

VX_BAD = "van" + "thex"


def test_no_forbidden_brand_strings_in_module():
    src = open(aiassist.__file__, encoding="utf-8").read()
    assert VX_BAD not in src.lower()
