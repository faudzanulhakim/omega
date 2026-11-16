"""Hermetic tests for the OMEGA brain (engine stubbed — never touches
ENGINE, no network, tmpdir-local)."""

import sys
import types

import pytest

from omega import brain
from omega.brain import (Brain, BrainState, Capability, CapabilityRegistry,
                         decide, default_registry, render_brain_report,
                         SCOPE_ACK_TEXT)


# ---------------------------------------------------------------- helpers

def fake_engine_runner(stage_results=None, findings=None, chains=None):
    """Build a deterministic stub engine runner (no ENGINE import)."""
    stage_results = stage_results if stage_results is not None else {
        "recon": {"hosts": ["example.local"], "ports": ["80", "443"]},
        "enum": {"urls": ["http://example.local/admin"],
                 "techs": ["nginx"]},
        "triage": {"findings": []},
        "chain": {"chains": []},
        "report": {"note": "engine report"},
    }
    findings = findings if findings is not None else []

    def runner(target, mode="auto", scope_ack=None, budget=None,
               cancel=None, log=None):
        if scope_ack is not True and scope_ack != SCOPE_ACK_TEXT:
            raise PermissionError("scope acknowledgment required")
        return {
            "target": target, "mode": mode, "scope_ack": True,
            "stages_planned": ["recon", "enum", "triage", "chain",
                               "report"],
            "stage_results": dict(stage_results),
            "findings": list(findings),
            "chains_planned": list(chains or []),
            "stages_run": list(stage_results),
            "errors": [],
        }

    return runner


@pytest.fixture
def reg():
    return default_registry()


# ---------------------------------------------------------------- registry

def test_registry_audit_at_least_15_and_all_risk_classified(reg):
    count, problems = reg.audit()
    assert count >= 15, f"only {count} capabilities registered"
    assert problems == []
    for cap in reg.all():
        assert cap.risk in ("passive", "active", "planning-only", "offense")
        assert callable(cap.fn)
        assert cap.kind in ("stage", "probe", "enum", "recon", "report")


def test_registry_rejects_bad_risk_and_duplicates():
    r = CapabilityRegistry()
    r.register(Capability("a", "probe", lambda s, b=None: {}, risk="passive"))
    with pytest.raises(ValueError):
        r.register(Capability("a", "probe", lambda s, b=None: {},
                              risk="passive"))
    with pytest.raises(ValueError):
        Capability("b", "probe", lambda s, b=None: {}, risk="yolo")


def test_registry_engine_stage_capabilities_exist(reg):
    for cid in ("stage.recon", "stage.enum", "stage.triage", "stage.chain",
                "stage.runbook", "stage.report"):
        assert reg.get(cid) is not None
    # chain/runbook must be planning-only: the brain never executes chains
    assert reg.get("stage.chain").risk == "planning-only"
    assert reg.get("stage.runbook").risk == "planning-only"


# ---------------------------------------------------------------- decide()

def test_decide_rule_no_recon_done():
    st = BrainState("example.local")
    cid = decide(st)
    assert cid == "probe.target_parse"  # deterministic bootstrap probe


def test_decide_rule_surface_has_web_triggers_enum(reg):
    st = BrainState("http://example.local")
    st.update_from_stage("recon", {"hosts": ["example.local"],
                                   "ports": ["443"],
                                   "urls": ["http://example.local"]})
    assert st.facts()["recon_done"] is True
    assert st.facts()["has_web"] is True
    cid = decide(st, reg)
    cap = reg.get(cid)
    assert cap.kind in ("enum", "stage")
    assert "has_web" in cap.requires


def test_decide_rule_untriaged_findings_trigger_triage(reg):
    st = BrainState("example.local")
    st.stage_results["recon"] = {}
    st.stage_results["enum"] = {}
    st.findings = [{"title": "XSS", "severity": "medium"}]
    assert decide(st, reg) == "stage.triage"


def test_decide_rule_high_findings_trigger_chain_planning(reg):
    st = BrainState("example.local")
    st.stage_results["recon"] = {}
    st.stage_results["enum"] = {}
    st.stage_results["triage"] = {}
    st.findings = [{"title": "RCE", "severity": "high"}]
    assert st.facts()["findings_high"] is True
    cid = decide(st, reg)
    assert cid == "stage.chain"
    assert reg.get(cid).risk == "planning-only"


def test_decide_rule_confirmed_findings_trigger_runbook(reg):
    st = BrainState("example.local")
    st.stage_results["recon"] = {}
    st.stage_results["enum"] = {}
    st.stage_results["triage"] = {}
    st.stage_results["chain"] = {}
    st.findings = [{"title": "SQLi", "severity": "high",
                    "status": "CONFIRMED"}]
    cid = decide(st, reg)
    assert cid == "stage.runbook"


def test_decide_rule_else_report(reg):
    st = BrainState("example.local")
    st.stage_results["recon"] = {}
    st.stage_results["enum"] = {}
    st.stage_results["triage"] = {}
    st.stage_results["report"] = {"note": "done"}
    # everything satisfied -> cheapest report capability
    cid = decide(st, reg)
    assert reg.get(cid).kind == "report"


def test_decide_is_deterministic(reg):
    st = BrainState("http://example.local")
    st.update_from_stage("recon", {"hosts": ["example.local"],
                                   "ports": ["443"],
                                   "urls": ["http://example.local"]})
    assert decide(st, reg) == decide(st, reg)


def test_decide_tie_break_by_cost_then_id():
    r = CapabilityRegistry()
    r.register(Capability("zeta", "recon", lambda s, b=None: {}, cost=1,
                          risk="passive"))
    r.register(Capability("alpha", "recon", lambda s, b=None: {}, cost=1,
                          risk="passive"))
    r.register(Capability("cheap", "probe", lambda s, b=None: {}, cost=0,
                          risk="passive"))
    st = BrainState("t")
    # rule 0 bootstrap: cheapest probe first
    assert decide(st, r) == "cheap"
    st.stage_results["cheap"] = {}
    # recon rule: tie on cost 1 -> alphabetical id wins
    assert decide(st, r) == "alpha"


def test_decide_budget_cap_returns_none_when_unaffordable():
    r = CapabilityRegistry()
    r.register(Capability("costly", "recon", lambda s, b=None: {}, cost=5,
                          risk="passive"))
    st = BrainState("t", budget=3)
    st.stage_results["probe.target_parse"] = {}
    assert decide(st, r) is None  # nothing affordable -> stop
    st.budget_remaining = 5
    assert decide(st, r) == "costly"


# ---------------------------------------------------------------- state

def test_brain_state_update_from_stage_merges_results():
    st = BrainState("example.local")
    n = st.update_from_stage("recon", {"hosts": ["h1"], "ports": ["80"],
                                       "urls": ["http://h1/"],
                                       "techs": ["nginx"]})
    assert st.surface["hosts"] == ["h1"]
    assert st.surface["ports"] == ["80"]
    assert n >= 4
    assert st.history[-1]["result"] == "ok"
    # idempotent-ish merge: duplicates not re-added
    st.update_from_stage("recon", {"hosts": ["h1"]})
    assert st.surface["hosts"] == ["h1"]


# ---------------------------------------------------------------- Brain.run

def test_run_requires_scope_ack():
    b = Brain(engine_runner=fake_engine_runner())
    with pytest.raises(PermissionError):
        b.run("example.local", scope_ack=None)
    with pytest.raises(PermissionError):
        b.run("example.local", scope_ack="nope")
    # no engine call happened: engine runner would raise on bad ack anyway


def test_run_budget_stop():
    b = Brain(engine_runner=fake_engine_runner(), budget=0)
    st, report = b.run("example.local", scope_ack=True)
    assert st.budget_remaining == 0
    assert st.steps == 0
    assert "(no steps executed)" in report


def test_run_cancel_stop():
    b = Brain(engine_runner=fake_engine_runner(), budget=50)
    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        return calls["n"] > 1  # cancel after the first step

    st, report = b.run("example.local", scope_ack=True, cancel=cancel)
    assert st.cancelled is True
    assert "cancelled" in report.lower()


def test_run_failure_containment(tmp_path):
    reg = default_registry()
    boom = Capability("boom.recon", "recon",
                      lambda s, b=None: (_ for _ in ()).throw(
                          RuntimeError("boom")),
                      cost=1, risk="passive")
    reg.register(boom)

    # make boom the first choice by starving surface facts
    b = Brain(registry=reg, engine_runner=fake_engine_runner(), budget=50)
    st, report = b.run("example.local", scope_ack=True)
    errors = [h for h in st.history if h["result"] == "error"]
    assert any("boom" in h["capability"] for h in errors)
    assert any("RuntimeError" in (h["detail"] or "") for h in errors)
    # loop survived and still produced a report with a timeline
    assert "## Decision timeline" in report
    assert st.steps > 0


def test_run_full_loop_local_fixture_ends_in_report_with_timeline(tmp_path):
    b = Brain(engine_runner=fake_engine_runner(
        findings=[{"title": "Open redirect", "severity": "medium"}]),
        budget=50)
    st, report = b.run("http://example.local", scope_ack=SCOPE_ACK_TEXT)
    assert st.steps > 0
    assert st.budget_remaining < 50
    assert st.stage_results.get("report") or any(
        h["capability"].startswith("report") for h in st.history)
    # timeline table with the required columns
    assert "| step | capability | result | new-facts |" in report
    assert "# OMEGA brain report" in report
    assert "Chains planned (not executed)" in report
    assert "Next steps" in report


def test_run_never_executes_chains():
    b = Brain(engine_runner=fake_engine_runner(
        chains=[{"id": "c1", "steps": ["a", "b"]}]), budget=50)
    st, report = b.run("http://example.local", scope_ack=True)
    # chain stage only PLANS; no chain execution capability exists at all
    for cap in b.registry.all():
        assert "execute" not in cap.id
    assert st.chains_planned == [{"id": "c1", "steps": ["a", "b"]}]
    assert "The brain never executes chains" in report


def test_run_max_steps_bound():
    # a registry whose every choice is a no-op recon: loop must still
    # terminate via max_steps
    r = CapabilityRegistry()
    r.register(Capability("noop.a", "recon", lambda s, b=None: {"x": 1},
                          cost=1, risk="passive"))
    r.register(Capability("report.end", "report",
                          lambda s, b=None: {}, cost=0,
                          risk="planning-only"))
    # hide the report capability from the rules by making recon forever
    # un-done (noop never sets 'recon' stage) -> max_steps terminates it
    b = Brain(registry=r, engine_runner=fake_engine_runner(), budget=1000)
    st, _ = b.run("example.local", scope_ack=True, max_steps=5)
    assert st.steps <= 5


def test_optional_probe_degrades_gracefully():
    reg = default_registry()
    cap = reg.get("probe.pytools")
    st = BrainState("t")
    result = cap.fn(st)  # omega.pytools does not exist
    assert "not available" in result.get("note", "")
    assert result  # empty-ish result, not an exception


def test_optional_probe_uses_module_when_present(monkeypatch):
    mod = types.ModuleType("omega.probes")
    mod.run = lambda state: {"hosts": ["from-probe"]}
    monkeypatch.setitem(sys.modules, "omega.probes", mod)
    reg = default_registry()
    st = BrainState("t")
    assert reg.get("probe.custom").fn(st) == {"hosts": ["from-probe"]}


def test_render_brain_report_contents():
    st = BrainState("http://example.local")
    st.update_from_stage("recon", {"hosts": ["example.local"],
                                   "ports": ["443"],
                                   "urls": ["http://example.local"]})
    st.update_from_stage("stage.enum", {"urls": ["http://example.local/a"],
                                        "techs": ["nginx"]})
    st.findings = [{"title": "RCE", "severity": "high",
                    "status": "CONFIRMED"}]
    st.chains_planned = [{"id": "c1"}]
    md = render_brain_report(st)
    for fragment in ("| step | capability | result | new-facts |",
                     "high/critical: 1", "confirmed: 1",
                     "planned (not executed)", "Next steps"):
        assert fragment in md
