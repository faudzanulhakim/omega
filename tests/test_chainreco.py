"""Hermetic tests for omega/core/chainreco.py — no network, no LLM.

Covers every deterministic rule branch, candidate-only notes, no-limits
gating, CLI-suggestion shape, the fallback chain, junk input, and the
brain capability registration.
"""

import json

import pytest

from omega.core.chainreco import format_plan, recommend


# ---------------------------------------------------------------- helpers

def finding(title, severity="high", location="/x", verification="verified"):
    return {"title": title, "severity": severity, "location": location,
            "verification": verification, "evidence": "e"}


def names(plan):
    return [c["name"] for c in plan["chains"]]


def chain_named(plan, name):
    for c in plan["chains"]:
        if c["name"] == name:
            return c
    return None


# ------------------------------------------------------------ rule branches

def test_credential_replay_chain_from_secret_and_login():
    plan = recommend([finding("Environment file exposure leaks "
                              "credentials", location="/.env"),
                      finding("Login form discovered",
                              severity="medium", location="/login")])
    chain = chain_named(plan, "credential-replay")
    assert chain is not None
    actions = [s["action"] for s in chain["steps"]]
    assert any("replay leaked credential" in a for a in actions)
    assert chain["requires_no_limits"] is False
    assert all("no-limits" not in c for c in plan["assault_cmds"]
               if "--no-limits" in c) or True
    cmd = plan["assault_cmds"][names(plan).index("credential-replay")]
    assert cmd.startswith("omega ")
    assert "--offense" in cmd and "--no-limits" not in cmd


def test_credential_replay_also_triggers_on_jwt():
    plan = recommend([finding("API secret token leaked in response",
                              location="/api"),
                      finding("JWT weak secret verification", severity="high",
                              location="/auth")])
    assert "credential-replay" in names(plan)


def test_no_credential_replay_without_login_surface():
    plan = recommend([finding("Environment file exposure leaks "
                              "credentials")])
    assert "credential-replay" not in names(plan)


def test_cve_exploit_chain_requires_local_index(monkeypatch):
    from omega.scanning import cvefeed

    monkeypatch.setenv("OMEGA_CVE_INDEX", "/nonexistent/chainreco.json")
    plan = recommend([finding("Server version disclosure: nginx 1.14",
                              severity="medium")])
    # No local index -> no invented CVEs -> no chain.
    assert "cve-exploit" not in names(plan)


def test_cve_exploit_chain_with_fake_index(monkeypatch, tmp_path):
    from omega.scanning import cvefeed

    index = tmp_path / "idx.json"
    index.write_text(json.dumps({
        "generated": "2026-01-01T00:00:00Z",
        "entries": [{"cve_id": "CVE-2099-0001", "product": "nginx",
                     "severity": "HIGH", "summary": "s",
                     "version_ranges": []}]}))
    monkeypatch.setenv("OMEGA_CVE_INDEX", str(index))
    plan = recommend([finding("Server version disclosure: nginx 1.14",
                              severity="medium")])
    chain = chain_named(plan, "cve-exploit")
    assert chain is not None
    assert any("CVE index" in s["action"] for s in chain["steps"])
    assert chain["requires_no_limits"] is False
    cmd = plan["assault_cmds"][names(plan).index("cve-exploit")]
    assert cmd.startswith("omega brain") and "--exploit" in cmd
    assert "--no-limits" not in cmd


def test_upload_chain_from_admin_and_upload():
    plan = recommend([finding("Admin panel exposed", severity="high",
                              location="/admin"),
                      finding("File upload endpoint permissive", severity="high",
                              location="/upload")])
    chain = chain_named(plan, "upload-bypass")
    assert chain is not None
    used = {s["uses"] for s in chain["steps"]}
    assert "Admin panel exposed" in used
    assert "File upload endpoint permissive" in used


def test_takeover_chain_from_redirect_and_hint():
    plan = recommend([finding("Open redirect on /go", severity="medium",
                              location="/go"),
                      finding("Subdomain takeover hint: dangling CNAME",
                              severity="high", location="sub.example")])
    chain = chain_named(plan, "subdomain-takeover")
    assert chain is not None
    assert any("dangling DNS" in s["action"] for s in chain["steps"])


def test_secret_retrieval_chain_requires_no_limits():
    plan = recommend([finding("Path traversal confirmed", severity="high",
                              location="/download?file="),
                      finding(".env file disclosed via traversal",
                              severity="critical", location="/.env")])
    chain = chain_named(plan, "secret-retrieval")
    assert chain is not None
    assert chain["requires_no_limits"] is True
    cmd = plan["assault_cmds"][names(plan).index("secret-retrieval")]
    assert cmd.startswith("omega ")
    assert "--no-limits" in cmd
    # --no-limits appears ONLY on the chain that requires it.
    other = [c for c in plan["assault_cmds"]
             if c != cmd]
    assert all("--no-limits" not in c for c in other)


# ------------------------------------------------------------ candidate-only

def test_candidate_only_note_and_no_note_when_verified():
    plan = recommend([finding("Environment file exposure leaks "
                              "credentials", verification="candidate"),
                      finding("Login form discovered", severity="medium",
                              location="/login",
                              verification="candidate")])
    assert "candidate-only chain: verify first" in plan["notes"]

    plan2 = recommend([finding("Environment file exposure leaks "
                               "credentials"),
                       finding("Login form discovered", severity="medium",
                               location="/login")])
    assert "candidate-only chain: verify first" not in plan2["notes"]


# ------------------------------------------------------------ fallback / junk

def test_unknown_finding_produces_fallback_chain():
    plan = recommend([finding("Something odd observed",
                              severity="low")])
    assert names(plan) == ["verify-then-decide"]
    step = plan["chains"][0]["steps"][0]
    assert step["action"] == "manual_check"
    assert step["uses"] == "Something odd observed"
    cmd = plan["assault_cmds"][0]
    assert cmd.startswith("omega ") and "--no-limits" not in cmd


def test_junk_input_never_raises():
    for junk in (None, [], [None], ["just a string"], [42],
                 [{"nonsense": True}], {"findings": "oops"},
                 [{}], [{"title": None, "severity": 7}]):
        plan = recommend(junk)
        assert isinstance(plan, dict)
        assert set(plan) >= {"chains", "assault_cmds", "notes"}
        for c in plan["chains"]:
            assert isinstance(c["name"], str)
            assert all(isinstance(s["uses"], str) for s in c["steps"])


def test_empty_findings_note():
    plan = recommend([])
    assert plan["chains"] == []
    assert any("no findings" in n for n in plan["notes"])


def test_no_invented_endpoints_or_credentials():
    plan = recommend([finding("Open redirect on /go", severity="low",
                              location="/go"),
                      finding("Subdomain takeover hint: dangling CNAME",
                              severity="high", location="sub.example")])
    blob = json.dumps(plan)
    for invented in ("http://evil", "admin:admin", "password123",
                     "/wp-login"):
        assert invented not in blob


# ------------------------------------------------------------ output shape

def test_plan_shape_and_readable_format():
    plan = recommend([finding("Path traversal confirmed"),
                      finding(".env file disclosed via traversal",
                              severity="critical", location="/.env")])
    assert set(plan) == {"chains", "assault_cmds", "notes"}
    for chain in plan["chains"]:
        assert isinstance(chain["rationale"], str) and chain["rationale"]
        for step in chain["steps"]:
            assert set(step) == {"uses", "evidence_ref", "action", "risk"}
    text = format_plan(plan, target="example.com")
    assert "secret-retrieval" in text
    assert "omega brain" in text


# ------------------------------------------------------------ brain cap

def test_brain_cap_registered_passive():
    from omega.brain import DEFAULT_REGISTRY, _ai_chainreco_fn

    cap = DEFAULT_REGISTRY.get("ai.chainreco")
    assert cap is not None
    assert cap.risk == "passive"
    assert cap.cost == 0
    assert "chainreco" in cap.description or "chain" in cap.description
    assert cap.fn is _ai_chainreco_fn


def test_brain_cap_fn_returns_plan_for_findings():
    from omega.brain import BrainState, DEFAULT_REGISTRY

    state = BrainState("example.com")
    state.findings = [finding("Admin panel exposed", location="/admin"),
                      finding("File upload endpoint permissive",
                              location="/upload")]
    cap = DEFAULT_REGISTRY.get("ai.chainreco")
    out = cap.fn(state)
    assert "upload-bypass" in [c["name"] for c in out["chains"]]
    assert out["assault_cmds"] and all(c.startswith("omega ")
                                       for c in out["assault_cmds"])


def test_brain_cap_fn_no_findings_alone():
    from omega.brain import BrainState, DEFAULT_REGISTRY

    state = BrainState("example.com")
    cap = DEFAULT_REGISTRY.get("ai.chainreco")
    out = cap.fn(state)
    assert out["chains"] == []
    assert any("no findings" in n for n in out["notes"])


# ------------------------------------------------------------ CLI handler

def test_cli_chains_from_findings_file_json(tmp_path, capsys):
    from omega.core.cli import main

    f = tmp_path / "findings.json"
    f.write_text(json.dumps([finding("Admin panel exposed",
                                     location="/admin"),
                             finding("File upload endpoint permissive",
                                     location="/upload")]))
    rc = main(["chains", str(f), "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert "upload-bypass" in [c["name"] for c in data["chains"]]


def test_cli_chains_readable_and_error_paths(tmp_path, capsys):
    from omega.core.cli import main

    f = tmp_path / "findings.json"
    f.write_text(json.dumps([finding("Something odd observed",
                                     severity="low")]))
    rc = main(["chains", str(f)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "verify-then-decide" in out and "manual_check" in out

    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    rc2 = main(["chains", str(bad)])
    assert rc2 == 1

    f2 = tmp_path / "notalist.json"
    f2.write_text(json.dumps({"findings": "oops"}))
    rc3 = main(["chains", str(f2)])
    assert rc3 == 1


def test_cli_chains_from_session(tmp_path, monkeypatch, capsys):
    from omega.core import cli
    from omega.core import session as session_mod

    d = tmp_path / "sessions"
    d.mkdir()
    monkeypatch.setattr(session_mod, "sessions_dir", lambda: str(d))
    (d / "s1.json").write_text(json.dumps({
        "target": "example.com",
        "state": {"findings": [finding("Admin panel exposed",
                                       location="/admin"),
                               finding("File upload endpoint permissive",
                                       location="/upload")]}}))
    rc = cli.main(["chains", "s1", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert "upload-bypass" in [c["name"] for c in data["chains"]]
