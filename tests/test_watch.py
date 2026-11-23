"""Tests for omega.watch — periodic monitoring mode.

Hermetic: OMEGA_SESSIONS_HOME points at a tmpdir and Brain.run is
stubbed, so no engine, network, or real brain is involved.
"""
import json

import pytest

from omega import watch as watch_mod
from omega import session as session_mod
from omega import cli


class FakeState:
    """Minimal stand-in for omega.brain.BrainState."""

    def __init__(self, target, surface, findings):
        self.target = target
        self.mode = "auto"
        self.surface = surface
        self.findings = findings
        self.chains_planned = []
        self.history = [{"step": 1}]


class FakeBrain:
    """Stubbed Brain: scripted states per run, safety gate enforced."""

    def __init__(self, script):
        self.script = script
        self.calls = []

    def run(self, target, mode="auto", scope_ack=None, max_steps=12,
            cancel=None):
        if scope_ack is not True:
            raise PermissionError("scope acknowledgment required")
        self.calls.append(target)
        surface, findings = self.script.pop(0)
        report = f"# fake report for {target}\n"
        return FakeState(target, surface, findings), report


@pytest.fixture
def sessions_home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMEGA_SESSIONS_HOME", str(tmp_path / "sessions"))
    return tmp_path / "sessions"


@pytest.fixture
def patch_brain(monkeypatch):
    def _install(script):
        fake = FakeBrain(script)
        monkeypatch.setattr("omega.brain.Brain", lambda: fake)
        return fake
    return _install


SURFACE_A = {"hosts": ["a.example.com"], "urls": ["http://a.example.com/"],
             "ports": ["a.example.com:80"], "techs": ["nginx"]}
SURFACE_B = {"hosts": ["a.example.com", "b.example.com"],
             "urls": ["http://a.example.com/", "http://b.example.com/"],
             "ports": ["a.example.com:80", "a.example.com:8080"],
             "techs": ["nginx"]}


def _finding(title, loc):
    return {"title": title, "location": loc}


def test_watch_baseline_no_previous_session(sessions_home, patch_brain):
    """First watch for a target: baseline only, no diff, exit code 0."""
    brain = patch_brain([
        (SURFACE_A, [_finding("XSS", "http://a.example.com/")]),
    ])
    result = watch_mod.watch("a.example.com", scope_ack=True,
                             session_label="run1")
    assert result["session_name"].startswith("a.example.com-run1")
    assert result["baseline_or_delta"] == {"baseline": True}
    assert "no new findings" in result["report_markdown"]
    assert watch_mod.alert_exit_code(result["baseline_or_delta"]) == 0
    # session was saved
    doc = session_mod.load_session(result["session_name"])
    assert doc["target"] == "a.example.com"
    assert doc["summary"]["findings"] == 1
    assert brain.calls == ["a.example.com"]


def test_watch_second_run_diffs_new_and_resolved(sessions_home, patch_brain):
    """Second run with mutated state: new + resolved findings and surface
    changes appear; verdict line says attention required; exit code 1."""
    patch_brain([
        (SURFACE_A, [_finding("XSS", "http://a.example.com/"),
                     _finding("Old Info Leak", "http://a.example.com/")]),
        (SURFACE_B, [_finding("XSS", "http://a.example.com/"),
                     _finding("SQLi", "http://a.example.com/login")]),
    ])
    first = watch_mod.watch("a.example.com", scope_ack=True,
                            session_label="run1")
    assert first["baseline_or_delta"] == {"baseline": True}

    second = watch_mod.watch("a.example.com", scope_ack=True,
                             session_label="run2")
    delta = second["baseline_or_delta"]
    assert "baseline" not in delta
    assert delta["new_findings"] == [("SQLi", "http://a.example.com/login")]
    assert delta["resolved_findings"] == [
        ("Old Info Leak", "http://a.example.com/")]
    assert "urls:http://b.example.com/" in delta["surface_changes"]["added"]
    assert "ports:a.example.com:8080" in delta["surface_changes"]["added"]
    assert delta["surface_changes"]["removed"] == []

    report = second["report_markdown"]
    assert "## New Findings" in report
    assert "[critical]" in report          # SQLi -> critical triage
    assert "## Resolved Findings" in report
    assert "Old Info Leak" in report
    assert "## Surface Changes" in report
    assert "added: ports:a.example.com:8080" in report
    assert "Verdict: NEW FINDINGS — attention required" in report
    assert watch_mod.alert_exit_code(delta) == 1


def test_alert_exit_code_clean_and_dirty():
    clean = {"new_findings": [], "resolved_findings": [],
             "surface_changes": {"added": [], "removed": []}}
    dirty = dict(clean, new_findings=[("XSS", "u")])
    assert watch_mod.alert_exit_code(clean) == 0
    assert watch_mod.alert_exit_code(dirty) == 1


def test_render_report_verdict_lines():
    clean = {"new_findings": [], "resolved_findings": [],
             "surface_changes": {"added": [], "removed": []}}
    dirty = dict(clean, new_findings=[("XSS", "u")])
    assert "Verdict: no new findings" in watch_mod.render_watch_report(clean)
    assert ("Verdict: NEW FINDINGS — attention required"
            in watch_mod.render_watch_report(dirty))


def test_watch_safety_gate_requires_ack(sessions_home, patch_brain):
    """No scope_ack -> PermissionError, nothing saved."""
    patch_brain([(SURFACE_A, [])])
    with pytest.raises(PermissionError):
        watch_mod.watch("a.example.com")
    assert session_mod.list_sessions() == []


def test_session_matching_by_target_only(sessions_home, patch_brain):
    """Sessions for other targets must not be picked as the baseline."""
    patch_brain([
        (SURFACE_A, []),   # other target baseline
        (SURFACE_A, []),   # our target baseline
        (SURFACE_B, []),   # our target second run
    ])
    watch_mod.watch("other.example.com", scope_ack=True, session_label="x")
    first = watch_mod.watch("a.example.com", scope_ack=True,
                            session_label="y")
    assert first["baseline_or_delta"] == {"baseline": True}
    second = watch_mod.watch("a.example.com", scope_ack=True,
                             session_label="z")
    assert second["baseline_or_delta"] != {"baseline": True}
    # diffed against the a.example.com baseline (0 findings), so the
    # b.example.com host is new surface but there are no new findings
    assert second["baseline_or_delta"]["new_findings"] == []
    assert ("hosts:b.example.com"
            in second["baseline_or_delta"]["surface_changes"]["added"])


def test_cli_watch_happy_path_and_json(sessions_home, patch_brain,
                                       capsys):
    """CLI: first watch exits 0, second with new findings exits 1 and
    prints the report; --json prints a JSON document."""
    patch_brain([
        (SURFACE_A, []),
        (SURFACE_A, [_finding("XSS", "http://a.example.com/")]),
        (SURFACE_A, [_finding("XSS", "http://a.example.com/")]),
    ])
    rc1 = cli.main(["watch", "a.example.com", "--scope-ack",
                    "--label", "run1"])
    assert rc1 == 0
    out1 = capsys.readouterr().out
    assert "Verdict: no new findings" in out1

    rc2 = cli.main(["watch", "a.example.com", "--scope-ack",
                    "--label", "run2"])
    assert rc2 == 1
    out2 = capsys.readouterr().out
    assert "Verdict: NEW FINDINGS — attention required" in out2

    rc3 = cli.main(["watch", "a.example.com", "--scope-ack",
                    "--label", "run3", "--json"])
    assert rc3 == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["session_name"].startswith("a.example.com-run3")
    assert payload["baseline_or_delta"]["new_findings"] == []


def test_cli_watch_missing_ack_exit_2(sessions_home, patch_brain, capsys):
    """CLI without --scope-ack refuses with exit code 2 and runs nothing."""
    patch_brain([(SURFACE_A, [])])
    rc = cli.main(["watch", "a.example.com"])
    assert rc == 2
    assert "scope-ack" in capsys.readouterr().err
    assert session_mod.list_sessions() == []


def test_session_names_include_label_or_timestamp(sessions_home,
                                                  patch_brain):
    patch_brain([(SURFACE_A, []), (SURFACE_A, [])])
    labeled = watch_mod.watch("a.example.com", scope_ack=True,
                              session_label="nightly")
    assert labeled["session_name"] == "a.example.com-nightly"
    stamp = watch_mod.watch("a.example.com", scope_ack=True)
    assert stamp["session_name"].startswith("a.example.com-20")
