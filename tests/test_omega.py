"""Hermetic tests for the OMEGA CLI (engine stubbed — never touches ENGINE)."""

import importlib
import json
import os
import stat
import subprocess
import sys
import types

import pytest

import omega.cli as cli

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------- fixtures

@pytest.fixture
def fake_engine(monkeypatch, tmp_path):
    """Stub offensive.engagement via a fake engine home; no engine writes."""
    fake_modes = {"auto": {"description": "stub", "stages": ["report"]},
                  "ctf": {"description": "stub", "stages": ["enum"]}}
    sentinels = {"ran": []}

    def run_engagement(target, mode=None, scope_ack=None, **kw):
        sentinels["ran"].append((target, mode, scope_ack))
        if scope_ack is not True and scope_ack != "ACK":
            raise PermissionError("scope acknowledgment required")
        if mode not in fake_modes:
            raise ValueError(f"unknown mode '{mode}'")
        return {"target": target, "mode": mode, "scope_ack": True,
                "findings": [], "chains_planned": []}

    def render_report(eng):
        return f"# OMEGA stub report — {eng['target']}"

    home = tmp_path / "engine-fake"
    pkg = home / "offensive"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    mod = types.ModuleType("offensive.engagement")
    mod.MODES = fake_modes
    mod.run_engagement = run_engagement
    mod.render_report = render_report
    (pkg / "engagement.py").write_text("# stub\n")

    # Block actual import: force load_engine to return our stubs.
    def fake_load(home_arg=None):
        if home_arg is None and not os.path.isdir(cli.engine_home()):
            raise cli.EngineHomeError("not found")
        # simulate real load by importing from fake home
        sys.path.insert(0, str(home))
        try:
            loaded = importlib.import_module("offensive.engagement")
            # Only inject stub attrs if the module isn't already patched
            # (e.g. by monkeypatch.setattr in a test).
            if getattr(loaded, "MODES", None) != fake_modes:
                loaded.MODES = fake_modes
            if not getattr(loaded, "_omega_stubbed", False):
                loaded.run_engagement = run_engagement
                loaded.render_report = render_report
                loaded._omega_stubbed = True
            return loaded, types.ModuleType("offensive.toolbridge")
        finally:
            sys.path.remove(str(home))

    monkeypatch.setattr(cli, "load_engine", fake_load)
    monkeypatch.setenv("OMEGA_ENGINE_HOME", str(home))
    return types.SimpleNamespace(sentinel=sentinels, home=str(home))


@pytest.fixture
def snap_engine():
    """Snapshot real engine tree mtimes to assert no writes."""
    real = os.environ.get("OMEGA_ENGINE_HOME", cli.DEFAULT_ENGINE_HOME)
    if not os.path.isdir(real):
        pytest.skip("real engine home not present")
    before = {}
    for root, _dirs, files in os.walk(real):
        for f in files:
            p = os.path.join(root, f)
            try:
                before[p] = os.stat(p).st_mtime_ns
            except OSError:
                pass
    return real, before


def assert_engine_unchanged(snap):
    real, before = snap
    for root, _dirs, files in os.walk(real):
        for f in files:
            p = os.path.join(root, f)
            if p.endswith(".pyc") or "__pycache__" in p:
                continue
            try:
                assert os.stat(p).st_mtime_ns == before[p], f"modified: {p}"
            except OSError:
                pass


# ------------------------------------------------------------------ tests

def test_resolves_home_and_loads_real_engine(snap_engine):
    real, _ = snap_engine
    os.environ["OMEGA_ENGINE_HOME"] = real
    eng, tb = cli.load_engine()
    assert hasattr(eng, "run_engagement")
    assert hasattr(tb, "run_bridge")
    assert len(eng.MODES) == 10
    importlib.invalidate_caches()
    sys.path.remove(real)


def test_missing_home_degrades_cleanly(monkeypatch):
    monkeypatch.setenv("OMEGA_ENGINE_HOME", "/nonexistent/omega-test-xyz")
    with pytest.raises(cli.EngineHomeError, match="OMEGA_ENGINE_HOME"):
        cli.load_engine()


def test_gate_refusal_missing_ack(fake_engine, capsys):
    rc = cli.main(["engage", "example.com", "--mode", "ctf"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--scope-ack" in err


def test_with_tools_sets_ptk(fake_engine, monkeypatch):
    monkeypatch.delenv("PTK_TOOLS", raising=False)
    rc = cli.main(["engage", "t.local", "--scope-ack", "--with-tools"])
    assert rc == 0
    assert os.environ.get("PTK_TOOLS") == "1"


def test_without_tools_clears_ptk(fake_engine, monkeypatch):
    monkeypatch.setenv("PTK_TOOLS", "1")
    cli.main(["engage", "t.local", "--scope-ack"])
    assert os.environ.get("PTK_TOOLS") != "1"


def test_json_output_mode(fake_engine, capsys):
    rc = cli.main(["engage", "t.local", "--mode", "ctf",
                   "--scope-ack", "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["target"] == "t.local"
    assert data["mode"] == "ctf"


def test_markdown_output_mode(fake_engine, capsys):
    rc = cli.main(["engage", "t.local", "--scope-ack"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.startswith("# OMEGA stub report — t.local")


def test_unknown_mode_exit_2(fake_engine, capsys):
    rc = cli.main(["engage", "t.local", "--mode", "nope", "--scope-ack"])
    assert rc == 2


def test_engine_refusal_maps_to_2(fake_engine, capsys, monkeypatch):
    # stub run_engagement raises PermissionError even with ack
    def boom(*a, **k):
        raise PermissionError("denied")
    import offensive.engagement as m
    monkeypatch.setattr(m, "run_engagement", boom)
    rc = cli.main(["engage", "t.local", "--scope-ack"])
    assert rc == 2


def test_no_writes_to_real_engine(fake_engine, snap_engine, monkeypatch):
    rc = cli.main(["engage", "t.local", "--scope-ack", "--json"])
    assert rc == 0
    assert_engine_unchanged(snap_engine)


def test_bin_omega_shim_exists_and_executable():
    shim = os.path.join(REPO_DIR, "bin", "omega")
    assert os.path.isfile(shim)
    mode = os.stat(shim).st_mode
    assert mode & stat.S_IXUSR, "bin/omega must be executable"


def test_shim_engage_help_real_engine():
    shim = os.path.join(REPO_DIR, "bin", "omega")
    env = dict(os.environ, OMEGA_ENGINE_HOME=os.path.join(REPO_DIR, "engine"))
    res = subprocess.run(["bash", shim, "engage", "--help"],
                         capture_output=True, text=True, env=env, timeout=60)
    assert res.returncode == 0, res.stderr
    assert "--scope-ack" in res.stdout
    assert "--with-tools" in res.stdout
