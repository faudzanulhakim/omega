"""Tests for the OMEGA Hermes plugin (hermes-plugin/omega)."""

import json
import os
from pathlib import Path

import pytest

import yaml

PLUGIN_DIR = Path(__file__).resolve().parent.parent / 'hermes-plugin' / 'omega'
OMEGA_HOME = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------- fixtures

class FakeCtx:
    """Records register_tool calls for assertions."""

    def __init__(self):
        self.calls = []

    def register_tool(self, name, toolset, schema, handler, check_fn=None, emoji=None):
        self.calls.append({'name': name, 'toolset': toolset, 'schema': schema,
                           'handler': handler, 'check_fn': check_fn, 'emoji': emoji})


@pytest.fixture
def plugin(monkeypatch):
    """Import the plugin package fresh with OMEGA_HOME pointing at this repo."""
    import importlib.util
    monkeypatch.setenv('OMEGA_HOME', str(OMEGA_HOME))
    spec = importlib.util.spec_from_file_location(
        'omega_hermes_plugin', PLUGIN_DIR / '__init__.py',
        submodule_search_locations=[str(PLUGIN_DIR)])
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.modules['omega_hermes_plugin'] = mod  # needed for relative imports
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def omega_module(plugin):
    return plugin._omega


# ---------------------------------------------------------------- plugin.yaml

def test_plugin_yaml_parses():
    data = yaml.safe_load((PLUGIN_DIR / 'plugin.yaml').read_text())
    assert data['name'] == 'omega'
    assert data['version'] == '1.0.0'
    assert 'Authorization enforced per-call' in data['description']
    assert data['author'] == 'Dee + OMEGA'
    assert data['provides_tools'] == ['omega_scan', 'omega_assault', 'omega_validate',
                                      'omega_followup', 'omega_chains',
                                      'omega_sessions', 'omega_report',
                                      'omega_stats', 'omega_autodeep',
                                      'omega_offense', 'omega_portfolio',
                                      'omega_evidence', 'omega_selftest',
                                      'omega_playbook']


def test_plugin_yaml_declares_assault_and_version_1_1_0():
    data = yaml.safe_load((PLUGIN_DIR / 'plugin.yaml').read_text())
    assert 'omega_assault' in data['provides_tools']
    assert data['version'] == '1.0.0'


def test_register_registers_fourteen_tools(plugin):
    ctx = FakeCtx()
    plugin.register(ctx)
    assert len(ctx.calls) == 14
    assert [c['name'] for c in ctx.calls] == ['omega_scan', 'omega_assault',
                                             'omega_validate',
                                             'omega_followup', 'omega_chains',
                                             'omega_sessions', 'omega_report',
                                             'omega_stats', 'omega_autodeep',
                                             'omega_offense', 'omega_portfolio',
                                             'omega_evidence', 'omega_selftest',
                                             'omega_playbook']
    assert all(c['toolset'] == 'omega' for c in ctx.calls)
    assert all(callable(c['handler']) for c in ctx.calls)
    assert all(callable(c['check_fn']) for c in ctx.calls)


def test_provides_tools_match_registered(plugin):
    declared = yaml.safe_load((PLUGIN_DIR / 'plugin.yaml').read_text())['provides_tools']
    ctx = FakeCtx()
    plugin.register(ctx)
    assert declared == [c['name'] for c in ctx.calls]


def test_every_tool_has_schema_type_object(plugin):
    ctx = FakeCtx()
    plugin.register(ctx)
    for c in ctx.calls:
        assert isinstance(c['schema'], dict)
        assert c['schema'].get('type') == 'object'
        assert isinstance(c['schema'].get('properties'), dict)


def test_scan_schema_requires_target_and_mentions_scope_ack(plugin):
    ctx = FakeCtx()
    plugin.register(ctx)
    schema = next(c['schema'] for c in ctx.calls if c['name'] == 'omega_scan')
    assert schema['required'] == ['target']
    assert 'scope_ack' in schema['properties']
    assert 'authoriz' in json.dumps(schema).lower()


# ---------------------------------------------------------------- scan gating

def test_scan_refuses_without_scope_ack(plugin, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError('subprocess must not run without scope_ack')
    monkeypatch.setattr(plugin._omega.subprocess, 'run', _boom)
    for kwargs in ({}, {'scope_ack': False}, {'scope_ack': 'yes'}):
        out = json.loads(plugin._omega.handle_scan({'target': 'example.com', **kwargs}))
        assert out['success'] is False
        assert 'scope_ack required' in out['error']


def test_scan_with_scope_ack_builds_correct_argv(plugin, monkeypatch, omega_module):
    captured = {}
    monkeypatch.setattr(omega_module, '_run', lambda argv, timeout=900: captured.update(argv=argv) or {'success': True})
    out = json.loads(plugin._omega.handle_scan({
        'target': 'example.com', 'mode': 'brain', 'scope_ack': True,
        'aggressive': True, 'polyglot': True, 'offense': True, 'exploit': True,
        'max_steps': 5, 'json': True}))
    assert out['success'] is True
    argv = captured['argv']
    assert argv[0] == 'bash'
    assert argv[1] == str(OMEGA_HOME / 'bin' / 'omega')
    assert argv[2] == 'brain' and argv[3] == 'example.com'
    assert '--scope-ack' in argv
    for flag in ('--aggressive', '--polyglot', '--offense', '--exploit', '--json'):
        assert flag in argv
    assert '--max-steps' in argv and argv[argv.index('--max-steps') + 1] == '5'
    # flags appear after the mode/target
    assert argv.index('--aggressive') > argv.index('example.com')


def test_scan_run_mode_requires_prompt(plugin):
    out = json.loads(plugin._omega.handle_scan({'target': 'example.com', 'mode': 'run', 'scope_ack': True}))
    assert out['success'] is False and 'prompt' in out['error']


# ---------------------------------------------------------------- other handlers

def test_sessions_default_action_list(plugin, monkeypatch, omega_module):
    captured = {}
    monkeypatch.setattr(omega_module, '_run', lambda argv, timeout=900: captured.update(argv=argv) or {'success': True})
    out = json.loads(plugin._omega.handle_sessions({}))
    assert out['success'] is True
    assert captured['argv'][2] == 'sessions' and captured['argv'][3] == 'list'


def test_sessions_diff_passes_session(plugin, monkeypatch, omega_module):
    captured = {}
    monkeypatch.setattr(omega_module, '_run', lambda argv, timeout=900: captured.update(argv=argv) or {'success': True})
    plugin._omega.handle_sessions({'action': 'diff', 'session': 'abc123'})
    assert 'abc123' in captured['argv']


def test_report_default_out_path(plugin, monkeypatch, omega_module):
    captured = {}
    monkeypatch.setattr(omega_module, '_run', lambda argv, timeout=900: captured.update(argv=argv) or {'success': True})
    out = json.loads(plugin._omega.handle_report({}))
    assert out['path'] == '/tmp/omega-report--.pdf'
    assert captured['argv'][2] == 'report'
    assert '--format' in captured['argv'] and '--out' in captured['argv']


def test_report_rejects_bad_format(plugin):
    out = json.loads(plugin._omega.handle_report({'fmt': 'xml'}))
    assert out['success'] is False


def test_stats_runs(plugin, monkeypatch, omega_module):
    captured = {}
    monkeypatch.setattr(omega_module, '_run', lambda argv, timeout=900: captured.update(argv=argv) or {'success': True, 'stdout': 'stats here'})
    out = json.loads(plugin._omega.handle_stats({}))
    assert out['success'] is True and out['stdout'] == 'stats here'
    assert captured['argv'][-1] == 'stats'


# ---------------------------------------------------------------- helpers

def test_omega_available_true_on_this_machine(plugin):
    assert (OMEGA_HOME / 'bin' / 'omega').is_file()
    assert plugin._omega._omega_available() is True


# ---------------------------------------------------------------- assault

def test_assault_refuses_without_scope_ack(plugin, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError('subprocess must not run without scope_ack')
    monkeypatch.setattr(plugin._omega.subprocess, 'run', _boom)
    for kwargs in ({}, {'scope_ack': False}, {'scope_ack': 'true'}, {'scope_ack': 1}):
        out = json.loads(plugin._omega.handle_assault({'target': 'example.com', **kwargs}))
        assert out['success'] is False
        assert 'scope_ack required' in out['error']


def test_assault_argv_brain_aggressive_json_scope_ack(plugin, monkeypatch, omega_module):
    captured = {'argvs': []}
    def fake_run(argv, timeout=900):
        captured['argvs'].append(argv)
        return {'success': True, 'stdout': ''}
    monkeypatch.setattr(omega_module, '_run', fake_run)
    out = json.loads(plugin._omega.handle_assault({'target': 'example.com', 'scope_ack': True}))
    assert out['success'] is True
    argv = captured['argvs'][0]
    assert argv[0] == 'bash'
    assert argv[1] == str(OMEGA_HOME / 'bin' / 'omega')
    assert argv[2] == 'brain' and argv[3] == 'example.com'
    for flag in ('--scope-ack', '--aggressive', '--json'):
        assert flag in argv
    assert '--max-steps' not in argv
    assert argv.index('--aggressive') > argv.index('example.com')
    # second call: report on the latest session
    rargv = captured['argvs'][1]
    assert rargv[2] == 'report' and rargv[3] == '-'
    assert '--out' in rargv and '--format' not in rargv


def test_assault_max_steps_passthrough(plugin, monkeypatch, omega_module):
    captured = {'argvs': []}
    def fake_run(argv, timeout=900):
        captured['argvs'].append(argv)
        return {'success': True, 'stdout': ''}
    monkeypatch.setattr(omega_module, '_run', fake_run)
    plugin._omega.handle_assault({'target': 'example.com', 'scope_ack': True, 'max_steps': 7})
    argv = captured['argvs'][0]
    assert '--max-steps' in argv
    assert argv[argv.index('--max-steps') + 1] == '7'


def test_assault_happy_path_report_path_and_findings(plugin, monkeypatch, omega_module):
    def fake_run(argv, timeout=900):
        if 'brain' in argv:
            return {'success': True, 'stdout': json.dumps({'findings': [{'id': 1}, {'id': 2}, {'id': 3}]})}
        return {'success': True, 'stdout': ''}
    monkeypatch.setattr(omega_module, '_run', fake_run)
    out = json.loads(plugin._omega.handle_assault({'target': 'evil.example.com', 'scope_ack': True}))
    assert out['success'] is True
    assert out['findings_count'] == 3
    assert out['report_path'] and out['report_path'].startswith('/tmp/omega-assault-evil-example-com-')
    assert out['report_path'].endswith('.pdf')
    assert 'stdout_tail' in out


def test_assault_report_failure_tolerated(plugin, monkeypatch, omega_module):
    def fake_run(argv, timeout=900):
        if 'brain' in argv:
            return {'success': True, 'stdout': 'not-json-at-all'}
        return {'success': False, 'exit_code': 2, 'stdout': '', 'stderr': 'no such session'}
    monkeypatch.setattr(omega_module, '_run', fake_run)
    out = json.loads(plugin._omega.handle_assault({'target': 'example.com', 'scope_ack': True}))
    assert out['success'] is True
    assert out['report_path'] is None
    assert out['findings_count'] is None
    assert 'report' in out.get('report_error', '').lower()


def test_assault_report_argv_slug_and_timestamp(plugin, monkeypatch, omega_module):
    import re
    captured = {'argvs': []}
    def fake_run(argv, timeout=900):
        captured['argvs'].append(argv)
        return {'success': True, 'stdout': ''}
    monkeypatch.setattr(omega_module, '_run', fake_run)
    plugin._omega.handle_assault({'target': 'https://Target.example.com/x_1', 'scope_ack': True})
    report_argv = captured['argvs'][1]
    out_path = report_argv[report_argv.index('--out') + 1]
    m = re.match(r'^/tmp/omega-assault-https-Target-example-com-x-1-\d{8}T\d{6}Z\.pdf$', out_path)
    assert m, f'unexpected report path: {out_path}'


def test_assault_registered_schema(plugin):
    ctx = FakeCtx()
    plugin.register(ctx)
    schema = next(c['schema'] for c in ctx.calls if c['name'] == 'omega_assault')
    assert schema['required'] == ['target', 'scope_ack']
    assert 'scope_ack' in schema['properties']
    assert 'authoriz' in json.dumps(schema).lower()


def test_never_raises_with_broken_run(plugin, monkeypatch, omega_module):
    def _broken(argv, timeout=900):
        raise RuntimeError('exploded')
    monkeypatch.setattr(omega_module, '_run', _broken)
    for handler, args in ((plugin._omega.handle_scan, {'target': 'x', 'scope_ack': True}),
                          (plugin._omega.handle_assault, {'target': 'x', 'scope_ack': True}),
                          (plugin._omega.handle_sessions, {}),
                          (plugin._omega.handle_report, {}),
                          (plugin._omega.handle_stats, {})):
        out = json.loads(handler(args))
        assert out['success'] is False and 'exploded' in out['error']


def test_omega_home_env_override(plugin, omega_module):
    assert str(omega_module.omega_home()) == str(OMEGA_HOME)
