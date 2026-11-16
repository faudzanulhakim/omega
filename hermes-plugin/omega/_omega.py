"""_omega.py — shared helpers for the OMEGA Hermes plugin.

OMEGA is an autonomous red-team operator: brutal in analysis, honest in
evidence (confirmed vs candidate), and never destructive — it breaks nothing,
destroys no data, and reports only what it can back with artifacts.

Resolves the OMEGA installation (env OMEGA_HOME overrides, else well-known
paths), runs the ``bin/omega`` shim safely, and provides never-raise wrappers
for all tool handlers.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

_RUN_TIMEOUT = 900  # seconds; OMEGA scans are long-running but bounded

_SCOPE_ACK_ERROR = (
    'scope_ack required: pass scope_ack=true to confirm you are authorized '
    'to test this target')


def omega_home() -> Path:
    """Resolve the OMEGA installation root deterministically. Order:
    1. env OMEGA_HOME (explicit operator override),
    2. the pinned path written by install.sh (next to this plugin copy),
    3. the omega shim found on PATH.
    No directory guessing: if none resolve, the returned path does not
    exist and _omega_available() reports False with a clear fix hint.
    """
    env = os.environ.get('OMEGA_HOME', '').strip()
    if env:
        return Path(env).expanduser()
    pinned = Path(__file__).resolve().parent / '_omega_home.txt'
    if pinned.is_file():
        try:
            candidate = Path(pinned.read_text(encoding='utf-8').strip())
            if candidate.is_dir():
                return candidate
        except OSError:
            pass
    shim = shutil.which('omega')
    if shim:
        return Path(shim).resolve().parent.parent
    return Path('/nonexistent-omega-home-unset-OMEGA_HOME')


def omega_bin() -> Path:
    """Path to the bash shim ``bin/omega`` under the resolved OMEGA home."""
    return omega_home() / 'bin' / 'omega'


def _omega_available() -> bool:
    """check_fn: the tool is offered only when the omega shim exists and is executable."""
    try:
        return omega_bin().is_file()
    except Exception:
        return False


def _run(argv: List[str], timeout: int = _RUN_TIMEOUT) -> Dict[str, Any]:
    """Run argv via subprocess with bounded timeout. Returns a plain dict; never raises.

    stdout/stderr are tail-truncated so giant scan output cannot flood the context.
    """
    try:
        proc = subprocess.run(
            argv, timeout=timeout, capture_output=True, text=True)
        return {
            'success': proc.returncode == 0,
            'exit_code': proc.returncode,
            'stdout': proc.stdout[-8000:] if proc.stdout else '',
            'stderr': proc.stderr[-2000:] if proc.stderr else ''}
    except subprocess.TimeoutExpired:
        return {'success': False, 'exit_code': None,
                'stdout': '', 'stderr': f'timed out after {timeout}s'}
    except FileNotFoundError:
        return {'success': False, 'exit_code': None, 'stdout': '',
                'stderr': f'executable not found: {argv[0]}'}
    except Exception as e:  # pragma: no cover — defensive
        return {'success': False, 'exit_code': None, 'stdout': '', 'stderr': str(e)}


def _fmt(result: Dict[str, Any]) -> str:
    """Format an _run() result dict as the JSON string handlers return."""
    import json
    try:
        return json.dumps(result)
    except Exception as e:
        return json.dumps({'success': False, 'error': str(e)})


def handle_scan(args: Dict[str, Any]) -> str:
    """omega_scan — hard gate on scope_ack before anything runs."""
    try:
        target = str(args.get('target') or '').strip()
        mode = args.get('mode') or 'brain'
        if mode not in ('brain', 'run'):
            return _fmt({'success': False, 'error': f"mode must be 'brain' or 'run', got {mode!r}"})
        if not target:
            return _fmt({'success': False, 'error': 'target is required'})
        if mode == 'run' and not str(args.get('prompt') or '').strip():
            return _fmt({'success': False, 'error': "prompt is required when mode='run'"})

        # AUTHORIZATION GATE: never run, never auto-add --scope_ack without it.
        if args.get('scope_ack') is not True:
            return _fmt({'success': False, 'error': _SCOPE_ACK_ERROR})

        argv = ['bash', str(omega_bin()), mode, target, '--scope-ack']
        if args.get('aggressive'):
            argv.append('--aggressive')
        if args.get('polyglot'):
            argv.append('--polyglot')
        if args.get('offense'):
            argv.append('--offense')
        if args.get('exploit'):
            argv.append('--exploit')
        max_steps = args.get('max_steps')
        if max_steps is not None:
            argv += ['--max-steps', str(int(max_steps))]
        if args.get('json'):
            argv.append('--json')
        return _fmt(_run(argv))
    except Exception as e:
        return _fmt({'success': False, 'error': str(e)})


def handle_assault(args: Dict[str, Any]) -> str:
    """omega_assault — one-shot brutal engagement: brain scan, then auto-report.

    Hard gate on scope_ack before anything runs. The report step is best-effort:
    a report failure never fails the tool.
    """
    try:
        target = str(args.get('target') or '').strip()
        if not target:
            return _fmt({'success': False, 'error': 'target is required'})

        # AUTHORIZATION GATE: never run, never auto-add --scope-ack without it.
        if args.get('scope_ack') is not True:
            return _fmt({'success': False, 'error': _SCOPE_ACK_ERROR})

        argv = ['bash', str(omega_bin()), 'brain', target, '--scope-ack',
                '--aggressive', '--json']
        max_steps = args.get('max_steps')
        if max_steps is not None:
            argv += ['--max-steps', str(int(max_steps))]

        brain = _run(argv)

        # Parse findings from the brain --json output when possible.
        findings_count = None
        try:
            import json
            parsed = json.loads(brain.get('stdout') or '')
            for key in ('findings', 'results'):
                if isinstance(parsed, dict) and isinstance(parsed.get(key), list):
                    findings_count = len(parsed[key])
                    break
        except Exception:
            findings_count = None

        # Auto-report on the latest session — best effort, never fatal.
        import datetime
        import re
        slug = re.sub(r'[^A-Za-z0-9]+', '-', target).strip('-') or 'target'
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        report_path = f'/tmp/omega-assault-{slug}-{timestamp}.pdf'
        report_argv = ['bash', str(omega_bin()), 'report', '-', '--out', report_path]
        lang = str(args.get('lang') or '').strip()
        if lang:
            report_argv += ['--lang', lang]
        report = _run(report_argv)
        report_note = None
        if not report.get('success'):
            report_path = None
            report_note = (
                f"report generation failed (exit_code={report.get('exit_code')}, "
                f"stderr={report.get('stderr', '')[:500]}); brain results unaffected")

        stdout_tail = (brain.get('stdout') or '')[-3000:]
        out = {
            'success': bool(brain.get('success')),
            'findings_count': findings_count,
            'report_path': report_path,
            'stdout_tail': stdout_tail,
        }
        if not brain.get('success'):
            out['error'] = brain.get('stderr', '')[:2000] or 'brain scan failed'
        if report_note:
            out['report_error'] = report_note
        return _fmt(out)
    except Exception as e:
        return _fmt({'success': False, 'error': str(e)})


def handle_sessions(args: Dict[str, Any]) -> str:
    """omega_sessions — list (last 10) or diff vs latest."""
    try:
        action = args.get('action') or 'list'
        session = args.get('session')
        if action not in ('list', 'diff'):
            return _fmt({'success': False, 'error': f"action must be 'list' or 'diff', got {action!r}"})
        argv = ['bash', str(omega_bin()), 'sessions', action]
        if action == 'diff' and session:
            argv.append(str(session))
        return _fmt(_run(argv))
    except Exception as e:
        return _fmt({'success': False, 'error': str(e)})


def handle_report(args: Dict[str, Any]) -> str:
    """omega_report — generate a report; never deletes anything."""
    try:
        session = str(args.get('session') or '-')
        fmt = args.get('fmt') or 'pdf'
        if fmt not in ('markdown', 'html', 'json', 'docx', 'pdf'):
            return _fmt({'success': False,
                         'error': f"fmt must be one of markdown|html|json|docx|pdf, got {fmt!r}"})
        out = args.get('out') or f'/tmp/omega-report-{session}.{fmt}'
        argv = ['bash', str(omega_bin()), 'report', session, '--out', str(out), '--format', str(fmt)]
        lang = str(args.get('lang') or '').strip()
        if lang:
            argv += ['--lang', lang]
        result = _run(argv)
        result['path'] = str(out)
        return _fmt(result)
    except Exception as e:
        return _fmt({'success': False, 'error': str(e)})


def handle_validate(args: Dict[str, Any]) -> str:
    """omega_validate — AI-claim validation gate (anti-hallucination)."""
    try:
        claims = args.get('claims')
        if not claims:
            return _fmt({'success': False,
                         'error': 'claims (JSON string or list of findings) '
                                  'is required'})
        import json as _json
        import tempfile as _tf
        import os as _os
        if isinstance(claims, str):
            try:
                parsed = _json.loads(claims)
            except ValueError as e:
                return _fmt({'success': False,
                             'error': f'claims is not valid JSON: {e}'})
        else:
            parsed = claims
        if not isinstance(parsed, list):
            parsed = [parsed]
        fd, path = _tf.mkstemp(suffix='.json')
        with _os.fdopen(fd, 'w') as fh:
            _json.dump(parsed, fh)
        argv = ['bash', str(omega_bin()), 'validate', path, '--json']
        base = str(args.get('base') or '').strip()
        if base:
            argv += ['--base', base]
        if args.get('drop_refuted'):
            argv.append('--drop-refuted')
        result = _run(argv, timeout=300)
        _os.unlink(path)
        result['tool'] = 'omega_validate'
        return _fmt(result)
    except Exception as e:
        return _fmt({'success': False, 'error': str(e)})


def handle_followup(args: Dict[str, Any]) -> str:
    """omega_followup — adaptive depth probes on a findings JSON file."""
    try:
        findings = str(args.get('findings') or '').strip()
        if not findings:
            return _fmt({'success': False,
                         'error': 'findings (path to a findings JSON file) '
                                  'is required'})
        argv = ['bash', str(omega_bin()), 'followup', findings, '--json']
        base = str(args.get('base') or '').strip()
        if base:
            argv += ['--base', base]
        budget = args.get('budget')
        if isinstance(budget, int) and budget > 0:
            argv += ['--budget', str(budget)]
        result = _run(argv, timeout=600)
        result['tool'] = 'omega_followup'
        return _fmt(result)
    except Exception as e:
        return _fmt({'success': False, 'error': str(e)})


def handle_chains(args: Dict[str, Any]) -> str:
    """omega_chains — deterministic exploit-chain recommendations."""
    try:
        session = str(args.get('session') or '').strip() or '-'
        argv = ['bash', str(omega_bin()), 'chains', session, '--json']
        result = _run(argv, timeout=120)
        result['tool'] = 'omega_chains'
        return _fmt(result)
    except Exception as e:
        return _fmt({'success': False, 'error': str(e)})

def handle_stats(args: Dict[str, Any]) -> str:
    """omega_stats — engine/session statistics as text."""
    try:
        return _fmt(_run(['bash', str(omega_bin()), 'stats']))
    except Exception as e:
        return _fmt({'success': False, 'error': str(e)})


def _tail(text: Optional[str], n: int) -> str:
    """Last n chars of text (kept for direct-tail use by handlers/tests)."""
    if not text:
        return ''
    return text[-n:]
