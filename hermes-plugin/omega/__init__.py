"""OMEGA Hermes plugin — 8 tools wrapping the omega red-team operator.

OMEGA is an autonomous red-team operator: brutal in analysis, honest in
evidence (confirmed vs candidate findings), and never destructive — no data
is ever destroyed, nothing is permanently broken.

Authorization is enforced per-call: omega_scan and omega_assault refuse to run
unless the caller explicitly passes scope_ack=True, and the plugin never adds
--scope-ack itself.

Registers ONLY tools (no hooks, no CLI commands) via register(ctx).
"""

from __future__ import annotations

import logging

from . import _omega
from ._omega import (_omega_available, handle_assault, handle_chains,
                     handle_followup, handle_report, handle_scan,
                     handle_sessions, handle_stats, handle_validate)

logger = logging.getLogger(__name__)

SCAN_SCHEMA = {
    'type': 'object',
    'description': (
        'Deploy the OMEGA autonomous red-team operator against a target. '
        'Pass scope_ack=true to confirm you are authorized to test this '
        'target — the operator refuses to move without it and never grants '
        'itself permission.'),
    'properties': {
        'target': {
            'type': 'string',
            'description': 'Target URL / host / scope for the scan.'},
        'mode': {
            'type': 'string',
            'enum': ['brain', 'run'],
            'description': "'brain' (autonomous planning, default) or 'run' (execute a PROMPT)."},
        'prompt': {
            'type': 'string',
            'description': 'PROMPT — required only when mode=run.'},
        'aggressive': {
            'type': 'boolean',
            'description': 'Enable --aggressive mode.'},
        'polyglot': {
            'type': 'boolean',
            'description': 'Enable --polyglot payload mode.'},
        'offense': {
            'type': 'boolean',
            'description': 'Enable --offense mode.'},
        'exploit': {
            'type': 'boolean',
            'description': 'Enable --exploit mode.'},
        'max_steps': {
            'type': 'integer',
            'description': 'Optional --max-steps N cap on autonomous steps.'},
        'json': {
            'type': 'boolean',
            'description': 'Pass --json for machine-readable output.'},
        'scope_ack': {
            'type': 'boolean',
            'description': (
                'MUST be true to run: asserts operator authorization to test '
                'this target. Without it the scan is refused.')}},
    'required': ['target']}

SESSIONS_SCHEMA = {
    'type': 'object',
    'description': (
        'Read-only operator log: list the last 10 OMEGA engagements or diff '
        'a session against the latest. No scope_ack needed — observation is '
        'always permitted.'),
    'properties': {
        'action': {
            'type': 'string',
            'enum': ['list', 'diff'],
            'description': "'list' (default) shows the last 10 sessions; 'diff' compares a session to the latest."},
        'session': {
            'type': 'string',
            'description': 'Session id — used with action=diff.'}},
    'required': []}

REPORT_SCHEMA = {
    'type': 'object',
    'description': (
        'Produce the OMEGA engagement report in one of 5 formats — brutal '
        'analysis, honest evidence: confirmed findings vs candidates, every '
        'claim backed by artifacts. Read-only; never deletes anything.'),
    'properties': {
        'session': {
            'type': 'string',
            'description': "Session id, or '-' for the latest (default)."},
        'out': {
            'type': 'string',
            'description': 'Output path; defaults to /tmp/omega-report-<session>.<fmt>.'},
        'fmt': {
            'type': 'string',
            'enum': ['markdown', 'html', 'json', 'docx', 'pdf'],
            'description': 'Report format (default pdf).'},
        'lang': {
            'type': 'string',
            'description': (
                'Report language: en, id, es, fr, de, pt, zh, ja, ar, ru, '
                'hi (default en). Structure/labels localized; finding '
                'evidence stays verbatim.')}},
    'required': []}

STATS_SCHEMA = {
    'type': 'object',
    'description': 'Operator scoreboard: OMEGA engine/session statistics as text.',
    'properties': {},
    'required': []}

VALIDATE_SCHEMA = {
    'type': 'object',
    'description': (
        'AI-claim validation gate (anti-hallucination): re-check any finding '
        'the assistant proposed against the live target. Evidence must '
        'reproduce verbatim — refuted claims are downgraded and tagged '
        'ai-claim:refuted, exit_code 2 means at least one claim was '
        'refuted. NEVER present a refuted claim as a vulnerability.'),
    'properties': {
        'claims': {
            'type': 'string',
            'description': (
                'JSON list (or JSON string) of proposed findings, each with '
                'title/severity/location/evidence.')},
        'base': {
            'type': 'string',
            'description': 'Base URL for relative locations.'},
        'drop_refuted': {
            'type': 'boolean',
            'description': 'Omit refuted/unverifiable claims from output.'}},
    'required': ['claims']}

FOLLOWUP_SCHEMA = {
    'type': 'object',
    'description': (
        'Adaptive follow-up loop: run second-depth probes (blind SQLi '
        'boolean, XSS DOM-context, traversal encodings, redirect variants, '
        'CSP parse) on scanner findings. Every probe result passes the '
        'validation gate — only verified claims are returned as findings. '
        'Read-only, benign payloads only.'),
    'properties': {
        'findings': {
            'type': 'string',
            'description': 'Path to a findings JSON file (e.g. from a session).'},
        'base': {
            'type': 'string',
            'description': 'Base URL for relative locations.'},
        'budget': {
            'type': 'integer',
            'description': 'Max probes to run (default 12).'}},
    'required': ['findings']}

CHAINS_SCHEMA = {
    'type': 'object',
    'description': (
        'Exploit-chain recommender: deterministic, grounded ONLY in '
        'verified session findings — credential replay, CVE exploit, '
        'upload bypass, takeover, secret retrieval — plus paste-ready '
        'omega assault commands. Read-only planning; nothing executes.'),
    'properties': {
        'session': {
            'type': 'string',
            'description': "Session id, or '-' for the latest (default)."}},
    'required': []}

ASSAULT_SCHEMA = {
    'type': 'object',
    'description': (
        'One-shot brutal engagement: launch the OMEGA red-team operator in '
        'aggressive autonomous mode against a target, then automatically '
        'generate the PDF report on the latest session. Full send, one call. '
        'Pass scope_ack=true to confirm you are authorized — without it '
        'nothing runs.'),
    'properties': {
        'target': {
            'type': 'string',
            'description': 'Target URL / host / scope for the engagement.'},
        'max_steps': {
            'type': 'integer',
            'description': 'Optional --max-steps N cap on autonomous steps.'},
        'scope_ack': {
            'type': 'boolean',
            'description': (
                'MUST be true to run: asserts operator authorization to test '
                'this target. Without it the assault is refused outright.')},
        'lang': {
            'type': 'string',
            'description': (
                'Auto-report language: en, id, es, fr, de, pt, zh, ja, ar, '
                'ru, hi (default en).')}},
    'required': ['target', 'scope_ack']}

_TOOLS = (
    ('omega_scan', SCAN_SCHEMA, handle_scan, '🛡️'),
    ('omega_assault', ASSAULT_SCHEMA, handle_assault, '⚔️'),
    ('omega_validate', VALIDATE_SCHEMA, handle_validate, '🧪'),
    ('omega_followup', FOLLOWUP_SCHEMA, handle_followup, '🔎'),
    ('omega_chains', CHAINS_SCHEMA, handle_chains, '⛓️'),
    ('omega_sessions', SESSIONS_SCHEMA, handle_sessions, '📜'),
    ('omega_report', REPORT_SCHEMA, handle_report, '📑'),
    ('omega_stats', STATS_SCHEMA, handle_stats, '📊'))


def register(ctx) -> None:
    """Register the 5 omega tools (called once by the plugin loader). Nothing else."""
    for name, schema, handler, emoji in _TOOLS:
        ctx.register_tool(name=name, toolset='omega', schema=schema,
                          handler=handler, check_fn=_omega_available, emoji=emoji)
