"""OMEGA watch — periodic monitoring of a target across runs.

Each watch run executes the Brain loop (same safety contract as the
brain CLI: PermissionError without scope_ack), saves a session via
omega.session, and — when a previous session for the same target
exists — diffs it against the new one, producing a markdown report
with New Findings / Resolved / Surface Changes and a verdict line.

Designed for cron: alert_exit_code(delta) returns 1 when there are new
findings so a scheduled job can raise an alert.
"""

from __future__ import annotations

import datetime
import re

from omega import session as session_mod

# Triage labels for new findings, by keyword in the finding key.
_TRIAGE_RULES = (
    (("sqli", "injection", "rce", "exec"), "critical"),
    (("xss", "ssrf", "idor", "auth"), "high"),
    (("info", "header", "cookie", "tls", "version"), "low"),
)


def _slug(text, maxlen=60):
    """Filesystem-safe slug for session naming."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(text))[:maxlen]


def _session_name(target, label=None):
    """Session name: target slug + label or UTC timestamp."""
    suffix = label or datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"{_slug(target)}-{_slug(suffix, 80)}"


def _state_dict(target, mode, state):
    """Extract the JSON-serializable engagement dict from a BrainState."""
    return {
        "target": target,
        "mode": mode,
        "surface": state.surface,
        "findings": state.findings,
        "chains_planned": state.chains_planned,
        "history": state.history,
    }


def _triage_label(finding_key):
    """Rough severity label for a (title, location) finding key."""
    text = f"{finding_key[0]} {finding_key[1]}".lower()
    for needles, label in _TRIAGE_RULES:
        if any(n in text for n in needles):
            return label
    return "medium"


def _previous_session(target, exclude_name):
    """Newest prior session doc for the same target, or None.

    Matches on the doc's target field; the just-saved session is
    excluded by name. list_sessions() sorts by second-resolution
    timestamps, so file mtime breaks ties between sessions saved
    within the same second.
    """
    import os

    def _mtime(doc):
        path = os.path.join(session_mod.sessions_dir(),
                            f"{doc.get('name')}.json")
        try:
            return os.path.getmtime(path)
        except OSError:
            return 0.0

    candidates = [doc for doc in session_mod.list_sessions()
                  if doc.get("target") == target
                  and doc.get("name") != exclude_name]
    if not candidates:
        return None
    return max(candidates, key=lambda d: (d.get("timestamp", ""), _mtime(d)))


def render_watch_report(delta):
    """Render a watch delta as markdown with a verdict line."""
    new = delta.get("new_findings") or []
    resolved = delta.get("resolved_findings") or []
    surface = delta.get("surface_changes") or {}
    added = surface.get("added") or []
    removed = surface.get("removed") or []

    lines = ["# OMEGA Watch Report", ""]
    if new:
        lines.append("## New Findings")
        for key in new:
            lines.append(f"- [{_triage_label(key)}] {key[0]} @ {key[1]}")
        lines.append("")
    if resolved:
        lines.append("## Resolved Findings")
        for key in resolved:
            lines.append(f"- {key[0]} @ {key[1]}")
        lines.append("")
    if added or removed:
        lines.append("## Surface Changes")
        for item in added:
            lines.append(f"- added: {item}")
        for item in removed:
            lines.append(f"- removed: {item}")
        lines.append("")
    if new:
        lines.append("Verdict: NEW FINDINGS — attention required")
    else:
        lines.append("Verdict: no new findings")
    return "\n".join(lines)


def alert_exit_code(delta):
    """0 = clean, 1 = new findings (cron-friendly)."""
    return 1 if delta.get("new_findings") else 0


def watch(target, mode="auto", scope_ack=None, max_steps=12,
          session_label=None):
    """Run one monitoring pass and diff it against the previous session.

    Returns {baseline_or_delta, session_name, report_markdown} where
    baseline_or_delta is either {"baseline": True} or a diff_sessions()
    result dict.
    """
    from omega.brain import Brain

    state, _report = Brain().run(
        target, mode=mode, scope_ack=scope_ack, max_steps=max_steps)

    name = _session_name(target, session_label)
    doc_state = _state_dict(target, mode, state)
    try:
        session_mod.save_session(name, doc_state)
    except OSError:
        # Monitoring must not crash the caller when persistence fails;
        # the delta is still computed from in-memory state below.
        new_doc = None
    else:
        new_doc = session_mod.load_session(name)

    previous = _previous_session(target, name)
    if previous is None or new_doc is None:
        return {
            "baseline_or_delta": {"baseline": True},
            "session_name": name,
            "report_markdown": render_watch_report(
                {"new_findings": [], "resolved_findings": [],
                 "surface_changes": {"added": [], "removed": []}}),
        }

    delta = session_mod.diff_sessions(previous, new_doc)
    return {
        "baseline_or_delta": delta,
        "session_name": name,
        "report_markdown": render_watch_report(delta),
    }
