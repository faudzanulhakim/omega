"""OMEGA session persistence — remember engagements across runs.

Sessions live in ~/.omega/sessions (override with OMEGA_SESSIONS_HOME,
tmpdir-safe for tests). Each session is a JSON document holding the
timestamp, target and summary counts plus the caller's state dict.
"""

from __future__ import annotations

import datetime
import json
import os


def sessions_dir():
    """Resolve the sessions directory (env-overridable, created lazily)."""
    home = os.environ.get("OMEGA_SESSIONS_HOME") or os.path.expanduser(
        os.path.join("~", ".omega", "sessions"))
    return home


def _governor_snapshot():
    """Per-host pacing stats for the audit trail (best-effort)."""
    try:
        from omega.core.governor import get_governor
        return get_governor().snapshot()
    except Exception:
        return {}


def _untrusted_audit(state_dict):
    """Scan finding evidence for instruction-injection carriers.

    Purely bookkeeping: flagged evidence is DATA, never acted on.
    """
    try:
        from omega.core.untrusted import scan_untrusted
        flagged = []
        for f in state_dict.get("findings") or []:
            if not isinstance(f, dict):
                continue
            evidence = f.get("evidence")
            if isinstance(evidence, (dict, list)):
                import json as _json
                evidence = _json.dumps(evidence, default=str)
            hits = scan_untrusted(str(evidence or ""))
            if hits:
                flagged.append({"finding": f.get("title"),
                                "patterns": [h["pattern"] for h in hits]})
        return {"flagged": flagged, "note": "flagged evidence is "
                "treated as data only — never as instructions"}
    except Exception:
        return {}


def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def save_session(name, state_dict):
    """Write <name>.json with a timestamp and summary counts.

    Returns the path written.
    """
    state_dict = dict(state_dict or {})
    now = datetime.datetime.now(datetime.timezone.utc)
    doc = {
        "name": name,
        "timestamp": now.isoformat(timespec="seconds"),
        "target": state_dict.get("target"),
        "summary": {
            "findings": len(state_dict.get("findings") or []),
            "hosts": len((state_dict.get("surface") or {})
                         .get("hosts") or []),
            "urls": len((state_dict.get("surface") or {})
                        .get("urls") or []),
            "ports": len((state_dict.get("surface") or {})
                         .get("ports") or []),
            "chains_planned": len(state_dict.get("chains_planned") or []),
            "steps": len(state_dict.get("history") or []),
        },
        "state": state_dict,
        # audit trail: replayable chain of decisions -> capabilities ->
        # findings (ARTEX-style exploration trail, headless edition)
        "audit": {
            "steps": len(state_dict.get("history") or []),
            "history": state_dict.get("history") or [],
            "governor": _governor_snapshot(),
            "untrusted": _untrusted_audit(state_dict),
        },
    }
    directory = _ensure_dir(sessions_dir())
    path = os.path.join(directory, f"{name}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, default=str)
    return path


def list_sessions():
    """Return session docs sorted newest-first (missing dir -> [])."""
    directory = sessions_dir()
    if not os.path.isdir(directory):
        return []
    out = []
    for fn in sorted(os.listdir(directory)):
        if not fn.endswith(".json"):
            continue
        path = os.path.join(directory, fn)
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            continue
        out.append(doc)
    out.sort(key=lambda d: d.get("timestamp", ""), reverse=True)
    return out


def load_session(name):
    """Load one session doc; KeyError when absent."""
    path = os.path.join(sessions_dir(), f"{name}.json")
    if not os.path.isfile(path):
        raise KeyError(f"no such session: {name!r}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------
# Diffing
# --------------------------------------------------------------------------

def _finding_key(f):
    if not isinstance(f, dict):
        return (repr(f), repr(f))
    title = str(f.get("title", f.get("name", repr(f))))
    location = str(f.get("location", f.get("url", f.get("host", ""))))
    return (title, location)


def _surface_set(state):
    surface = state.get("surface") or {}
    items = []
    for key in ("hosts", "urls", "ports", "techs"):
        for v in surface.get(key) or []:
            items.append(f"{key}:{v}")
    return set(items)


def diff_sessions(a, b):
    """Diff session doc a (older) against b (newer).

    Returns {new_findings, resolved_findings, surface_changes} keyed by
    (title, location).
    """
    fa = {_finding_key(f) for f in (a.get("state") or {}).get("findings")
          or []}
    fb = {_finding_key(f) for f in (b.get("state") or {}).get("findings")
          or []}
    sa = _surface_set(a.get("state") or {})
    sb = _surface_set(b.get("state") or {})
    return {
        "new_findings": sorted(fb - fa),
        "resolved_findings": sorted(fa - fb),
        "surface_changes": {
            "added": sorted(sb - sa),
            "removed": sorted(sa - sb),
        },
    }
