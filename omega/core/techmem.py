"""omega/core/techmem — cross-target technology attack memory.

lessonsv2 is per-endpoint and per-host. techmem is per STACK
FINGERPRINT: what technique/mutation worked against a nginx+ModSec
stack on host A is reusable on host B with the same fingerprint.
Storage rides lessons.json-style doc (``stacks`` key) via
OMEGA_LESSONS_HOME. Records SHAPE hints only — never secret values.
"""
import os

from omega.core.lessons import _now, load_lessons, save_lessons

__all__ = ["stack_key", "record_stack", "consult_stack", "stack_summary"]


def _stack_entry(doc, key):
    stacks = doc.setdefault("stacks", {})
    return stacks.setdefault(key, {"worked": [], "blocked": [],
                                   "notes": [], "updated": None})


def stack_key(techs):
    """Deterministic fingerprint key from a tech list."""
    return "+".join(sorted({str(t).lower() for t in (techs or [])
                            if t}))


def record_stack(techs, technique, verdict, hint=None, lessons=None):
    """Record an outcome for a stack fingerprint.

    verdict: worked|blocked|note. ``hint`` must be a SHAPE hint
    (e.g. 'double-encode passed', 'case-swap bypassed 403') — never a
    raw exploit string or secret.
    """
    doc = load_lessons()
    entry = _stack_entry(doc, stack_key(techs))
    key = "worked" if verdict == "worked" else \
        "blocked" if verdict == "blocked" else "notes"
    item = hint if hint else technique
    lst = entry[key]
    if item not in lst:
        lst.append(item)
        del lst[:-50]
    entry["updated"] = _now()
    save_lessons(doc)
    return entry


def consult_stack(techs, lessons=None):
    """Ranked techniques that worked for this stack fingerprint."""
    doc = load_lessons()
    entry = _stack_entry(doc, stack_key(techs))
    return {"stack": stack_key(techs),
            "worked": list(entry.get("worked") or []),
            "blocked": list(entry.get("blocked") or [])}


def stack_summary(lessons=None):
    doc = load_lessons()
    return {k: len(v.get("worked") or [])
            for k, v in (doc.get("stacks") or {}).items()}
