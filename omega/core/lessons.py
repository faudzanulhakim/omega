"""omega/core/lessons.py — per-target lessons learned, persisted.

Across engagements OMEGA remembers what happened to each host:

- payload classes that got blocked / filtered (don't waste budget)
- payload shapes that went through (reuse first)
- WAF / rate-limit signals observed and their timestamps
- framework kits that proved useful

Storage: ~/.omega/lessons.json (override OMEGA_LESSONS_HOME).
Pure data + small helper API; no network. Never stores credentials.
"""

from __future__ import annotations

import datetime
import json
import os

__all__ = [
    "BLOCKED", "WORKED", "lessons_path", "load_lessons", "save_lessons",
    "record_blocked", "record_worked", "record_waf",
    "consult", "lessons_summary",
]

BLOCKED = "blocked"
WORKED = "worked"
WAF = "waf"

_MAX_ITEMS = 200


def lessons_path():
    return os.environ.get("OMEGA_LESSONS_HOME") or os.path.expanduser(
        os.path.join("~", ".omega", "lessons.json"))


def _now():
    return datetime.datetime.now(
        datetime.timezone.utc).isoformat(timespec="seconds")


def load_lessons():
    path = lessons_path()
    if not os.path.isfile(path):
        return {"version": 1, "hosts": {}}
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        if isinstance(doc, dict) and isinstance(doc.get("hosts"), dict):
            return doc
    except (OSError, ValueError):
        pass
    return {"version": 1, "hosts": {}}


def save_lessons(doc):
    path = lessons_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, default=str)
    os.replace(tmp, path)
    return path


def _host_entry(doc, host):
    hosts = doc.setdefault("hosts", {})
    entry = hosts.setdefault(str(host or "unknown").lower(), {
        "first_seen": _now(),
        BLOCKED: [],
        WORKED: [],
        WAF: [],
        "frameworks": [],
    })
    entry.setdefault(BLOCKED, [])
    entry.setdefault(WORKED, [])
    entry.setdefault(WAF, [])
    entry.setdefault("frameworks", [])
    return entry


def _add(entry, key, value, limit=_MAX_ITEMS):
    value = str(value)
    if value in entry[key]:
        entry[key].remove(value)
    entry[key].append(value)
    if len(entry[key]) > limit:
        del entry[key][0:len(entry[key]) - limit]
    entry["last_seen"] = _now()


def record_blocked(host, token, lessons=None):
    """Remember a blocked payload class / technique token for a host."""
    doc = lessons if lessons is not None else load_lessons()
    entry = _host_entry(doc, host)
    _add(entry, BLOCKED, token)
    save_lessons(doc)
    return doc


def record_worked(host, token, lessons=None):
    """Remember a payload shape / technique that got through."""
    doc = lessons if lessons is not None else load_lessons()
    entry = _host_entry(doc, host)
    _add(entry, WORKED, token)
    save_lessons(doc)
    return doc


def record_waf(host, vendor, lessons=None):
    """Remember an observed WAF / rate-limit vendor signal."""
    doc = lessons if lessons is not None else load_lessons()
    entry = _host_entry(doc, host)
    _add(entry, WAF, vendor)
    save_lessons(doc)
    return doc


def record_frameworks(host, names, lessons=None):
    doc = lessons if lessons is not None else load_lessons()
    entry = _host_entry(doc, host)
    for n in names or []:
        _add(entry, "frameworks", n, limit=20)
    save_lessons(doc)
    return doc


def consult(host, lessons=None):
    """Return the lesson entry for a host {'blocked','worked','waf',...}."""
    doc = lessons if lessons is not None else load_lessons()
    entry = (doc.get("hosts") or {}).get(str(host or "").lower())
    return dict(entry) if entry else {BLOCKED: [], WORKED: [], WAF: [],
                                      "frameworks": []}


def lessons_summary(doc=None):
    doc = doc if doc is not None else load_lessons()
    hosts = doc.get("hosts") or {}
    return {
        "hosts": len(hosts),
        "blocked_total": sum(len(h.get(BLOCKED) or [])
                             for h in hosts.values()),
        "worked_total": sum(len(h.get(WORKED) or [])
                            for h in hosts.values()),
        "waf_hosts": sum(1 for h in hosts.values() if h.get(WAF)),
    }
