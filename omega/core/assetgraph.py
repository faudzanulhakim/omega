"""OMEGA asset graph — persistent, delta-aware target knowledge.

A JSON document (default ~/.omega/assets.json, override with
OMEGA_ASSETS_HOME) accumulates everything OMEGA has ever learned about
each host: URLs, ports, technologies, parameters, and finding titles.
Each entity carries first_seen / last_seen / hits, so repeat scans
become delta scans: only unknown entities are new signal.

Design (ARTEX-inspired, simplified for headless OMEGA):
- one flat JSON file, no database dependency
- merge is idempotent: re-saving the same facts changes only
  last_seen/hits counters
- delta(state) -> {new_urls, new_ports, new_techs} for the run report
- no network access anywhere in this module
"""

from __future__ import annotations

import datetime
import json
import os

__all__ = [
    "assets_path",
    "load_graph",
    "save_graph",
    "update_from_state",
    "delta_from_state",
]

_VERSION = 1


def assets_path():
    home = os.environ.get("OMEGA_ASSETS_HOME") or os.path.expanduser(
        os.path.join("~", ".omega", "assets.json"))
    return home


def _now():
    return datetime.datetime.now(
        datetime.timezone.utc).isoformat(timespec="seconds")


def _empty():
    return {"version": _VERSION, "updated": None, "hosts": {}}


def load_graph():
    """Load the asset graph (missing/corrupt file -> fresh graph)."""
    path = assets_path()
    if not os.path.isfile(path):
        return _empty()
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return _empty()
    if not isinstance(doc, dict) or "hosts" not in doc:
        return _empty()
    return doc


def save_graph(graph):
    """Persist the graph atomically (tmp + replace)."""
    path = assets_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    graph["updated"] = _now()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(graph, fh, indent=2, default=str)
    os.replace(tmp, path)
    return path


def _host_entry(graph, host):
    host = (host or "unknown").strip().lower()
    return graph["hosts"].setdefault(host, {
        "first_seen": _now(),
        "urls": {},
        "ports": {},
        "techs": {},
        "params": {},
        "findings": {},
    })


def _touch(store, key, extra=None):
    """Mark key as seen; return True when it is NEW."""
    entry = store.setdefault(key, {"hits": 0})
    if extra and isinstance(extra, dict):
        for k, v in extra.items():
            entry.setdefault(k, v)
    new = entry["hits"] == 0
    entry["hits"] += 1
    entry["last_seen"] = _now()
    return new


def update_from_state(state, graph=None):
    """Merge a scan state/engagement dict into the graph.

    Accepts either a raw state dict or a saved session doc (state
    nested under 'state'). Returns (graph, delta) where delta lists
    every entity first seen in THIS update.
    """
    if isinstance(state, dict) and isinstance(state.get("state"), dict):
        state = state["state"]
    state = state or {}
    graph = graph if graph is not None else load_graph()
    surface = state.get("surface") or {}
    hosts = [h for h in (surface.get("hosts") or []) if h]
    if not hosts and state.get("target"):
        hosts = [str(state["target"])]
    delta = {"hosts": [], "urls": [], "ports": [], "techs": [],
             "params": [], "findings": []}

    for host in hosts:
        entry = _host_entry(graph, host)
        if entry.get("hits", 0) == 0:
            delta["hosts"].append(host)
        entry["hits"] = entry.get("hits", 0) + 1

        for url in surface.get("urls") or []:
            if _touch(entry["urls"], str(url)):
                delta["urls"].append(str(url))
        for port in surface.get("ports") or []:
            if _touch(entry["ports"], str(port)):
                delta["ports"].append(str(port))
        for tech in surface.get("techs") or []:
            if _touch(entry["techs"], str(tech)):
                delta["techs"].append(str(tech))
        for param in surface.get("params") or []:
            if _touch(entry["params"], str(param)):
                delta["params"].append(str(param))
        for f in state.get("findings") or []:
            if not isinstance(f, dict):
                continue
            title = str(f.get("title") or f.get("kind") or "finding")
            if _touch(entry["findings"], title,
                      {"severity": f.get("severity"),
                       "verification": f.get("verification")}):
                delta["findings"].append(title)
    save_graph(graph)
    return graph, delta


def delta_from_state(state):
    """Convenience: update and return only the delta dict."""
    _, delta = update_from_state(state)
    return delta
