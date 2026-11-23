"""omega/core/lessonsv2 — per-endpoint lessons (lessons.py v2 layer).

lessons.py remembers per-HOST what got blocked/worked. v2 remembers
per-ENDPOINT and propagates across similar endpoints (same path
prefix, same stack) so the AI reuses what survived instead of
re-learning on every scan.

Storage rides the same lessons.json doc (``endpoints`` key per host);
never stores credentials or secret values — tokens are recorded as
shape hints only (kind + short prefix, like lessons.py).
"""
import os

from omega.core.lessons import _host_entry, _now, load_lessons, \
    save_lessons

__all__ = ["record_endpoint", "consult_endpoint", "propagate_hint",
           "endpoint_summary"]


def _ep_entry(doc, host, endpoint):
    hostdoc = _host_entry(doc, host)
    eps = hostdoc.setdefault("endpoints", {})
    return eps.setdefault(endpoint, {"blocked": [], "worked": [],
                                     "notes": []})


def _add(entry, key, value, limit=50):
    lst = entry.setdefault(key, [])
    if value not in lst:
        lst.append(value)
        del lst[:-limit]


def record_endpoint(host, endpoint, verdict, token_kind="payload",
                    hint=None, lessons=None):
    """Record a per-endpoint outcome. verdict: blocked|worked|note.

    ``hint`` must be a SHAPE hint (e.g. 'single-quote blocked',
    'double-encode passed') — never a raw secret value.
    """
    own = lessons is None
    doc = lessons or load_lessons()
    entry = _ep_entry(doc, host, endpoint)
    item = "%s|%s|%s" % (_now(), token_kind, hint or "")
    _add(entry, verdict if verdict in ("blocked", "worked") else
         "notes", item)
    if own:
        save_lessons(doc)
    return entry


def consult_endpoint(host, endpoint, lessons=None):
    """What does memory say about this endpoint (and its siblings)?

    Returns {'worked': [...], 'blocked': [...], 'from': endpoint|
    sibling-name} — sibling knowledge is labeled so the AI knows it
    was propagated, not observed here.
    """
    doc = lessons or load_lessons()
    hostdoc = (doc.get("hosts") or {}).get(host) or {}
    eps = hostdoc.get("endpoints") or {}
    direct = eps.get(endpoint)
    if direct:
        return {"worked": list(direct.get("worked") or []),
                "blocked": list(direct.get("blocked") or []),
                "from": endpoint}
    # sibling propagation: same first path segment
    seg = "/" + endpoint.strip("/").split("/")[0] if \
        endpoint.strip("/") else "/"
    for name, entry in eps.items():
        if name != endpoint and (name.startswith(seg) or
                                 seg.startswith("/" +
                                               name.strip("/").split(
                                                   "/")[0])):
            return {"worked": list(entry.get("worked") or []),
                    "blocked": list(entry.get("blocked") or []),
                    "from": name + " (sibling, propagated)"}
    return {"worked": [], "blocked": [], "from": None}


def propagate_hint(host, source_endpoint, target_endpoint,
                   lessons=None):
    """Copy worked/blocked hints from one endpoint to a sibling."""
    doc = lessons or load_lessons()
    got = consult_endpoint(host, source_endpoint, lessons=doc)
    if not got["from"] or got["from"].endswith("(sibling, "
                                               "propagated)"):
        return False
    src = got["from"].split(" (")[0]
    eps = _host_entry(doc, host).setdefault("endpoints", {})
    dst = eps.setdefault(target_endpoint, {"blocked": [], "worked": [],
                                           "notes": []})
    for key in ("worked", "blocked"):
        for item in (eps.get(src) or {}).get(key) or []:
            _add(dst, key, item + "|propagated-from:%s" % src)
    save_lessons(doc)
    return True


def record_outcome(host, endpoint, technique, success, lessons=None):
    """Record a technique-level outcome for adaptive ranking.

    technique: short shape hint (e.g. 'double-encode'). success:
    bool. Win-rate feeds rank_techniques so future scans try what
    worked first on this endpoint/siblings.
    """
    own = lessons is None
    doc = lessons or load_lessons()
    entry = _ep_entry(doc, host, endpoint)
    outcomes = entry.setdefault("outcomes", {})
    tally = outcomes.setdefault(technique, {"win": 0, "loss": 0})
    tally["win" if success else "loss"] += 1
    if own:
        save_lessons(doc)
    return tally


def rank_techniques(host, endpoint, lessons=None):
    """Techniques ranked by observed win-rate (desc), 0-rate last.

    Returns [{'technique', 'win', 'loss', 'rate'}] — evidence-driven
    ordering for the next scan pass.
    """
    doc = lessons or load_lessons()
    eps = ((doc.get("hosts") or {}).get(host) or {}).get(
        "endpoints") or {}
    ranked = []
    seg = "/" + endpoint.strip("/").split("/")[0] if \
        endpoint.strip("/") else "/"
    for ep, entry in eps.items():
        if ep != endpoint and not (ep.startswith(seg) or
                                   seg.startswith("/" +
                                                 ep.strip("/").split(
                                                     "/")[0])):
            continue
        for tech, tally in (entry.get("outcomes") or {}).items():
            win = tally.get("win", 0)
            loss = tally.get("loss", 0)
            total = win + loss
            ranked.append({"technique": tech, "win": win,
                           "loss": loss,
                           "rate": round(win / total, 2) if total
                           else 0.0,
                           "from": ep})
    ranked.sort(key=lambda x: (-x["rate"], -(x["win"] + x["loss"])))
    return ranked


def endpoint_summary(host, lessons=None):
    doc = lessons or load_lessons()
    eps = ((doc.get("hosts") or {}).get(host) or {}).get(
        "endpoints") or {}
    return {ep: {"worked": len(v.get("worked") or []),
                 "blocked": len(v.get("blocked") or [])}
            for ep, v in eps.items()}
