"""omega/core/scheduler — impact-based attack scheduling.

Red-team operators do not attack alphabetically: they rank targets by
potential impact and spend budget top-down. This module scores every
URL in the surface (admin/internal/api/auth keywords, parameter
richness, auth surfaces, tech signals) and returns the ordered attack
queue the brain should follow.
"""
import re

__all__ = ["rank_targets"]

_SCORERS = [
    (re.compile(r"(admin|manage|dashboard|panel)", re.I), 30,
     "admin surface"),
    (re.compile(r"(api|graphql|rest|v1|v2)", re.I), 20, "API surface"),
    (re.compile(r"(login|signin|auth|session|jwt|token)", re.I), 18,
     "auth surface"),
    (re.compile(r"(internal|debug|staging|test|backup|config)", re.I),
     25, "sensitive/internal"),
    (re.compile(r"(upload|import|file|attachment)", re.I), 22,
     "file handling"),
    (re.compile(r"(pay|order|checkout|cart|balance|withdraw)", re.I),
     26, "money/state surface"),
    (re.compile(r"(user|account|profile|member)", re.I), 12,
     "identity surface"),
]


def rank_targets(surface, techs=None, budget=None):
    """Ordered attack queue from the surface.

    surface: {'urls': [...], 'forms': [...], 'params': [...]}.
    Returns {"queue": [{"url", "score", "why"}], "total": n}.
    """
    urls = list((surface or {}).get("urls") or [])
    scored = []
    for u in urls:
        score = 5.0  # base: every endpoint is worth one probe
        why = []
        for rx, pts, label in _SCORERS:
            if rx.search(u):
                score += pts
                why.append(label)
        q = u.split("?")[1] if "?" in u else ""
        nparams = len([p for p in q.split("&") if p])
        if nparams:
            score += min(nparams * 4, 20)
            why.append(f"{nparams} params")
        if (surface or {}).get("forms"):
            for f in surface["forms"]:
                if f.get("url") == u:
                    score += 15
                    why.append("form")
        scored.append({"url": u, "score": round(score, 1),
                       "why": why or ["generic endpoint"]})
    scored.sort(key=lambda x: -x["score"])
    if budget:
        scored = scored[:budget]
    return {"queue": scored, "total": len(scored)}
