"""omega/core/planner — score-driven scan planner.

Turns the accumulated surface state (open ports, detected frameworks,
TLS weaknesses, endpoints, prior findings) into a RANKED list of
next-stage scans. The brain consults the planner when the current
stage produced evidence, so scanning is adaptive instead of a fixed
sequence. Pure function over state data; no network access.
"""
import os


def score_surface(state):
    """Score the observed attack surface.

    ``state`` is a brain state-like object: ``.target`` plus optional
    ``.findings`` and ``.history`` (list of dicts with
    ``capability``/``result``/``new_facts``). Returns a dict:
    {"score": int, "next": [(suite_or_cap, priority, reason), ...]}.
    Higher score = richer surface = deeper stages are worth running.
    """
    findings = getattr(state, "findings", None) or []
    history = getattr(state, "history", None) or []
    target = str(getattr(state, "target", "") or "")

    sev_weight = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1,
                  "INFO": 0}
    score = sum(sev_weight.get(
        str(f.get("severity") or "INFO").upper(), 0)
        for f in findings)

    # the more capabilities actually produced facts, the richer the
    # surface — depth pays off
    productive = sum(1 for h in history
                     if (h.get("new_facts") or 0) > 0
                     and h.get("result") == "ok")
    score += productive * 2

    next_stages = []
    sources = {str(f.get("source") or "") for f in findings}

    # evidence-driven escalation ladder (highest priority first)
    if any("portsweep" in s for s in sources):
        next_stages.append(
            ("polyglot.tlsprobe", 7, "open TLS-capable port seen"))
        next_stages.append(
            ("polyglot.subhunt", 6, "live host confirmed — map vhosts"))
    if any("subhunt" in s for s in sources):
        next_stages.append(
            ("polyglot.fuzzwave", 5, "vhosts found — fuzz content"))
    if any("tlsprobe" in s or "legacy" in s for s in sources):
        next_stages.append(
            ("fusion.run_full", 6, "TLS weaknesses widen the stack "
             "assumption — run the full suite"))
    if any("jsmine" in s or "secrets" in s for s in sources):
        next_stages.append(
            ("autochain.harvest", 8, "client-side secret leak seen — "
             "harvest stage likely to produce more"))
    if any("sqli" in s.lower() for s in sources):
        next_stages.append(
            ("offense.injection", 9, "SQLi signal — escalate to the "
             "gated offense layer (operator approval still applies)"))
    if any("smuggler" in s for s in sources):
        next_stages.append(
            ("fusion.run_full", 8, "smuggling differential — full "
             "suite for the surrounding bug class"))
    if any("graphql" in s.lower() for s in sources):
        next_stages.append(
            ("polyglot.gqlprobe", 8, "GraphQL endpoint live — probe "
             "introspection/batching abuse"))

    # stable ordering: priority desc, then name
    next_stages.sort(key=lambda t: (-t[1], t[0]))
    # dedupe by suite id, keep the highest priority
    seen = set()
    ranked = []
    for suite, prio, why in next_stages:
        if suite not in seen:
            seen.add(suite)
            ranked.append((suite, prio, why))
    return {"target": target, "score": score, "next": ranked,
            "productive_stages": productive}


def plan_next(state, max_stages=4):
    """Return up to ``max_stages`` (suite, priority, reason) tuples."""
    doc = score_surface(state)
    return doc["next"][:max_stages]


def narrate_plan(state):
    """One-line human summary of the plan (for the brain log)."""
    doc = score_surface(state)
    if not doc["next"]:
        return "planner: surface score %d — no escalation warranted" \
            % doc["score"]
    head = "; ".join("%s (p%d: %s)" % (s, p, w)
                     for s, p, w in doc["next"][:3])
    return "planner: surface score %d — next: %s" % (doc["score"], head)


PLANNER_ENV = "OMEGA_PLANNER"
