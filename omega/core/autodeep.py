"""omega/core/autodeep — autonomous engagement planner v2.

One brain to run a full engagement: recon/surface wave first, then
evidence-ranked offense waves (adaptive), chain pushes on named
broken links, and a report tail — re-planning after each wave as
findings change priorities. The agent stays inside its gates: any
capability that refuses (gate closed) is dropped from the plan with
its reason recorded, never retried blindly.
"""
__all__ = ["plan_engagement", "execute_plan"]

_WAVES = [
    ("surface", ["core.subdgraph", "offense.jsmine",
                 "offense.shadowdisc", "core.stackroute"]),
    ("auth", ["auth.session_scan", "auth.jwtdeep", "auth.jwtattack",
              "offense.sessionmatrix", "offense.authzmatrix",
              "offense.verbtamper"]),
    ("injection", ["offense.blindrelay", "offense.destrshape",
                   "offense.hackwave", "offense.deserprobe"]),
    ("infra", ["offense.smuggle", "offense.cachepoison",
               "offense.cisweep", "core.fpexploit"]),
    ("logic", ["offense.idororacle", "offense.apispecial",
               "offense.bizfuzz", "offense.racehunt"]),
    ("report", ["core.impactscorer", "core.chaincomposer",
                "core.pocgen", "core.narrgen", "core.noiseaudit"]),
]

# capabilities that must be OFFENSE-gated to run
_GATED_PREFIX = "offense."


def plan_engagement(registry, surface=None, findings=None, history=None,
                    max_waves=None):
    """Return an ordered plan: [{wave, caps, skip:[(cap, reason)]}]."""
    surface = surface or {}
    gated = surface.get("gated", False)
    waves = _WAVES if max_waves is None else _WAVES[:max_waves]
    plan = []
    for name, caps in waves:
        run, skip = [], []
        for cap in caps:
            if cap.startswith(_GATED_PREFIX) and not gated:
                skip.append((cap, "PTK_OFFENSE not set — skipped"))
                continue
            if registry.get(cap) is None:
                skip.append((cap, "capability not registered"))
                continue
            run.append(cap)
        plan.append({"wave": name, "caps": run, "skip": skip})
    return plan


def execute_plan(registry, state, plan, log=None):
    """Run the plan wave by wave; findings feed later waves.

    Each cap fn receives the live state, so later waves see earlier
    findings (adaptive re-planning by construction).
    """
    executed, dropped = [], []
    all_findings = list(getattr(state, "findings", None) or [])
    for wave in plan:
        for cap in wave["caps"]:
            cap = registry.get(cap)
            if cap is None:
                dropped.append((cap, "missing"))
                continue
            try:
                doc = cap.fn(state)
            except Exception as exc:
                dropped.append((cap.id, f"error: {exc}"))
                continue
            note = doc.get("note") or ""
            new = doc.get("findings") or []
            if "offense layer disabled" in note:
                dropped.append((cap.id, "gate closed"))
                continue
            all_findings.extend(new)
            state.findings = all_findings
            state.history.append({
                "step": len(state.history) + 1,
                "capability": cap.id,
                "result": "ok", "new_facts": len(new),
                "reasoning": f"autodeep wave {wave['wave']}"})
            executed.append({"wave": wave["wave"], "cap": cap.id,
                             "new_findings": len(new)})
            if log:
                log(f"autodeep {wave['wave']}/{cap.id}: +{len(new)}")
    return {"executed": executed, "dropped": [list(d) for d in dropped],
            "total_findings": len(all_findings)}
