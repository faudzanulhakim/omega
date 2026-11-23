"""omega/core/engagement — autonomous engagement loop (campaign v2).

A close-loop driver: run a stage, consult the score-driven planner,
run the next stage the planner ranks, repeat until the planner says
no escalation is warranted, the stage budget is exhausted, or the
planner requests a stage that is unavailable locally.

Hard rules:
- the loop NEVER opens offense/exploit tiers itself; offense stages
  run only when the operator's env already opened those gates
- every stage failure degrades to a trace entry, never raises
- multi-target mode fans out sequentially (no parallel hammering
  without the operator's explicit swarm)

Public API:
    run_engagement(target, fetch=None, max_stages=8, ...) -> dict
    run_multi(targets, ...) -> dict
    aggregate(results) -> dict
"""
from omega.core.planner import score_surface


class _StageState:
    """Minimal brain-state-like shim the planner can score."""

    def __init__(self, target):
        self.target = target
        self.findings = []
        self.history = []
        self.notes = []


def run_engagement(target, fetch=None, max_stages=8, stage_fns=None,
                   request_budget=3000, log=None):
    """Run the autonomous loop against ONE target.

    ``stage_fns`` maps stage-name -> callable(state) -> dict with
    optional ``findings``/``note``/``requests``. When ``stage_fns``
    is None a default passive pipeline is used (recon/probe only).
    """
    if stage_fns is None:
        stage_fns = _default_passive_stages(fetch)
    state = _StageState(target)
    requests_used = 0
    trace = []
    stop_reason = "stage-budget"

    # bootstrap: always run the FIRST available stage once, so the
    # planner has a surface to score (a planner consulted on an empty
    # state would saturate immediately)
    bootstrap = next((name for name in stage_fns), None)
    if bootstrap and int(max_stages) > 0:
        if log:
            log("engagement bootstrap: %s" % bootstrap)
        try:
            out = stage_fns[bootstrap](state) or {}
        except Exception as exc:
            out = {"error": str(exc)}
        new_f = out.get("findings") or []
        state.findings.extend(new_f)
        requests_used += int(out.get("requests") or 0)
        state.history.append({
            "step": 0, "capability": bootstrap,
            "result": "error" if out.get("error") else "ok",
            "new_facts": len(new_f)})
        trace.append({"step": 0, "stage": bootstrap, "reason":
                      "bootstrap (planner needs a surface)",
                      "status": "error" if out.get("error") else "ok",
                      "new_findings": len(new_f)})

    for step in range(1, int(max_stages) + 1):
        plan = score_surface(state)
        nxt = plan["next"][:1]
        if not nxt:
            stop_reason = "planner-saturated (no escalation warranted)"
            break
        suite, prio, why = nxt[0]
        fn = stage_fns.get(suite)
        if fn is None:
            stop_reason = "planner requested unavailable stage: " + suite
            trace.append({"step": step, "wanted": suite, "reason": why,
                          "status": "unavailable"})
            break
        if requests_used >= int(request_budget):
            stop_reason = "request budget exhausted"
            break
        if log:
            log("engagement step %d: %s (%s)" % (step, suite, why))
        try:
            out = fn(state) or {}
        except Exception as exc:
            out = {"error": str(exc)}
        new_f = out.get("findings") or []
        state.findings.extend(new_f)
        requests_used += int(out.get("requests") or 0)
        state.history.append({
            "step": step, "capability": suite,
            "result": "error" if out.get("error") else "ok",
            "new_facts": len(new_f)})
        state.notes.append(out.get("note") or "")
        trace.append({"step": step, "stage": suite, "reason": why,
                      "status": "error" if out.get("error") else "ok",
                      "new_findings": len(new_f)})

    return {"target": target, "stages": trace,
            "findings": state.findings, "stop_reason": stop_reason,
            "requests_used": requests_used,
            "planner_final": score_surface(state)}


def _default_passive_stages(fetch):
    """Default stage map: passive recon/probe only, never offense."""

    def headers_stage(state):
        if fetch is None:
            return {"note": "no fetch available"}
        st, headers, body = fetch("GET", state.target, body=None)
        if not isinstance(headers, dict):
            return {"note": "no headers"}
        sec = ["content-security-policy", "strict-transport-security",
               "x-frame-options", "x-content-type-options"]
        missing = [h for h in sec if not headers.get(h)]
        findings = []
        if missing:
            findings.append({
                "title": "security headers missing: "
                         + ", ".join(missing),
                "severity": "MEDIUM" if len(missing) > 2 else "LOW",
                "verification": "candidate",
                "manual_check": "curl -sI %s" % state.target,
                "source": "engagement/headers",
                "location": state.target,
                "evidence": "absent: " + ", ".join(missing)})
        return {"findings": findings, "requests": 1}

    return {
        "campaign.headers": headers_stage,
        "polyglot.techprof": lambda state: {
            "note": "requires PTK_POLYGLOT gate + go toolchain"},
    }


# ------------------------------------------------------- multi-target

def run_multi(targets, fetch=None, max_stages=8, stage_fns=None,
              request_budget=3000, log=None):
    """Fan the engagement across N targets, sequentially."""
    results = []
    for t in targets or []:
        t = str(t or "").strip()
        if not t or "://" not in t:
            continue
        if log:
            log("engagement target: %s" % t)
        results.append(run_engagement(t, fetch=fetch,
                                      max_stages=max_stages,
                                      stage_fns=stage_fns,
                                      request_budget=request_budget,
                                      log=log))
    return {"results": results, "aggregate": aggregate(results)}


def aggregate(results):
    """Risk-ranked cross-target aggregate."""
    weight = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1,
              "INFO": 0}
    ranked = []
    for r in results:
        score = sum(weight.get(str(f.get("severity") or "INFO")
                               .upper(), 0)
                    for f in r.get("findings") or [])
        ranked.append({"target": r.get("target"), "risk": score,
                       "findings": len(r.get("findings") or []),
                       "stages": len(r.get("stages") or []),
                       "stop_reason": r.get("stop_reason")})
    ranked.sort(key=lambda x: -x["risk"])
    return {"ranking": ranked,
            "total_findings": sum(x["findings"] for x in ranked),
            "targets": len(ranked)}
