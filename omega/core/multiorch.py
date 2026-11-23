"""omega/core/multiorch — multi-target orchestrator.

Runs the SAME capability set across a LIST of targets (from a file,
CT graph, or operator list), aggregates per-target summaries, and
renders a portfolio view ranked by severity mass. Each target gets
its own state object; gates apply per target (per-host authorization
list required via surface.targets_auth).
"""
__all__ = ["run_portfolio", "render_portfolio"]


def run_portfolio(registry, targets, make_state, plan=None, log=None):
    """targets: [url,...]; make_state(target)->state-like object.

    Returns per-target results and a ranked portfolio.
    """
    from omega.core.autodeep import execute_plan, plan_engagement
    results = []
    for t in targets or []:
        state = make_state(t)
        p = plan or plan_engagement(registry, surface={
            "gated": (state.surface or {}).get("gated", False)})
        doc = execute_plan(registry, state, p, log=log)
        sevs = {}
        for f in state.findings:
            s = f.get("severity", "INFO")
            sevs[s] = sevs.get(s, 0) + 1
        results.append({"target": t, "findings": len(state.findings),
                        "executed": len(doc["executed"]),
                        "dropped": len(doc["dropped"]),
                        "severities": sevs})
    # rank: CRITICAL mass first
    weight = {"CRITICAL": 100, "HIGH": 30, "MEDIUM": 8, "LOW": 2,
              "INFO": 0}
    for r in results:
        r["risk_mass"] = sum(weight.get(s, 0) * n
                             for s, n in r["severities"].items())
    results.sort(key=lambda r: -r["risk_mass"])
    return {"portfolio": results, "targets": len(results)}


def render_portfolio(doc):
    lines = [f"## Portfolio — {doc['targets']} target(s), ranked"]
    for r in doc["portfolio"]:
        s = ", ".join(f"{k}:{v}" for k, v in sorted(
            r["severities"].items(), key=lambda kv: -kv[1]))
        lines.append(f"- {r['target']}: {r['findings']} findings "
                     f"({s or 'none'}), risk mass {r['risk_mass']}, "
                     f"{r['executed']} steps ok / {r['dropped']} dropped")
    return "\n".join(lines)
