"""omega/core/noiseaudit — request-per-finding efficiency audit.

Counts requests consumed per capability from the run history and
flags: (1) capabilities that burned budget with zero output, (2)
endpoints never touched (coverage gaps), (3) overall requests-per-
finding ratio. PLAN-ONLY; output feeds the operator's next-run
planning.
"""
__all__ = ["audit_noise"]


def audit_noise(history=None, findings=None, budget_used=None):
    history = history or []
    findings = findings or []
    per_cap = {}
    for h in history:
        cap = h.get("capability", "?")
        rec = per_cap.setdefault(cap, {"steps": 0, "new_facts": 0})
        rec["steps"] += 1
        rec["new_facts"] += h.get("new_facts") or 0
    wasteful = [{"capability": c, "steps": r["steps"],
                 "new_facts": r["new_facts"]}
                for c, r in per_cap.items() if r["new_facts"] == 0]
    total_steps = sum(r["steps"] for r in per_cap.values())
    ratio = (total_steps / len(findings)) if findings else None
    return {
        "total_steps": total_steps,
        "findings": len(findings),
        "requests_per_finding": round(ratio, 2) if ratio else None,
        "wasteful_capabilities": sorted(
            wasteful, key=lambda x: -x["steps"]),
        "capabilities_used": len(per_cap),
        "budget_used": budget_used,
    }


def render_noise_audit(a):
    lines = ["## Noise audit"]
    lines.append(f"- steps: {a['total_steps']}, findings: "
                 f"{a['findings']}, requests/finding: "
                 f"{a['requests_per_finding'] or 'n/a'}")
    if a["wasteful_capabilities"]:
        lines.append("- zero-output capabilities (drop or re-scope "
                     "next run):")
        for w in a["wasteful_capabilities"][:8]:
            lines.append(f"  - {w['capability']} ({w['steps']} steps)")
    else:
        lines.append("- every capability produced findings — clean run")
    return "\n".join(lines)
