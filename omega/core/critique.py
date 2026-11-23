"""omega/core/critique — post-scan self-critique.

After a scan/engagement finishes, the brain reviews its own output:
are the findings' evidences strong, is there a false-positive smell,
which planner stages never ran although the surface warranted them?
The output is a structured critique doc plus a followup list. ONLY
passive followups are auto-approved; everything offense-shaped is
returned as a recommendation for the operator, never executed here.
"""
from omega.core.planner import score_surface

# evidence quality smells (FP guards)
_VAGUE_EVIDENCE_MARKERS = ("n/a", "none", "possible", "maybe",
                           "suspected")


def critique(findings, history=None, target="", planner_plan=None):
    """Review findings + history; return the critique doc.

    ``findings``: list of finding dicts.
    ``history``: list of stage-history dicts
        ({capability, result, new_facts}).
    ``planner_plan``: optional score_surface() doc from the END of the
        run — stages still ranked but unexecuted become followups.
    """
    findings = findings or []
    history = history or []
    fp_smells = []
    weak_evidence = []
    for f in findings:
        ev = str(f.get("evidence") or "").strip()
        if not ev:
            weak_evidence.append(f.get("title"))
            continue
        low = ev.lower()
        if any(m in low for m in _VAGUE_EVIDENCE_MARKERS) and \
                len(ev) < 40:
            fp_smells.append({"title": f.get("title"),
                              "why": "vague/short evidence",
                              "evidence": ev})
    # unverified top-severity findings are the classic FP vector
    for f in findings:
        if str(f.get("severity") or "").upper() in ("HIGH",
                                                    "CRITICAL") and \
                str(f.get("verification") or "candidate") == \
                "candidate" and not f.get("reverify_statuses"):
            fp_smells.append({
                "title": f.get("title"),
                "why": "HIGH/CRITICAL still candidate without a "
                       "replay check",
                "evidence": str(f.get("evidence") or "")[:80]})

    dead_stages = [h.get("capability") for h in history
                   if h.get("result") == "error"]
    empty_stages = [h.get("capability") for h in history
                    if h.get("result") == "ok"
                    and not (h.get("new_facts") or 0)]

    followups = []
    for smell in fp_smells[:10]:
        followups.append({"action": "re-verify",
                          "target_finding": smell["title"],
                          "auto_approved": False,
                          "reason": smell["why"]})
    if planner_plan:
        for suite, prio, why in (planner_plan.get("next") or [])[:5]:
            followups.append({"action": "run-stage", "stage": suite,
                              "priority": prio, "reason": why,
                              "auto_approved": prio <= 5})
    return {
        "target": target,
        "findings_reviewed": len(findings),
        "weak_evidence": [t for t in weak_evidence if t],
        "fp_smells": fp_smells,
        "dead_stages": dead_stages,
        "empty_stages": empty_stages,
        "followups": followups,
        "verdict": _verdict(findings, fp_smells, weak_evidence),
    }


def _verdict(findings, fp_smells, weak_evidence):
    if not findings:
        return "no findings — surface likely clean or stages too " \
               "shallow; consider a deeper profile"
    ratio = len(fp_smells) / max(1, len(findings))
    if ratio > 0.4:
        return "LOW CONFIDENCE: %.0f%% of findings carry FP smells " \
               "— manual review required" % (ratio * 100)
    if weak_evidence:
        return "OK with caveats: %d finding(s) lack evidence" \
            % len(weak_evidence)
    return "GOOD: findings carry evidence and passed the FP guard"


def narrate_critique(doc):
    """Human-readable critique block (for the brain log/report)."""
    lines = ["# Self-critique — %s" % doc.get("target", ""),
             "Verdict: %s" % doc.get("verdict")]
    if doc.get("fp_smells"):
        lines.append("FP smells (%d):" % len(doc["fp_smells"]))
        for s in doc["fp_smells"][:6]:
            lines.append("  - %s (%s)" % (s["title"], s["why"]))
    if doc.get("dead_stages"):
        lines.append("Stages that errored: %s"
                     % ", ".join(doc["dead_stages"]))
    if doc.get("empty_stages"):
        lines.append("Stages that produced nothing: %s"
                     % ", ".join(doc["empty_stages"]))
    auto = [f for f in doc.get("followups") or []
            if f.get("auto_approved")]
    manual = [f for f in doc.get("followups") or []
              if not f.get("auto_approved")]
    if auto:
        lines.append("Auto-approved followups: %s"
                     % ", ".join(str(f.get("stage") or
                                     f.get("target_finding"))
                                 for f in auto))
    if manual:
        lines.append("Operator decisions needed: %s"
                     % ", ".join(str(f.get("stage") or
                                     f.get("target_finding"))
                                 for f in manual[:5]))
    return "\n".join(lines)
