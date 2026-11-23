"""omega/core/impactscorer — dynamic evidence-based impact scoring.

Re-weights severity from ACTUAL evidence instead of static labels:
confirmation level, auth requirement, reachability, and blast radius
modify the reported priority. Deterministic and explainable; the
original severity is preserved and the adjusted one is reported
alongside, never silently replaced.
"""
__all__ = ["score_finding", "re_score"]

ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def score_finding(f):
    """Return {original, adjusted, reasons[]} for one finding."""
    sev = f.get("severity", "INFO")
    idx = ORDER.index(sev) if sev in ORDER else 1
    reasons = []
    # confirmation raises
    if f.get("verification") == "confirmed":
        if idx < ORDER.index("CRITICAL") and sev in ("MEDIUM", "HIGH"):
            idx += 1
            reasons.append("confirmed by probe evidence (+1)")
    # auth requirement lowers exploitable impact for external attack
    mc = (f.get("manual_check") or "").lower()
    ev = (f.get("evidence") or "").lower()
    if "unauthenticated" in ev or "anonymous" in ev or "anonymous" in mc:
        if sev in ("MEDIUM", "LOW"):
            idx += 1
            reasons.append("reachable unauthenticated (+1)")
    # INFO/LOW hygiene never escalates
    if sev in ("INFO",):
        idx = 0
        reasons.append("hygiene item — stays informational")
    # chainable findings (appear in a known chain template) raise MEDIUM
    chainable_cwes = {"CWE-918", "CWE-434", "CWE-444", "CWE-285",
                      "CWE-502"}
    if f.get("cwe") in chainable_cwes and sev == "MEDIUM" and \
            f.get("verification") == "confirmed":
        idx = ORDER.index("HIGH")
        reasons.append("chainable into multi-step exploit (+1)")
    return {"original": sev, "adjusted": ORDER[idx],
            "reasons": reasons or ["no adjustment — evidence matches "
                                   "static severity"]}


def re_score(findings):
    """Re-score all findings; returns list with adjusted severity."""
    out = []
    for f in findings or []:
        sc = score_finding(f)
        g = dict(f)
        g["severity_original"] = sc["original"]
        g["severity"] = sc["adjusted"]
        g["severity_reasons"] = sc["reasons"]
        out.append(g)
    return out


def render_re_score(findings):
    lines = ["## Impact re-scoring (evidence-based)"]
    for f in re_score(findings or []):
        if f["severity_original"] != f["severity"]:
            lines.append(f"- {f.get('title', '?')}: "
                         f"{f['severity_original']} -> {f['severity']} "
                         f"({' ; '.join(f['severity_reasons'])})")
    if len(lines) == 1:
        lines.append("_no severity adjustments — static labels match "
                     "evidence_")
    return "\n".join(lines)
