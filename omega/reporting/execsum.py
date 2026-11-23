"""omega/reporting/execsum — audience-specific summaries.

One finding set, three views:

  - executive: risk posture, business language, no jargon or paths
  - manager:   counts by severity/owner, top items, remediation waves
  - dev:       per-finding location, CWE, score, PoC, fix direction

Pure transformation over sanitized findings; no side effects.
"""
__all__ = ["for_executive", "for_manager", "for_developer",
           "all_audiences"]

_SEV = ("HIGH", "MEDIUM", "LOW", "INFO")


def _counts(findings):
    c = {s: 0 for s in _SEV}
    for f in findings or []:
        s = str(f.get("severity", "INFO")).upper()
        c[s if s in c else "INFO"] += 1
    return c


def _posture(counts):
    if counts.get("HIGH"):
        return "elevated", "Material weaknesses were confirmed and " \
            "need remediation before the next release."
    if counts.get("MEDIUM"):
        return "moderate", "Several weaknesses were confirmed; none " \
            "allow immediate full compromise, but they should be " \
            "closed in the current cycle."
    if counts.get("LOW"):
        return "low", "Only low-impact observations were confirmed."
    return "minimal", "No confirmed weaknesses were observed in the " \
        "tested surface."


def for_executive(findings, target="target"):
    counts = _counts(findings)
    level, line = _posture(counts)
    confirmed = sum(1 for f in findings or []
                    if str(f.get("verification", "")).lower() in
                    ("verified", "confirmed"))
    return {
        "audience": "executive",
        "target": target,
        "risk_level": level,
        "summary": line,
        "headline": "%d confirmed issue(s); overall exposure: %s" %
        (confirmed, level),
        "counts": counts,
        "ask": "Approve remediation of the confirmed items; "
               "candidate items are pending manual verification.",
    }


def for_manager(findings, target="target"):
    counts = _counts(findings)
    items = []
    for f in sorted(findings or [],
                    key=lambda x: _SEV.index(str(
                        x.get("severity", "INFO")).upper())
                    if str(x.get("severity", "INFO")).upper() in _SEV
                    else 3):
        items.append({
            "id": f.get("id", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", "INFO"),
            "score": _canonical(f)["cvss_score"],
            "verification": f.get("verification", "candidate"),
        })
        if len(items) >= 10:
            break
    waves = {"wave-1 (now)": [], "wave-2 (cycle)": [],
             "wave-3 (backlog)": []}
    for it in items:
        sev = str(it["severity"]).upper()
        if sev == "HIGH":
            waves["wave-1 (now)"].append(it["title"])
        elif sev == "MEDIUM":
            waves["wave-2 (cycle)"].append(it["title"])
        else:
            waves["wave-3 (backlog)"].append(it["title"])
    return {"audience": "manager", "target": target,
            "counts": counts, "top_items": items,
            "remediation_waves": {k: v for k, v in waves.items() if v}}


def _fmt_cvss(scored):
    """Honest CVSS string: 'unavailable' when no vector/score could be
    established, never a fabricated default."""
    if not scored.get("cvss_vector") or scored.get("cvss_score") is None:
        return "unavailable"
    return "%s (%.1f)" % (scored["cvss_vector"], scored["cvss_score"])


def _canonical(f):
    """Canonical CVSS vector/score via score_finding — recomputes from
    a valid vector or derives from CWE/severity; stale scores never
    reach the summary as-is."""
    try:
        from omega.reporting.cvss import score_finding
        return score_finding(f)
    except Exception:
        return {"cvss_vector": f.get("cvss_vector", "n/a"),
                "cvss_score": 0.0}


def for_developer(findings, target="target"):
    rows = []
    for f in findings or []:
        scored = _canonical(f)
        rows.append({
            "title": f.get("title", ""),
            "location": f.get("location", ""),
            "cwe": f.get("cwe") or "",
            "cvss": _fmt_cvss(scored),
            "verification": f.get("verification", "candidate"),
            "manual_check": f.get("manual_check", ""),
            "poc": (f.get("poc") or {}).get("command") or "",
            "fix": f.get("recommendation", "") or
                   "see CWE reference for remediation guidance",
        })
    return {"audience": "developer", "target": target, "items": rows}


def all_audiences(findings, target="target"):
    return {"executive": for_executive(findings, target),
            "manager": for_manager(findings, target),
            "developer": for_developer(findings, target)}
