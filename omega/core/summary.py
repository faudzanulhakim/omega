"""omega/core/summary — executive summary generator.

Turns a findings list + engagement doc into a human-language executive
summary grouped by severity: what was found, what it enables, what to
do first. Deterministic templates (no LLM call — the brain can wrap
this, but the report stays reproducible offline). English base text;
report layer handles the 11-language rendering.
"""
from omega.core.autochain import narrate as kill_chain_narrate

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# title-keyword -> impact sentence fragment
_IMPACT_RULES = [
    ("session fixation", "an attacker can fix the victim's session ID "
     "and take over the account after login"),
    ("session survives logout", "a 'logged out' session remains usable "
     "— stolen cookies keep working after the user logs out"),
    ("sql injection", "full database read/write may be possible "
     "through the injection point"),
    ("prototype pollution", "server-side object merging can be bent "
     "into privilege-bypass gadgets"),
    ("request smuggling", "front-end/back-end desync can bypass "
     "controls and poison shared caches"),
    ("secret material in client bundle", "credentials shipped to every "
     "visitor's browser; rotation required"),
    ("introspection enabled", "the full API schema is disclosed, "
     "accelerating targeted abuse"),
    ("race condition", "limit-once business actions can be replayed "
     "concurrently"),
    ("directory/file exists", "sensitive paths are exposed to "
     "unauthenticated enumeration"),
    ("security headers missing", "the page is exposed to common "
     "client-side attack classes that headers normally blunt"),
    ("subdomain resolves", "additional attack surface reachable "
     "outside the primary host"),
    ("open port", "services are exposed beyond the web front-end"),
]


def _impact_for(finding):
    title = str(finding.get("title") or "").lower()
    for kw, impact in _IMPACT_RULES:
        if kw in title:
            return impact
    return "expands the attacker's foothold on the target"


def executive_summary(findings, target="", history=None):
    """Build the executive summary doc.

    Returns {"target", "headline", "by_severity": {sev: [strings]},
    "do_first": [..], "counts": {..}}.
    """
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    counts = {}
    by_sev = {}
    for f in findings:
        sev = str(f.get("severity") or "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
        title = str(f.get("title") or "finding")
        by_sev.setdefault(sev, []).append(
            "%s — %s" % (title, _impact_for(f)))

    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    headline_bits = []
    if critical:
        headline_bits.append("%d critical" % critical)
    if high:
        headline_bits.append("%d high" % high)
    medium = counts.get("MEDIUM", 0)
    if medium:
        headline_bits.append("%d medium" % medium)
    headline = ("%s: %s issue(s) found" %
                (target or "engagement", " + ".join(headline_bits) or
                 "no significant")) if findings else \
        "%s: no significant issues found" % (target or "engagement")

    do_first = []
    for sev in _SEVERITY_ORDER[:2]:
        for line in by_sev.get(sev, [])[:3]:
            do_first.append(line)
    if not do_first:
        # no critical/high: fall back to the highest severity present
        for sev in _SEVERITY_ORDER[2:]:
            if by_sev.get(sev):
                do_first = by_sev[sev][:3]
                break
    return {"target": target, "headline": headline,
            "by_severity": {k: v for k, v in by_sev.items()
                            if k in _SEVERITY_ORDER},
            "counts": counts, "do_first": do_first,
            "kill_chain": kill_chain_narrate(
                {"state": {"target": target, "findings": findings,
                           "history": history or []}})}


def narrate_executive(doc):
    """Markdown rendering of the executive summary doc."""
    lines = ["## Executive summary", ""]
    lines.append(doc.get("headline") or "")
    lines.append("")
    for sev in _SEVERITY_ORDER:
        items = doc.get("by_severity") or {}
        if items.get(sev):
            lines.append("**%s** (%d):" % (sev, len(items[sev])))
            for line in items[sev]:
                lines.append("- %s" % line)
            lines.append("")
    if doc.get("do_first"):
        lines.append("**Fix first:**")
        for line in doc["do_first"]:
            lines.append("1. %s" % line)
    return "\n".join(lines)
