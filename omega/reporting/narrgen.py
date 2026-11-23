"""omega/reporting/narrgen — dynamic executive summary per audience.

Renders the engagement narrative from ACTUAL findings for three
audiences: developers (fixable detail), security (risk + chain),
management (impact + effort). No template fluff: sections only appear
when findings support them.
"""
from collections import Counter

__all__ = ["render_narrative"]

_CWE_ACTION = {
    "CWE-79": "escape output / add CSP",
    "CWE-89": "parameterized queries",
    "CWE-918": "egress allowlist for server-side fetches",
    "CWE-434": "validate upload type+content, serve from separate "
               "origin",
    "CWE-285": "centralize authorization checks server-side",
    "CWE-287": "harden session/JWT validation",
    "CWE-444": "normalize CL/TE handling at the front end",
    "CWE-538": "remove dev artifacts from web root",
    "CWE-502": "avoid deserializing untrusted data",
    "CWE-942": "strict CORS allowlist",
    "CWE-639": "object-level authorization per request",
    "CWE-521": "rotate the credential; enforce strength policy",
}


def render_narrative(findings, target="", chains=None):
    findings = findings or []
    sev = Counter(f.get("severity", "INFO") for f in findings)
    cwes = Counter(f.get("cwe", "?") for f in findings
                   if f.get("cwe"))
    crit, high = sev.get("CRITICAL", 0), sev.get("HIGH", 0)
    lines_dev = ["## Summary — for developers"]
    if findings:
        lines_dev.append(
            f"{len(findings)} findings ({crit} critical, {high} high). "
            f"Top classes: "
            + ", ".join(f"{c} x{n}" for c, n in cwes.most_common(4))
            + ".")
        for c, n in cwes.most_common(5):
            action = _CWE_ACTION.get(c)
            if action:
                lines_dev.append(f"- {c} ({n}): {action}")
    else:
        lines_dev.append("no findings — nothing to fix this run.")
    lines_sec = ["## Summary — for security"]
    if crit or high:
        lines_sec.append(
            f"{crit + high} exploitable-class findings need triage "
            f"before this target is considered safe.")
        for c in chains or []:
            if c.get("status") in ("complete", "partial"):
                lines_sec.append(
                    f"- exploit chain '{c['name']}' is "
                    f"{c['status']}"
                    + (f" (broken link: {c['broken_link']})"
                       if c.get("broken_link") else ""))
    else:
        lines_sec.append("no exploitable-class findings this run.")
    lines_mgmt = ["## Summary — for management"]
    if crit or high:
        lines_mgmt.append(
            f"The application {('at ' + target) if target else ''} "
            f"has {crit + high} high-impact weaknesses an attacker "
            f"could reach. Recommended: schedule fixes this sprint; "
            f"re-scan after remediation (report diff shows what "
            f"changed).")
    else:
        lines_mgmt.append(
            "No critical or high impact weaknesses found this run; "
            "keep the scan cadence.")
    return "\n".join(lines_dev + [""] + lines_sec + [""] + lines_mgmt)
