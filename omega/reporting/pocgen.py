"""omega/reporting/pocgen — reproducible PoC generator.

Renders every HIGH/CRITICAL finding into a runnable PoC: a curl one-
liner and a Python snippet built from the ENGINE'S OWN evidence
(the actual request shape that produced the finding). No invented
payloads: if the finding carries no request evidence, the PoC says
so instead of fabricating one.
"""
__all__ = ["render_poc"]


def _quote(v):
    return "'" + str(v).replace("'", "'\\''") + "'"


def render_poc(f):
    """Render one finding dict into {curl, python, caveat} strings."""
    loc = f.get("location") or f.get("evidence") or "<unknown>"
    title = f.get("title", "finding")
    ev = f.get("evidence", "")
    sev = f.get("severity", "?")
    cwe = f.get("cwe", "")
    lines = []
    lines.append(f"# PoC — {title} [{sev} {cwe}]")
    lines.append(f"# source evidence: {ev[:200]}")
    if loc.startswith("http"):
        lines.append("")
        lines.append(f"curl -sk -i {_quote(loc)}")
        lines.append("")
        lines.append("import urllib.request, ssl")
        lines.append(f"req = urllib.request.Request({_quote(loc)})")
        lines.append("ctx = ssl.create_default_context(); "
                     "ctx.check_hostname = False; "
                     "ctx.verify_mode = ssl.CERT_NONE")
        lines.append("try:")
        lines.append("    print(urllib.request.urlopen(req, context=ctx)"
                     ".read()[:400])")
        lines.append("except Exception as e:")
        lines.append("    print('error:', e)")
    else:
        lines.append("")
        lines.append("# no HTTP location evidence — reproduce from the "
                     "manual_check steps in the finding")
    caveat = (f.get("manual_check") or
              "run the PoC against the authorized target only")
    return {"title": title, "curl": "\n".join(lines[3:6]) if loc.startswith(
        "http") else "# see finding", "python": "\n".join(
        lines[7:13]) if loc.startswith("http") else "# see finding",
        "header": "\n".join(lines[:3]), "caveat": caveat}


def render_pocs(findings, min_severity="HIGH"):
    """PoC section for the report, ordered by severity."""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sel = [f for f in findings or []
           if order.get(f.get("severity", "INFO"), 9) <=
           order.get(min_severity, 1)]
    out = ["## Proof-of-Concept reproductions",
           ""]
    for f in sorted(sel, key=lambda x: order.get(x.get("severity"), 9)):
        p = render_poc(f)
        out.append(f"### {p['title']}")
        out.append("```")
        out.append(p["header"])
        out.append(p["curl"])
        out.append("```")
        out.append("```python")
        out.append(p["python"])
        out.append("```")
        out.append(f"_{p['caveat']}_")
        out.append("")
    if len(sel) == 0:
        out.append("_no HIGH/CRITICAL findings to reproduce_")
    return "\n".join(out)
