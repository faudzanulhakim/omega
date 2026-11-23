"""omega/reporting/poc — auto-generated curl proof-of-concept.

For every finding with a location, emit a replayable curl command
that reproduces the observation WITHOUT performing destructive
actions: state-changing methods carry a leading comment and the
command is not executed by OMEGA — it is documentation for the
operator. Payloads come from the finding's own evidence fields, so
nothing is invented; missing data produces a RECON-only line.
"""
__all__ = ["build_poc", "attach_pocs", "render_poc_block"]

_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def _quote(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


def build_poc(finding):
    """Return {'method', 'url', 'command', 'note'} for one finding."""
    loc = str(finding.get("location") or "").strip()
    if not loc.startswith(("http://", "https://", "/")):
        return {"method": None, "url": loc, "command": None,
                "note": "no replayable URL (finding lacks a request "
                        "location)"}
    method = str(finding.get("method") or "GET").upper()
    loc_q = _quote(loc)
    parts = ["curl -sk"]
    if method not in _SAFE_METHODS:
        parts.append("-X %s" % method)
    hdrs = finding.get("headers") or {}
    if isinstance(hdrs, dict):
        for k, v in list(hdrs.items())[:4]:
            parts.append("-H %s" % _quote("%s: %s" % (k, v)))
    body = finding.get("body")
    if body:
        parts.append("--data %s" % _quote(str(body)[:512]))
    parts.append(loc_q)
    cmd = " ".join(parts)
    note = ""
    if method not in _SAFE_METHODS:
        note = ("# state-changing request — review before running; "
                "evidence recorded during the scan is the source of "
                "truth")
    return {"method": method, "url": loc, "command": cmd,
            "note": note}


def attach_pocs(findings):
    """Add a `poc` dict to each finding (non-destructive)."""
    out = []
    for f in findings or []:
        f = dict(f)
        f["poc"] = build_poc(f)
        out.append(f)
    return out


def render_poc_block(poc, indent="  "):
    """Markdown block for a finding section."""
    if not poc or not poc.get("command"):
        return ""
    lines = []
    if poc.get("note"):
        lines.append(indent + poc["note"])
    lines.append(indent + "```bash")
    lines.append(indent + poc["command"])
    lines.append(indent + "```")
    return "\n".join(lines)
