"""omega/reporting/killchain — kill-chain narrative for reports.

Turns an attack graph (omega.core.attackgraph) into a readable
narrative section: how an attacker gets in, how far they get, and
what stands in the way. Plain markdown, 3 audiences preserved from
execsum style. Never inflates: unproven steps say so plainly.
"""
from omega.core.attackgraph import build_attack_graph

__all__ = ["render_killchain"]

_STEP_TEMPLATES = {
    "CWE-918": "SSRF entry point",
    "CWE-200": "sensitive data exposure",
    "CWE-798": "hard-coded / default credential",
    "CWE-78": "command injection",
    "CWE-250": "running with unnecessary privileges",
    "CWE-269": "improper privilege management",
    "CWE-287": "improper authentication",
    "CWE-502": "deserialization",
    "CWE-89": "SQL injection",
    "CWE-22": "path traversal",
    "CWE-611": "XXE",
    "CWE-350": "trust boundary / takeover",
}


def _title(cwe):
    return _STEP_TEMPLATES.get(cwe, cwe)


def render_killchain(findings, target="", log=None):
    """Markdown narrative section for the report. Returns str."""
    graph = build_attack_graph(findings, log=log)
    chains = graph.get("chains") or []
    if not chains:
        return ""
    lines = ["## Kill-chain narrative", ""]
    complete = [c for c in chains if c.get("complete")]
    partial = [c for c in chains if not c.get("complete")]
    if complete:
        lines.append(f"**{len(complete)} evidence-backed chain(s) were "
                     f"assembled from this session's findings.**")
        lines.append("")
    for i, c in enumerate(chains, 1):
        steps = c.get("steps") or []
        if not steps:
            continue
        first = steps[0]
        lines.append(f"### Chain {i}: {_title(first.get('from'))} -> "
                     f"{_title(first.get('to'))}...")
        lines.append("")
        lines.append("An attacker who has the first capability can, "
                     "step by step:")
        lines.append("")
        for j, s in enumerate(steps, 1):
            ev = s.get("evidence")
            mark = "proven" if ev else "projected"
            evtxt = f' (evidence: "{ev}")' if ev else ""
            lines.append(f"{j}. {s.get('transition')} -> {_title(s.get('to'))}"
                         f" — **{mark}**{evtxt}. Next: {s.get('action')}.")
        lines.append("")
        missing = c.get("missing") or []
        if missing:
            lines.append(f"Not yet proven: {'; '.join(missing)}.")
            lines.append("")
    if partial and not complete:
        lines.append("All chains above are projections: the later steps "
                     "name what is still unproven — they are next-step "
                     "orders, not confirmed compromises.")
        lines.append("")
    lines.append("_Every step above derives from session evidence; "
                 "projected steps require operator validation before "
                 "being treated as fact._")
    return "\n".join(lines)
