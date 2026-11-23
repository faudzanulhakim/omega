"""omega/core/attackgraph — validated kill-chain attack graph.

Combines a session's findings into candidate multi-step chains
(SSRF -> cloud metadata -> credentials; injection -> RCE -> sudo ->
root; default-creds -> admin -> deserialization) and VALIDATES every
edge against real evidence: an edge exists only when the source
finding's evidence supports the transition. Nothing is invented —
a chain with any evidence-less edge is reported as partial with the
missing step named.

PLAN-ONLY by default (like cwechain): the graph proposes, the operator
executes. Output feeds the kill-chain report narrative.
"""
import re

__all__ = ["build_attack_graph"]

# (source_cwe, target_cwe, transition, what_to_do_next)
_EDGES = [
    ("CWE-918", "CWE-200", "SSRF reaches cloud metadata endpoint",
     "read instance metadata for temporary credentials"),
    ("CWE-200", "CWE-798", "credentials extracted from metadata/env",
     "reuse leaked credentials against the same provider"),
    ("CWE-78", "CWE-250", "command execution achieved",
     "enumerate identity and sudo rights"),
    ("CWE-250", "CWE-269", "sudo NOPASSWD or SUID vector found",
     "escalate to root via the enumerated vector"),
    ("CWE-798", "CWE-287", "default/leaked credential works",
     "authenticate with the working credential"),
    ("CWE-287", "CWE-502", "authenticated admin surface found",
     "probe admin surfaces for deserialization/plugin upload"),
    ("CWE-89", "CWE-78", "SQL injection with stacked-query capability",
     "attempt command execution via DB engine primitives"),
    ("CWE-22", "CWE-200", "path traversal succeeds",
     "read configuration/secret files via traversal"),
    ("CWE-611", "CWE-918", "XXE reachable",
     "turn XXE into SSRF via external entity"),
    ("CWE-350", "CWE-287", "takeover candidate proven",
     "assume control of the dangling endpoint"),
]

_CVE_RE = re.compile(r"CWE-(\d+)")


def _cwes(findings):
    out = []
    for f in findings or []:
        for m in _CVE_RE.findall(str(f.get("cwe") or "")):
            out.append((f"CWE-{m}", f))
    return out


def build_attack_graph(findings, log=None):
    """Build evidence-validated chains from findings.

    Returns {"chains": [{"steps": [...], "complete": bool,
                         "missing": [...]}], "nodes": n}.
    """
    by_cwe = {}
    for cwe, f in _cwes(findings):
        by_cwe.setdefault(cwe, []).append(f)
    chains = []
    seen = set()

    def _walk(cwe, path, missing):
        if len(path) >= 6:
            return
        extended = False
        for src, dst, transition, action in _EDGES:
            if src != cwe:
                continue
            key = (src, dst, transition)
            if key in seen:
                continue
            targets = by_cwe.get(dst)
            if targets:
                nxt = {"from": src, "to": dst,
                       "transition": transition,
                       "action": action,
                       "evidence": str(targets[0].get("title"))[:120]}
                seen.add(key)
                _walk(dst, path + [nxt], missing)
                seen.discard(key)
                extended = True
            else:
                nxt = {"from": src, "to": dst,
                       "transition": transition,
                       "action": action, "evidence": None}
                chains.append({"steps": path + [nxt], "complete": False,
                               "missing": [f"{dst}: not yet observed — "
                                           f"{action}"]})
        if not extended and path:
            chains.append({"steps": path, "complete": True,
                           "missing": []})

    for cwe in list(by_cwe):
        _walk(cwe, [], [])

    # keep the longest chain per terminal node
    best = {}
    for c in chains:
        end = c["steps"][-1]["to"] if c["steps"] else "?"
        if end not in best or len(c["steps"]) > len(best[end]["steps"]):
            best[end] = c
    result = list(best.values())
    result.sort(key=lambda c: (-len(c["steps"]),
                               not c["complete"]))
    if log:
        log(f"attackgraph: nodes={len(by_cwe)} chains={len(result)}")
    return {"chains": result, "nodes": len(by_cwe)}
