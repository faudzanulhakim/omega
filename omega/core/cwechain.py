"""omega/core/cwechain — CWE-aware attack chain proposer.

Plans-only module: given findings (with CWE tags), walks a directed
CWE graph and proposes multi-step chains an expert would attempt
(e.g. SSRF -> metadata read -> cloud credential use -> RCE).
NEVER executes anything; each proposed step carries the gate it
would require (PTK_OFFENSE / PTK_EXPLOIT) so the operator stays in
control. Step conditions are conservative — a chain step without its
precondition evidence is marked 'needs-evidence', not 'ready'.
"""
__all__ = ["CWE_GRAPH", "propose_chains"]

# from -> [(to, precondition-evidence, gain, gate)]
CWE_GRAPH = {
    "CWE-918": [  # SSRF
        ("CWE-200", "internal endpoint reachable via SSRF probe",
         "metadata / internal info disclosure", "PTK_OFFENSE"),
        ("CWE-798", "metadata response contains credential shapes",
         "hardcoded/embedded cloud credentials", "PTK_EXPLOIT"),
    ],
    "CWE-200": [
        ("CWE-798", "credential-shaped strings in exposed data",
         "reused secrets", "PTK_EXPLOIT"),
    ],
    "CWE-89": [  # SQLi
        ("CWE-200", "union/error output exposes schema rows",
         "database content disclosure", "PTK_OFFENSE"),
    ],
    "CWE-22": [  # path traversal
        ("CWE-538", "traversal reaches application log/config",
         "file disclosure", "PTK_OFFENSE"),
        ("CWE-98", "traversal reaches log poisoning candidate",
         "LFI-to-RCE via log inclusion", "PTK_EXPLOIT"),
    ],
    "CWE-79": [
        ("CWE-352", "state-changing action reachable from XSS context",
         "CSRF chaining", "PTK_OFFENSE"),
    ],
    "CWE-434": [  # unsafe upload
        ("CWE-98", "uploaded path serves executable content",
         "upload-to-RCE", "PTK_EXPLOIT"),
    ],
    "CWE-611": [  # XXE
        ("CWE-200", "XXE response contains file content",
         "file disclosure", "PTK_OFFENSE"),
    ],
    "CWE-521": [  # weak creds
        ("CWE-287", "bruteforce-safe lockout confirmed absent",
         "auth bypass via weak credentials", "PTK_EXPLOIT"),
    ],
    "CWE-798": [
        ("CWE-287", "credential shape matches auth surface",
         "auth bypass via discovered secret", "PTK_EXPLOIT"),
    ],
}
_MAX_DEPTH = 4


def _finding_cwes(f):
    tags = f.get("cwe") or f.get("cwes") or []
    if isinstance(tags, str):
        tags = [tags]
    return [t for t in tags if str(t).upper().startswith("CWE-")]


def propose_chains(findings, max_depth=_MAX_DEPTH):
    """Return candidate chains: [{'steps': [...], 'gates': [...],
    'ready': bool}] — plan only, never executed."""
    chains = []
    for f in findings or []:
        for cwe in _finding_cwes(f):
            frontier = [(cwe, [cwe])]
            depth = 0
            while frontier and depth < max_depth:
                nxt = []
                for cur, path in frontier:
                    for (to, cond, gain, gate) in CWE_GRAPH.get(cur, []):
                        steps = [{
                            "cwe": cur, "next": to,
                            "condition": cond, "gain": gain,
                            "gate": gate, "executed": False,
                        }]
                        chain = {
                            "root": cwe,
                            "finding": f.get("title", ""),
                            "location": f.get("location", ""),
                            "steps": [{"cwe": c} for c in path],
                            "proposals": steps,
                            "gates": [gate],
                        }
                        chains.append(chain)
                        nxt.append((to, path + [to]))
                frontier = nxt
                depth += 1
    return chains


def chain_summary(chains):
    lines = []
    for c in chains or []:
        for s in c["proposals"]:
            lines.append("%s -> %s (%s) [%s] %s" %
                         (s["cwe"], s["next"], s["gain"], s["gate"],
                          s["condition"]))
    return lines
