"""omega/core/subdgraph — passive subdomain & origin graph.

Passive-only surface expansion: queries crt.sh (certificate
transparency log) for subdomains of the target domain, resolves
CNAMEs for known-alignment checks (takeover candidates ride the
existing offense.takeover cap), and emits a target list the
scheduler can consume. No active DNS brute — the wordless CT query
plus resolution of what the CT log ALREADY published. OFFENSE-GATED
(PTK_OFFENSE).
"""
import os
import socket
from urllib.parse import urlparse

__all__ = ["run_subdgraph"]


def run_subdgraph(target, fetch=None, log=None, gate_open_fn=None,
                  max_subs=50):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    host = urlparse(target if "//" in target else "http://" +
                    str(target)).hostname or str(target)
    domain = ".".join(host.split(".")[-2:])
    subs = set()
    try:
        fetch = fetch or (lambda *a, **k: None)
        import json as _json
        url = ("https://crt.sh/?q=%." + domain +
               "&output=json&exclude=expired")
        resp = fetch(url)
        if resp is not None:
            body = getattr(resp, "text", "") or ""
            data = _json.loads(body) if body.strip() else []
            for entry in data[:500]:
                for name in str(entry.get("name_value", "")).split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(domain) and name != domain and \
                            len(subs) < max_subs:
                        subs.add(name)
    except Exception as exc:
        return {"note": f"crt.sh query failed: {exc}"}
    # resolve what CT published (passive names only)
    resolved = {}
    for s in sorted(subs)[:max_subs]:
        try:
            ip = socket.gethostbyname(s)
            resolved[s] = ip
        except Exception:
            resolved[s] = None
    alive = {s: ip for s, ip in resolved.items() if ip}
    dead = [s for s, ip in resolved.items() if not ip]
    findings = [{
        "title": f"{len(alive)} CT-published subdomains resolve "
                 f"(+{len(dead)} unresolvable) for {domain}",
        "severity": "INFO",
        "source": "subdgraph/ct",
        "evidence": f"live: {sorted(alive)[:8]}",
        "location": domain,
        "verification": "candidate",
        "manual_check": "feed alive hosts into scheduler/horizontal "
                        "with the operator's authorization per host",
        "cwe": "CWE-200",
    }]
    if log:
        log(f"subdgraph: {len(subs)} CT names, {len(alive)} resolve")
    return {"findings": findings, "subdomains": sorted(subs),
            "resolved": alive, "unresolvable": dead,
            "probes": len(subs)}
