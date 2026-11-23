"""omega/offensive/offense/verbtamper — HTTP verb tampering RBAC probe.

Access-control bypass differential: a protected endpoint that rejects
GET may accept POST/PUT/PATCH/HEAD/DELETE for the same resource.
Classified only when a NON-GET verb returns a materially different
(successful) response than the denied GET. OFFENSE-GATED
(PTK_OFFENSE). Candidate + manual_check.
"""
import os

__all__ = ["run_verbtamper"]

VERBS = ("POST", "PUT", "PATCH", "HEAD", "DELETE")


def run_verbtamper(target, fetch=None, endpoints=None, log=None,
                   gate_open_fn=None):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    endpoints = endpoints or ["/admin", "/api/users", "/api/settings",
                              "/api/orders"]
    findings = []
    probes = 0
    base = str(target).rstrip("/")
    for ep in endpoints:
        url = base + ep
        try:
            get_r = fetch(url, method="GET")
            probes += 1
        except Exception:
            continue
        if get_r is None:
            continue
        g_status = getattr(get_r, "status", 0)
        g_body = (getattr(get_r, "text", "") or "")[:80]
        if g_status < 400:
            continue  # not a denied endpoint — nothing to bypass
        for verb in VERBS:
            try:
                r = fetch(url, method=verb, body="{}")
                probes += 1
            except Exception:
                continue
            if r is None:
                continue
            status = getattr(r, "status", 0)
            body = (getattr(r, "text", "") or "")[:80]
            # materially different = success vs the denied GET
            if status < 400 and body and body != g_body:
                findings.append({
                    "title": f"verb tampering: {ep} denies GET "
                             f"({g_status}) but accepts {verb} "
                             f"({status})",
                    "severity": "HIGH",
                    "source": "verbtamper/differential",
                    "evidence": f"GET={g_status} vs {verb}={status} "
                                f"with different body",
                    "location": url,
                    "verification": "candidate",
                    "manual_check": "verify the non-GET response really "
                                    "serves the protected resource "
                                    "(not a generic 200)",
                    "cwe": "CWE-285",
                })
                break
    if log:
        log(f"verbtamper: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
