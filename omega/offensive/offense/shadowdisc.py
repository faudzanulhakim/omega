"""omega/offensive/offense/shadowdisc — shadow endpoint discovery.

Wordless discovery: fingerprint the target's soft-404 (random path
response shape: status/body-size/body-hash), then probe a compact
candidate list — anything that differs from the soft-404 profile is
a REAL endpoint. Includes API-contract paths (swagger/openapi/
graphql). OFFENSE-GATED (PTK_OFFENSE). Candidate + manual_check.
"""
import hashlib
import os

__all__ = ["run_shadowdisc"]

CANDIDATES = [
    "/swagger.json", "/openapi.yaml", "/api-docs", "/graphql",
    "/actuator", "/metrics", "/health", "/status", "/info",
    "/api/v1", "/api/v2", "/v1/users", "/admin/login",
    "/debug", "/console", "/phpinfo.php", "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml", "/config", "/backup",
    "/test", "/staging", "/old", "/api/graphql", "/ws",
]


def _profile(r):
    body = (getattr(r, "text", "") or "")
    return (getattr(r, "status", 0), len(body),
            hashlib.sha256(body[:2048].encode()).hexdigest()[:10])


def run_shadowdisc(target, fetch=None, candidates=None, log=None,
                   gate_open_fn=None):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    candidates = candidates or CANDIDATES
    base = str(target).rstrip("/")
    probes = 0
    # fingerprint soft-404 with three random paths
    prof404 = set()
    for junk in ("/omegq1", "/omegz9x", "/omegq7kd"):
        try:
            r = fetch(base + junk)
            probes += 1
            if r is not None:
                prof404.add(_profile(r))
        except Exception:
            continue
    found = []
    for c in candidates:
        try:
            r = fetch(base + c)
            probes += 1
        except Exception:
            continue
        if r is None:
            continue
        p = _profile(r)
        if p in prof404:
            continue  # soft-404 mirage
        status = p[0]
        if status < 400 or status in (401, 403):
            sev = "LOW" if status in (401, 403) else "MEDIUM"
            found.append({
                "title": f"shadow endpoint discovered: {c} "
                         f"(HTTP {status}, distinct from soft-404)",
                "severity": sev,
                "source": "shadowdisc/fingerprint",
                "evidence": f"response profile {p[1]}B differs from "
                            f"the site's soft-404 profile",
                "location": base + c,
                "verification": "candidate",
                "manual_check": "probe the endpoint content to classify "
                                "(401/403 = exists but protected)",
                "cwe": "CWE-538",
            })
    if log:
        log(f"shadowdisc: probes={probes} found={len(found)}")
    return {"findings": found, "probes": probes,
            "soft404_profiles": len(prof404)}
