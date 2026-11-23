"""omega/offensive/offense/authzmatrix — authorization matrix tester.

Role x endpoint x method differential: with credential sets provided
by the operator (never auto-cracked), requests every endpoint as
every role and flags cross-role access differentials — the proof of
broken access control is that a LOWER-privilege principal received
the SAME response as the higher one. paced by pace_s. OFFENSE-GATED
(PTK_OFFENSE).
"""
import os
import time

__all__ = ["run_authzmatrix"]

ENDPOINTS = ["/", "/api/me", "/api/users", "/admin", "/admin/users",
             "/api/orders", "/api/settings"]
METHODS = ["GET"]


def run_authzmatrix(target, roles=None, fetch=None, endpoints=None,
                    log=None, pace_s=0.0, gate_open_fn=None):
    """roles: {role_name: auth_headers_dict}; a None-headers entry or
    the reserved name 'anonymous' means unauthenticated requests."""
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    roles = roles or {"anonymous": None}
    endpoints = endpoints or ENDPOINTS
    findings = []
    probes = 0
    # signature per endpoint per role
    counter = [0]

    def probe(url, headers):
        try:
            resp = fetch(url, headers=headers or {})
            counter[0] += 1
        except Exception:
            return None
        if resp is None:
            return None
        return (getattr(resp, "status", 0),
                (getattr(resp, "text", "") or "")[:120])

    matrix = {}
    for role, hdrs in roles.items():
        for ep in endpoints:
            url = str(target).rstrip("/") + ep
            if pace_s:
                time.sleep(pace_s)
            matrix[(role, ep)] = probe(url, hdrs)

    eps = set(endpoints)
    for role, hdrs in roles.items():
        if role == "anonymous":
            continue
        for ep in eps:
            anon = matrix.get(("anonymous", ep))
            mine = matrix.get((role, ep))
            if not anon or not mine:
                continue
            anon_status, anon_body = anon
            my_status, my_body = mine
            if anon_status and anon_status == my_status and \
                    my_status < 300 and anon_body == my_body:
                # anonymous sees the SAME authenticated view as role
                findings.append({
                    "title": f"broken access control: {ep} returns "
                             f"identical response for anonymous and "
                             f"'{role}'",
                    "severity": "HIGH",
                    "source": "authzmatrix/differential",
                    "evidence": f"both got {my_status} with matching "
                                f"body prefix",
                    "location": str(target).rstrip("/") + ep,
                    "verification": "candidate",
                    "manual_check": "confirm the body is really the "
                                    "protected resource (not a shared "
                                    "404/landing template)",
                    "cwe": "CWE-285",
                })
    if log:
        log(f"authzmatrix: roles={len(roles)} eps={len(endpoints)} "
            f"findings={len(findings)}")
    return {"findings": findings, "probes": counter[0], "matrix": {
        "roles": list(roles), "endpoints": endpoints}}
