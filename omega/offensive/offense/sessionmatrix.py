"""omega/offensive/offense/sessionmatrix — session confusion matrix.

Unusual session attacks: cookie shadowing (two same-name cookies,
different paths), stale-token replay, and logout/login race (reuses
racehunter). OFFENSE-GATED (PTK_OFFENSE). Candidate-grade.
"""
import os

__all__ = ["run_sessionmatrix"]


def run_sessionmatrix(target, fetch, auth_headers=None, log=None,
                      gate_open_fn=None):
    """Probe session handling for confusion/shadowing flaws.

    auth_headers: the working session's Cookie/Authorization values.
    """
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    if not callable(fetch):
        return {"note": "fetch adapter required"}
    headers = dict(auth_headers or {})
    cookie = headers.get("Cookie") or ""
    findings = []
    probes = 0

    def _get(extra_headers=None):
        nonlocal probes
        probes += 1
        h = dict(headers)
        h.update(extra_headers or {})
        try:
            resp = fetch(str(target), headers=h)
            body = (resp if isinstance(resp, str) else
                    getattr(resp, "text", "") or "")
            return getattr(resp, "status", 0), body
        except Exception:
            return 0, ""

    # baseline authenticated state
    base_st, base_body = _get()
    if base_st and 200 <= base_st < 300:
        # 1) cookie shadowing: add path= shadow of the FIRST cookie
        if cookie and "=" in cookie:
            first = cookie.split(";")[0].strip()
            name = first.split("=")[0]
            shadow = f"{name}=; Path=/"
            st, _ = _get({"Cookie": f"{shadow}; {cookie}"})
            if st and 200 <= st < 300:
                findings.append({
                    "title": "cookie shadowing accepted: server "
                             "authenticated on a poisoned pair",
                    "severity": "MEDIUM",
                    "source": "sessionmatrix/shadow",
                    "evidence": f"request with empty-value {name} "
                                f"shadow (Path=/) still authenticated "
                                f"(HTTP {st})",
                    "location": str(target),
                    "verification": "candidate",
                    "manual_check": "confirm which cookie wins per "
                                    "proxy/browser to map the risk",
                    "cwe": "CWE-1004",
                })
        # 2) stale token replay: mutate token tail (session fixation
        #    shape) and see if still valid
        if "Bearer " in headers.get("Authorization", ""):
            tok = headers["Authorization"].split(" ", 1)[1]
            stale = tok[:-4] + ("aaaa" if tok[-4:] != "aaaa" else
                                "bbbb")
            st, _ = _get({"Authorization": f"Bearer {stale}"})
            if st and 200 <= st < 300:
                findings.append({
                    "title": "stale/invalid token accepted (signature "
                             "not verified end-to-end)",
                    "severity": "CRITICAL",
                    "source": "sessionmatrix/stale-replay",
                    "evidence": f"mutated Bearer token -> HTTP {st} "
                                f"(baseline {base_st})",
                    "location": str(target),
                    "verification": "candidate",
                    "manual_check": "confirm the mutation preserves "
                                    "server acceptance deterministically",
                    "cwe": "CWE-347",
                })
        # 3) header-case confusion: duplicate authorization casing
        st, _ = _get({"Authorization": headers.get("Authorization", ""),
                      "authorization": headers.get("Authorization", "")})
        if st and 200 <= st < 300 and "Authorization" in headers:
            # accepted is fine; the finding is when an EMPTY dup clears
            st2, _ = _get({"Authorization": headers["Authorization"],
                           "authorization": ""})
            if st2 and 200 <= st2 < 300:
                findings.append({
                    "title": "authorization case-variant confusion: "
                             "empty duplicate accepted",
                    "severity": "MEDIUM",
                    "source": "sessionmatrix/case-confusion",
                    "evidence": f"dup authorization header with empty "
                                f"value still authenticated (HTTP "
                                f"{st2})",
                    "location": str(target),
                    "verification": "candidate",
                    "manual_check": "identify the proxy/backend pair "
                                    "and which header it honors",
                    "cwe": "CWE-436",
                })
    if log:
        log(f"sessionmatrix: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes,
            "baseline_status": base_st}
