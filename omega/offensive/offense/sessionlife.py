"""omega/offensive/offense/sessionlife — session lifecycle auditor.

Differential checks on session behavior (deterministic, no lockouts):
logout invalidation (does the old cookie still work?), session
timeout behavior, remember-me persistence shape, and password-reset
token reuse/predictability SHAPE (entropy over a few observed tokens
— never stores token values). OFFENSE-GATED (PTK_OFFENSE).
"""
import os
import time

__all__ = ["run_sessionlife"]

_ENTROPY_MARKS = ("0123456789",)


def _looks_predictable(token):
    if not token:
        return True
    if len(set(token)) <= 4:
        return True
    if token.isdigit() and int(token) < 10 ** 6:
        return True
    if token.lower() == token.lower()[0] * len(token):
        return True
    return False


def run_sessionlife(target, fetch=None, auth_headers=None, log=None,
                    gate_open_fn=None, reset_tokens=None):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    auth_headers = auth_headers or {}
    findings = []
    probes = 0
    base = str(target).rstrip("/")
    protected = base + "/api/me"

    def authorized(r):
        return r is not None and getattr(r, "status", 0) < 400 and \
            "unauthorized" not in (getattr(r, "text", "") or "").lower()

    # 1. logout invalidation
    try:
        r0 = fetch(protected, headers=auth_headers)
        probes += 1
        if authorized(r0):
            fetch(base + "/logout", method="POST", headers=auth_headers)
            probes += 1
            r1 = fetch(protected, headers=auth_headers)
            probes += 1
            if authorized(r1):
                findings.append({
                    "title": "logout does NOT invalidate the session "
                             "token",
                    "severity": "HIGH",
                    "source": "sessionlife/logout",
                    "evidence": "protected endpoint still authorized "
                                "after logout",
                    "location": protected,
                    "verification": "confirmed",
                    "manual_check": "stolen pre-logout token stays "
                                    "valid forever — rotate sessions "
                                    "server-side",
                    "cwe": "CWE-613",
                })
    except Exception:
        pass
    # 2. remember-me persistence shape
    for hdr_name, marker in (("X-Remember", "1"),):
        try:
            r = fetch(protected, headers={**auth_headers, hdr_name: marker})
            probes += 1
            h = {str(k).lower(): str(v)
                 for k, v in (getattr(r, "headers", {}) or {}).items()}
            setc = h.get("set-cookie", "")
            if setc and ("max-age=31536000" in setc.lower() or
                         "expires=20" in setc.lower()):
                findings.append({
                    "title": "session cookie persisted for ~1 year "
                             "(remember-me without re-auth)",
                    "severity": "MEDIUM",
                    "source": "sessionlife/persistence",
                    "evidence": "long-lived Set-Cookie on authed "
                                "endpoint",
                    "location": protected,
                    "verification": "candidate",
                    "manual_check": "long-lived sessions need device "
                                    "binding + revocation list",
                    "cwe": "CWE-613",
                })
        except Exception:
            pass
    # 3. reset-token reuse / predictability SHAPE
    if reset_tokens and len(reset_tokens) >= 2:
        t1, t2 = reset_tokens[0], reset_tokens[1]
        if t1 == t2:
            findings.append({
                "title": "password-reset token REUSED across requests "
                         "(identical token observed twice)",
                "severity": "HIGH",
                "source": "sessionlife/reset-reuse",
                "evidence": "same token shape observed twice",
                "location": base + "/reset",
                "verification": "candidate",
                "manual_check": "verify the second use actually "
                                "resets (not just echoes)",
                "cwe": "CWE-640",
            })
        elif _looks_predictable(t1):
            findings.append({
                "title": "password-reset token looks predictable "
                         "(low entropy shape)",
                "severity": "MEDIUM",
                "source": "sessionlife/reset-entropy",
                "evidence": "token shape has low character diversity",
                "location": base + "/reset",
                "verification": "candidate",
                "manual_check": "collect more token samples to "
                                "estimate entropy before reporting",
                "cwe": "CWE-330",
            })
    if log:
        log(f"sessionlife: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
