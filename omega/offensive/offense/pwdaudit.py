"""omega/offensive/offense/pwdaudit — limited online password audit.

Audits a SMALL operator-supplied credential list against ONE login
endpoint, audit-style — NOT an attack-style brute:
  * wordlist is tiny and explicit (top-N credible passwords or the
    operator's own list), never a multi-million list;
  * paced (human-like gap between attempts, env-tunable);
  * lockout detection: after 2 consecutive unfamiliar failures the
    audit STOPS for that account;
  * one run per account; every attempt is logged with evidence.
OFFENSE-GATED (PTK_OFFENSE). Hits are candidate + manual_check.
"""
import os
import time

__all__ = ["run_pwdaudit"]

DEFAULT_TOP = ["password", "123456", "admin123", "qwerty", "letmein",
               "Welcome1", "P@ssw0rd", "changeme"]
FAIL_MARKS = ("incorrect", "invalid", "wrong", "failed", "salah")


def run_pwdaudit(target, fetch=None, username=None, passwords=None,
                 pace_s=1.0, log=None, gate_open_fn=None):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    if not username:
        return {"note": "pwdaudit: username required (operator-supplied)"}
    if passwords is None:
        passwords = DEFAULT_TOP[:5]
    passwords = list(passwords)[:8]  # hard cap — audit, not attack
    findings = []
    attempts = []
    unknown_fail_streak = 0
    stopped = False
    login_url = str(target).rstrip("/") + "/login"
    for pwd in passwords:
        if stopped:
            break
        try:
            resp = fetch(login_url, method="POST",
                         body=f"username={username}&password={pwd}")
        except Exception as exc:
            attempts.append({"pwd_shape": pwd[:3] + "***", "error": str(exc)})
            break
        status = getattr(resp, "status", 0) if resp else 0
        body = (getattr(resp, "text", "") or "").lower()
        attempts.append({"pwd_shape": pwd[:3] + "***", "status": status})
        if status in (200, 302) and "dashboard" in body or \
                (status in (200, 302) and not any(
                    m in body for m in FAIL_MARKS) and body):
            findings.append({
                "title": f"weak credential accepted for {username} "
                         f"(password shape: {pwd[:3]}***)",
                "severity": "HIGH",
                "source": "pwdaudit/audit",
                "evidence": f"login accepted at attempt "
                            f"{len(attempts)} (paced audit)",
                "location": login_url,
                "verification": "candidate",
                "manual_check": "log in manually to confirm and "
                                "rotate the credential immediately",
                "cwe": "CWE-521",
            })
            break
        known_fail = any(m in body for m in FAIL_MARKS) or status in (
            401, 403)
        if known_fail:
            unknown_fail_streak = 0
        else:
            unknown_fail_streak += 1
            if unknown_fail_streak >= 2:
                stopped = True
        if pace_s:
            time.sleep(pace_s)
    if log:
        log(f"pwdaudit: attempts={len(attempts)} hits={len(findings)} "
            f"stopped={stopped}")
    return {"findings": findings, "attempts": attempts,
            "stopped_early": stopped,
            "note": f"paced audit of {len(attempts)} candidates for "
                    f"{username} (cap 8, lockout-aware)"}
