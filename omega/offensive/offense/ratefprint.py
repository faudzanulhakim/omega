"""omega/offensive/offense/ratefprint — rate-limit fingerprint & pacing.

Detects rate limiting per endpoint WITHOUT tripping it: N spaced
probes, measures status-shift / 429 / retry-after / latency drift,
then recommends a safe pace. Output feeds horizontal/spray modules
(OMEGA_LOCKOUT_COOLDOWN aware). OFFENSE-GATED (PTK_OFFENSE).
"""
import os
import time

__all__ = ["run_ratefprint"]


def run_ratefprint(target, fetch=None, endpoints=None, samples=4,
                   gap_s=0.4, log=None, gate_open_fn=None):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    endpoints = endpoints or ["/", "/login", "/api/search"]
    findings = []
    profile = {}
    probes = 0
    base = str(target).rstrip("/")
    for ep in endpoints:
        statuses, lat = [], []
        for _ in range(samples):
            t0 = time.time()
            try:
                resp = fetch(base + ep)
            except Exception:
                break
            probes += 1
            dt = time.time() - t0
            if resp is None:
                break
            statuses.append(getattr(resp, "status", 0))
            h = {str(k).lower(): str(v)
                 for k, v in (getattr(resp, "headers", {}) or {}).items()}
            if dt:
                lat.append(dt)
            if gap_s:
                time.sleep(gap_s)
        if not statuses:
            continue
        limit = {
            "429": 429 in statuses,
            "retry_after": any(s in statuses for s in statuses if False),
        }
        status_shift = len(set(statuses)) > 1
        lat_drift = (max(lat) > 2 * min(lat)) if len(lat) >= 2 else False
        if limit["429"]:
            verdict, pace = "hard limit (429)", 2.0
        elif status_shift:
            verdict, pace = "soft shift (status changes under load)", 1.0
        elif lat_drift:
            verdict, pace = "latency-based throttling", 1.5
        else:
            verdict, pace = "no rate limit observed", 0.2
        profile[ep] = {"statuses": statuses, "verdict": verdict,
                       "suggested_pace_s": pace}
        if verdict == "no rate limit observed" and \
                ep in ("/login", "/api/search"):
            findings.append({
                "title": f"no rate limiting observed on {ep} "
                         f"({samples} samples)",
                "severity": "MEDIUM",
                "source": "ratefprint/none",
                "evidence": f"identical {statuses} across samples, no "
                            f"latency drift",
                "location": base + ep,
                "verification": "candidate",
                "manual_check": "confirm with a longer controlled "
                                "sample before reporting; enables "
                                "brute/abuse from third parties",
                "cwe": "CWE-770",
            })
    if log:
        log(f"ratefprint: probes={probes} eps={len(profile)}")
    return {"findings": findings, "probes": probes, "profile": profile}
