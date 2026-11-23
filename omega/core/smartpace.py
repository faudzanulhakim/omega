"""omega/core/smartpace — server-aware adaptive pacing.

Watches response latency/429 drift between waves and recommends (or
enforces, when asked) a slower pace under load. Pure measurement:
never generates extra load beyond its probes. Feeds OMEGA_LOCKOUT_
COOLDOWN-aware modules.
"""
import os
import time

__all__ = ["measure_pace", "recommend"]


def measure_pace(fetch, probe_url, samples=5, gap_s=0.3):
    """Return {latencies, has_429, drift_ratio} from spaced samples."""
    lat = []
    has_429 = False
    for _ in range(samples):
        t0 = time.time()
        try:
            r = fetch(probe_url)
        except Exception:
            break
        dt = time.time() - t0
        if r is None:
            break
        if getattr(r, "status", 0) == 429:
            has_429 = True
        lat.append(dt)
        if gap_s:
            time.sleep(gap_s)
    drift = (max(lat) / max(min(lat), 1e-6)) if len(lat) >= 2 else 1.0
    return {"latencies": lat, "has_429": has_429,
            "drift_ratio": round(drift, 2)}


def recommend(m):
    """Return (pace_s, reason) from a measurement."""
    if m["has_429"]:
        return 2.0, "429 observed — back off to 2s between probes"
    if m["drift_ratio"] > 3.0:
        return 1.5, "latency drifting >3x — server under load, slow down"
    if max(m["latencies"] or [0]) > 2.0:
        return 1.0, "baseline latency high — keep requests spaced"
    return 0.2, "server healthy — normal pace"
