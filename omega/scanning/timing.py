"""omega/timing.py — timing-based blind detection.

Compares TTFB (time-to-first-byte) distributions between a baseline
request and a candidate request across N samples (N from env
``OMEGA_TIMING_SAMPLES``, default 5). Statistics are median + MAD; a
differential is only flagged when the candidate median exceeds the
baseline median by a configured factor AND the differential clears a
MAD-based margin AND repeated confirmation rounds reproduce it.

Two checks, both GET-only and read-only:

  login_timing_probe  — timing-based username enumeration on a login
      endpoint: compare an existing-looking account name against a
      random nonexistent one. A stable differential -> candidate
      MEDIUM finding (never confirmed: response timing is noisy on
      real targets).
  token_timing_probe  — timing-based token/id existence: compare a
      known value for a parameter against a random one. Same rule.

Out of scope here (owned by the exploit layer): HTTP parameter timing
probes for blind OS command injection.

``run_timing`` never raises; failures land in ``result['skipped']``.
Findings follow the ENGINE convention (omega.probes.Finding), with
sample counts, medians and MADs recorded in evidence.
"""

from __future__ import annotations

import os
import random
import time
import urllib.parse

from omega.probes import Finding, default_fetch

__all__ = [
    "DEFAULT_SAMPLES",
    "MAX_SAMPLES",
    "DEFAULT_FACTOR",
    "DEFAULT_ROUNDS",
    "MIN_MARGIN_S",
    "env_samples",
    "median",
    "mad",
    "time_url",
    "timing_differential",
    "login_timing_probe",
    "token_timing_probe",
    "run_timing",
]

DEFAULT_SAMPLES = 5
MAX_SAMPLES = 20
DEFAULT_FACTOR = 2.5
DEFAULT_ROUNDS = 2
# A differential must beat this floor even when both MADs are ~0 on a
# fast, quiet server (sub-millisecond responses otherwise look "stable").
MIN_MARGIN_S = 0.05


def env_samples():
    """Sample count from OMEGA_TIMING_SAMPLES, clamped to [1, 20]."""
    try:
        n = int(os.environ.get("OMEGA_TIMING_SAMPLES", DEFAULT_SAMPLES))
    except (TypeError, ValueError):
        n = DEFAULT_SAMPLES
    return max(1, min(n, MAX_SAMPLES))


def _clip(text, limit=300):
    text = str(text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


# ------------------------------------------------------------------ stats

def median(values):
    """Median of a non-empty numeric list; 0.0 for empty input."""
    vals = sorted(float(v) for v in (values or []))
    if not vals:
        return 0.0
    n = len(vals)
    mid = n // 2
    if n % 2:
        return vals[mid]
    return (vals[mid - 1] + vals[mid]) / 2.0


def mad(values):
    """Median absolute deviation of a list; 0.0 for empty input."""
    vals = [float(v) for v in (values or [])]
    if not vals:
        return 0.0
    m = median(vals)
    return median([abs(v - m) for v in vals])


# ----------------------------------------------------------------- timing

def time_url(url, fetch=None, samples=None):
    """GET ``url`` N times; return the list of elapsed seconds.

    Transport errors count as failed samples (recorded as None and
    excluded from the statistics rather than poisoning the median).
    """
    if fetch is None:
        fetch = default_fetch
    n = env_samples() if samples is None else max(1, min(int(samples), MAX_SAMPLES))
    out = []
    for _ in range(n):
        t0 = time.monotonic()
        try:
            fetch("GET", url)
            out.append(max(time.monotonic() - t0, 1e-6))
        except Exception:
            out.append(None)
    return out


def timing_differential(url_baseline, url_candidate, fetch=None,
                        samples=None, factor=DEFAULT_FACTOR,
                        rounds=DEFAULT_ROUNDS):
    """Measure baseline vs candidate TTFB distributions over ``rounds``.

    A round is "flagged" when candidate_median > baseline_median *
    ``factor`` AND the gap exceeds max(2 * max(MADs), MIN_MARGIN_S).
    The differential is ``confirmed`` only when EVERY round is flagged;
    it is ``flagged`` when at least one round is; otherwise ``none``.
    Returns {flagged, confirmed, rounds, samples, baseline: {...},
    candidate: {...}} with per-arm median/MAD of the LAST round.
    """
    rounds = max(1, int(rounds))
    round_flags = []
    last = None
    for _ in range(rounds):
        b = time_url(url_baseline, fetch, samples)
        c = time_url(url_candidate, fetch, samples)
        b_ok = [v for v in b if v is not None]
        c_ok = [v for v in c if v is not None]
        b_med, b_mad = median(b_ok), mad(b_ok)
        c_med, c_mad = median(c_ok), mad(c_ok)
        margin = max(2.0 * max(b_mad, c_mad), MIN_MARGIN_S)
        flagged = bool(
            b_ok and c_ok
            and c_med > b_med * float(factor)
            and (c_med - b_med) > margin
        )
        round_flags.append(flagged)
        last = {
            "samples": len(b_ok),
            "baseline_median": b_med,
            "baseline_mad": b_mad,
            "candidate_median": c_med,
            "candidate_mad": c_mad,
        }
    confirmed = bool(round_flags) and all(round_flags)
    return {
        "flagged": any(round_flags),
        "confirmed": confirmed,
        "rounds": rounds,
        "factor": float(factor),
        **last,
    }


def _finding(title, diff, url, note_suffix=""):
    evidence = {
        "url": _clip(url, 200),
        "samples": diff["samples"],
        "baseline_median": round(diff["baseline_median"], 6),
        "baseline_mad": round(diff["baseline_mad"], 6),
        "candidate_median": round(diff["candidate_median"], 6),
        "candidate_mad": round(diff["candidate_mad"], 6),
        "factor": diff["factor"],
        "rounds": diff["rounds"],
        "confirmed": diff["confirmed"],
    }
    return Finding(
        title=title,
        severity="medium",
        verification="candidate",
        verification_note=(
            "Response-time differential reproduced across %d rounds; "
            "timing is inherently noisy on real targets — manual "
            "verification required%s" % (diff["rounds"], note_suffix)),
        manual_check="curl -o /dev/null -s -w '%%{time_starttransfer}\\n' "
                     + _clip(url, 200),
        location=url,
        evidence=evidence,
        source="omega-timing",
    )


def _rand_user():
    return "user_" + "".join(random.choice("0123456789abcdef")
                             for _ in range(12))


def login_timing_probe(login_url, probe_user="admin", user_param="username",
                       password_param="password", fetch=None,
                       samples=None, factor=DEFAULT_FACTOR,
                       rounds=DEFAULT_ROUNDS):
    """Timing-based username enumeration on a login endpoint.

    Baseline: a random nonexistent user. Candidate: ``probe_user``.
    Returns {findings, differential}.
    """
    base_url = login_url + ("&" if "?" in login_url else "?")
    baseline = base_url + urllib.parse.urlencode(
        {user_param: _rand_user(), password_param: "x"})
    candidate = base_url + urllib.parse.urlencode(
        {user_param: probe_user, password_param: "x"})
    diff = timing_differential(baseline, candidate, fetch, samples,
                               factor, rounds)
    findings = []
    if diff["confirmed"]:
        findings.append(_finding(
            "Timing differential on login response (username "
            "enumeration candidate)", diff, login_url))
    return {"findings": findings, "differential": diff}


def token_timing_probe(url, param, known_value, fetch=None, samples=None,
                       factor=DEFAULT_FACTOR, rounds=DEFAULT_ROUNDS):
    """Timing-based token/id existence check for one query parameter.

    Baseline: a random value for ``param``. Candidate: ``known_value``.
    Returns {findings, differential}.
    """
    sep = "&" if "?" in url else "?"
    baseline = url + sep + urllib.parse.urlencode(
        {param: "".join(random.choice("0123456789abcdef") for _ in range(16))})
    candidate = url + sep + urllib.parse.urlencode({param: known_value})
    diff = timing_differential(baseline, candidate, fetch, samples,
                               factor, rounds)
    findings = []
    if diff["confirmed"]:
        findings.append(_finding(
            "Timing differential for parameter '%s' (existence check "
            "candidate)" % param, diff, url))
    return {"findings": findings, "differential": diff}


# -------------------------------------------------------------- entrypoint

def run_timing(target, login_url=None, known_values=None, fetch=None,
               samples=None, factor=DEFAULT_FACTOR, rounds=DEFAULT_ROUNDS):
    """Run all applicable timing checks. Never raises.

    ``known_values``: {param_name: known_value} probed against ``target``.
    Returns {findings, ran, skipped}.
    """
    result = {"findings": [], "ran": [], "skipped": {}}
    if fetch is None:
        fetch = default_fetch
    base_url = target if "://" in target else "http://" + target

    if login_url:
        try:
            res = login_timing_probe(base_url + login_url, fetch=fetch,
                                     samples=samples, factor=factor,
                                     rounds=rounds)
            result["findings"].extend(res["findings"])
            result["ran"].append("login_timing")
        except Exception as exc:
            result["skipped"]["login_timing"] = _clip(repr(exc), 200)

    for param, value in dict(known_values or {}).items():
        try:
            res = token_timing_probe(base_url, param, value, fetch=fetch,
                                     samples=samples, factor=factor,
                                     rounds=rounds)
            result["findings"].extend(res["findings"])
            result["ran"].append("token_timing:%s" % param)
        except Exception as exc:
            result["skipped"]["token_timing:%s" % param] = _clip(repr(exc), 200)

    return result
