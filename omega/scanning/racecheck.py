"""omega/racecheck.py — GET-only concurrency consistency check.

Fires a SMALL number (default 5, hard cap 20) of IDENTICAL GET requests
concurrently and compares the responses. Inconsistent status codes or
bodies under identical concurrent load is weak evidence of a missing
serialization / check-then-act window — always a CANDIDATE (severity
low), never confirmed. GET-only by design: anything that could mutate
state (non-GET) is REFUSED with ValueError; total requests are
hard-capped at 20.

Findings follow the ENGINE convention (omega.deepchecks.Finding),
source=omega-race/probe. ``run_racecheck`` never raises.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

__all__ = [
    "DEFAULT_CONCURRENCY",
    "MAX_REQUESTS",
    "Finding",
    "race_probe",
    "run_racecheck",
]

from omega.deepchecks import Finding
from omega.probes import allowlist_ok

DEFAULT_CONCURRENCY = 5
MAX_REQUESTS = 20


def _clip(text, limit=200):
    text = str(text)
    return text if len(text) <= limit else text[:limit - 3] + "..."


def race_probe(target, fetch=None, n=DEFAULT_CONCURRENCY, timeout=30,
               method="GET"):
    """Fire ``n`` identical GETs concurrently and diff the responses.

    A non-GET ``method`` is REFUSED with ValueError (the probe must
    never mutate state). Returns {requests_sent, statuses, consistent,
    serialization, findings}. Request cap: ``n`` is clamped to
    MAX_REQUESTS (20).
    """
    _strict_get_only(method)  # raises ValueError for anything but GET
    if fetch is None:
        from omega.deepchecks import default_fetch
        fetch = default_fetch
    n = max(1, min(int(n), MAX_REQUESTS))
    base_url = target if "://" in target else "http://" + target

    def one(_i):
        try:
            st, _h, body = fetch("GET", base_url)
            return int(st or 0), (body or b"")
        except Exception as exc:  # transport error is a distinct outcome
            return 0, repr(exc).encode("latin-1", "replace")

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(one, range(n)))
    statuses = [r[0] for r in results]
    bodies = [r[1] for r in results]
    consistent = len(set(statuses)) <= 1 and \
        len({b[:512] for b in bodies}) <= 1
    findings = []
    if not consistent:
        findings.append(Finding(
            title="inconsistent responses under concurrent identical "
                  "GETs (possible missing serialization)",
            severity="low",
            confidence="low",
            verification="candidate",
            verification_note=(
                "%d identical concurrent GET requests produced %d "
                "distinct status/body combinations (%s). This is weak "
                "evidence of inconsistent state handling under "
                "concurrency — a CANDIDATE only; no state was mutated "
                "(GET-only probe) and manual verification is required."
                % (len(statuses),
                   len({(s, b[:512]) for s, b in results}),
                   _clip(str(statuses)))),
            manual_check="repeat with curl in parallel: for i in 1..N; "
                         "curl -s -o /dev/null -w '%{http_code}\\n' "
                         "URL & done",
            location=_clip(base_url),
            evidence={"requests": len(statuses),
                      "statuses": statuses,
                      "distinct_bodies":
                          len({b[:512] for b in bodies})},
            source="omega-race/probe"))
        findings.append(Finding(
            title="serialization inconsistency INFO: responses differ "
                  "under concurrency",
            severity="info",
            confidence="medium",
            verification="candidate",
            verification_note=(
                "INFO companion to the race candidate: the server "
                "returned non-uniform responses to %d identical "
                "concurrent GETs (no state was mutated; GET-only). "
                "Useful for the serialization review of the endpoint."
                % len(statuses)),
            manual_check="compare sequential vs concurrent responses",
            location=_clip(base_url),
            evidence={"requests": len(statuses), "statuses": statuses},
            source="omega-race/probe"))
    return {
        "requests_sent": len(results),
        "statuses": statuses,
        "consistent": consistent,
        "serialization": ("info: responses consistent under %d "
                          "concurrent identical GETs" % len(statuses)
                          if consistent else
                          "info: responses inconsistent under "
                          "concurrency"),
        "findings": findings,
    }


def run_racecheck(target, fetch=None, allowlist=None, log=None,
                  n=DEFAULT_CONCURRENCY):
    """Allowlist-gated, never-raises wrapper around ``race_probe``.

    Returns {findings, ran, skipped, requests_sent, serialization}.
    """
    result = {"findings": [], "ran": [], "skipped": {},
              "requests_sent": 0, "serialization": None}
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = (
            "target %r not in allowlist" % target)
        if log:
            log("racecheck skipped: target not in allowlist: %r" % target)
        return result
    try:
        out = race_probe(target, fetch=fetch, n=n)
        result["findings"] = out["findings"]
        result["requests_sent"] = out["requests_sent"]
        result["serialization"] = out["serialization"]
        result["ran"].append("race_probe")
        if log:
            log("racecheck: %d request(s), %d finding(s)"
                % (out["requests_sent"], len(out["findings"])))
    except Exception as exc:  # never raise
        result["skipped"]["race_probe"] = "error: %s" % exc
        if log:
            log("racecheck failed: %s" % exc)
    return result


# strict-mode helper kept for the contract: a non-GET method is refused
def _strict_get_only(method):
    if str(method).upper() != "GET":
        raise ValueError(
            "racecheck is GET-only: refused method %r" % method)
    return "GET"
