"""omega/offense/fuzz.py — gated mutation fuzzing engine for AUTHORIZED
targets.

Functions:
  mutate(value, rng)      — deterministic single mutation (bitflip,
                            dictionary injection, overlong strings,
                            format strings, unicode tricks, encoding
                            chains) driven by a seeded random.Random.
  fuzz_params(target, fetch, params, budget, log, seed) — fuzz query
                            parameters and detect anomalies via a
                            response-class differential (status code
                            class, length bucket, reflected-marker
                            detection, timeout detection).

Anomaly findings are 'candidate' unless a crash signature is seen
(5xx + error fingerprint in the body) in which case 'confirmed'.
Every finding records the seed and the exact mutated value so the run
is reproducible. Requires the offense gate (PTK_OFFENSE=1) — raises
PermissionError otherwise. Read-only: only GET probes against the
supplied target parameter.
"""

from __future__ import annotations

import base64
import random
import urllib.parse

from omega.offense import count_request, budget_left, max_requests, \
    offense_gate_ok

__all__ = [
    "FUZZ_DICT",
    "CRASH_FINGERPRINTS",
    "MUTATIONS_PER_PARAM",
    "mutate",
    "fuzz_params",
]

# Dictionary values injected by mutate (quotes, brackets, null bytes,
# overlong-ish tokens, format strings, unicode tricks, path tricks).
FUZZ_DICT = [
    '"', "'", "`", "<", ">", "()", "[]", "{}", "%00", "%27", "%2e%2e%2f",
    "%s%s%s%s", "%x %x %x", "%n", "%d%d%d", "{{7*7}}", "${7*7}",
    "../../etc/passwd", "<script>alert(1)</script>", "\\",
]

# Unicode trick values appended by the unicode mutation.
UNICODE_TRICKS = ["\u202e", "\ufeff", "\u0000", "\u200b", "\ufffd"]

# Error fingerprints that, together with a 5xx status, mark a finding
# 'confirmed'.
CRASH_FINGERPRINTS = (
    "traceback", "exception", "syntax error", "parse error",
    "internal server error", "stack overflow", "segmentation",
    "fatal error", "sql syntax", "unexpected token",
    "unhandled error", "warning:",
)

MUTATIONS_PER_PARAM = 6
DEFAULT_SEED = 1337


def mutate(value, rng):
    """Return one mutated copy of ``value`` using the seeded ``rng``.

    Deterministic: the same (value, rng state) always produces the same
    result. One of six operations is picked:
      0 bitflip (single byte XOR in the UTF-8 encoding)
      1 character injection from FUZZ_DICT
      2 overlong string (512-char tail)
      3 format string append
      4 unicode trick append
      5 encoding chain (url / double-url / base64)
    """
    value = str(value)
    op = rng.randrange(6)
    if op == 0:
        raw = bytearray(value.encode("utf-8", "replace"))
        if raw:
            raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
        return bytes(raw).decode("utf-8", "replace")
    if op == 1:
        pos = rng.randrange(len(value) + 1)
        return value[:pos] + rng.choice(FUZZ_DICT) + value[pos:]
    if op == 2:
        return value + "A" * 512
    if op == 3:
        return value + rng.choice(["%s%s%s%s", "%x %x %x", "%n",
                                   "%d%d%d"])
    if op == 4:
        return value + rng.choice(UNICODE_TRICKS)
    enc = rng.choice(["url", "double-url", "base64"])
    if enc == "url":
        return urllib.parse.quote(value, safe="")
    if enc == "double-url":
        return urllib.parse.quote(
            urllib.parse.quote(value, safe=""), safe="")
    return base64.b64encode(value.encode("utf-8", "replace")).decode()


def _probe_url(target, name, value):
    sep = "&" if "?" in target else "?"
    return target + sep + urllib.parse.urlencode({name: value})


def _body_text(body):
    if isinstance(body, (bytes, bytearray)):
        return body.decode("utf-8", "replace")
    return str(body)


def fuzz_params(target, fetch, params, budget=None, log=None,
                seed=DEFAULT_SEED, method="GET",
                mutations_per_param=MUTATIONS_PER_PARAM):
    """Fuzz query parameters of ``target`` with seeded mutations.

    params — mapping {param_name: original_value}
    budget — max requests for this run (also capped by budget_left()).
    seed   — RNG seed; recorded in every finding's evidence so the run
             is reproducible.

    Anomaly detection per candidate response (vs the param baseline):
      * status code class shift (e.g. 2xx -> 5xx)
      * length bucket shift (>50% change in body length)
      * reflected marker: a FUZZ_DICT token (len > 4) appears decoded
        in the body but not in the baseline body
      * timeout detection: fetch raises (treated as status 0)

    verification is 'candidate' unless the crash signature holds
    (status >= 500 AND a CRASH_FINGERPRINTS entry in the body) which
    upgrades it to 'confirmed'. Returns
    {findings: [...], attempts, seed}.
    """
    offense_gate_ok()
    rng = random.Random(seed)
    cap = max_requests() if budget is None else int(budget)
    cap = max(0, min(cap, budget_left()))
    attempts = 0
    findings = []

    def _log(msg):
        if log is not None:
            try:
                log(msg)
            except Exception:
                pass

    def _send(url):
        nonlocal attempts
        count_request(1)
        attempts += 1
        try:
            status, headers, body = fetch(method, url)
            return int(status), _body_text(body)
        except Exception:
            return 0, ""

    for name, orig in params.items():
        if attempts >= cap or budget_left() <= 0:
            break
        base_status, base_text = _send(
            _probe_url(target, name, str(orig)))
        base_class = base_status // 100
        for _ in range(max(0, mutations_per_param)):
            if attempts >= cap or budget_left() <= 0:
                break
            value = mutate(orig, rng)
            status, text = _send(_probe_url(target, name, value))

            anomalies = []
            if status == 0:
                anomalies.append("timeout/connection failure")
            else:
                if status // 100 != base_class:
                    anomalies.append("status class %dxx -> %dxx"
                                     % (base_class, status // 100))
                ratio = (len(text) / len(base_text)
                         if len(base_text) > 0 else None)
                if ratio is not None and (ratio < 0.5 or ratio > 1.5):
                    anomalies.append("length bucket shift (%d -> %d)"
                                     % (len(base_text), len(text)))
                for token in FUZZ_DICT:
                    if len(token) > 4 and token in text \
                            and token not in base_text:
                        anomalies.append("reflected marker %r"
                                         % token)
                        break

            if not anomalies:
                continue
            crash = status >= 500 and any(
                fp in text.lower() for fp in CRASH_FINGERPRINTS)
            findings.append({
                "title": "Fuzzing anomaly on parameter '%s'" % name,
                "severity": "medium" if not crash else "high",
                "confidence": "high" if crash else "low",
                "verification": "confirmed" if crash else "candidate",
                "verification_note":
                    ("5xx response carrying an error fingerprint "
                     "reproduced the crash signature"
                     if crash else
                     "single differential anomaly; re-verify manually "
                     "before reporting"),
                "location": target,
                "param": name,
                "evidence": "seed=%d value=%r anomalies=%s status=%d"
                            % (seed, value, "; ".join(anomalies),
                               status),
                "source": "omega-offense/fuzz_params",
                "seed": seed,
            })
            _log("fuzz_params: %s anomaly on %r (value=%r, status=%d)"
                 % ("crash" if crash else "candidate", name, value,
                    status))
    return {"findings": findings, "attempts": attempts,
            "seed": seed}
