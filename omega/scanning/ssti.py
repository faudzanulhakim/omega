"""omega/scanning/ssti.py — engine-specific server-side template
injection prober (fusion suite name: ``ssti-engine``).

Extends the existing arithmetic-marker detection (omega/chaos.py
``SSTI-evidence``) with ENGINE FINGERPRINTING and engine-specific SAFE
proof payloads:

  stage 1  arithmetic probes distinguish the expression syntax class:
             {{7*7}}  -> Jinja2 / Twig class
             ${7*7}   -> FreeMarker / Velocity class
             <%= 7*7 %> -> ERB / EJS class
             #{7*7}   -> Pebble / Thymeleaf class
             {7*7}    -> Smarty class
  stage 2  a single engine-specific SECOND-ARYTHMETIC proof payload
           disambiguates within the class (e.g. {{7*'7'}} -> 7777777
           only in Jinja2, stays 49 in Twig).

SAFETY CONTRACT: probes are inert arithmetic expressions only — no
attribute access, no filters chaining, no code execution beyond
arithmetic and string repetition. Every finding is
``verification='candidate'`` (evidence-level, mirrors chaos.py's
SSTI-evidence honesty rule).
"""

from __future__ import annotations

import secrets
import urllib.parse

__all__ = [
    "Finding",
    "ENGINES",
    "disambiguate",
    "fingerprint",
    "registry",
    "run_ssti",
]

# syntax class -> (probe payload, expected result, disambiguator payload,
#                  disambiguator result, engine name)
ENGINES = [
    ("jinja2", "{{7*7}}", "49", "{{7*'7'}}", "7777777"),
    ("twig", "{{7*7}}", "49", "{{7*'7'}}", "49"),
    ("freemarker", "${7*7}", "49", "${7*'7'}", "49"),
    ("erb", "<%= 7*7 %>", "49", "<%= 7*'7' %>", "49"),
    ("pebble", "#{7*7}", "49", "#{7*'7'}", "49"),
    ("smarty", "{7*7}", "49", "{7*'7'}", "49"),
]

PROBE_PARAMS = ["q", "name", "template", "msg", "search", "page", "text"]
PROBE_PATHS = ["/", "/search", "/render", "/preview", "/index.php"]


class Finding(dict):
    """ENGINE-convention finding dict (differential, candidate-only)."""

    def __init__(self, title, severity, verification_note, manual_check,
                 location, evidence, source, confidence="medium"):
        super().__init__(
            title=title,
            severity=severity,
            confidence=confidence,
            verification="candidate",
            verification_note=verification_note,
            manual_check=manual_check,
            location=location,
            evidence=evidence[:300],
            source=source,
        )


def _text(body):
    if isinstance(body, bytes):
        return body.decode("latin-1")
    return str(body or "")


def _engine_for(payload):
    for engine, probe, _exp, _dis, _dre in ENGINES:
        if probe == payload:
            return engine
    return "unknown"


def fingerprint(base_url, fetch, payload, expected):
    """Send one arithmetic probe via query param (and path fallback);
    return (param_or_None, response_text) when the RESULT is reflected
    differentially (result present on probe, absent on baseline and on
    an inert-control request)."""
    canary = "ssti-%s" % secrets.token_hex(4)
    baseline_url = base_url.rstrip("/") + "/?" + urllib.parse.urlencode(
        {"q": canary})
    st_b, _hb, b_b = fetch("GET", baseline_url)
    base_text = _text(b_b)
    for path in PROBE_PATHS:
        for param in PROBE_PARAMS:
            url = base_url.rstrip("/") + path + "?" + urllib.parse.urlencode(
                {param: payload})
            st, _h, body = fetch("GET", url)
            text = _text(body)
            if expected not in text:
                continue
            if expected in base_text:
                continue  # baseline already renders the number (FP guard)
            return param, path, text, canary, base_text, st, st_b
    return None


def disambiguate(base_url, fetch, param, path, dis_payload, dis_result):
    """Run the engine-specific second payload on the same param/path."""
    url = base_url.rstrip("/") + path + "?" + urllib.parse.urlencode(
        {param: dis_payload})
    st, _h, body = fetch("GET", url)
    return dis_result in _text(body), st


def probe_engine(base_url, fetch, engine, probe, expected, dis_payload,
                 dis_result):
    """Fingerprint + disambiguate one engine; returns finding or None."""
    hit = fingerprint(base_url, fetch, probe, expected)
    if hit is None:
        return None
    param, path, text, canary, base_text, st, st_b = hit
    confirmed, _dis_status = disambiguate(base_url, fetch, param, path,
                                          dis_payload, dis_result)
    if confirmed:
        engine_name = engine
        conf = "high"
    else:
        engine_name = "%s-class (unconfirmed)" % engine
        conf = "medium"
    return Finding(
        title="SSTI evidence: template engine %s evaluated %s at %s"
              % (engine_name, probe, path),
        severity="high",
        verification_note=(
            "The arithmetic probe %s was rendered as %s (absent from "
            "the baseline) via parameter %r%s — server-side template "
            "evaluation of user input. SAFE-PROBE ONLY: the payload is "
            "pure arithmetic; no attribute access, filter chaining or "
            "code execution was attempted. Candidate (SSTI-evidence): "
            "exploitability requires manual authorized testing."
            % (probe, expected, param,
               "; disambiguator %s -> %s confirms %s"
               % (dis_payload, dis_result, engine)
               if conf == "high" else "")),
        manual_check='curl -sS "%s%s?%s=%s"'
                     % (base_url.rstrip("/"), path,
                        urllib.parse.quote(param),
                        urllib.parse.quote(probe)),
        location=base_url.rstrip("/") + path,
        evidence="engine=%s probe=%r expected=%s param=%s status=%s "
                 "baseline_status=%s" % (engine_name, probe, expected,
                                         param, st, st_b),
        source="omega-ssti/fingerprint",
        confidence=conf)


registry = [
    ("jinja2", "{{7*7}}", "49", "{{7*'7'}}", "7777777"),
    ("twig", "{{7*7}}", "49", "{{7*'7'}}", "49"),
    ("freemarker", "${7*7}", "49", "${7*'7'}", "49"),
    ("erb", "<%= 7*7 %>", "49", "<%= 7*'7' %>", "49"),
    ("pebble", "#{7*7}", "49", "#{7*'7'}", "49"),
    ("smarty", "{7*7}", "49", "{7*'7'}", "49"),
]


class _BudgetExhausted(Exception):
    pass


class _CountingFetch:
    def __init__(self, fetch, cap):
        self._fetch = fetch
        self.cap = cap
        self.sent = 0

    def __call__(self, method, url, headers=None, body=None):
        if self.sent >= self.cap:
            raise _BudgetExhausted()
        resp = self._fetch(method, url, headers=headers, body=body)
        self.sent += 1
        return resp


def run_ssti(target, fetch, budget=250, log=None, allowlist=None):
    """Run the engine-fingerprinting SSTI suite. Never raises; per-check
    errors become skipped entries. Returns
    {findings, skipped, requests_sent, ran}."""
    from omega.probes import allowlist_ok

    result = {"findings": [], "skipped": {}, "requests_sent": 0, "ran": []}
    base_url = target if "://" in target else "http://" + target
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = \
            "target %r not in allowlist" % target
        if log:
            log("ssti skipped: target not in allowlist: %r" % target)
        return result
    fb = _CountingFetch(fetch, budget)
    exhausted = False
    hit_probes = set()  # probe payloads already evidenced (dedupe class)
    for engine, probe, expected, dis, dis_result in registry:
        if exhausted:
            result["skipped"][engine] = "budget exhausted"
            continue
        if probe in hit_probes:
            # an earlier engine with the SAME syntax-class payload already
            # produced a finding — re-probing cannot add information.
            result["skipped"][engine] = \
                "syntax class already covered by an earlier engine hit"
            continue
        try:
            found = probe_engine(base_url, fb, engine, probe, expected,
                                 dis, dis_result)
        except _BudgetExhausted:
            result["skipped"][engine] = "budget exhausted"
            exhausted = True
            continue
        except Exception as exc:
            result["skipped"][engine] = "error: %s" % exc
            if log:
                log("ssti %s failed: %s" % (engine, exc))
            continue
        result["ran"].append(engine)
        if found:
            hit_probes.add(probe)
            result["findings"].append(found)
            if log:
                log("ssti %s: finding (%s)" % (engine, found["confidence"]))
    result["requests_sent"] = fb.sent
    return result
