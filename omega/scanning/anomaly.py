"""omega/anomaly.py — response anomaly model.

Learns a baseline profile per path during initial probes (status code,
header NAME set, length bucket, content-type), then flags deviations
observed during active testing:

  * unexpected 5xx responses                    -> MEDIUM candidate
  * new security-sensitive headers appearing
    only on the error response                  -> LOW candidate
  * stack traces (Python traceback, Java stack,
    ASP.NET yellow screen, PHP error output)    -> HIGH **confirmed**
      (unambiguous fingerprints)
  * debug flags (Django debug page markers,
    settings.DEBUG=True, display_errors, ...)   -> MEDIUM candidate
  * content-type deviation                      -> LOW candidate

Every finding carries evidence with the matched fingerprint line
(truncated to 300 chars). Only unambiguous fingerprints are
``confirmed``; everything else stays a ``candidate``.

``run_anomaly`` never raises; failures land in ``result['skipped']``.
"""

from __future__ import annotations

import re

from omega.probes import Finding, default_fetch

__all__ = [
    "STACK_TRACE_FINGERPRINTS",
    "DEBUG_FLAG_FINGERPRINTS",
    "SENSITIVE_HEADERS",
    "LENGTH_BUCKET",
    "learn_baseline",
    "check_path",
    "run_anomaly",
]

LENGTH_BUCKET = 512

# Unambiguous stack-trace fingerprints: (label, compiled regex).
_STACK_PATTERNS = [
    ("python traceback", r"Traceback \(most recent call last\)"),
    ("java stack trace", r"(?:Caused by: )?[\w$.]+(?:Exception|Error):? "
                        r"(?:\r?\n?\s+at [\w$.]+\()"),
    ("asp.net yellow screen", r"Server Error in '.+' Application"),
    ("asp.net stack trace", r"\[HttpException\]|\[InvalidOperationException\]"),
    ("php error output", r"(?:Fatal error|Warning|Parse error):"),
    ("ruby backtrace", r"from .*:\d+:in `"),
    ("go panic", r"panic: .*goroutine \d+ \["),
]
STACK_TRACE_FINGERPRINTS = [
    (label, re.compile(pat, re.I)) for label, pat in _STACK_PATTERNS
]

# Debug-mode markers: candidate, never auto-confirmed.
DEBUG_FLAG_FINGERPRINTS = [
    (label, re.compile(pat, re.I)) for label, pat in [
        ("django debug page", r"django\.views\.debug|Exception Value:"),
        ("django debug mode", r"settings\.DEBUG\s*=\s*True|DEBUG = True"),
        ("flask debug pin", r"werkzeug debugger|debugger pin"),
        ("laravel app_debug", r"APP_DEBUG|Whoops!.*has occurred"),
        ("symfony dev panel", r"symfony.*exception.*dev|WebProfiler"),
        ("rails dev error", r"action_controller::routingerror"),
        ("dotnet developer page",
         r"Developer Exception Page|aspnetcore.*developer.*exception"),
    ]
]

# Header names that only ever appearing on error responses is itself
# a finding (info-leak / debug surface).
SENSITIVE_HEADERS = {
    "x-debug", "x-debug-token", "x-php-error", "x-aspnet-version",
    "x-aspnetmvc-version", "x-powered-by", "x-runtime", "x-django-version",
    "x-symfony-version", "x-laravel-version", "x-rails-version",
    "x-execution-time", "x-trace-id-set-by-debug",
}

_CLIP = 300


def _clip(text, limit=_CLIP):
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _match_line(body_text, regex):
    """First line (<=300 chars) matching the regex, else None."""
    for line in body_text.splitlines():
        if regex.search(line):
            return _clip(line.strip())
    return None


# --------------------------------------------------------------- baseline

def _length_bucket(body):
    return len(body or b"") // LENGTH_BUCKET


def _profile(status, headers, body):
    return {
        "status": int(status or 0),
        "headers": sorted(str(k).lower() for k in (headers or {})),
        "length_bucket": _length_bucket(body),
        "content_type": str(headers.get("Content-Type")
                            or headers.get("content-type") or ""),
    }


def learn_baseline(target, paths, fetch=None):
    """Fetch each path once and build {path: profile} (never raises)."""
    if fetch is None:
        fetch = default_fetch
    base_url = target if "://" in target else "http://" + target
    baseline = {}
    for path in paths or []:
        url = base_url + (path if path.startswith("/") else "/" + path)
        try:
            status, headers, body = fetch("GET", url)
        except Exception:
            status, headers, body = 0, {}, b""
        baseline[path] = _profile(status, headers, body)
    return baseline


# ----------------------------------------------------------------- checks

def check_path(url, profile, fetch=None):
    """Fetch ``url`` and diff it against its baseline ``profile``.

    Returns {"findings": [...], "deviations": [labels], "response":
    {status, headers, length_bucket}}. Never raises.
    """
    if fetch is None:
        fetch = default_fetch
    out = {"findings": [], "deviations": []}
    try:
        status, headers, body = fetch("GET", url)
    except Exception as exc:
        out["deviations"].append("transport-error")
        out["error"] = _clip(repr(exc), 200)
        return out
    out["response"] = {
        "status": int(status or 0),
        "length_bucket": _length_bucket(body),
    }
    try:
        body_text = (body or b"").decode("utf-8", "replace")
    except Exception:
        body_text = ""

    def add(title, severity, verification, note, evidence, source_part):
        out["findings"].append(Finding(
            title=title,
            severity=severity,
            verification=verification,
            verification_note=note,
            manual_check="curl -sS -D - " + _clip(url, 200),
            location=url,
            evidence=evidence,
            source="omega-anomaly/" + source_part,
        ))

    # 1. stack traces: unambiguous -> CONFIRMED, high.
    for label, regex in STACK_TRACE_FINGERPRINTS:
        line = _match_line(body_text, regex)
        if line:
            out["deviations"].append("stack-trace:" + label)
            add("Stack trace exposed in response (%s)" % label,
                "high", "confirmed",
                "Unambiguous fingerprint: %s" % label,
                {"fingerprint": line, "status": int(status or 0)},
                "stack-trace")

    # 2. debug flags: candidate, medium.
    for label, regex in DEBUG_FLAG_FINGERPRINTS:
        line = _match_line(body_text, regex)
        if line:
            out["deviations"].append("debug-flag:" + label)
            add("Debug-mode marker in response (%s)" % label,
                "medium", "candidate",
                "Debug fingerprint matched; confirm manually",
                {"fingerprint": line, "status": int(status or 0)},
                "debug-flag")

    # 3. unexpected 5xx.
    if int(status or 0) >= 500 and int(profile.get("status") or 0) < 500:
        out["deviations"].append("unexpected-5xx")
        add("Unexpected 5xx response (baseline status %s)"
            % profile.get("status"),
            "medium", "candidate",
            "Server error not present in the learned baseline",
            {"status": int(status or 0),
             "body": _clip(body_text[:_CLIP])},
            "5xx")

    # 4. new security-sensitive headers.
    header_names = {str(k).lower() for k in (headers or {})}
    new_sensitive = sorted(
        header_names & SENSITIVE_HEADERS
        - set(profile.get("headers") or []))
    if new_sensitive:
        out["deviations"].append("new-sensitive-headers")
        add("Security-sensitive headers appeared on this response",
            "low", "candidate",
            "Headers absent from the learned baseline",
            {"headers": ", ".join(new_sensitive)[:_CLIP]},
            "headers")

    # 5. content-type deviation.
    ct = str(headers.get("Content-Type") or headers.get("content-type") or "")
    base_ct = profile.get("content_type") or ""
    if ct and base_ct and ct.split(";")[0].strip().lower() \
            != base_ct.split(";")[0].strip().lower():
        out["deviations"].append("content-type")
        add("Content-Type deviates from baseline",
            "low", "candidate",
            "Baseline content-type: %s" % base_ct,
            {"baseline": base_ct[:_CLIP], "observed": ct[:_CLIP]},
            "content-type")

    return out


# -------------------------------------------------------------- entrypoint

def run_anomaly(target, paths, fetch=None):
    """Learn a baseline over ``paths`` then re-probe each for anomalies.

    Returns {findings, ran, skipped, baseline, deviations}. Never
    raises: per-path failures land in ``result['skipped']``.
    """
    result = {"findings": [], "ran": [], "skipped": {},
              "baseline": {}, "deviations": []}
    if fetch is None:
        fetch = default_fetch
    base_url = target if "://" in target else "http://" + target
    try:
        result["baseline"] = learn_baseline(base_url, paths, fetch)
    except Exception as exc:
        result["skipped"]["baseline"] = _clip(repr(exc), 200)
        return result
    for path, profile in result["baseline"].items():
        url = base_url + (path if path.startswith("/") else "/" + path)
        try:
            res = check_path(url, profile, fetch)
            result["findings"].extend(res["findings"])
            result["deviations"].extend(res["deviations"])
            result["ran"].append(path)
        except Exception as exc:
            result["skipped"][path] = _clip(repr(exc), 200)
    return result
