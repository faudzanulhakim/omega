"""omega/scanning/resetpoison.py — password reset poisoning detector
(fusion suite name: ``resetpoison``).

On paths containing reset/password/forgot (from path_info plus common
defaults) that accept POST, a benign reset request
(email=probe...@omegaprobe.invalid) is replayed with Host:
attacker.example and X-Forwarded-Host: attacker.example variants. A HIGH
candidate is emitted when the injected host appears in the response
body (or a follow-up fetch) in a reset-URL/link context. A LOW
candidate flags reset tokens exposed in URL/referrer-style query
patterns. Never raises; bounded; benign probes only.
"""

from __future__ import annotations

import re

from omega.scanning.deepchecks import default_fetch

__all__ = [
    "Finding",
    "INJECT_HOST",
    "RESET_PATH_DEFAULTS",
    "run_resetpoison",
]

INJECT_HOST = "attacker.example"
RESET_PATH_DEFAULTS = ("/reset", "/reset-password", "/password-reset",
                       "/forgot-password", "/forgot", "/password/reset")
RESET_PATH_RE = re.compile(r"reset|password|forgot", re.I)
LINK_CONTEXT_RE = re.compile(
    r"""(?:https?://[^\"'\s<>]*attacker\.example[^\"'\s<>]*)"""
    r"""|(?:href\s*=\s*["'][^"']*attacker\.example[^"']*)""", re.I)
RESET_CONTEXT_RE = re.compile(r"reset|password|forgot", re.I)
TOKEN_URL_RE = re.compile(
    r"""(?:[?&](?:reset_?token|token|key)=[0-9a-f\-]{8,})"""
    r"""|(?:(?:location|referrer)\s*[:=]\s*[^\s]*token=[0-9a-f\-]{8,})""",
    re.I)
PROBE_EMAIL = "omegaprobe+reset@omegaprobe.invalid"


class Finding(dict):
    """ENGINE-convention finding dict (candidate only)."""

    def __init__(self, title, severity, verification, verification_note,
                 manual_check, location, evidence, source,
                 confidence="medium"):
        super().__init__(
            title=title,
            severity=severity,
            confidence=confidence,
            verification=verification,
            verification_note=verification_note,
            manual_check=manual_check,
            location=location,
            evidence=str(evidence)[:300],
            source=source,
        )


def _text(body):
    if isinstance(body, bytes):
        return body.decode("latin-1")
    return str(body or "")


def _req(fetch, method, url, headers=None, body=None):
    try:
        st, hdrs, raw = fetch(method, url, headers=headers, body=body)
        return st, hdrs or {}, _text(raw)
    except Exception:
        return None


def _candidate_paths(path_info, max_paths):
    paths = []
    info = path_info if isinstance(path_info, dict) else {}
    for p in info.get("paths") or []:
        p = str(p)
        if p and RESET_PATH_RE.search(p) and p not in paths:
            paths.append(p)
    for p in RESET_PATH_DEFAULTS:
        if p not in paths:
            paths.append(p)
    return paths[:max_paths]


def _post_accepted(status):
    # Only endpoints that accepted POST are probed further.
    return status is not None and status not in (404, 405, 501) \
        and status < 500


def run_resetpoison(base_url, fetch=default_fetch, path_info=None,
                    gate=False, max_paths=6, budget=60):
    """Host-header injection / reset poisoning checks. Returns a list
    of Finding dicts; never raises."""
    out = []
    base = base_url if "://" in base_url else "http://" + base_url
    base = base.rstrip("/")
    sent = 0
    probe_body = "email=%s&submit=1" % PROBE_EMAIL
    form_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    variants = (
        ("Host", INJECT_HOST),
        ("X-Forwarded-Host", INJECT_HOST),
    )
    try:
        for path in _candidate_paths(path_info, max_paths):
            if sent >= budget or len(out) >= 6:
                break
            url = base + path
            baseline = _req(fetch, "GET", url)
            sent += 1
            if baseline is None:
                continue

            # LOW candidate: reset token already in URL/referrer pattern.
            low_evidence = TOKEN_URL_RE.search(baseline[2]) \
                or TOKEN_URL_RE.search(str(baseline[1].get("Location", "")))
            if low_evidence:
                out.append(Finding(
                    title="Password reset token exposed in URL/referrer "
                          "pattern at %s" % path,
                    severity="low", verification="candidate",
                    verification_note=(
                        "A reset-token-like value appears in a URL/"
                        "Location/referrer context on %s. Tokens in URLs "
                        "leak via Referer headers and browser history; "
                        "manual confirm required. Candidate only." % path),
                    manual_check="curl -sS -i %s" % url,
                    location=url, evidence=str(low_evidence.group(0)),
                    source="omega-resetpoison", confidence="medium"))

            # Baseline benign POST decides whether the endpoint accepts
            # POST at all; anything else is skipped.
            post0 = _req(fetch, "POST", url, headers=form_headers,
                         body=probe_body)
            sent += 1
            if post0 is None or not _post_accepted(post0[0]):
                continue

            for hdr, val in variants:
                if sent >= budget:
                    break
                res = _req(fetch, "POST", url,
                           headers=dict(form_headers, **{hdr: val}),
                           body=probe_body)
                sent += 1
                if res is None:
                    continue
                hit = LINK_CONTEXT_RE.search(res[2]) \
                    and RESET_CONTEXT_RE.search(res[2])
                if not hit and sent < budget:
                    # follow-up fetch (cached-link emulation)
                    follow = _req(fetch, "GET", url)
                    sent += 1
                    if follow:
                        hit = LINK_CONTEXT_RE.search(follow[2]) \
                            and RESET_CONTEXT_RE.search(follow[2])
                        res = follow or res
                if hit:
                    out.append(Finding(
                        title="Password reset poisoning via %s header on "
                              "%s" % (hdr, path),
                        severity="high", verification="candidate",
                        verification_note=(
                            "The injected host %s appears in a reset-"
                            "link context after sending %s: %s with a "
                            "benign probe email. Host-header injection "
                            "into reset emails enables account takeover; "
                            "manual confirm required. Candidate only."
                            % (INJECT_HOST, hdr, INJECT_HOST)),
                        manual_check="curl -sS -i -X POST -H '%s: %s' "
                                     "-d 'email=x@example.com' %s"
                                     % (hdr, val, url),
                        location=url,
                        evidence=res[2][:300],
                        source="omega-resetpoison", confidence="medium"))
    except Exception:
        pass
    return out
