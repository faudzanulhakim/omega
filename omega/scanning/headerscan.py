"""omega/headerscan.py — DEEP RESPONSE-HEADER AUDIT: 11 checks over the
response headers only (plus tiny differentials for CORS reflection).

Python-only, non-destructive, evidence-level. Requests used: GET /
OPTIONS (with the documented CORS preflight headers), and a small set
of GETs to sensitive-looking paths for the Cache-Control check. Every
CORS assertion is differential-first: this module sends ITS OWN Origin
and only reacts to the echo. All findings are ``candidate`` — this
module never claims ``confirmed``; verification is evidence-level.

Honest severity rules:
- HSTS is meaningless over plain http:// — the check records a skip
  (``hsts_absent_https``: 'n/a: target is not https') instead of a
  finding when the target scheme is not https.

Finding shape matches the ENGINE convention (plain dict):
title / severity / confidence / verification / verification_note /
manual_check (real curl command against the REAL target) / location /
evidence (string, <= 300 chars) / source=omega-headerscan/<name>.

``run_headerscan(target, fetch, budget=30, log=None)`` never raises;
per-check errors become entries in ``skipped``; returns
{findings, skipped, requests_sent, ran}.
"""

from __future__ import annotations

import secrets

__all__ = [
    "Finding",
    "cache_control_sensitive",
    "clickjacking",
    "cookie_flags",
    "cors_credentials_echo",
    "cors_preflight_reflection",
    "csp_policy_audit",
    "hsts_absent_https",
    "permissions_policy_missing",
    "powered_by_banner",
    "referrerpolicy_missing",
    "registry",
    "run_headerscan",
    "xxss_protection_legacy",
]

SENSITIVE_PATHS = ["/login", "/account", "/admin"]


class Finding(dict):
    """ENGINE-convention finding dict (evidence-level, candidate-only)."""

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


# ---------------------------------------------------------------- helpers

def _lower(headers):
    return {str(k).lower(): v for k, v in (headers or {}).items()}


def _ev(parts):
    if isinstance(parts, str):
        return parts[:300]
    return " ".join("%s=%s" % (k, v) for k, v in parts.items())[:300]


def _cookies(set_cookie_value):
    """Split a (possibly comma-joined) Set-Cookie value into pairs."""
    import re
    out = []
    for chunk in re.split(r",(?=\s*[^;,=\s]+=[^;,]*)",
                          set_cookie_value or ""):
        chunk = chunk.strip()
        if "=" in chunk:
            name = chunk.split("=", 1)[0].strip()
            toks = [t.strip() for t in chunk.lower().split(";")]
            out.append((name, {
                "secure": "secure" in toks,
                "httponly": "httponly" in toks,
                "samesite": any(t.startswith("samesite") for t in toks),
            }))
    return out


# ----------------------------------------------------------------- checks

def clickjacking(base_url, fetch):
    """Missing/deny X-Frame-Options AND no CSP frame-ancestors — LOW
    candidate (the page may be framed)."""
    st, headers, _b = fetch("GET", base_url.rstrip("/") + "/")
    low = _lower(headers)
    xfo = (low.get("x-frame-options") or "").strip().lower()
    csp = (low.get("content-security-policy") or "")
    xfo_ok = xfo in ("deny", "sameorigin")
    csp_ok = "frame-ancestors" in csp.lower()
    if xfo_ok or csp_ok:
        return []
    return [Finding(
        title="Clickjacking exposure: no framing protection on baseline "
              "response",
        severity="low",
        verification_note=(
            "The baseline response carries neither a deny/sameorigin "
            "X-Frame-Options nor a CSP frame-ancestors directive — the "
            "page may be embedded in attacker frames. Exploitability "
            "depends on the page's actions; manual verification required."),
        manual_check='curl -sS -i "%s/"' % base_url.rstrip("/"),
        location=base_url.rstrip("/") + "/",
        evidence=_ev({"status": st, "xfo": xfo or "missing",
                      "csp_frame_ancestors": bool(csp_ok)}),
        source="omega-headerscan/clickjacking")]


def hsts_absent_https(base_url, fetch):
    """HSTS absent on an https target — LOW candidate. On http:// this
    check is skipped by run_headerscan (n/a), never a finding."""
    st, headers, _b = fetch("GET", base_url.rstrip("/") + "/")
    low = _lower(headers)
    if low.get("strict-transport-security"):
        return []
    return [Finding(
        title="Strict-Transport-Security header absent (https target)",
        severity="low",
        verification_note=(
            "The https baseline response carries no Strict-Transport-"
            "Security header — browsers will not enforce TLS-only "
            "connections; SSL-stripping remains possible on subsequent "
            "visits."),
        manual_check='curl -sS -i "%s/"' % base_url.rstrip("/"),
        location=base_url.rstrip("/") + "/",
        evidence=_ev({"status": st, "hsts": "missing"}),
        source="omega-headerscan/hsts_absent_https")]


def csp_policy_audit(base_url, fetch):
    """CSP absent entirely, or present but allowing unsafe-inline/
    unsafe-eval — LOW candidate."""
    st, headers, _b = fetch("GET", base_url.rstrip("/") + "/")
    low = _lower(headers)
    csp = (low.get("content-security-policy") or "").strip()
    if not csp:
        return [Finding(
            title="Content-Security-Policy header absent",
            severity="low",
            verification_note=(
                "The baseline response carries no Content-Security-Policy "
                "header — no browser-side mitigation against injected "
                "script execution."),
            manual_check='curl -sS -i "%s/"' % base_url.rstrip("/"),
            location=base_url.rstrip("/") + "/",
            evidence=_ev({"status": st, "csp": "missing"}),
            source="omega-headerscan/csp_policy_audit")]
    low_csp = csp.lower()
    unsafe = [d for d in ("unsafe-inline", "unsafe-eval") if d in low_csp]
    if unsafe:
        return [Finding(
            title="CSP weakened by %s" % " and ".join(unsafe),
            severity="low",
            verification_note=(
                "The Content-Security-Policy allows %s, which largely "
                "defeats inline-script/eval mitigations. Impact depends "
                "on the site's injection surface; candidate only."
                % " and ".join(unsafe)),
            manual_check='curl -sS -i "%s/"' % base_url.rstrip("/"),
            location=base_url.rstrip("/") + "/",
            evidence=_ev({"status": st, "unsafe_directives": unsafe,
                          "csp": csp[:120]}),
            source="omega-headerscan/csp_policy_audit")]
    return []


def referrerpolicy_missing(base_url, fetch):
    """Referrer-Policy header missing on the baseline response — LOW."""
    st, headers, _b = fetch("GET", base_url.rstrip("/") + "/")
    low = _lower(headers)
    if low.get("referrer-policy"):
        return []
    return [Finding(
        title="Referrer-Policy header absent",
        severity="low",
        verification_note=(
            "The baseline response carries no Referrer-Policy header — "
            "full URLs (including query strings, possibly tokens) may "
            "leak to third-party sites via the Referer header."),
        manual_check='curl -sS -i "%s/"' % base_url.rstrip("/"),
        location=base_url.rstrip("/") + "/",
        evidence=_ev({"status": st, "referrer_policy": "missing"}),
        source="omega-headerscan/referrerpolicy_missing")]


def permissions_policy_missing(base_url, fetch):
    """Permissions-Policy header missing on the baseline response —
    INFO fingerprint-grade note."""
    st, headers, _b = fetch("GET", base_url.rstrip("/") + "/")
    low = _lower(headers)
    if low.get("permissions-policy") or low.get("feature-policy"):
        return []
    return [Finding(
        title="Permissions-Policy header absent",
        severity="info",
        verification_note=(
            "The baseline response carries no Permissions-Policy (or "
            "legacy Feature-Policy) header — powerful browser features "
            "(camera, geolocation, ...) are not explicitly restricted."),
        manual_check='curl -sS -i "%s/"' % base_url.rstrip("/"),
        location=base_url.rstrip("/") + "/",
        evidence=_ev({"status": st, "permissions_policy": "missing"}),
        source="omega-headerscan/permissions_policy_missing")]


def cache_control_sensitive(base_url, fetch):
    """Sensitive-looking paths (200 responses) without a no-store style
    Cache-Control — LOW candidate per path, differential: only 200s."""
    findings = []
    base = base_url.rstrip("/")
    for path in SENSITIVE_PATHS:
        st, headers, _b = fetch("GET", base + path)
        if st != 200:
            continue
        cc = (_lower(headers).get("cache-control") or "").strip().lower()
        if "no-store" in cc or "private" in cc:
            continue
        findings.append(Finding(
            title="Cache-Control missing/private-less on sensitive path %s"
                  % path,
            severity="low",
            verification_note=(
                "GET %s returns HTTP 200 with Cache-Control %r — shared "
                "caches may store the response. Whether truly sensitive "
                "content is cached requires manual (authenticated) "
                "verification." % (path, cc or "absent")),
            manual_check='curl -sS -i "%s%s"' % (base, path),
            location=base + path,
            evidence=_ev({"status": st, "cache_control": cc or "absent"}),
            source="omega-headerscan/cache_control_sensitive"))
    return findings


def xxss_protection_legacy(base_url, fetch):
    """X-XSS-Protection header present — INFO (legacy/deprecated)."""
    st, headers, _b = fetch("GET", base_url.rstrip("/") + "/")
    low = _lower(headers)
    raw = low.get("x-xss-protection")
    if not raw:
        return []
    return [Finding(
        title="Legacy X-XSS-Protection header present",
        severity="info",
        verification_note=(
            "The response carries X-XSS-Protection: %s — the auditor "
            "filter is deprecated and was removed from modern browsers; "
            "informational only." % raw),
        manual_check='curl -sS -i "%s/"' % base_url.rstrip("/"),
        location=base_url.rstrip("/") + "/",
        evidence=_ev({"status": st, "x_xss_protection": raw}),
        source="omega-headerscan/xxss_protection_legacy")]


def powered_by_banner(base_url, fetch):
    """X-Powered-By (or X-AspNet-Version) version disclosure — INFO."""
    st, headers, _b = fetch("GET", base_url.rstrip("/") + "/")
    low = _lower(headers)
    banners = {h: low[h] for h in ("x-powered-by", "x-aspnet-version")
               if low.get(h)}
    if not banners:
        return []
    return [Finding(
        title="Technology/version disclosed in X-Powered-By style headers",
        severity="info",
        verification_note=(
            "The baseline response discloses technology banners (%s) — "
            "fingerprint information for attackers." % ", ".join(banners)),
        manual_check='curl -sS -i "%s/"' % base_url.rstrip("/"),
        location=base_url.rstrip("/") + "/",
        evidence=_ev({"status": st, **{k: v[:40] for k, v in
                                       banners.items()}}),
        source="omega-headerscan/powered_by_banner")]


def cors_credentials_echo(base_url, fetch):
    """Send our own Origin; HIGH candidate only when ACAO echoes OUR
    arbitrary origin AND Access-Control-Allow-Credentials is true."""
    base = base_url.rstrip("/")
    origin = "https://omega-cors-%s.example" % secrets.token_hex(4)
    st, headers, _b = fetch("GET", base + "/",
                            headers={"Origin": origin})
    low = _lower(headers)
    acao = low.get("access-control-allow-origin")
    acac = low.get("access-control-allow-credentials")
    if acao != origin:
        return []
    if str(acac).lower() == "true":
        return [Finding(
            title="CORS: arbitrary origin echoed WITH credentials allowed",
            severity="high",
            verification_note=(
                "This module sent Origin: %s and the response echoes it "
                "in Access-Control-Allow-Origin together with "
                "Access-Control-Allow-Credentials: true — any origin can "
                "make credentialed cross-origin reads. Candidate; "
                "manual verification required." % origin),
            manual_check=('curl -sS -i -H "Origin: %s" "%s/"' % (origin,
                                                                 base)),
            location=base + "/",
            evidence=_ev({"status": st, "acao": origin,
                          "acac": str(acac)}),
            source="omega-headerscan/cors_credentials_echo",
            confidence="high")]
    return [Finding(
        title="CORS: arbitrary origin echoed without credentials",
        severity="low",
        verification_note=(
            "The response echoes an arbitrary attacker Origin in "
            "Access-Control-Allow-Origin but does not allow credentials "
            "— impact limited to reading public resources cross-origin."),
        manual_check='curl -sS -i -H "Origin: %s" "%s/"' % (origin, base),
        location=base + "/",
        evidence=_ev({"status": st, "acao": origin,
                      "acac": str(acac) if acac else "absent"}),
        source="omega-headerscan/cors_credentials_echo")]


def cookie_flags(base_url, fetch):
    """Set-Cookie missing SameSite/Secure/HttpOnly — LOW per cookie."""
    st, headers, _b = fetch("GET", base_url.rstrip("/") + "/")
    raw = _lower(headers).get("set-cookie")
    if not raw:
        return []
    findings = []
    for name, flags in _cookies(raw):
        missing = [f for f in ("secure", "httponly", "samesite")
                   if not flags[f]]
        if not missing:
            continue
        findings.append(Finding(
            title="Cookie '%s' missing flags: %s" % (name,
                                                     ", ".join(missing)),
            severity="low",
            verification_note=(
                "The baseline response sets cookie '%s' without %s. "
                "Impact depends on the cookie's role; manual review "
                "required." % (name, ", ".join(missing))),
            manual_check='curl -sS -i "%s/"' % base_url.rstrip("/"),
            location=base_url.rstrip("/") + "/",
            evidence=_ev({"status": st, "cookie": name,
                          "missing": missing}),
            source="omega-headerscan/cookie_flags"))
    return findings


def cors_preflight_reflection(base_url, fetch):
    """OPTIONS preflight with Access-Control-Request-Method: DELETE —
    LOW candidate when the preflight echoes our arbitrary Origin."""
    base = base_url.rstrip("/")
    origin = "https://omega-pf-%s.example" % secrets.token_hex(4)
    st, headers, _b = fetch("OPTIONS", base + "/", headers={
        "Origin": origin,
        "Access-Control-Request-Method": "DELETE",
    })
    low = _lower(headers)
    acao = low.get("access-control-allow-origin")
    if acao == origin:
        return [Finding(
            title="CORS preflight reflects arbitrary origin (DELETE "
                  "requested)",
            severity="low",
            verification_note=(
                "An OPTIONS preflight carrying Origin: %s and "
                "Access-Control-Request-Method: DELETE was answered with "
                "an identical ACAO echo — arbitrary cross-origin method "
                "preflights are permitted. Candidate." % origin),
            manual_check=('curl -sS -i -X OPTIONS -H "Origin: %s" '
                          '-H "Access-Control-Request-Method: DELETE" '
                          '"%s/"' % (origin, base)),
            location=base + "/",
            evidence=_ev({"status": st, "acao": origin,
                          "requested_method": "DELETE"}),
            source="omega-headerscan/cors_preflight_reflection")]
    return []


# -------------------------------------------------------------- registry

# Ordered registry: name -> check callable. Requests: GET (baseline and
# the three sensitive paths) and one documented CORS preflight OPTIONS.
registry = [
    ("clickjacking", clickjacking),
    ("hsts_absent_https", hsts_absent_https),
    ("csp_policy_audit", csp_policy_audit),
    ("referrerpolicy_missing", referrerpolicy_missing),
    ("permissions_policy_missing", permissions_policy_missing),
    ("cache_control_sensitive", cache_control_sensitive),
    ("xxss_protection_legacy", xxss_protection_legacy),
    ("powered_by_banner", powered_by_banner),
    ("cors_credentials_echo", cors_credentials_echo),
    ("cookie_flags", cookie_flags),
    ("cors_preflight_reflection", cors_preflight_reflection),
]


class _BudgetExhausted(Exception):
    """Internal: raised when the per-run request budget is spent."""


class _CountingFetch:
    """Wraps an injected fetch with a strict request cap and a counter."""

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


def run_headerscan(target, fetch, budget=30, log=None):
    """Run all registered header-audit checks against ``target``.

    Never raises: every check error becomes a skip entry in
    ``skipped``; a spent budget skips the remaining checks. HSTS is
    skipped as 'n/a: target is not https' over plain http. Returns
    {findings, skipped, requests_sent, ran}.
    """
    result = {"findings": [], "skipped": {}, "requests_sent": 0, "ran": []}
    base_url = target if "://" in target else "https://" + target
    scheme = base_url.split("://", 1)[0].lower()
    fb = _CountingFetch(fetch, budget)
    exhausted = False
    for name, check in registry:
        if exhausted:
            result["skipped"][name] = "budget exhausted"
            continue
        if name == "hsts_absent_https" and scheme != "https":
            result["skipped"][name] = "n/a: target is not https"
            continue
        try:
            found = check(base_url, fb)
        except _BudgetExhausted:
            result["skipped"][name] = "budget exhausted"
            exhausted = True
            if log:
                log("headerscan %s: budget exhausted after %d requests"
                    % (name, fb.sent))
            continue
        except Exception as exc:  # never raise
            result["skipped"][name] = "error: %s" % exc
            if log:
                log("headerscan check %s failed: %s" % (name, exc))
            continue
        result["ran"].append(name)
        result["findings"].extend(found)
        if log:
            log("headerscan %s: %d finding(s)" % (name, len(found)))
    result["requests_sent"] = fb.sent
    return result
