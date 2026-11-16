"""omega/scanning/csrf.py — CSRF protection analysis (fusion suite
name: ``csrf``).

For each form-bearing path from ``path_info`` plus common ones
(``/login``, ``/register``, ``/settings``, ``/profile``):

- GET the page and parse ``<form>`` tags (action, method, inputs);
- state-changing form (method=POST, action not login/logout) with NO
  csrf token field (hidden input named csrf|token|_token|authenticity)
  and no anti-CSRF cookie pattern -> MEDIUM candidate;
- session cookie without a ``SameSite`` attribute -> LOW candidate note
  (cookie info reused from path_info when present);
- cross-origin form-action check: POST the parsed form fields minus
  token fields with ``Origin: https://evil.example`` and an appended
  benign marker value, compared against a same-origin baseline POST;
  HIGH candidate ONLY when the response is 200 AND the body differs
  from the baseline (indicates a state change).

Every finding is routed through ``claimcheck.validate_claim`` (fetch
based) so only verified claims survive. Benign: never submits
destructive values — the marker value is appended to one existing
field only. Never raises; budget-capped.
"""

from __future__ import annotations

import re
import secrets

from omega.scanning.claimcheck import validate_claim
from omega.scanning.deepchecks import Finding, default_fetch

__all__ = [
    "REQUEST_BUDGET",
    "COMMON_FORM_PATHS",
    "MARKER",
    "TOKEN_NAME_RE",
    "extract_forms",
    "parse_cookies",
    "run_csrf",
]

REQUEST_BUDGET = 30

COMMON_FORM_PATHS = ("/login", "/register", "/settings", "/profile")

MARKER = "omegacsrf" + secrets.token_hex(4)

TOKEN_NAME_RE = re.compile(r"csrf|token|_token|authenticity", re.I)
SAMESITE_RE = re.compile(r"samesite", re.I)
SESSION_COOKIE_RE = re.compile(r"^(sess|session|sid|sessionid|jsessionid"
                               r"|phpsessid|auth)", re.I)
NON_STATE_ACTION_RE = re.compile(r"login|logout|signin|signout|search"
                                 r"|/search", re.I)

FORM_RE = re.compile(r"<form\b[^>]*>", re.I)
ATTR_RE = re.compile(
    r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|\'([^\']*)\')')
INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)


def _text(body):
    if isinstance(body, bytes):
        return body.decode("latin-1", "replace")
    return str(body or "")


def _attrs(tag):
    out = {}
    for m in ATTR_RE.finditer(tag):
        out[m.group(1).lower()] = m.group(3) or m.group(4) or ""
    # bare attributes (e.g. method=post without quotes are still matched
    # by ATTR_RE when unquoted is absent; handle unquoted values too)
    for m in re.finditer(r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)=([^\s"\'<>]+)',
                         tag):
        out.setdefault(m.group(1).lower(), m.group(2))
    return out


def extract_forms(html):
    """Parse <form> tags: list of dicts {action, method, raw, has_token,
    fields:[names]} — pure regex, never raises."""
    forms = []
    try:
        for m in FORM_RE.finditer(html or ""):
            tag = m.group(0)
            a = _attrs(tag)
            end = html.find("</form", m.end())
            body_html = html[m.end(): end if end != -1 else m.end() + 2000]
            fields = []
            has_token = False
            for im in INPUT_RE.finditer(body_html):
                ia = _attrs(im.group(0))
                name = ia.get("name") or ""
                if name:
                    fields.append(name)
                if (ia.get("type") or "").lower() == "hidden" \
                        and TOKEN_NAME_RE.search(name):
                    has_token = True
            forms.append({
                "action": a.get("action") or "",
                "method": (a.get("method") or "get").lower(),
                "raw": tag,
                "has_token": has_token,
                "fields": fields,
            })
    except Exception:
        return forms
    return forms


def parse_cookies(headers):
    """Session-ish cookie names + whether ANY Set-Cookie carries
    SameSite. Returns list of (name, has_samesite) tuples."""
    out = []
    raw = headers.get("Set-Cookie") or ""
    try:
        for part in raw.split(","):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name = part.split("=", 1)[0].strip()
            out.append((name, bool(SAMESITE_RE.search(part))))
    except Exception:
        return out
    return out


def _path_info_cookies(path_info):
    """Cookie hints from path_info: {'cookies': {'sess': {'samesite':
    True}}} — best effort."""
    info = path_info or {}
    out = {}
    try:
        cookies = info.get("cookies")
        if isinstance(cookies, dict):
            for name, val in cookies.items():
                samesite = False
                if isinstance(val, dict):
                    samesite = bool(val.get("samesite"))
                elif isinstance(val, str):
                    samesite = bool(SAMESITE_RE.search(val))
                out[str(name)] = samesite
    except Exception:
        return {}
    return out


def _validated(findings, base_url, fetch):
    """Route candidate findings through claimcheck.validate_claim; keep
    only claims that verify against the live target. Never raises."""
    kept = []
    for f in findings:
        try:
            res = validate_claim(dict(f), fetch=fetch, base_url=base_url)
        except Exception:
            continue
        if res.get("validation") == "verified":
            f["verification_note"] = (
                str(f.get("verification_note") or "")
                + " [claim gate: verified]")
            kept.append(f)
    return kept


def run_csrf(base_url, fetch=default_fetch, path_info=None, gate=False):
    """CSRF protection analysis suite. Returns a list of Finding dicts;
    never raises; budget-capped; all findings claim-gate validated."""
    findings = []
    base = (base_url or "").rstrip("/")
    if not base:
        return findings
    info = path_info or {}
    budget = REQUEST_BUDGET

    paths = [p for p in (info.get("paths") or [])
             if isinstance(p, str) and p.startswith("/")]
    for cp in COMMON_FORM_PATHS:
        if cp not in paths:
            paths.append(cp)
    paths = paths[:8]

    cookie_hints = _path_info_cookies(path_info)
    cross_origin_candidates = []

    for path in paths:
        if budget <= 0:
            break
        url = base + path
        try:
            st, headers, body = fetch("GET", url)
        except Exception:
            continue
        budget -= 1
        if not (200 <= (st or 0) < 300):
            continue
        html = _text(body)
        forms = extract_forms(html)

        for f in forms:
            if f["method"] != "post" or not f["action"]:
                continue
            if NON_STATE_ACTION_RE.search(f["action"]):
                continue
            if f["has_token"]:
                continue
            # no anti-CSRF cookie pattern either?
            anti_cookie = any(
                samesite for name, samesite in
                parse_cookies(headers)) or cookie_hints.get(
                "sess", None) or cookie_hints.get("session", None)
            if anti_cookie:
                continue
            findings.append(Finding(
                title="State-changing form without CSRF token at %s"
                      % path,
                severity="medium", verification="candidate",
                verification_note=(
                    "Form posting to '%s' carries no hidden CSRF token "
                    "field (csrf|token|_token|authenticity) and no "
                    "anti-CSRF cookie pattern was observed. Candidate "
                    "only; confirm exploitability manually." % f["action"]),
                manual_check=(
                    "Review the form at %s and attempt a cross-site "
                    "POST with a fresh session." % url),
                location=url,
                evidence=f["raw"][:300],
                source="omega-csrf/missing_token"))
            cross_origin_candidates.append((path, f))
            break  # one tokenless form per page is enough

        # SameSite attribute absent on session cookie (note)
        for name, samesite in parse_cookies(headers):
            if samesite or not SESSION_COOKIE_RE.match(name):
                continue
            findings.append(Finding(
                title="Session cookie without SameSite attribute (%s)"
                      % name,
                severity="low", verification="candidate",
                verification_note=(
                    "Set-Cookie for '%s' carries no SameSite attribute; "
                    "combined with a tokenless state-changing form this "
                    "raises cross-site request risk. Candidate note "
                    "only." % name),
                manual_check=(
                    "curl -sS -i %s | grep -i set-cookie" % url),
                location=url,
                evidence={"cookie_name": name[:5]},
                source="omega-csrf/samesite_missing"))

    # Cross-origin form-action check (capped to 2 probes)
    for path, form in cross_origin_candidates[:2]:
        if budget <= 0:
            break
        url = base + path
        fields = [n for n in form["fields"]
                  if not TOKEN_NAME_RE.search(n)][:8]
        body_pairs = ["%s=%s" % (n, "probe") for n in fields]
        if not body_pairs:
            body_pairs = ["probe=1"]
        # benign: append the marker value to the first field only
        body_pairs[0] = body_pairs[0] + MARKER
        post_body = "&".join(body_pairs)
        try:
            st_base, _h, b_base = fetch("POST", url, body=post_body)
            st_evil, _h2, b_evil = fetch(
                "POST", url, headers={"Origin": "https://evil.example",
                                      "Content-Type":
                                          "application/x-www-form-urlencoded"},
                body=post_body)
        except Exception:
            continue
        budget -= 2
        if st_evil != 200 or st_base != 200:
            continue
        if _text(b_evil) == _text(b_base):
            continue  # no state-change signal
        findings.append(Finding(
            title="Cross-origin form action accepted state change at %s"
                  % path,
            severity="high", verification="candidate",
            verification_note=(
                "POSTing the form fields with Origin: "
                "https://evil.example returned 200 with a body "
                "differing from the same-origin baseline — the action "
                "appears to accept cross-origin state changes. Marker "
                "'%s' appended benignly; HIGH candidate, confirm "
                "manually." % MARKER),
            manual_check=(
                "Replay the cross-origin POST from a real browser "
                "context at %s" % url),
            location=url,
            evidence={"origin_probe": True},
            source="omega-csrf/cross_origin_post"))

    return _validated(findings, base, fetch)
