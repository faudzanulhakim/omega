"""omega/scanning/secops.py — low-severity security-hygiene bundle
(fusion suite name: ``secops-hygiene``).

Three read-only checks:

  (a) /.well-known/security.txt presence + validity: missing on a
      production target -> LOW INFO; present but malformed (no
      Contact or Expires field) -> LOW candidate.
  (b) robots.txt interesting Disallow paths: parsed and surfaced as
      INFO recon hints (they point at unlinked admin/api areas).
  (c) HTML forms with password/otp/card inputs that carry
      autocomplete="on" (or no autocomplete restriction where the
      input is a one-time code) -> MEDIUM candidate per OWASP
      ASVS 2.1.1/9.1.

(d) verbose error disclosure is intentionally NOT covered here —
    omega.anomaly owns that differential.

All GET-only, non-destructive; findings are candidate/info only
(honesty contract: hygiene signals, not exploits).
"""

from __future__ import annotations

import re
import secrets

__all__ = [
    "Finding",
    "REQUIRED_SEC_TXT_FIELDS",
    "INTERESTING_DISALLOWS",
    "SENSITIVE_INPUT_RE",
    "parse_robots",
    "security_txt_check",
    "robots_interesting_paths",
    "autocomplete_scan",
    "run_secops",
]

REQUIRED_SEC_TXT_FIELDS = ("contact", "expires")
INTERESTING_DISALLOWS = (
    "admin", "api", "backup", "config", "debug", "internal", "private",
    "secret", "test", "staging", "panel", "dashboard", "phpmyadmin",
    "jenkins", "actuator", "console",
)
SENSITIVE_INPUT_RE = re.compile(
    r"<input\b[^>]*>", re.I)
_TYPE_RE = re.compile(r"""type\s*=\s*["']?([\w-]+)""", re.I)
_AUTOCOMPLETE_RE = re.compile(
    r"""autocomplete\s*=\s*["']?([\w-]+)""", re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.I | re.S)
_FORM_ACTION_RE = re.compile(r"""action\s*=\s*["']?([^"'\s>]+)""", re.I)


class Finding(dict):
    """ENGINE-convention finding dict (info/candidate only)."""

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


def _get(fetch, url):
    """Contained GET: returns (status, text) or (None, '') on error."""
    try:
        st, _h, body = fetch("GET", url)
        return st, _text(body)
    except Exception:
        return None, ""


# ------------------------------------------------------------ security.txt

def security_txt_check(base_url, fetch, require_on_production=True):
    """/.well-known/security.txt presence + validity. Returns a list
    with 0 or 1 finding. Missing -> low INFO (counsel note); malformed
    -> low candidate. Never raises."""
    url = base_url.rstrip("/") + "/.well-known/security.txt"
    st, body = _get(fetch, url)
    if st is None:
        return []
    if st == 200 and body.strip():
        lower = body.lower()
        missing = [f for f in REQUIRED_SEC_TXT_FIELDS
                   if not re.search(r"^\s*%s\s*:" % f, lower, re.M)]
        if missing:
            return [Finding(
                title="security.txt is present but malformed (missing: %s)"
                      % ", ".join(missing),
                severity="low", verification="candidate",
                verification_note=(
                    "/.well-known/security.txt returned 200 but lacks the "
                    "required field(s) %s (RFC 9116). A malformed "
                    "security policy can misroute vulnerability reports. "
                    "Candidate only." % ", ".join(missing)),
                manual_check="curl -sS %s" % url,
                location=url, evidence=body[:300],
                source="omega-secops/security_txt", confidence="medium")]
        return []  # present and valid — no finding
    return [Finding(
        title="No /.well-known/security.txt (RFC 9116)",
        severity="low", verification="candidate",
        verification_note=(
            "The target does not publish /.well-known/security.txt "
            "(status %s). Recommended (not mandatory) for production "
            "hosts so researchers can find a reporting channel. INFO-"
            "grade hygiene; fix is a static text file." % st),
        manual_check="curl -sS %s" % url,
        location=url, evidence="status=%s" % st,
        source="omega-secops/security_txt", confidence="high")]


# ------------------------------------------------------------- robots.txt

def parse_robots(body):
    """Parse Disallow paths from robots.txt text."""
    out = []
    for line in body.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            val = line.split(":", 1)[1].strip()
            if val and val != "/":
                out.append(val)
    return out


def robots_interesting_paths(base_url, fetch):
    """INFO recon hints from robots.txt Disallow entries that look
    interesting (admin/api/backup/...). 0-1 findings."""
    url = base_url.rstrip("/") + "/robots.txt"
    st, body = _get(fetch, url)
    if st != 200 or not body.strip():
        return []
    disallows = parse_robots(body)
    interesting = [p for p in disallows
                   if any(k in p.lower() for k in INTERESTING_DISALLOWS)]
    if not interesting:
        return []
    return [Finding(
        title="robots.txt discloses %d interesting disallow path(s)"
              % len(interesting),
        severity="info", verification="candidate",
        verification_note=(
            "robots.txt Disallow entries point at unlinked areas "
            "(%s). Not a vulnerability by itself — robots.txt is "
            "public — but these paths are valuable recon input and "
            "were fed back into the enumeration pool." %
            ", ".join(interesting[:5])),
        manual_check="curl -sS %s" % url,
        location=url, evidence="disallow=%s" % ",".join(interesting[:10]),
        source="omega-secops/robots", confidence="high")]


# ----------------------------------------------------- autocomplete=on

def _sensitive_input(input_tag):
    """Password/OTP/card inputs only (OWASP ASVS 2.1.1 scope)."""
    t = _TYPE_RE.search(input_tag)
    typ = t.group(1).lower() if t else ""
    if typ in ("password", "tel"):
        return typ
    nm = re.search(r"""name\s*=\s*["']([^"']+)["']""", input_tag, re.I)
    if nm and re.search(r"card|cvv|csc|cvc|otp|one[-_]?time",
                        nm.group(1), re.I):
        return typ or "text"
    return None


def autocomplete_scan(base_url, fetch, paths=None):
    """MEDIUM candidate per OWASP when password/one-time-code inputs
    allow autocomplete. Returns deduplicated findings list."""
    out, seen = [], set()
    for page in (paths if paths is not None else
                 ("", "/login", "/signin", "/signup", "/account")):
        url = base_url.rstrip("/") + "/" + page.lstrip("/")
        st, html = _get(fetch, url)
        if st != 200 or not html:
            continue
        for form in _FORM_RE.findall(html):
            action = _FORM_ACTION_RE.search(form)
            loc = base_url.rstrip("/") + "/" + \
                (action.group(1) if action else page).lstrip("/")
            for tag in SENSITIVE_INPUT_RE.findall(form):
                typ = _sensitive_input(tag)
                if typ is None:
                    continue
                ac = _AUTOCOMPLETE_RE.search(tag)
                val = ac.group(1).lower() if ac else None
                key = (loc, typ, val)
                if val == "on":
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(Finding(
                        title='Sensitive input (type="%s") allows '
                              'autocomplete="on" at %s' % (typ, loc),
                        severity="medium", verification="candidate",
                        verification_note=(
                            'A sensitive input field carries '
                            'autocomplete="on", so browsers may store '
                            'the value in the profile/autofill store '
                            '(OWASP ASVS 2.1.1: passwords and one-time '
                            'codes must disable autocomplete). '
                            'Candidate only — automated flag; confirm '
                            'the input is genuinely sensitive.'),
                        manual_check='view-source:%s' % loc,
                        location=loc, evidence=tag[:300],
                        source="omega-secops/autocomplete",
                        confidence="medium"))
                elif val in ("one-time-code",) or typ == "password" \
                        and val in ("cc-csc", "cc-number"):
                    out.append(Finding(
                        title='One-time-code input misuses autocomplete '
                              'value "%s" at %s' % (val, loc),
                        severity="medium", verification="candidate",
                        verification_note=(
                            'A sensitive input uses autocomplete="%s" — '
                            'check whether this is a genuine one-time-'
                            'code field (allowed) or a mislabeled '
                            'password/OTP field (OWASP ASVS 2.1.1). '
                            'Candidate only.' % val),
                        manual_check='view-source:%s' % loc,
                        location=loc, evidence=tag[:300],
                        source="omega-secops/autocomplete",
                        confidence="medium"))
    return out


# -------------------------------------------------------------- runner

def run_secops(target, fetch, budget=20, log=None, allowlist=None):
    """Run the hygiene bundle. Never raises; per-check errors become
    skipped entries. Returns {findings, skipped, ran, requests_sent}."""
    from omega.probes import allowlist_ok

    result = {"findings": [], "skipped": {}, "ran": [],
              "requests_sent": 0}
    base_url = target if "://" in target else "http://" + target
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = \
            "target %r not in allowlist" % target
        if log:
            log("secops skipped: target not in allowlist: %r" % target)
        return result

    sent = 0

    def counted(method, url, headers=None, body=None):
        nonlocal sent
        sent += 1
        return fetch(method, url, headers=headers, body=body)

    checks = (
        ("security_txt", lambda: security_txt_check(base_url, counted)),
        ("robots", lambda: robots_interesting_paths(base_url, counted)),
        ("autocomplete", lambda: autocomplete_scan(base_url, counted)),
    )
    for name, check in checks:
        if sent >= budget:
            result["skipped"][name] = "budget exhausted"
            continue
        try:
            found = check()
        except Exception as exc:
            result["skipped"][name] = "%s: %s" % (type(exc).__name__, exc)
            continue
        result["ran"].append(name)
        result["findings"].extend(found)

    result["requests_sent"] = sent
    if log:
        log("secops: %d check(s) ran, %d finding(s)"
            % (len(result["ran"]), len(result["findings"])))
    return result
