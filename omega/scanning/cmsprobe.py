"""omega/scanning/cmsprobe.py — CMS fingerprint and known-exposure
probe (fusion suite name: ``cmsprobe``).

Fingerprints WordPress, Drupal and Joomla via benign GET-only markers
and reports known CMS exposure surfaces:

  WordPress:
    - /wp-login.php present                     -> detection (medium)
    - /wp-json/wp/v2/users returning a JSON
      user list                                 -> HIGH candidate
      (username enumeration)
    - /xmlrpc.php responding ok                 -> medium
    - /wp-content/uploads directory listing     -> medium
  Drupal:
    - /user/login, /core/install.php            -> detection (medium)
    - /CHANGELOG.txt                            -> version disclosure (low)
  Joomla:
    - /administrator/, /language/en-GB/en-GB.xml -> detection (medium)
  Generic:
    - /readme.html, /LICENSE.txt version disclosures -> low

All GET-only, non-destructive, benign markers only. Never raises.
"""

from __future__ import annotations

import json
import re

__all__ = [
    "Finding",
    "CMS_PROBES",
    "run_cmsprobe",
]

from omega.scanning.deepchecks import default_fetch

CMS_PROBES = (
    ("wp-login", "/wp-login.php", "wordpress", "medium"),
    ("wp-users", "/wp-json/wp/v2/users", "wordpress", "high"),
    ("wp-xmlrpc", "/xmlrpc.php", "wordpress", "medium"),
    ("wp-uploads", "/wp-content/uploads/", "wordpress", "medium"),
    ("drupal-login", "/user/login", "drupal", "medium"),
    ("drupal-install", "/core/install.php", "drupal", "medium"),
    ("drupal-changelog", "/CHANGELOG.txt", "drupal", "low"),
    ("joomla-admin", "/administrator/", "joomla", "medium"),
    ("joomla-lang", "/language/en-GB/en-GB.xml", "joomla", "medium"),
    ("readme", "/readme.html", "generic", "low"),
    ("license", "/LICENSE.txt", "generic", "low"),
)

LISTING_RE = re.compile(
    r"index of /|directory listing for|<title>directory listing</title>",
    re.I)
VERSION_RE = re.compile(r"\b\d+\.\d+(\.\d+)?[a-z0-9.-]*\b")


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


def _get(fetch, url):
    """Contained GET -> (status, headers, text) or (None, {}, '');
    never raises."""
    try:
        st, hdrs, raw = fetch("GET", url)
        return st, hdrs or {}, _text(raw)
    except Exception:
        return None, {}, ""


def _json_user_list(st, body, ctype):
    """True when /wp-json/wp/v2/users actually returned a JSON array
    of user objects (not an error/rest_no_route body)."""
    if st != 200:
        return False
    try:
        data = json.loads(body)
    except Exception:
        return False
    if isinstance(data, list) and data and isinstance(data[0], dict):
        keys = {k.lower() for k in data[0]}
        return bool(keys & {"id", "name", "slug"}) and \
            "slug" in keys or "name" in keys
    return False


def _detect_detail(name, path, st, body):
    """Plausible-content check per probe marker."""
    if st != 200 or not body.strip():
        return False
    if name == "wp-login":
        return "wp-admin" in body or "wordpress" in body.lower() \
            or "user_login" in body
    if name == "wp-xmlrpc":
        low = body.lower()
        return "xml-rpc" in low or "xmlrpc" in low
    if name == "wp-uploads":
        return bool(LISTING_RE.search(body))
    if name == "drupal-login":
        return "drupal" in body.lower() or "user_login" in body \
            or "name=\"pass\"" in body
    if name == "drupal-install":
        return "drupal" in body.lower() or "install" in body.lower()
    if name == "drupal-changelog":
        return "drupal" in body.lower()
    if name == "joomla-admin":
        return "joomla" in body.lower() or "administrator" in body.lower() \
            or "mod_login" in body
    if name == "joomla-lang":
        return "<meta" in body or "joomla" in body.lower() \
            or "<?xml" in body
    if name == "readme":
        return "readme" in body.lower() and VERSION_RE.search(body)
    if name == "license":
        return "license" in body.lower() or "gnu" in body.lower()
    return True


def run_cmsprobe(base_url, fetch=default_fetch, path_info=None,
                 gate=False, budget=12):
    """CMS fingerprint + known-exposure probe. Returns a list of
    Finding dicts; never raises. ``path_info``/``gate`` accepted for
    suite-signature symmetry."""
    out = []
    base = base_url if "://" in base_url else "http://" + base_url
    base = base.rstrip("/")
    sent = 0
    try:
        for name, path, cms, sev in CMS_PROBES:
            if sent >= budget:
                break
            url = base + path
            st, hdrs, body = _get(fetch, url)
            sent += 1
            if st is None:
                continue
            if name == "wp-users":
                if _json_user_list(st, body, hdrs.get("Content-Type")):
                    out.append(Finding(
                        title="WordPress user enumeration via REST API "
                              "(wp/v2/users)",
                        severity="high", verification="candidate",
                        verification_note=(
                            "/wp-json/wp/v2/users returned a JSON list of "
                            "user objects without authentication, exposing "
                            "valid usernames to unauthenticated callers. "
                            "Candidate only — confirm the users are real "
                            "and not a fixture."),
                        manual_check="curl -sS %s" % url,
                        location=url, evidence=body[:200],
                        source="omega-cmsprobe", confidence="high"))
                continue
            if _detect_detail(name, path, st, body):
                if name in ("readme", "license", "drupal-changelog"):
                    ver = VERSION_RE.search(body)
                    note = ("Version disclosure via %s (status 200)%s. "
                            "Public version metadata helps attackers pick "
                            "targeted CVEs. Low-severity, candidate only."
                            % (path, " — version-like token %r found"
                               % ver.group(0) if ver else ""))
                elif name == "wp-uploads":
                    note = ("/wp-content/uploads/ returns a directory "
                            "listing, exposing uploaded file names. "
                            "Candidate only.")
                else:
                    note = ("Content at %s matches the %s fingerprint "
                            "marker for %s (status %s). CMS detection is "
                            "informational context for the report; "
                            "candidate only." % (path, name, cms, st))
                out.append(Finding(
                    title="%s fingerprint marker: %s (%s)" % (cms, name,
                                                              path),
                    severity=sev, verification="candidate",
                    verification_note=note,
                    manual_check="curl -sS %s" % url,
                    location=url, evidence=body[:200],
                    source="omega-cmsprobe", confidence="medium"))
    except Exception:
        pass
    return out
