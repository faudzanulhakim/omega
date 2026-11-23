"""omega/tfinger.py — technology fingerprint precision (pure Python).

Wappalyzer-style passive signals from response headers, cookies, HTML/JS
markers and meta generator tags. Produces a tech-stack summary with
confidence levels (high = exact banner match, medium = unambiguous
marker, low = generic hint), extracts versions where present, and
correlates parsed versions against the offline CVE pins in
omega/scanning/cvexref.py (read-only reuse — that module is NOT
modified).

``run_tfinger`` never raises; source=omega-tfinger/<name>.
"""

from __future__ import annotations

import re

__all__ = [
    "Finding",
    "SIGNALS",
    "extract_version",
    "fingerprint",
    "summarize_stack",
    "run_tfinger",
]

from omega.deepchecks import Finding
from omega.probes import default_fetch
from omega.scanning.cvexref import correlate

# ---------------------------------------------------------------------------
# Signal table. Each signal:
#   product     — canonical name
#   category    — server | framework | cms | js | analytics | build
#   header      — optional header name (matched case-insensitively)
#   header_re   — regex over that header's value (optional)
#   marker_re   — regex over the response body (HTML/JS markers)
#   cookie      — optional cookie name prefix
#   confidence  — high | medium | low
# ---------------------------------------------------------------------------

SIGNALS = [
    {"product": "Apache HTTP Server", "category": "server", "header": "server",
     "header_re": r"(?:^|\s)Apache", "confidence": "high",
     "version_re": r"Apache/(\d[\d.]*)"},
    {"product": "nginx", "category": "server", "header": "server",
     "header_re": r"(?:^|\s)nginx", "confidence": "high",
     "version_re": r"nginx/(\d[\d.]*)"},
    {"product": "Microsoft IIS", "category": "server", "header": "server",
     "header_re": r"(?:^|\s)Microsoft-IIS", "confidence": "high",
     "version_re": r"Microsoft-IIS/(\d[\d.]*)"},
    {"product": "Tomcat", "category": "server",
     "header": "x-powered-by", "header_re": r"Tomcat", "confidence": "high",
     "version_re": r"Tomcat/(\d[\d.]*)"},
    {"product": "Express", "category": "framework", "header": "x-powered-by",
     "header_re": r"Express", "confidence": "high",
     "version_re": r"Express/(\d[\d.]*)"},
    {"product": "PHP", "category": "framework", "header": "x-powered-by",
     "header_re": r"PHP", "confidence": "high",
     "version_re": r"PHP/(\d[\d.]*)"},
    {"product": "Next.js", "category": "framework", "header": "x-powered-by",
     "header_re": r"Next\.?js", "confidence": "high",
     "version_re": r"Next\.?js\s*/?\s*(\d[\d.]*)"},
    {"product": "ASP.NET", "category": "framework",
     "header": "x-aspnet-version", "header_re": r"\d", "confidence": "high",
     "version_re": r"(\d[\d.]*)"},
    {"product": "WordPress", "category": "cms", "header": None,
     "marker_re": r"wp-content|wp-includes", "confidence": "medium",
     "version_re": r"WordPress\s*/?\s*v?(\d[\d.]*)"},
    {"product": "Drupal", "category": "cms", "header": None,
     "marker_re": r"Drupal\.settings|/sites/default/files",
     "confidence": "medium"},
    {"product": "Joomla", "category": "cms", "header": None,
     "marker_re": r"/media/jui/|Joomla!", "confidence": "medium"},
    {"product": "React", "category": "js", "header": None,
     "marker_re": r"__REACT_DEVTOOLS|data-reactroot|_reactListening",
     "confidence": "medium"},
    {"product": "Vue.js", "category": "js", "header": None,
     "marker_re": r"data-v-[0-9a-f]{8}|__VUE__", "confidence": "medium"},
    {"product": "Angular", "category": "js", "header": None,
     "marker_re": r"ng-version=|ng-app", "confidence": "medium",
     "version_re": r"ng-version=[\"'](\d[\d.]*)"},
    {"product": "jQuery", "category": "js", "header": None,
     "marker_re": r"jquery[.\-/]?\d", "confidence": "low",
     "version_re": r"jquery[.\-/]?(\d[\d.]*)"},
    {"product": "Google Analytics", "category": "analytics", "header": None,
     "marker_re": r"googletagmanager\.com/gtag|google-analytics\.com",
     "confidence": "medium"},
    {"product": "Cloudflare", "category": "server", "header": "server",
     "header_re": r"cloudflare", "confidence": "high",
     "cookie": "__cf"},
    {"product": "Laravel", "category": "framework", "header": None,
     "cookie": "laravel_session", "confidence": "medium"},
    {"product": "Django", "category": "framework", "header": None,
     "cookie": "csrftoken", "confidence": "low"},
    {"product": "Webpack", "category": "build", "header": None,
     "marker_re": r"webpackJsonp|__webpack_require__", "confidence": "medium"},
]

_META_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{2,120})["']""",
    re.IGNORECASE)

_VERSION_RE_KEYS = ("version_re",)


def extract_version(text, pattern):
    """Extract a version string via ``pattern`` (first capture group)."""
    if not pattern:
        return None
    m = re.search(pattern, text)
    return m.group(1) if m else None


def fingerprint(headers=None, body=None, cookies=None):
    """Match the signal table against one response.

    ``headers``: dict-like of response headers (lower-case keys fine).
    ``body``: response body as text.
    ``cookies``: iterable of cookie names (or Set-Cookie strings).
    Returns list of {"product", "category", "version", "confidence",
    "evidence"} — best signal per product (highest confidence wins).
    """
    headers = headers or {}
    body = body or ""
    cookie_blob = " ".join(cookies or [])
    # normalize header keys to lower-case
    hmap = {str(k).lower(): str(v) for k, v in headers.items()}

    rank = {"high": 3, "medium": 2, "low": 1}
    best = {}
    for sig in SIGNALS:
        conf = sig["confidence"]
        product = sig["product"]
        matched = False
        evidence = ""
        version = None
        if sig.get("header"):
            hval = hmap.get(sig["header"], "")
            if hval and sig.get("header_re") and \
                    re.search(sig["header_re"], hval, re.IGNORECASE):
                matched = True
                evidence = "%s: %s" % (sig["header"], hval.strip())
                version = extract_version(hval, sig.get("version_re"))
        if not matched and sig.get("cookie"):
            if re.search(re.escape(sig["cookie"]), cookie_blob,
                         re.IGNORECASE):
                matched = True
                evidence = "cookie: " + sig["cookie"]
        if not matched and sig.get("marker_re"):
            m = re.search(sig["marker_re"], body, re.IGNORECASE)
            if m:
                matched = True
                evidence = m.group(0)[:120]
                version = extract_version(body, sig.get("version_re"))
        if not matched:
            continue
        cur = best.get(product)
        if cur is None or rank[conf] > rank[cur["confidence"]]:
            best[product] = {"product": product,
                             "category": sig["category"],
                             "version": version,
                             "confidence": conf,
                             "evidence": evidence[:300]}

    # meta generator: independent, medium confidence unless it upgrades
    for m in _META_GENERATOR_RE.finditer(body):
        content = m.group(1).strip()
        for sig in SIGNALS:
            if re.search(re.escape(sig["product"].split()[0]), content,
                         re.IGNORECASE):
                cur = best.get(sig["product"])
                cand = {"product": sig["product"],
                        "category": sig["category"],
                        "version": extract_version(
                            content, sig.get("version_re")) or "unknown",
                        "confidence": "medium",
                        "evidence": "meta generator: " + content}
                if cur is None:
                    best[sig["product"]] = cand
                elif cur["version"] in (None, "") and cand["version"]:
                    cur["version"] = cand["version"]
                    cur["evidence"] = cand["evidence"]
                break

    # keep best-ordered stable list
    return sorted(best.values(),
                  key=lambda t: (-rank[t["confidence"]], t["product"]))


def summarize_stack(techs):
    """One-line summary: 'nginx/1.18.0 (server, high), React (js, medium)'."""
    parts = []
    for t in techs:
        label = t["product"]
        if t.get("version"):
            label += "/" + t["version"]
        parts.append("%s (%s, %s)" % (label, t["category"], t["confidence"]))
    return ", ".join(parts)


def run_tfinger(target, fetch=None):
    """Passive fingerprint of ``target`` (one GET + one HEAD-less GET is
    enough). Returns {"findings": [...], "techs": [...], "summary": str,
    "requests_sent": N}.
    """
    fetch = fetch or default_fetch
    url = target if "://" in target else "http://" + target
    try:
        st, headers, body = fetch("GET", url)
        body_text = (body or b"").decode("latin-1", "replace")
    except Exception:
        headers, body_text = {}, ""
        st = 0

    cookie_names = []
    for k, v in (headers or {}).items():
        if k.lower() == "set-cookie":
            cookie_names.extend(
                c.split("=", 1)[0].strip() for c in v.split(";") if c)

    techs = fingerprint(headers, body_text, cookie_names)
    summary = summarize_stack(techs)
    result = {"findings": [], "techs": techs, "summary": summary,
              "requests_sent": 1}

    # CVE correlation: reuse cvexref (read-only).
    fps = [{"product": t["product"], "version": t["version"]}
           for t in techs if t.get("version")]
    xref = correlate(fps)
    result["findings"].extend(xref.get("findings") or [])

    if techs:
        result["findings"].append(Finding(
            title="Technology stack: %s" % (summary or "unknown"),
            severity="info", confidence="high", verification="candidate",
            verification_note="Passive fingerprint from headers, cookies "
                              "and body markers; version strings are "
                              "banner-extracted, not verified.",
            manual_check="curl -sSI %s" % url,
            location=url, evidence={"techs": techs[:20]},
            source="omega-tfinger/stack"))
    return result
