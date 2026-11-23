"""omega/scanning/secretjs.py — secrets in JavaScript bundles
(fusion suite name: ``secretjs``).

Fetches the homepage plus path_info pages (bounded), collects the JS
assets referenced from them (bounded 10) and regex-scans each bundle
(and its .map source map) for hardcoded secrets:

  - AWS access keys            AKIA + 16 chars
  - private key blocks         -----BEGIN ... PRIVATE KEY-----
  - Google API keys            AIza + 35 chars
  - JWT tokens                 eyJ... header.payload.sig
  - generic api_key/secret/password assignments with quoted values
  - Slack tokens               xox[baprs]-...
  - Stripe keys                sk_live_/sk_test_...
  - internal URLs / credentials inside .map source maps

Each unique pattern hit becomes a HIGH candidate finding with a
REDACTED evidence excerpt (first 8 chars then ellipsis). Benign
markers only; never raises.
"""

from __future__ import annotations

import re

__all__ = [
    "Finding",
    "SECRET_PATTERNS",
    "MAX_JS_ASSETS",
    "redact",
    "run_secretjs",
]

from omega.scanning.deepchecks import default_fetch

MAX_JS_ASSETS = 10
MAX_PAGES = 5

# (pattern-key, compiled regex, description)
SECRET_PATTERNS = (
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}"),
     "AWS access key id"),
    ("private-key-block", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
     "private key block"),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
     "Google API key"),
    ("jwt-token", re.compile(
        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),
     "JWT token"),
    ("generic-secret", re.compile(
        r"""(?:api[_-]?key|secret|password|passwd)\s*[:=]\s*["']"""
        r"""[^"']{8,}["']""", re.I),
     "generic secret assignment"),
    ("slack-token", re.compile(r"xox[bpars]-[0-9A-Za-z\-]{10,}"),
     "Slack token"),
    ("stripe-key", re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{16,}"),
     "Stripe secret key"),
)

SOURCEMAP_INTERNAL_RE = re.compile(
    r"""(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+"""
    r"""|[\w.-]+\.internal|[\w.-]+\.local)[^\s"'\\]*""", re.I)

SCRIPT_SRC_RE = re.compile(
    r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
SOURCEMAP_REF_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


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
    """Contained GET -> (status, text) or (None, ''); never raises."""
    try:
        st, _h, raw = fetch("GET", url)
        return st, _text(raw)
    except Exception:
        return None, ""


def redact(match_text):
    """REDACTED evidence excerpt: first 8 chars then ellipsis."""
    return (match_text[:8] + "...") if len(match_text) > 8 else match_text


def _asset_url(base, page_url, src):
    """Resolve a script src against the page URL."""
    if src.startswith("//"):
        return "http:" + src
    if src.startswith("http://") or src.startswith("https://"):
        return src
    if src.startswith("/"):
        return base + src
    root = page_url.rsplit("/", 1)[0]
    return root + "/" + src


def _collect_assets(base, fetch, pages):
    """JS + sourcemap URLs referenced from the given pages."""
    js, maps = [], []
    for page in pages[:MAX_PAGES]:
        url = base + page if page.startswith("/") else base + "/" + page
        st, html = _get(fetch, url)
        if st != 200 or not html:
            continue
        for src in SCRIPT_SRC_RE.findall(html):
            full = _asset_url(base, url, src)
            if full.endswith(".map"):
                if full not in maps:
                    maps.append(full)
            elif full not in js:
                js.append(full)
        for mp in SOURCEMAP_REF_RE.findall(html):
            full = _asset_url(base, url, mp)
            if full not in maps:
                maps.append(full)
    return js[:MAX_JS_ASSETS], maps[:MAX_JS_ASSETS]


def _scan_text(kind, url, text, out, seen):
    """Regex-scan one body; HIGH candidate per unique pattern hit."""
    for key, rx, desc in SECRET_PATTERNS:
        m = rx.search(text)
        if m and (url, key) not in seen:
            seen.add((url, key))
            out.append(Finding(
                title="Possible %s hardcoded in %s (%s)"
                      % (desc, kind, url),
                severity="high", verification="candidate",
                verification_note=(
                    "A pattern matching %s was found in %s %s "
                    "(evidence REDACTED). Hardcoded secrets in client-"
                    "reachable assets are exposed to every visitor; "
                    "confirm and rotate. Candidate only."
                    % (desc, kind, url)),
                manual_check="curl -sS %s | grep -n %r" % (url, key),
                location=url, evidence=redact(m.group(0)),
                source="omega-secretjs", confidence="medium"))
    if kind == "sourcemap":
        m = SOURCEMAP_INTERNAL_RE.search(text)
        if m and (url, "sourcemap-internal") not in seen:
            seen.add((url, "sourcemap-internal"))
            out.append(Finding(
                title="Source map discloses internal URLs/hosts: %s" % url,
                severity="high", verification="candidate",
                verification_note=(
                    "A .map source map served at %s references internal "
                    "hosts or credential-like strings, leaking internal "
                    "topology. Candidate only." % url),
                manual_check="curl -sS %s" % url,
                location=url, evidence=redact(m.group(0)),
                source="omega-secretjs", confidence="medium"))


def run_secretjs(base_url, fetch=default_fetch, path_info=None,
                 gate=False, budget=20):
    """Secret scan of JS bundles. Returns a list of Finding dicts;
    never raises. ``gate`` accepted for suite-signature symmetry."""
    out = []
    base = base_url if "://" in base_url else "http://" + base_url
    base = base.rstrip("/")
    sent = 0
    try:
        info = path_info if isinstance(path_info, dict) else {}
        pages = ["/"] + [p for p in (info.get("paths") or [])
                         if isinstance(p, str) and p]
        js, maps = _collect_assets(base, fetch, pages)
        seen = set()
        for url in (js + maps)[:budget]:
            st, body = _get(fetch, url)
            sent += 1
            if st != 200 or not body:
                continue
            kind = "sourcemap" if url.endswith(".map") else "js bundle"
            _scan_text(kind, url, body, out, seen)
            if not url.endswith(".map") and sent < budget:
                for mp in SOURCEMAP_REF_RE.findall(body):
                    murl = _asset_url(base, url, mp)
                    if murl.endswith(".map") and sent < budget:
                        mst, mbody = _get(fetch, murl)
                        sent += 1
                        if mst == 200 and mbody:
                            _scan_text("sourcemap", murl, mbody, out, seen)
                        break
    except Exception:
        pass
    return out
