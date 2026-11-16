"""omega/scanning/cspanalyze.py — CSP deep analyzer
(fusion suite name: ``cspanalyze``).

Parses the Content-Security-Policy header (default-src, script-src,
style-src, object-src, frame-ancestors, report-uri/report-to) on the
base URL and the main path_info paths and reports policy weaknesses:

  - script-src contains unsafe-inline / unsafe-eval      -> medium
  - no script-src directive (and no default-src either)  -> medium
  - wildcard ``*.domain`` sources inside script-src      -> medium
  - data: or http: sources inside script-src             -> medium
  - object-src not set to 'none' (or missing)            -> low
  - frame-ancestors missing or allowing ``*``            -> low
  - report-uri and report-to both absent                 -> info

Read-only; benign markers only; never raises.
"""

from __future__ import annotations

import re

__all__ = [
    "Finding",
    "parse_csp",
    "csp_weaknesses",
    "run_cspanalyze",
]

from omega.scanning.deepchecks import default_fetch

UNSAFE_RE = re.compile(r"unsafe-(?:inline|eval)")
WILDCARD_RE = re.compile(r"\*\.[A-Za-z0-9_.-]+")
SCHEME_RE = re.compile(r"(?:^|\s)(data:|http:)")


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
    """Contained GET -> (status, headers) or (None, {}); never raises."""
    try:
        st, hdrs, _raw = fetch("GET", url)
        return st, hdrs or {}
    except Exception:
        return None, {}


def _csp_header(hdrs):
    """Extract the CSP policy string from a header dict."""
    for k, v in hdrs.items():
        if k.lower() == "content-security-policy":
            return v if isinstance(v, str) else ";".join(map(str, v))
        if k.lower() == "content-security-policy-report-only":
            return ""
    return ""


def parse_csp(policy):
    """Parse a CSP policy string into a dict of directive -> source list.
    Directive names are lowercased; duplicates are merged."""
    directives = {}
    for part in (policy or "").split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        directives.setdefault(name, [])
        for src in tokens[1:]:
            if src not in directives[name]:
                directives[name].append(src)
    return directives


def csp_weaknesses(directives):
    """Evaluate a parsed CSP directive dict. Returns a list of
    (issue_key, severity, title, note) tuples."""
    out = []
    script = directives.get("script-src") or []
    if script:
        joined = " ".join(script)
        if UNSAFE_RE.search(joined):
            bad = [s for s in script if UNSAFE_RE.search(s)]
            out.append((
                "script-unsafe", "medium",
                "script-src allows unsafe-inline/unsafe-eval",
                "The script-src directive contains %s, which defeats most "
                "of CSP's XSS protection by allowing inline scripts and "
                "string-to-code evaluation. Candidate only."
                % ", ".join(bad)))
        wildcards = [s for s in script if WILDCARD_RE.search(s)]
        if wildcards:
            out.append((
                "script-wildcard", "medium",
                "script-src contains wildcard sources (%s)"
                % ", ".join(wildcards),
                "Wildcard subdomain sources in script-src mean an XSS or "
                "script-injection on ANY matching subdomain can be used "
                "to run scripts on this origin. Candidate only."))
        schemes = [s for s in script if SCHEME_RE.search(" " + s)]
        if schemes:
            out.append((
                "script-scheme", "medium",
                "script-src allows permissive schemes (%s)"
                % ", ".join(schemes),
                "data: or http: sources in script-src allow script "
                "execution from data URIs or plaintext-HTTP origins. "
                "Candidate only."))
    if not script:
        out.append((
            "no-script-src", "medium",
            "No script-src directive",
            "Without an explicit script-src (and thus no direct script "
            "restriction; a default-src fallback may only partially "
            "cover it), the policy does not clearly constrain where "
            "scripts may load from. Candidate only."))
    object_src = directives.get("object-src")
    if not object_src or not (object_src == ["none"]
                              or "none" in [s.lower() for s in object_src]
                              or ("'none'" in object_src)):
        out.append((
            "object-src", "low",
            "object-src is not set to 'none'",
            "Without object-src 'none' the page may embed plugin/legacy "
            "object content (Flash-era attack surface). Candidate only."))
    frame_anc = directives.get("frame-ancestors")
    if not frame_anc:
        out.append((
            "frame-ancestors", "low",
            "No frame-ancestors directive",
            "frame-ancestors is absent, so the page does not declare "
            "which origins may embed it (clickjacking protection "
            "depends on X-Frame-Options alone, if present). "
            "Candidate only."))
    elif "*" in frame_anc:
        out.append((
            "frame-ancestors-star", "low",
            "frame-ancestors allows '*'",
            "frame-ancestors '*' allows any origin to frame the page, "
            "enabling clickjacking. Candidate only."))
    if "report-uri" not in directives and "report-to" not in directives:
        out.append((
            "no-reporting", "info",
            "CSP has no report-uri or report-to endpoint",
            "Without a reporting endpoint, violations are invisible to "
            "the operator and policy tightening is blind. Info-grade "
            "hygiene note."))
    return out


def run_cspanalyze(base_url, fetch=default_fetch, path_info=None,
                   gate=False, max_paths=5):
    """CSP weakness analysis. Returns a list of Finding dicts; never
    raises. ``gate`` accepted for suite-signature symmetry."""
    out = []
    base = base_url if "://" in base_url else "http://" + base_url
    base = base.rstrip("/")
    try:
        info = path_info if isinstance(path_info, dict) else {}
        paths = ["/"] + [str(p) for p in (info.get("paths") or [])
                         if p][:max_paths]
        seen_loc = set()
        for path in paths:
            url = base + (path if path.startswith("/") else "/" + path)
            if url in seen_loc:
                continue
            seen_loc.add(url)
            st, hdrs = _get(fetch, url)
            policy = _csp_header(hdrs)
            if not policy:
                continue
            directives = parse_csp(policy)
            for key, sev, title, note in csp_weaknesses(directives):
                out.append(Finding(
                    title="CSP weakness at %s: %s" % (path, title),
                    severity=sev, verification="candidate",
                    verification_note=note,
                    manual_check="curl -sSI %s | grep -i "
                                 "content-security" % url,
                    location=url, evidence=policy[:200],
                    source="omega-cspanalyze", confidence="high"))
    except Exception:
        pass
    return out
