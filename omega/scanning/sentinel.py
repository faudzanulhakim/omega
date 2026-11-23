"""omega/sentinel.py — SENTINEL PASSIVE INTEL: 14 decode-only /
differential checks for content-level weaknesses (CSP bypass intel,
JWT claim hygiene, secret patterns, PII leaks, mass-assignment hints,
takeover fingerprints, auth-bypass and IDOR differentials) not covered
by omega/hyper.py, omega/headerscan.py or omega/deepchecks.py.

Method policy: GET / HEAD / OPTIONS only, with ONE documented
exception — ``xxe_safe_probe`` sends a POST carrying a well-formed XML
document whose external entity points at a NON-RESOLVING local marker
domain (``.invalid`` TLD). It is never ``file://``, never an internal
host, and is sent ONLY to an endpoint already observed to consume XML
(XML content-type or ``<?xml`` body on a prior GET); the safe-read
semantics are that a data endpoint parses the document without side
effects. Every other check is decode-only: tokens, secrets and
fingerprints are analysed offline and NO exploit is ever attempted.

All findings are ``candidate`` — this module never claims
``confirmed``. Constant-response servers produce ZERO findings: the
two differential checks (auth_bypass_diff, idor_pattern_probe) require
the documented control differential to hold.

Finding shape (ENGINE convention, plain dict):
title / severity / confidence / verification / verification_note /
manual_check (real curl against the REAL target) / location /
evidence (string, <= 300 chars, redacted) / source=omega-sentinel/<name>.

``run_sentinel(target, fetch, budget=80, log=None, allowlist=None)``
never raises; per-check errors become entries in ``skipped``; returns
{findings, skipped, requests_sent, ran}. The request budget is counted
in ``requests_sent`` (total <= budget).
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse

__all__ = [
    "Finding",
    "api_key_pattern_scan",
    "auth_bypass_diff",
    "csp_bypass_intel",
    "deserialization_hints",
    "email_pii_leak",
    "favicon_intel",
    "graphql_csrf_hint",
    "idor_pattern_probe",
    "jwt_claims_audit",
    "mass_assignment_hints",
    "privacy_comments_scan",
    "registry",
    "run_sentinel",
    "takeover_deep",
    "websocket_discovery",
    "xxe_safe_probe",
]

SOURCE_PREFIX = "omega-sentinel"

# Provider secret prefixes (targeted, known formats — generic entropy
# scanning of arbitrary strings is deliberately NOT done to keep FPs low).
API_KEY_PATTERNS = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("stripe_live", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b")),
    ("github_token", re.compile(r"\bghp_[0-9a-zA-Z]{30,}\b")),
    ("github_fine_pat", re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{30,}\b")),
    ("slack_bot", re.compile(r"\bxoxb-[0-9a-zA-Z-]{20,}\b")),
    ("google_api", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("gitlab_pat", re.compile(r"\bglpat-[0-9a-zA-Z_-]{16,}\b")),
]

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"
                    r"(?:\.[A-Za-z0-9_-]*)?")

SENSITIVE_CLAIMS = ("password", "passwd", "ssn", "credit_card",
                    "api_key", "secret")

TAKEOVER_FINGERPRINTS = [
    ("github_pages", "There isn't a GitHub Pages site here"),
    ("aws_s3", "NoSuchBucket"),
    ("aws_s3_alt", "The specified bucket does not exist"),
    ("gitlab_pages", "Repository not found"),
]

DESER_MARKERS = [
    ("java_serialized", re.compile(r"\brO0AB[A-Za-z0-9+/=]{8,}")),
    ("php_object", re.compile(r"\bO:\d+:\s*\"[^\"]{1,64}\":\d+:")),
    ("python_pickle", re.compile(r"(unpickling error|pickle\.loads|"
                                 r"c_copyreg\s*\n_reconstructor)", re.I)),
]

COMMENT_SENSITIVE_RE = re.compile(
    r"(todo|fixme|internal\.[a-z0-9.-]+|password\s*[:=]|secret\s*[:=])",
    re.I)

WS_RE = re.compile(r"\b(wss?://[^\s\"'<>\\]+)")

MASS_ASSIGN_FIELDS = ("is_admin", "isadmin", "role", "verified",
                      "balance", "is_superuser", "isstaff")

AUTH_PROBE_PATHS = ["/admin", "/api/users", "/dashboard", "/account"]

IDOR_CANDIDATE_RE = re.compile(r"/api/[a-z0-9_./-]*?\d+", re.I)

FAVICON_GENERATORS = [
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("gif", b"GIF8"),
    ("jpeg", b"\xff\xd8\xff"),
    ("bmp", b"BM"),
    ("ico", b"\x00\x00\x01\x00"),
]

XXE_CANARY = "omega-xxe-canary"
XXE_SYSTEM = "http://omega-xxe-canary.invalid/never"
XXE_PATHS = ["/api/xml", "/xml", "/parse", "/import", "/api/parse",
             "/soap", "/xmlrpc", "/upload/xml"]


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

def _curl(base_url, path, extra=""):
    return 'curl -sS -i "%s%s"%s' % (base_url.rstrip("/"), path,
                                     (" " + extra) if extra else "")


def _ev(parts):
    if isinstance(parts, str):
        return parts[:300]
    return " ".join("%s=%s" % (k, v) for k, v in parts.items())[:300]


def _text(body):
    return body.decode("latin-1", "replace") if isinstance(body, bytes) \
        else str(body or "")


def _lower_headers(headers):
    return {str(k).lower(): v for k, v in (headers or {}).items()}


def _header(headers, name):
    return _lower_headers(headers).get(name.lower())


def _redact_email(addr):
    """Local part fully redacted; domain kept for triage."""
    return "***@" + addr.split("@", 1)[1]


def _redact_key(matched):
    """Provider secret: only the first 6 characters are ever shown."""
    return matched[:6] + "...REDACTED(len=%d)" % len(matched)


def _b64url_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _looks_json(headers, body):
    ctype = (_header(headers, "content-type") or "").lower()
    if "json" in ctype:
        return True
    t = _text(body).lstrip()
    return t[:1] in ("{", "[")


def _page_links(base_url, html):
    """Extract same-site http(s) links from an HTML page."""
    out = []
    base = base_url.rstrip("/")
    for m in re.finditer(r'(?:href|src|action)=["\']([^"\']+)["\']',
                         html, re.I):
        raw = m.group(1)
        if raw.startswith(("ws://", "wss://", "javascript:", "mailto:",
                           "#", "data:")):
            continue
        if raw.startswith("//"):
            raw = "http:" + raw
        elif not raw.startswith("http://") and not raw.startswith("https://"):
            raw = base + "/" + raw.lstrip("/")
        p = urllib.parse.urlsplit(raw)
        if p.netloc == urllib.parse.urlsplit(base).netloc:
            out.append(urllib.parse.urlunsplit(
                (p.scheme, p.netloc, p.path, p.query, "")))
    return out


def _decode_jwt(token):
    """Decode-only JWT inspection. Returns (header, payload) or None."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[1]:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("latin-1"))
        payload = json.loads(_b64url_decode(parts[1]).decode("latin-1"))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


# ----------------------------------------------------------------- checks

def csp_bypass_intel(base_url, fetch):
    """Parse the CSP directive-by-directive: one candidate LOW per
    weakness (unsafe-inline in script-src, wildcard/http script hosts,
    missing object-src AND default-src). Decode-only."""
    st, headers, _b = fetch("GET", base_url.rstrip("/") + "/")
    csp = (_header(headers, "content-security-policy") or "").strip()
    if not csp:
        return []
    directives = {}
    for part in csp.split(";"):
        toks = part.strip().split()
        if toks:
            directives[toks[0].lower()] = toks[1:]
    script = directives.get("script-src")
    findings = []
    if script:
        joined = " ".join(script).lower()
        if "'unsafe-inline'" in joined:
            findings.append(("script-src allows 'unsafe-inline'",
                             "inline event handlers and <script> blocks "
                             "execute despite CSP"))
        if "*" in script or any(v.startswith("*.") or
                                v.startswith("http://")
                                for v in script):
            findings.append(("script-src uses a wildcard or plain-http "
                             "script host", "a subdomain or MITM can "
                             "serve attacker-controlled script"))
    if "object-src" not in directives and "default-src" not in directives:
        findings.append(("no object-src and no default-src",
                         "flash/object embedding is unrestricted"))
    out = []
    for title, why in findings:
        out.append(Finding(
            title="CSP weakness: %s" % title,
            severity="low",
            verification_note=(
                "Content-Security-Policy %s — %s. No bypass was "
                "attempted; exploitability depends on the site's "
                "injection surface and requires manual verification."
                % (title, why)),
            manual_check='curl -sS -i "%s/" | grep -i content-security'
                         % base_url.rstrip("/"),
            location=base_url.rstrip("/") + "/",
            evidence=_ev({"status": st, "csp": csp[:160]}),
            source="%s/csp_bypass_intel" % SOURCE_PREFIX))
    return out


def jwt_claims_audit(base_url, fetch):
    """Find JWTs in Set-Cookie values / Authorization-style patterns in
    response bodies and DECODE ONLY (no signature attack, no crafted
    token sent): alg=none, missing exp, exp > 30 days, sensitive
    claims => candidate LOW/MEDIUM."""
    st, headers, body = fetch("GET", base_url.rstrip("/") + "/")
    tokens = []
    set_cookie = _header(headers, "set-cookie") or ""
    tokens.extend(JWT_RE.findall(set_cookie))
    auth_style = re.search(r"authorization[\"'\s:=]+(eyJ[A-Za-z0-9_.=-]+)",
                           _text(body), re.I)
    if auth_style:
        tokens.extend(JWT_RE.findall(auth_style.group(1)))
    tokens.extend(JWT_RE.findall(_text(body)))
    findings = []
    for token in tokens:
        decoded = _decode_jwt(token)
        if not decoded:
            continue
        header, payload = decoded
        alg = str(header.get("alg", ""))
        if alg.lower() == "none" or not token.split(".")[2].strip("="):
            findings.append(Finding(
                title="JWT with alg=none structure observed in response",
                severity="medium",
                verification_note=(
                    "A JWT observed in the response decodes to a header "
                    "declaring alg=none (or an empty signature segment). "
                    "Decode-only: no crafted token was ever sent. Server "
                    "acceptance of unsigned tokens requires manual "
                    "verification."),
                manual_check=_curl(base_url, "/") + " # decode token "
                             "offline (base64url), do not replay",
                location=base_url.rstrip("/") + "/",
                evidence=_ev({"alg": alg or "none",
                              "claims": sorted(payload)[:6]}),
                source="%s/jwt_claims_audit" % SOURCE_PREFIX,
                confidence="high"))
        exp = payload.get("exp")
        if exp is None:
            findings.append(Finding(
                title="JWT without exp claim (no expiry)",
                severity="low",
                verification_note=(
                    "A JWT observed in the response decodes to a payload "
                    "with no exp claim — the token never expires "
                    "structurally. Decode-only."),
                manual_check=_curl(base_url, "/") + " # decode the token "
                             "offline (base64url), confirm no exp claim",
                location=base_url.rstrip("/") + "/",
                evidence=_ev({"alg": alg, "claims": sorted(payload)[:6]}),
                source="%s/jwt_claims_audit" % SOURCE_PREFIX))
        elif isinstance(exp, (int, float)):
            issued = payload.get("iat") or payload.get("nbf") or 0
            lifetime = exp - issued
            if lifetime > 30 * 86400:
                findings.append(Finding(
                    title="JWT validity exceeds 30 days (%d days)"
                          % (lifetime // 86400),
                    severity="low",
                    verification_note=(
                        "A JWT observed in the response decodes to an exp "
                        "more than 30 days after its iat/nbf. Long-lived "
                        "tokens widen the replay window. Decode-only."),
                    manual_check=_curl(base_url, "/") + " # decode the "
                                 "token offline and review the exp/iat "
                                 "gap against policy",
                    location=base_url.rstrip("/") + "/",
                    evidence=_ev({"alg": alg,
                                  "lifetime_days": int(lifetime // 86400)}),
                    source="%s/jwt_claims_audit" % SOURCE_PREFIX))
        sensitive = [c for c in payload if
                     any(s in c.lower() for s in SENSITIVE_CLAIMS)]
        if sensitive:
            findings.append(Finding(
                title="JWT payload carries sensitive claims: %s"
                      % ", ".join(sensitive[:3]),
                severity="medium",
                verification_note=(
                    "A JWT observed in the response decodes to a payload "
                    "containing sensitive-looking claims (%s). JWTs are "
                    "base64-readable by any holder; sensitive data must "
                    "not ride in the payload. Decode-only."
                    % ", ".join(sensitive[:3])),
                manual_check=_curl(base_url, "/") + " # decode the token "
                             "offline and confirm the claim values are "
                             "real secrets, then rotate",
                location=base_url.rstrip("/") + "/",
                evidence=_ev({"alg": alg, "sensitive_claims":
                              sensitive[:4]}),
                source="%s/jwt_claims_audit" % SOURCE_PREFIX,
                confidence="high"))
    return findings


def api_key_pattern_scan(base_url, fetch, _pages=None):
    """Scan response bodies for provider-prefixed key-like strings
    (AKIA/sk_live/ghp_/xoxb-/AIza/glpat-/github_pat_). Candidate HIGH;
    evidence shows ONLY the first 6 characters — never the full key."""
    findings = []
    seen = set()
    for url, body in _iter_pages(base_url, fetch, _pages):
        text = _text(body)
        for kind, rx in API_KEY_PATTERNS:
            for m in rx.finditer(text):
                matched = m.group(0)
                if matched in seen:
                    continue
                seen.add(matched)
                findings.append(Finding(
                    title="Provider API key pattern (%s) in response body"
                          % kind,
                    severity="high",
                    verification_note=(
                        "A response body contains a string matching the "
                        "documented %s key format (provider prefix plus "
                        "the expected character alphabet/length). The "
                        "key is REDACTED in evidence; validity requires "
                        "manual offline verification — no verification "
                        "request was sent to the provider." % kind),
                    manual_check=_curl(base_url,
                                       _path_of(base_url, url)) +
                                 " # inspect body offline; revoke/rotate "
                                 "if confirmed",
                    location=url,
                    evidence=_ev({"kind": kind,
                                  "match": _redact_key(matched),
                                  "page": _path_of(base_url, url)}),
                    source="%s/api_key_pattern_scan" % SOURCE_PREFIX,
                    confidence="high"))
    return findings


def email_pii_leak(base_url, fetch, _pages=None):
    """Email addresses in unexpected responses (error pages, JSON
    dumps) => candidate LOW. The domain-local part is redacted in
    evidence."""
    findings = []
    seen = set()
    probe = base_url.rstrip("/") + "/omega-sentinel-nonexistent-%s" % _rand()
    st_err, _h, err_body = fetch("GET", probe)
    contexts = [("error_page_404", err_body)] if st_err in (404, 400, 500) \
        else []
    for url, body in _iter_pages(base_url, fetch, _pages):
        if _looks_json(None, body):
            contexts.append((url, body))
    for where, body in contexts:
        for m in EMAIL_RE.finditer(_text(body)):
            addr = m.group(0)
            if addr.lower().endswith((".png", ".gif", ".jpg", ".webp")):
                continue
            if addr in seen:
                continue
            seen.add(addr)
            findings.append(Finding(
                title="Email address exposed in %s" % where,
                severity="low",
                verification_note=(
                    "A %s response contains a syntactically valid email "
                    "address. Personal data may be leaking to anonymous "
                    "callers. The local part is redacted in evidence; "
                    "whether the address is intentional (support contact) "
                    "or PII requires manual review." % where),
                manual_check=_curl(base_url, _path_of(base_url, where)),
                location=base_url.rstrip("/") + _path_of(base_url, where),
                evidence=_ev({"context": where,
                              "email": _redact_email(addr)}),
                source="%s/email_pii_leak" % SOURCE_PREFIX))
    return findings


def mass_assignment_hints(base_url, fetch, _pages=None):
    """Registration/profile-looking endpoints exposing writable-looking
    privileged fields (is_admin, role, verified, balance, ...) in form
    or JSON schema responses => candidate LOW. Decode-only."""
    base = base_url.rstrip("/")
    candidates = ["/register", "/signup", "/profile", "/api/user",
                  "/api/register", "/users/new"]
    for url, body in _iter_pages(base_url, fetch, _pages, max_pages=2):
        for link in _page_links(base, _text(body)):
            low = link.lower()
            if any(k in low for k in ("regist", "signup", "profile",
                                      "account/settings")):
                candidates.append(link)
    findings = []
    seen = set()
    for path in candidates[:6]:
        st, headers, body = fetch("GET", path if "://" in path
                                  else base + path)
        if st != 200:
            continue
        text = _text(body)
        if not (("<form" in text.lower()) or _looks_json(headers, body)):
            continue
        hits = [f for f in MASS_ASSIGN_FIELDS
                if re.search(r'name\s*=\s*["\']%s["\']|"%s"\s*:'
                             % (f, f), text, re.I)]
        key = (path, tuple(hits))
        if hits and key not in seen:
            seen.add(key)
            findings.append(Finding(
                title="Privileged field names exposed at %s: %s"
                      % (_path_of(base, path), ", ".join(hits[:4])),
                severity="low",
                verification_note=(
                    "The registration/profile-looking endpoint %s exposes "
                    "privileged field names (%s) in its form/JSON schema. "
                    "Whether the server actually accepts mass-assigned "
                    "values was NOT tested (decode-only); manual "
                    "verification required." % (path, ", ".join(hits[:4]))),
                manual_check=_curl(base, _path_of(base, path)),
                location=base + _path_of(base, path),
                evidence=_ev({"status": st, "fields": hits[:6]}),
                source="%s/mass_assignment_hints" % SOURCE_PREFIX))
    return findings


def graphql_csrf_hint(base_url, fetch, _pages=None):
    """A graphql endpoint that answers a GET ?query= with a JSON body
    and where no CSRF token was observed => candidate LOW. GET only —
    the query is a documented safe read."""
    base = base_url.rstrip("/")
    endpoints = ["/graphql"]
    for url, body in _iter_pages(base_url, fetch, _pages, max_pages=1):
        for link in _page_links(base, _text(body)):
            if "graphql" in link.lower():
                endpoints.append(link)
    seen = set()
    for path in endpoints[:3]:
        if path in seen:
            continue
        seen.add(path)
        url = path if "://" in path else base + path
        sep = "&" if "?" in url else "?"
        st, headers, body = fetch("GET", url + sep + "query={__typename}")
        if st != 200:
            continue
        text = _text(body)
        if not _looks_json(headers, body) or "errors" not in text and \
                "__typename" not in text and "data" not in text:
            continue
        if "csrf" in text.lower():
            continue
        return [Finding(
            title="GraphQL endpoint accepts GET queries (no CSRF token "
                  "observed)",
            severity="low",
            verification_note=(
                "GET %s returned a JSON graphql-style response without "
                "any CSRF token observed on the site. GET-issued state-"
                "changing operations would be CSRF-able; only a safe "
                "{__typename} read was sent. Manual verification of the "
                "mutation surface required." % _path_of(base, path)),
            manual_check=_curl(base, _path_of(base, path))
                         + '?query=%7B__typename%7D',
            location=url,
            evidence=_ev({"status": st, "endpoint": _path_of(base, path),
                          "method": "GET", "csrf_observed": False}),
            source="%s/graphql_csrf_hint" % SOURCE_PREFIX)]
    return []


def websocket_discovery(base_url, fetch, _pages=None):
    """Detect ws:// or wss:// endpoints referenced in HTML/JS. INFO
    inventory only — this module NEVER connects to the socket."""
    findings = []
    seen = set()
    for url, body in _iter_pages(base_url, fetch, _pages):
        for m in WS_RE.finditer(_text(body)):
            ws = m.group(1).rstrip(".,;)")
            if ws in seen:
                continue
            seen.add(ws)
            findings.append(Finding(
                title="WebSocket endpoint referenced: %s" % ws,
                severity="info",
                verification_note=(
                    "A page served by the target references a WebSocket "
                    "endpoint (%s). Inventory only — no connection, "
                    "handshake or origin check was attempted." % ws),
                manual_check='curl -sS -i -H "Connection: Upgrade" -H '
                             '"Upgrade: websocket" -H "Sec-WebSocket-Key: '
                             'dGhlIHNhbXBsZSBub25jZQ==" "%s"'
                             % base_url.rstrip("/"),
                location=url,
                evidence=_ev({"websocket": ws,
                              "page": _path_of(base_url, url)}),
                source="%s/websocket_discovery" % SOURCE_PREFIX))
    return findings


def xxe_safe_probe(base_url, fetch, _pages=None):
    """The module's ONLY POST. A well-formed XML document whose external
    entity resolves to a NON-RESOLVING local marker domain
    (http://omega-xxe-canary.invalid/ — .invalid never resolves; never
    file://, never an internal host) is posted to an endpoint FIRST
    observed to consume XML (XML content-type or <?xml body on a prior
    GET). Safe-read semantics: a data endpoint parses the document
    without side effects. A response mentioning the canary entity name
    or disclosing external-entity parser support => candidate MEDIUM."""
    base = base_url.rstrip("/")
    # Observe which candidate endpoints consume XML (GET only).
    xml_endpoints = []
    for path in XXE_PATHS[:5]:
        st, headers, body = fetch("GET", base + path)
        ctype = (_header(headers, "content-type") or "").lower()
        if st == 200 and ("xml" in ctype or
                          _text(body).lstrip().startswith("<?xml")):
            xml_endpoints.append(path)
    if not xml_endpoints:
        return []
    findings = []
    for path in xml_endpoints[:2]:
        payload = ('<?xml version="1.0" encoding="UTF-8"?>'
                   '<!DOCTYPE data [<!ENTITY %s SYSTEM "%s">]>'
                   "<data><probe>&%s;</probe></data>"
                   % (XXE_CANARY, XXE_SYSTEM, XXE_CANARY))
        st, headers, body = fetch("POST", base + path,
                                  headers={"Content-Type":
                                           "application/xml"},
                                  body=payload.encode("latin-1"))
        text = _text(body).lower()
        hit = (XXE_CANARY in text or
               "external entity" in text or
               "entity" in text and ("parser" in text or "sax" in text))
        if not hit:
            continue
        findings.append(Finding(
            title="XML parser at %s processes external entities"
                  % path,
            severity="medium",
            verification_note=(
                "POSTing a DOCTYPE whose external entity points at the "
                "non-resolving marker domain %s (never file://, never an "
                "internal host) made the parser disclose entity support "
                "or echo the entity name. Safe-read semantics: no side "
                "effect on a data endpoint. Exfil-to-file/internal-SSRF "
                "impact requires manual authorized verification."
                % XXE_SYSTEM),
            manual_check='curl -sS -i -X POST -H "Content-Type: '
                         'application/xml" --data-binary @probe.xml '
                         '"%s%s" # probe.xml uses only the .invalid '
                         'canary entity' % (base, path),
            location=base + path,
            evidence=_ev({"status": st, "endpoint": path,
                          "canary": XXE_CANARY,
                          "system": XXE_SYSTEM}),
            source="%s/xxe_safe_probe" % SOURCE_PREFIX,
            confidence="high"))
    return findings


def deserialization_hints(base_url, fetch, _pages=None):
    """Response bodies containing Java serialization markers (rO0AB),
    PHP object patterns (O:\\d+:) or Python pickle hints => candidate
    HIGH, decode-only."""
    findings = []
    seen = set()
    for url, body in _iter_pages(base_url, fetch, _pages):
        text = _text(body)
        for kind, rx in DESER_MARKERS:
            m = rx.search(text)
            if not m:
                continue
            key = (kind, url)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                title="Deserialization artifact in response (%s)" % kind,
                severity="high",
                verification_note=(
                    "A response body contains a %s marker (%r). The "
                    "artifact was decoded/recognised offline only — no "
                    "payload was crafted or submitted. Whether a "
                    "deserialization sink actually exists requires "
                    "manual authorized verification."
                    % (kind, m.group(0)[:40])),
                manual_check=_curl(base_url,
                                   _path_of(base_url, url)) +
                             " # inspect artifact offline",
                location=url,
                evidence=_ev({"kind": kind,
                              "marker": m.group(0)[:60]}),
                source="%s/deserialization_hints" % SOURCE_PREFIX,
                confidence="high"))
    return findings


def takeover_deep(base_url, fetch, _pages=None):
    """Well-known takeover fingerprints ('There isn't a GitHub Pages site
    here', 'NoSuchBucket', 'The specified bucket does not exist',
    'Repository not found') in any referenced response => candidate
    HIGH, decode-only."""
    findings = []
    seen = set()
    for url, body in _iter_pages(base_url, fetch, _pages,
                                 statuses=(200, 400, 401, 403, 404, 500)):
        text = _text(body)
        for kind, fp in TAKEOVER_FINGERPRINTS:
            if fp in text and kind not in seen:
                seen.add(kind)
                findings.append(Finding(
                    title="Takeover fingerprint (%s) in response at %s"
                          % (kind, _path_of(base_url, url)),
                    severity="high",
                    verification_note=(
                        "The response at %s contains the well-known %s "
                        "fingerprint (%r). Decode-only: no DNS/CNAME "
                        "claim was attempted. Whether the dangling "
                        "resource is actually claimable requires manual "
                        "verification against the referenced host."
                        % (_path_of(base_url, url), kind, fp)),
                    manual_check=_curl(base_url,
                                       _path_of(base_url, url)) +
                                 " # then check the referenced host's "
                                 "DNS manually",
                    location=url,
                    evidence=_ev({"fingerprint": fp[:60],
                                  "page": _path_of(base_url, url)}),
                    source="%s/takeover_deep" % SOURCE_PREFIX,
                    confidence="high"))
    return findings


def auth_bypass_diff(base_url, fetch):
    """Documented differential for up to 4 protected-looking paths:
    compare an anonymous GET against a GET carrying a BOGUS 'Authorization:
    Bearer omega-probe' header. Finding when a protected path serves
    authenticated-style 200/JSON content outside the normal 401/403
    baseline — either anonymously or under the bogus token. CONTROL:
    a bogus-token response equal to the anonymous baseline means no
    bypass and produces NO finding."""
    base = base_url.rstrip("/")
    findings = []
    for path in AUTH_PROBE_PATHS[:4]:
        st_anon, h_anon, b_anon = fetch("GET", base + path)
        st_probe, h_probe, b_probe = fetch(
            "GET", base + path,
            headers={"Authorization": "Bearer omega-probe"})
        baseline_locked = st_anon in (401, 403)
        # Control: bogus token behaves like the anonymous baseline -> clean.
        if baseline_locked and st_probe == st_anon:
            continue
        # Control: bogus token refused like the baseline AND anonymous is
        # refused -> nothing to report.
        if baseline_locked and st_probe in (401, 403) and \
                not _looks_json(h_probe, b_probe):
            continue
        anon_open = (not baseline_locked) and st_anon == 200 and \
            _looks_json(h_anon, b_anon)
        probe_open = baseline_locked and st_probe == 200 and \
            _looks_json(h_probe, b_probe) and b_probe != b_anon
        if not (anon_open or probe_open):
            continue
        if anon_open:
            how = "anonymous GET"
            st, hdrs, body = st_anon, h_anon, b_anon
        else:
            how = "GET with bogus 'Bearer omega-probe' token"
            st, hdrs, body = st_probe, h_probe, b_probe
        findings.append(Finding(
            title="Protected-looking path %s served without valid "
                  "authentication (%s)" % (path, how),
            severity="medium",
            verification_note=(
                "Documented differential on %s: anonymous status %s vs "
                "bogus-token status %s. %s returned authenticated-style "
                "200/JSON content outside the normal 401/403 baseline "
                "(anonymous=%s, bogus-token=%s). The bogus-token control "
                "differs from the baseline, so this is not a "
                "constant-response artifact; the content itself must be "
                "manually confirmed as privileged data."
                % (path, st_anon, st_probe, how, st_anon, st_probe)),
            manual_check=_curl(base, path) + ' and curl -sS -i -H '
                         '"Authorization: Bearer omega-probe" "%s%s"'
                         % (base, path),
            location=base + path,
            evidence=_ev({"path": path, "anon_status": st_anon,
                          "bogus_token_status": st_probe,
                          "json": True, "via": how,
                          "body_sample": _text(body)[:80]}),
            source="%s/auth_bypass_diff" % SOURCE_PREFIX))
    return findings


def idor_pattern_probe(base_url, fetch, _pages=None):
    """Numeric-id JSON endpoints (/api/users/1 style) discovered from
    links or probed directly: id=1 and id=2 fetched anonymous. BOTH
    returning DIFFERENT valid records without auth => candidate MEDIUM
    'possible unauthenticated enumeration'. CONTROL: 404/403 for both =>
    clean, NO finding."""
    base = base_url.rstrip("/")
    candidates = [base + "/api/users/1", base + "/api/users/2"]
    for url, body in _iter_pages(base_url, fetch, _pages, max_pages=1):
        for m in IDOR_CANDIDATE_RE.finditer(_text(body)):
            frag = m.group(0)
            root = frag.rstrip("0123456789")
            if root and root != frag:
                candidates.append(base + root + "1")
                candidates.append(base + root + "2")
    results = {}
    for url in candidates[:8]:
        st, headers, body = fetch("GET", url)
        results[url] = (st, headers, body)
    for url1 in list(results):
        if not url1.endswith("1"):
            continue
        url2 = url1[:-1] + "2"
        if url2 not in results:
            continue
        st1, h1, b1 = results[url1]
        st2, h2, b2 = results[url2]
        # Control: both refused (404/403) => clean, NO finding.
        if st1 in (404, 401, 403) and st2 in (404, 401, 403):
            continue
        if st1 == 200 and st2 == 200 and b1 != b2 and \
                _looks_json(h1, b1) and _looks_json(h2, b2):
            path = url1[len(base):]
            return [Finding(
                title="Possible unauthenticated enumeration at %s" % path,
                severity="medium",
                verification_note=(
                    "Documented differential: anonymous GET %s and %s "
                    "both returned HTTP 200 with JSON records whose "
                    "bodies differ (%d vs %d bytes) — sequential ids are "
                    "enumerable without authentication. No ids beyond 2 "
                    "were fetched and no records were modified."
                    % (path, url2[len(base):], len(b1), len(b2))),
                manual_check=_curl(base, path) + ' and curl -sS -i "%s"'
                             % url2,
                location=url1,
                evidence=_ev({"id1_status": st1, "id2_status": st2,
                              "distinct_bodies": True,
                              "auth": "none"}),
                source="%s/idor_pattern_probe" % SOURCE_PREFIX)]
    return []


def favicon_intel(base_url, fetch):
    """GET /favicon.ico: fingerprint by Content-Type + exact-size bucket
    + known generator signatures in the first bytes. INFO tech hint
    only."""
    base = base_url.rstrip("/")
    st, headers, body = fetch("GET", base + "/favicon.ico")
    if st != 200 or not body:
        return []
    ctype = (_header(headers, "content-type") or "").split(";")[0].strip()
    gen = "unknown"
    for kind, magic in FAVICON_GENERATORS:
        if body[:len(magic)] == magic:
            gen = kind
            break
    size_bucket = len(body) // 1024  # KB bucket
    return [Finding(
        title="favicon.ico fingerprint (%s, ~%dKB bucket, %s)"
              % (gen or ctype or "unknown", size_bucket,
                 ctype or "no content-type"),
        severity="info",
        verification_note=(
            "GET /favicon.ico returned HTTP %d (%d bytes, first-byte "
            "signature %s, content-type %s). Informational technology "
            "hint only — favicons can correlate a target across "
            "environments." % (st, len(body), gen, ctype or "absent")),
        manual_check=_curl(base, "/favicon.ico"),
        location=base + "/favicon.ico",
        evidence=_ev({"status": st, "content_type": ctype or "absent",
                      "size": len(body), "generator": gen}),
        source="%s/favicon_intel" % SOURCE_PREFIX,
        confidence="low")]


def privacy_comments_scan(base_url, fetch, _pages=None):
    """HTML comments containing TODO/FIXME, internal hostnames or
    password/secret assignments => candidate LOW (leaky developer
    comments)."""
    findings = []
    seen = set()
    for url, body in _iter_pages(base_url, fetch, _pages):
        text = _text(body)
        for m in re.finditer(r"<!--(.*?)-->", text, re.S):
            comment = m.group(1).strip()
            if not comment:
                continue
            m2 = COMMENT_SENSITIVE_RE.search(comment)
            if not m2:
                continue
            key = (comment[:60], url)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                title="Sensitive HTML comment leaked (%s...)"
                      % comment[:30],
                severity="low",
                verification_note=(
                    "A served page embeds an HTML comment matching a "
                    "sensitive pattern (%r): TODO/FIXME notes, internal "
                    "hostnames or credential-looking assignments are "
                    "readable by any anonymous client."
                    % m2.group(0)[:40]),
                manual_check=_curl(base_url,
                                   _path_of(base_url, url)) +
                             " # grep the body for '<!--'",
                location=url,
                evidence=_ev({"comment": comment[:120],
                              "page": _path_of(base_url, url)}),
                source="%s/privacy_comments_scan" % SOURCE_PREFIX))
    return findings


# ----------------------------------------------------------- internals

def _rand():
    import secrets  # stdlib, non-deterministic canaries
    return secrets.token_hex(4)


def _path_of(base_url, url):
    """Relative path of a URL (or pseudo-locator) vs the base."""
    if url in ("error_page_404",):
        return "/omega-sentinel-nonexistent"
    if "://" not in url:
        return url if url.startswith("/") else "/" + url
    base = urllib.parse.urlsplit(base_url.rstrip("/"))
    p = urllib.parse.urlsplit(url)
    path = p.path or "/"
    if (p.scheme, p.netloc) != (base.scheme, base.netloc):
        return path
    return path + (("?" + p.query) if p.query else "")


def _iter_pages(base_url, fetch, _pages=None, max_pages=4,
                statuses=(200,)):
    """Yield (url, body) for the root page plus up to max_pages
    same-site links. Bodies are fetched per call site (no shared cache)
    to keep every check self-contained; the injected fetch is budget-
    capped by run_sentinel."""
    base = base_url.rstrip("/")
    st, _h, root = fetch("GET", base + "/")
    if st == 200:
        yield base + "/", root
    links = _page_links(base, _text(root)) if st == 200 else []
    seen = set()
    for link in links:
        if len(seen) >= max_pages:
            break
        if link in seen:
            continue
        seen.add(link)
        st2, _h2, body = fetch("GET", link)
        if st2 in statuses:
            yield link, body


registry = [
    ("csp_bypass_intel", csp_bypass_intel),
    ("jwt_claims_audit", jwt_claims_audit),
    ("api_key_pattern_scan", api_key_pattern_scan),
    ("email_pii_leak", email_pii_leak),
    ("mass_assignment_hints", mass_assignment_hints),
    ("graphql_csrf_hint", graphql_csrf_hint),
    ("websocket_discovery", websocket_discovery),
    ("xxe_safe_probe", xxe_safe_probe),
    ("deserialization_hints", deserialization_hints),
    ("takeover_deep", takeover_deep),
    ("auth_bypass_diff", auth_bypass_diff),
    ("idor_pattern_probe", idor_pattern_probe),
    ("favicon_intel", favicon_intel),
    ("privacy_comments_scan", privacy_comments_scan),
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
        if method not in ("GET", "HEAD", "OPTIONS", "POST"):
            raise ValueError("sentinel forbids method %r" % method)
        resp = self._fetch(method, url, headers=headers, body=body)
        self.sent += 1
        return resp


def run_sentinel(target, fetch, budget=80, log=None, allowlist=None):
    """Run all registered sentinel checks against ``target``.

    Never raises: every check error becomes a skip entry in
    ``skipped``; a spent budget skips the remaining checks. The request
    budget is enforced in ``requests_sent`` (total <= budget). Returns
    {findings, skipped, requests_sent, ran}.
    """
    from omega.probes import allowlist_ok

    result = {"findings": [], "skipped": {}, "requests_sent": 0, "ran": []}
    base_url = target if "://" in target else "http://" + target
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = \
            "target %r not in allowlist" % target
        if log:
            log("sentinel skipped: target not in allowlist: %r" % target)
        return result
    fb = _CountingFetch(fetch, budget)
    exhausted = False
    for name, check in registry:
        if exhausted:
            result["skipped"][name] = "budget exhausted"
            continue
        try:
            found = check(base_url, fb)
        except _BudgetExhausted:
            result["skipped"][name] = "budget exhausted"
            exhausted = True
            if log:
                log("sentinel %s: budget exhausted after %d requests"
                    % (name, fb.sent))
            continue
        except Exception as exc:  # never raise
            result["skipped"][name] = "error: %s" % exc
            if log:
                log("sentinel check %s failed: %s" % (name, exc))
            continue
        result["ran"].append(name)
        result["findings"].extend(found)
        if log:
            log("sentinel %s: %d finding(s)" % (name, len(found)))
    result["requests_sent"] = fb.sent
    return result
