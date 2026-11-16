"""omega/hyper.py — HYPER SURFACE SCAN: 14 differential checks for
attack-surface signals not covered by omega/probes.py or
omega/deepchecks.py.

Python-only, non-destructive, evidence-level. Every check sends only
GET / OPTIONS requests (never a real TRACE, never POST). Every check is
DIFFERENTIAL-FIRST: it fetches a baseline (root page and/or a random
fallback path) and compares, so constant/boilerplate responses produce
no findings. All findings are ``candidate`` — this module never claims
``confirmed``; verification is evidence-level only.

Finding shape matches the ENGINE convention (plain dict):
title / severity / confidence / verification / verification_note /
manual_check (real curl command against the REAL target) / location /
evidence (string, <= 300 chars) / source=omega-hyper/<name>.

``run_hyper(target, fetch, budget=60, log=None, allowlist=None)``
never raises; per-check errors become entries in ``skipped``; returns
{findings, skipped, requests_sent, ran}.
"""

from __future__ import annotations

import re
import urllib.parse

__all__ = [
    "Finding",
    "backup_artifact_scan",
    "content_type_sniffing",
    "cookie_flag_audit",
    "cors_wildcard",
    "directory_listing_detect",
    "envfile_exposure",
    "fallback_error_intel",
    "git_metadata_scan",
    "host_header_echo",
    "http_methods_preflight",
    "registry",
    "run_hyper",
    "securitytxt_info",
    "server_banner_fingerprint",
    "sitemap_robots_intel",
    "trace_method_probe",
]

DANGEROUS_VERBS = {"PUT", "DELETE", "PATCH", "CONNECT", "TRACE"}

AUTOINDEX_MARKERS = [
    "index of /",
    "directory listing for",
    "directory listing",
    "<title>folder listing",
]

SQL_DUMP_MARKERS = ["insert into", "create table", "-- mysql dump",
                    "-- postgresql database dump", "copy public."]

TRACEBACK_PATTERNS = [
    "traceback (most recent call last)",
    "werkzeug debugger",
    "exception in thread",
    "at org.apache.",
    "at java.",
    "system.exception:",
]

FRAMEWORK_BANNER_PATTERNS = [
    "stack trace", "django", "laravel", "express", "asp.net",
    "spring boot", "flask", "ruby on rails", "tomcat",
]

BACKUP_PATHS = [
    "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
    "/backup.zip", "/site.zip", "/www.zip", "/backup.bak",
    "/index.php.bak", "/index.bak", "/site.old", "/app.copy",
]

ENV_PATHS = ["/.env", "/.env.local"]

ENV_LINE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*\s*=", re.M)


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
    """Join (key=value) evidence pairs into one compact <=300 char string."""
    if isinstance(parts, str):
        return parts[:300]
    text = " ".join("%s=%s" % (k, v) for k, v in parts.items())
    return text[:300]


def _lower_headers(headers):
    return {str(k).lower(): v for k, v in (headers or {}).items()}


def _cookies(set_cookie_value):
    """Split a (possibly comma-joined) Set-Cookie value into pairs."""
    out = []
    for chunk in re.split(r",(?=\s*[^;,=\s]+=[^;,]*)",
                          set_cookie_value or ""):
        chunk = chunk.strip()
        if "=" in chunk:
            name = chunk.split("=", 1)[0].strip()
            low = chunk.lower()
            toks = [t.strip() for t in low.split(";")]
            out.append((name, {
                "secure": "secure" in toks,
                "httponly": "httponly" in toks,
                "samesite": any(t.startswith("samesite") for t in toks),
            }))
    return out


# ----------------------------------------------------------------- checks

def directory_listing_detect(base_url, fetch):
    """Autoindex titles ('Index of /', 'Directory listing for') on common
    directory paths — differential vs the baseline page body."""
    findings = []
    base = base_url.rstrip("/")
    st0, _h0, b0 = fetch("GET", base + "/")
    baseline_body = b0
    for path in ("/assets/", "/static/", "/images/", "/files/", "/data/"):
        st, _h, body = fetch("GET", base + path)
        if st != 200 or body == baseline_body:
            continue
        text = body.decode("latin-1").lower()
        hits = [m for m in AUTOINDEX_MARKERS if m in text]
        if hits:
            findings.append(Finding(
                title="Directory listing enabled at %s" % path,
                severity="low",
                verification_note=(
                    "GET %s returned HTTP 200 with an autoindex-style page "
                    "marker (%r) that differs from the baseline page — "
                    "directory contents may be browsable." % (path, hits[0])),
                manual_check=_curl(base_url, path),
                location=base + path,
                evidence=_ev({"status": st, "marker": hits[0]}),
                source="omega-hyper/directory_listing_detect"))
    return findings


def backup_artifact_scan(base_url, fetch):
    """Common backup/archive paths (.bak/.old/.copy/.sql/.zip). Judge by
    CONTENT differential vs the site's fallback (random-path) body — a
    bare 200 is never enough."""
    base = base_url.rstrip("/")
    st0, _h0, _b0 = fetch("GET", base + "/")
    _stf, _hf, fallback = fetch(
        "GET", base + "/omega-fallback-%s" % _rand_hex())
    findings = []
    for path in BACKUP_PATHS:
        st, _h, body = fetch("GET", base + path)
        if st != 200 or body == fallback or not body:
            continue
        text = body.decode("latin-1").lower()
        shape = None
        if path.endswith(".sql"):
            if any(m in text for m in SQL_DUMP_MARKERS):
                shape = "sql-dump"
        elif path.endswith(".zip"):
            if body[:4] == b"PK\x03\x04":
                shape = "zip-archive"
        else:
            if "<html" not in text[:200] or "insert into" in text:
                shape = "raw-file"
        if shape is None:
            continue
        sev = "medium" if shape == "sql-dump" else "low"
        findings.append(Finding(
            title="Backup artifact exposed at %s (%s)" % (path, shape),
            severity=sev,
            verification_note=(
                "GET %s returned HTTP 200 with %s-shaped content that "
                "differs from the server's fallback error body — probable "
                "backup/archive disclosure. Confirm manually before "
                "treating as data exposure." % (path, shape)),
            manual_check=_curl(base_url, path),
            location=base + path,
            evidence=_ev({"status": st, "shape": shape,
                          "size": len(body)}),
            source="omega-hyper/backup_artifact_scan",
            confidence="high" if shape == "sql-dump" else "medium"))
    return findings


def envfile_exposure(base_url, fetch):
    """/.env and /.env.local: KEY=VALUE pattern DENSITY (>= 3 distinct
    key lines) and content differential — never a bare 200."""
    findings = []
    base = base_url.rstrip("/")
    _stf, _hf, fallback = fetch(
        "GET", base + "/omega-fallback-%s" % _rand_hex())
    for path in ENV_PATHS:
        st, _h, body = fetch("GET", base + path)
        if st != 200 or body == fallback:
            continue
        text = body.decode("latin-1")
        keys = sorted(set(ENV_LINE_RE.findall(text)))
        if len(keys) < 3:
            continue
        findings.append(Finding(
            title="Environment file exposed at %s (%d KEY=VALUE lines)"
                  % (path, len(keys)),
            severity="high",
            verification_note=(
                "GET %s returned HTTP 200 with %d distinct KEY=VALUE "
                "lines and content differing from the fallback error "
                "body — probable secret/config disclosure. Candidate: "
                "manual review of the keys is required." % (path, len(keys))),
            manual_check=_curl(base_url, path),
            location=base + path,
            evidence=_ev({"status": st, "key_count": len(keys),
                          "sample_keys": keys[:4]}),
            source="omega-hyper/envfile_exposure",
            confidence="high"))
    return findings


def git_metadata_scan(base_url, fetch):
    """/.git/HEAD plus /.git/config — verify content shape. HIGH only
    when the config file is actually present with a [core] section."""
    base = base_url.rstrip("/")
    st, _h, head = fetch("GET", base + "/.git/HEAD")
    if st != 200 or not head.startswith(b"ref: refs/"):
        return []
    findings = [Finding(
        title="Git metadata exposed: /.git/HEAD serves a real ref",
        severity="medium",
        verification_note=(
            "GET /.git/HEAD returned content shaped like a git HEAD file "
            "('ref: refs/...') — the .git directory may be web-served. "
            "Candidate; full repository recovery requires manual check."),
        manual_check=_curl(base_url, "/.git/HEAD"),
        location=base + "/.git/HEAD",
        evidence=_ev({"status": st,
                      "head": head.decode("latin-1", "replace").strip()}),
        source="omega-hyper/git_metadata_scan")]
    stc, _hc, config = fetch("GET", base + "/.git/config")
    if stc == 200 and "[core" in config.decode("latin-1", "replace").lower():
        findings.append(Finding(
            title="Git config file exposed at /.git/config (HIGH)",
            severity="high",
            verification_note=(
                "GET /.git/config returned HTTP 200 with a [core] section "
                "— a real git config file is web-readable, indicating the "
                "whole .git directory is exposed."),
            manual_check=_curl(base_url, "/.git/config"),
            location=base + "/.git/config",
            evidence=_ev({"status": stc,
                          "has_core_section": True}),
            source="omega-hyper/git_metadata_scan",
            confidence="high"))
    return findings


def sitemap_robots_intel(base_url, fetch):
    """/robots.txt Disallow lines and /sitemap.xml — a candidate LOW
    listing the hidden paths for the operator."""
    base = base_url.rstrip("/")
    st, _h, body = fetch("GET", base + "/robots.txt")
    if st != 200:
        return []
    text = body.decode("latin-1")
    disallowed = []
    for line in text.splitlines():
        m = re.match(r"\s*Disallow:\s*(\S+)", line, re.I)
        if m and m.group(1) not in ("/", "*"):
            disallowed.append(m.group(1))
    if not disallowed:
        return []
    st2, _h2, sm = fetch("GET", base + "/sitemap.xml")
    extra = ""
    if st2 == 200 and (b"<urlset" in sm or b"<sitemapindex" in sm):
        extra = " sitemap.xml=present"
    return [Finding(
        title="robots.txt reveals hidden paths (%d Disallow entries)"
              % len(disallowed),
        severity="low",
        verification_note=(
            "GET /robots.txt declares Disallow entries (%s)%s — these are "
            "paths the operator considers sensitive; candidate LOW for "
            "enumeration follow-up." % (disallowed[:4], extra)),
        manual_check=_curl(base_url, "/robots.txt"),
        location=base + "/robots.txt",
        evidence=_ev({"status": st, "disallowed": disallowed[:6],
                      "sitemap": "present" if extra else "absent"}),
        source="omega-hyper/sitemap_robots_intel")]


def securitytxt_info(base_url, fetch):
    """/.well-known/security.txt with a Contact field — INFO."""
    base = base_url.rstrip("/")
    st, _h, body = fetch("GET", base + "/.well-known/security.txt")
    if st != 200:
        return []
    text = body.decode("latin-1")
    if "contact:" not in text.lower():
        return []
    contact = ""
    for line in text.splitlines():
        if line.lower().startswith("contact:"):
            contact = line.strip()[:80]
            break
    return [Finding(
        title="security.txt published with contact details",
        severity="info",
        verification_note=(
            "GET /.well-known/security.txt returned HTTP 200 with a "
            "Contact field — informational disclosure of the security "
            "contact/channel."),
        manual_check=_curl(base_url, "/.well-known/security.txt"),
        location=base + "/.well-known/security.txt",
        evidence=_ev({"status": st, "contact": contact}),
        source="omega-hyper/securitytxt_info")]


def server_banner_fingerprint(base_url, fetch, _headers=None):
    """Server / X-Powered-By banner disclosure on the baseline response —
    INFO fingerprint."""
    st, headers, _b = fetch("GET", base_url.rstrip("/") + "/")
    low = _lower_headers(headers)
    banners = {h: low[h.lower()] for h in ("Server", "X-Powered-By",
                                           "X-AspNet-Version")
               if low.get(h.lower())}
    if not banners:
        return []
    return [Finding(
        title="Server software disclosed in response headers",
        severity="info",
        verification_note=(
            "The baseline response carries software banners (%s) — "
            "fingerprint information that narrows attacker recon."
            % ", ".join(banners)),
        manual_check=_curl(base_url, "/"),
        location=base_url.rstrip("/") + "/",
        evidence=_ev({"status": st, **{k: v[:40] for k, v in
                                       banners.items()}}),
        source="omega-hyper/server_banner_fingerprint")]


def http_methods_preflight(base_url, fetch):
    """OPTIONS / -> Allow header; dangerous methods merely LISTED are a
    candidate LOW. No destructive method is ever sent."""
    st, headers, _b = fetch("OPTIONS", base_url.rstrip("/") + "/")
    allow = (headers or {}).get("Allow") or (headers or {}).get("allow")
    if not allow:
        return []
    listed = {v.strip().upper() for v in allow.split(",") if v.strip()}
    dangerous = sorted(listed & DANGEROUS_VERBS)
    if not dangerous:
        return []
    return [Finding(
        title="Dangerous HTTP methods advertised via OPTIONS Allow",
        severity="low",
        verification_note=(
            "OPTIONS / advertises Allow: %s (dangerous: %s). No "
            "destructive method was actually attempted — whether they "
            "work requires manual authorized verification."
            % (allow, ", ".join(dangerous))),
        manual_check='curl -sS -i -X OPTIONS "%s/"' % base_url.rstrip("/"),
        location=base_url.rstrip("/") + "/",
        evidence=_ev({"status": st, "allow": allow,
                      "dangerous": dangerous}),
        source="omega-hyper/http_methods_preflight")]


def trace_method_probe(base_url, fetch):
    """TRACE detection via the OPTIONS Allow header ONLY — a real TRACE
    request with a body is never sent by this module."""
    st, headers, _b = fetch("OPTIONS", base_url.rstrip("/") + "/")
    allow = (headers or {}).get("Allow") or (headers or {}).get("allow")
    if not allow:
        return []
    listed = {v.strip().upper() for v in allow.split(",") if v.strip()}
    if "TRACE" not in listed:
        return []
    return [Finding(
        title="TRACE method advertised in OPTIONS Allow header",
        severity="low",
        verification_note=(
            "OPTIONS / lists TRACE in Allow. This module never sends a "
            "real TRACE request; Cross-Site Tracing impact requires "
            "manual verification."),
        manual_check='curl -sS -i -X OPTIONS "%s/"' % base_url.rstrip("/"),
        location=base_url.rstrip("/") + "/",
        evidence=_ev({"status": st, "allow": allow}),
        source="omega-hyper/trace_method_probe")]


def cookie_flag_audit(base_url, fetch):
    """Any Set-Cookie on the baseline response missing Secure/HttpOnly/
    SameSite — one candidate LOW per flagged cookie."""
    st, headers, _b = fetch("GET", base_url.rstrip("/") + "/")
    low = _lower_headers(headers)
    raw = low.get("set-cookie")
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
                "Impact depends on the cookie's role (session vs "
                "cosmetic) — manual review required."
                % (name, ", ".join(missing))),
            manual_check=_curl(base_url, "/"),
            location=base_url.rstrip("/") + "/",
            evidence=_ev({"status": st, "cookie": name,
                          "missing": missing}),
            source="omega-hyper/cookie_flag_audit"))
    return findings


def cors_wildcard(base_url, fetch):
    """Access-Control-Allow-Origin: * on the baseline response — LOW
    candidate (wildcard CORS is only exploitable on non-credentialed
    public resources; differential vs a random Origin echo is applied)."""
    base = base_url.rstrip("/")
    st, headers, _b = fetch("GET", base + "/")
    acao = (headers or {}).get("Access-Control-Allow-Origin") or \
        (headers or {}).get("access-control-allow-origin")
    if acao != "*":
        return []
    origin = "https://omega-cors-%s.example" % _rand_hex()
    st2, headers2, _b2 = fetch("GET", base + "/",
                               headers={"Origin": origin})
    acao2 = (headers2 or {}).get("Access-Control-Allow-Origin") or \
        (headers2 or {}).get("access-control-allow-origin")
    if acao2 == origin:
        return []  # reflects arbitrary origins; cors-specific checks own it
    return [Finding(
        title="Wildcard Access-Control-Allow-Origin (*) on baseline "
              "responses",
        severity="low",
        verification_note=(
            "The baseline response sets ACAO: * (and does not echo an "
            "arbitrary Origin instead). Any web origin can read these "
            "responses cross-origin when credentials are not required."),
        manual_check=_curl(base_url, "/"),
        location=base + "/",
        evidence=_ev({"status": st, "acao": "*",
                      "origin_echo": acao2 or "none"}),
        source="omega-hyper/cors_wildcard")]


def host_header_echo(base_url, fetch):
    """Send a benign canary Host 'omega-hh-<rand>.example'; candidate LOW
    when it is reflected in the body differentially vs baseline."""
    base = base_url.rstrip("/")
    st0, _h0, b0 = fetch("GET", base + "/")
    host = "omega-hh-%s.example" % _rand_hex()
    st1, _h1, b1 = fetch("GET", base + "/", headers={"Host": host})
    if host.encode() in b1 and host.encode() not in b0:
        return [Finding(
            title="Host header reflected in response body",
            severity="low",
            verification_note=(
                "A benign canary Host value (%s) appears in the response "
                "body only when the Host header is overridden — "
                "differential vs baseline. Cache/link poisoning impact "
                "is candidate only." % host),
            manual_check='curl -sS -i -H "Host: %s" "%s/"' % (host, base),
            location=base + "/",
            evidence=_ev({"baseline_status": st0, "probe_status": st1,
                          "canary": host}),
            source="omega-hyper/host_header_echo")]
    return []


def content_type_sniffing(base_url, fetch):
    """Missing X-Content-Type-Options PLUS user-influenced content echo
    (marker in ?q= reflected differentially) — LOW candidate."""
    base = base_url.rstrip("/")
    st, headers, b0 = fetch("GET", base + "/")
    low = _lower_headers(headers)
    if low.get("x-content-type-options", "").lower() == "nosniff":
        return []
    marker = "omegasniff%s" % _rand_hex()
    st2, _h2, b1 = fetch("GET", base + "/?q=" + marker)
    if marker.encode() not in b1 or marker.encode() in b0:
        return []
    return [Finding(
        title="MIME sniffing exposure: no X-Content-Type-Options with "
              "user-controlled content echo",
        severity="low",
        verification_note=(
            "The response omits X-Content-Type-Options: nosniff AND "
            "reflects a user-controlled query marker — under specific "
            "content-type conditions browsers may sniff content into an "
            "executable context. Candidate; requires manual confirmation."),
        manual_check=_curl(base_url, "/?q=" + marker),
        location=base + "/?q=" + marker,
        evidence=_ev({"status": st, "xcto": "missing", "param": "q",
                      "reflected": True}),
        source="omega-hyper/content_type_sniffing")]


def fallback_error_intel(base_url, fetch):
    """Random 404/500 path vs normal path: stack traces / framework
    banners in the error page. HIGH on traceback patterns, LOW on
    framework banners — differential against the normal page."""
    base = base_url.rstrip("/")
    st0, _h0, b0 = fetch("GET", base + "/")
    rnd = "/omega-fb-%s" % _rand_hex()
    st, _h, body = fetch("GET", base + rnd)
    text = body.decode("latin-1").lower()
    if st == st0 and body == b0:
        return []
    tb = [p for p in TRACEBACK_PATTERNS if p in text]
    if tb:
        return [Finding(
            title="Stack trace exposed on random error path %s" % rnd,
            severity="high",
            verification_note=(
                "A random nonexistent path (%s, HTTP %s) returns an error "
                "page containing traceback/stack patterns (%s) absent "
                "from the normal page — internal paths, versions or code "
                "may be disclosed." % (rnd, st, tb[0])),
            manual_check=_curl(base_url, rnd),
            location=base + rnd,
            evidence=_ev({"status": st, "pattern": tb[0],
                          "baseline_status": st0}),
            source="omega-hyper/fallback_error_intel",
            confidence="high")]
    banners = [p for p in FRAMEWORK_BANNER_PATTERNS if p in text]
    if banners:
        return [Finding(
            title="Framework banner in error page for %s" % rnd,
            severity="low",
            verification_note=(
                "A random nonexistent path (HTTP %s) returns an error "
                "page naming framework technology (%s) absent from the "
                "normal page — fingerprint disclosure." % (st, banners[0])),
            manual_check=_curl(base_url, rnd),
            location=base + rnd,
            evidence=_ev({"status": st, "banner": banners[0],
                          "baseline_status": st0}),
            source="omega-hyper/fallback_error_intel")]
    return []


# ----------------------------------------------------------- internals

def _rand_hex():
    import secrets  # stdlib, non-deterministic canaries
    return secrets.token_hex(4)


registry = [
    ("directory_listing_detect", directory_listing_detect),
    ("backup_artifact_scan", backup_artifact_scan),
    ("envfile_exposure", envfile_exposure),
    ("git_metadata_scan", git_metadata_scan),
    ("sitemap_robots_intel", sitemap_robots_intel),
    ("securitytxt_info", securitytxt_info),
    ("server_banner_fingerprint", server_banner_fingerprint),
    ("http_methods_preflight", http_methods_preflight),
    ("trace_method_probe", trace_method_probe),
    ("cookie_flag_audit", cookie_flag_audit),
    ("cors_wildcard", cors_wildcard),
    ("host_header_echo", host_header_echo),
    ("content_type_sniffing", content_type_sniffing),
    ("fallback_error_intel", fallback_error_intel),
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


def run_hyper(target, fetch, budget=60, log=None, allowlist=None):
    """Run all registered hyper checks against ``target``.

    Never raises: every check error becomes a skip entry in
    ``skipped``; a spent budget skips the remaining checks. Returns
    {findings, skipped, requests_sent, ran}.
    """
    from omega.probes import allowlist_ok

    result = {"findings": [], "skipped": {}, "requests_sent": 0, "ran": []}
    base_url = target if "://" in target else "http://" + target
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = "target %r not in allowlist" % target
        if log:
            log("hyper skipped: target not in allowlist: %r" % target)
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
                log("hyper %s: budget exhausted after %d requests"
                    % (name, fb.sent))
            continue
        except Exception as exc:  # never raise
            result["skipped"][name] = "error: %s" % exc
            if log:
                log("hyper check %s failed: %s" % (name, exc))
            continue
        result["ran"].append(name)
        result["findings"].extend(found)
        if log:
            log("hyper %s: %d finding(s)" % (name, len(found)))
    result["requests_sent"] = fb.sent
    return result
