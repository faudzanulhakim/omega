"""omega/deepchecks.py — the DEEP-CHECK army: 15 additional read-only,
evidence-collection vulnerability checks.

Python-only, non-destructive. Every check sends only GET / HEAD /
OPTIONS requests against the TARGET, plus exactly two documented safe
read POSTs inside the graphql checks (introspection and a 2-item batch
of identical ``{ __typename }`` queries — pure reads, no mutation).
No payloads that execute on the target, no shell-outs.

Design (mirrors omega/probes.py):
- Each check is ``<name>(base_url, fetch=default_fetch, path_info=None,
  **options)`` where ``fetch`` is an injectable callable
  ``fetch(method, url, headers=None, body=None) -> (status, headers_dict,
  body_bytes)``. The default uses stdlib http.client with short
  timeouts, never follows redirects, and supports duplicated request
  headers (list values) for the cache-poisoning check.
- ``path_info`` is the dict of already-discovered paths from prior
  enumeration (e.g. {"paths": [...], "jwt": "...", "params": [...]});
  graphql/jwt checks only fire when a relevant path/token is known.
- A finding is ``confirmed`` ONLY when the documented differential
  condition fully holds; otherwise ``candidate`` (or nothing).
- Finding shape matches the ENGINE convention (plain dict):
  title / severity / confidence / verification / verification_note /
  manual_check / location / evidence / source=omega-deep/<name>.
- ``run_deepchecks`` never raises; returns {findings, ran, skipped}.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import socket
import urllib.parse

__all__ = [
    "FETCH_TIMEOUT",
    "Finding",
    "admin_panel_discovery",
    "allowlist_ok",
    "cache_poison_deception",
    "debug_endpoints",
    "default_fetch",
    "default_page_fingerprint",
    "graphql_batch_dos_hint",
    "graphql_introspection",
    "idor_heuristic",
    "jwt_flaw_scan",
    "open_bucket_hint",
    "path_traversal_reflection",
    "prototype_pollution_client",
    "rate_limit_detect",
    "registry",
    "run_deepchecks",
    "sqli_error_diff",
    "subdomain_takeover_hint",
    "xss_reflection_diff",
]

from omega.probes import allowlist_ok  # noqa: F401  (re-exported)

FETCH_TIMEOUT = 5.0

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "sql syntax",
    "ora-",
    "psycopg",
    "sqlite",
    "unterminated string",
    "warning: mysql",
    "pg::syntaxerror",
    "system.data.sqlclient",
]

# Common weak HMAC secrets (20 words) — verify-only, never brute-force.
JWT_COMMON_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "changeme", "admin",
    "key", "test", "qwerty", "letmein", "welcome", "iloveyou",
    "default", "supersecret", "mysecret", "token", "abc123", "hello",
    "example", "secretkey",
]

TAKEOVER_FINGERPRINTS = [
    "s3.amazonaws.com", "s3-website", "herokuapp.com", "herokudns.com",
    "github.io", "azurewebsites.net", "cloudfront.net", "elasticbeanstalk.com",
    "wordpress.com", "zendesk.com", "fastly.net", "surge.sh",
    "bitbucket.io", "ghost.io", "helpjuice.com", "helpscoutcdn.com",
    "pantheon.io", "readme.io", "pagespeedmobilizer.com", "shopify",
]

TAKEOVER_404_MARKERS = [
    "NoSuchBucket", "There isn't a GitHub Pages site here",
    "you've found a dead domain", "no such app", "domain not found",
    "the request could not be satisfied", "fastly error",
    "there isn't a github pages site here",
]

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql"]

DEBUG_ENDPOINTS = [
    ("/.env", [".env", "DB_PASSWORD", "APP_KEY", "SECRET", "API_KEY"]),
    ("/debug", ["debug", "django", "traceback", "werkzeug"]),
    ("/phpinfo", ["phpinfo()", "PHP Version"]),
    ("/phpinfo.php", ["phpinfo()", "PHP Version"]),
    ("/actuator", ["_links", "health", "self"]),
    ("/trace", ["trace", "session"]),
    ("/console", ["console", "werkzeug", "pdb", "interactive"]),
]

ADMIN_MARKERS = [
    "admin panel", "administrator", "dashboard", "wp-admin",
    "tomcat manager", "manager gui", "sign in to get started",
    "control panel", "login to the", " administration",
]

DEFAULT_PAGE_MARKERS = [
    ("apache2", "apache2 default page", "It works!"),
    ("nginx", "nginx default page", "Welcome to nginx!"),
    ("tomcat", "tomcat default page", "Apache Tomcat"),
    ("iis", "iis default page", "Welcome to IIS"),
    ("jetty", "jetty default page", "Welcome to Jetty"),
]

XSS_MARKER = "omegaxss7f3a9c"
PP_MARKER = "ppinjectedomega"


class Finding(dict):
    """ENGINE-convention finding dict with safe construction defaults."""

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
            evidence=evidence,
            source=source,
        )


# ------------------------------------------------------------------ fetch

def default_fetch(method, url, headers=None, body=None):
    """Stdlib http.client fetch. Returns (status:int, headers:dict,
    body:bytes). Never follows redirects. Header values may be lists
    (sent duplicated). Raises on network errors."""
    p = urllib.parse.urlparse(url)
    if p.scheme == "https":
        conn = http.client.HTTPSConnection(p.hostname, p.port or 443,
                                           timeout=FETCH_TIMEOUT)
    else:
        conn = http.client.HTTPConnection(p.hostname, p.port or 80,
                                          timeout=FETCH_TIMEOUT)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    hdrs = []
    for k, v in (headers or {}).items():
        if isinstance(v, (list, tuple)):
            for item in v:
                hdrs.append((k, str(item)))
        else:
            hdrs.append((k, str(v)))
    payload = body.encode() if isinstance(body, str) else body
    try:
        conn.putrequest(method, path)
        for k, v in hdrs:
            conn.putheader(k, v)
        if payload is not None:
            conn.putheader("Content-Length", str(len(payload)))
        conn.endheaders()
        if payload is not None:
            conn.send(payload)
        resp = conn.getresponse()
        data = resp.read(65536)
        resp_headers = {}
        for k, v in resp.getheaders():
            if k in resp_headers:
                resp_headers[k] += ", " + v
            else:
                resp_headers[k] = v
        return resp.status, resp_headers, data
    finally:
        conn.close()


def _curl(base_url, path_and_query, method="curl -sS -i"):
    return '%s "%s%s"' % (method, base_url.rstrip("/"), path_and_query)


def _post(fetch, url, headers, body):
    """POST a documented-safe read body through an injectable fetch.

    The fetch contract for graphql checks includes ``body=``; a fetch
    that predates it raises TypeError which run_deepchecks contains as
    a skip.
    """
    return fetch("POST", url, headers=headers, body=body)


def _path_info_paths(path_info):
    if not isinstance(path_info, dict):
        return []
    return [str(x) for x in (path_info.get("paths") or [])]


def _host_of(base_url):
    return urllib.parse.urlparse(
        base_url if "://" in base_url else "http://" + base_url).hostname


def _is_loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() in ("localhost",)


# --------------------------------------------------------------- checks

def path_traversal_reflection(base_url, fetch=default_fetch, path_info=None,
                              params=None, canary_file=None,
                              canary_content=None):
    """../ sequences in a path-ish parameter. CONFIRMED only if the
    canary marker (operator-set file content) is reflected in the
    response. Evidence-only: nothing beyond the canary is requested."""
    params = params or ["file", "path", "page", "include", "template",
                        "dir", "name"]
    if canary_file is None and isinstance(path_info, dict) \
            and path_info.get("canary"):
        canary = path_info["canary"]
        canary_file = canary.get("file")
        canary_content = canary.get("content")
    if canary_file is None:
        # No operator canary -> no evidence to confirm against, and we
        # refuse to go fishing for arbitrary files: stay silent.
        return []
    marker = canary_content or "OMEGA-CANARY"
    findings = []
    depth = "../" * 6
    for param in params:
        q = urllib.parse.urlencode({param: depth + canary_file})
        url = base_url.rstrip("/") + "/?" + q
        st, _h, body = fetch("GET", url)
        if marker.encode() in body:
            findings.append(Finding(
                title="Path traversal: canary file reflected via "
                      "parameter '%s'" % param,
                severity="high",
                verification="confirmed",
                verification_note=(
                    "The operator-supplied canary file content was "
                    "reflected in the response when traversing with "
                    "../ sequences via parameter '%s'. Evidence-only: "
                    "no file other than the canary was requested." % param),
                manual_check=_curl(base_url, "/?" + q),
                location=url,
                evidence={"param": param, "canary_file": canary_file,
                          "status": st},
                source="omega-deep/path_traversal_reflection"))
            break
    return findings


def xss_reflection_diff(base_url, fetch=default_fetch, path_info=None,
                        params=None):
    """Harmless marker string reflected in the body vs baseline.
    NEVER auto-confirmed; notes the reflection context
    (html/attr/js)."""
    params = params or ["q", "search", "name", "keyword", "msg", "comment"]
    st0, _h0, base_body = fetch("GET", base_url.rstrip("/") + "/")
    # Build (path, param) probe pairs: default root params first, then
    # paths/params discovered during crawling so reflection checks cover
    # endpoints other than '/' (bounded to keep the request count sane).
    probes = [(base_url.rstrip("/") + "/", p) for p in params]
    pi = path_info or {}
    seen_params = list(dict.fromkeys(
        list(pi.get("params") or []) + params))
    for path in (pi.get("paths") or [])[:20]:
        if not isinstance(path, str) or not path:
            continue
        for p in seen_params[:10]:
            probes.append((base_url.rstrip("/") + path, p))
    for probe_path, param in probes:
        url = probe_path + ("&" if "?" in probe_path else "?") + \
            urllib.parse.urlencode({param: XSS_MARKER})
        try:
            st, _h, body = fetch("GET", url)
        except Exception:
            continue
        base_key = probe_path
        if XSS_MARKER.encode() in body:
            text = body.decode("latin-1")
            idx = text.find(XSS_MARKER)
            low = text.lower()
            last_open = low.rfind("<script", 0, idx)
            last_close = low.rfind("</script", 0, idx)
            before = text[max(0, idx - 60):idx]
            if last_open > last_close:
                ctx = "js"
            elif re.search(r"=\s*[\"'][^\"']*$", before):
                ctx = "attr"
            else:
                ctx = "html"
            return [Finding(
                title="User input reflected in response (param '%s', "
                      "%s context)" % (param, ctx),
                severity="low" if ctx == "html" else "medium",
                verification="candidate",
                verification_note=(
                    "A harmless marker string was reflected in the "
                    "response body (differential vs baseline) in a %s "
                    "context. XSS exploitability was NOT tested — no "
                    "script payload was sent; manual verification "
                    "required." % ctx),
                manual_check=_curl(base_url, "/?" + urllib.parse.urlencode(
                    {param: XSS_MARKER})),
                location=url,
                evidence={"param": param, "context": ctx, "status": st},
                source="omega-deep/xss_reflection_diff")]
    return []


def sqli_error_diff(base_url, fetch=default_fetch, path_info=None,
                    params=None):
    """Single-quote marker in a parameter. CONFIRMED only on a
    differential SQL error signature (probe errors, baseline does not).
    """
    params = params or ["id", "q", "search", "user", "name", "category"]
    for param in params:
        url0 = base_url.rstrip("/") + "/?" + urllib.parse.urlencode(
            {param: "1"})
        url1 = base_url.rstrip("/") + "/?" + urllib.parse.urlencode(
            {param: "1'"})
        _st0, _h0, b0 = fetch("GET", url0)
        st1, _h1, b1 = fetch("GET", url1)
        t0 = b0.decode("latin-1").lower()
        t1 = b1.decode("latin-1").lower()
        hits = [s for s in SQL_ERROR_SIGNATURES if s in t1 and s not in t0]
        if hits:
            return [Finding(
                title="SQL error signature triggered by quote in "
                      "parameter '%s'" % param,
                severity="high",
                verification="confirmed",
                verification_note=(
                    "A single-quote marker in parameter '%s' produced a "
                    "differential SQL error signature (%s) that the "
                    "baseline request did not show — evidence of "
                    "SQL-injectable input handling." % (param, hits[0])),
                manual_check=_curl(base_url, "/?" + urllib.parse.urlencode(
                    {param: "1'"})),
                location=url1,
                evidence={"param": param, "signatures": hits,
                          "status": st1},
                source="omega-deep/sqli_error_diff")]
    return []


def prototype_pollution_client(base_url, fetch=default_fetch,
                               path_info=None):
    """__proto__ in the URL; candidate when the injected key is merged
    into an inline JS config object in the response."""
    probes = [
        "?__proto__[%s]=1" % PP_MARKER,
        "?__proto__=%s" % PP_MARKER,
        "?constructor[prototype][%s]=1" % PP_MARKER,
    ]
    for q in probes:
        url = base_url.rstrip("/") + "/" + q
        st, _h, body = fetch("GET", url)
        text = body.decode("latin-1")
        for script in re.findall(r"<script[^>]*>(.*?)</script>", text,
                                 re.I | re.S):
            if PP_MARKER in script and re.search(
                    r"__proto__|constructor|prototype", script, re.I):
                return [Finding(
                    title="Prototype pollution sink: injected key merged "
                          "into inline JS config",
                    severity="medium",
                    verification="candidate",
                    verification_note=(
                        "The __proto__ marker appeared inside an inline "
                        "<script> block together with a merge/prototype "
                        "reference after a __proto__ URL parameter was "
                        "sent. Client-side merge behavior requires "
                        "manual (browser) verification."),
                    manual_check=_curl(base_url, "/" + q),
                    location=url,
                    evidence={"query": q, "status": st,
                              "inline_script_hit": True},
                    source="omega-deep/prototype_pollution_client")]
    return []


def cache_poison_deception(base_url, fetch=default_fetch, path_info=None):
    """Duplicate X-Forwarded-Host + unique param. CONFIRMED only if the
    cache distinguishes the response (Vary/Age/X-Cache differential)
    in addition to the differential body reflection."""
    evil = "omegapoison.example"
    uniq = "omegacb%d" % (hash(base_url) & 0xFFFFFF)
    st0, h0, b0 = fetch("GET", base_url.rstrip("/") + "/")
    url = base_url.rstrip("/") + "/?%s=1" % uniq
    st1, h1, b1 = fetch("GET", url, headers={
        "X-Forwarded-Host": [evil, evil]})
    low0 = {k.lower(): v for k, v in h0.items()}
    low1 = {k.lower(): v for k, v in h1.items()}
    reflected = evil.encode() in b1 and evil.encode() not in b0
    cache_signal = (
        low1.get("vary", "") != low0.get("vary", "")
        or "age" in low1
        or "x-cache" in low1
        or low1.get("cache-control", "") != low0.get("cache-control", ""))
    if reflected and cache_signal:
        return [Finding(
            title="Cache poisoning/deception: duplicate X-Forwarded-Host "
                  "differentiates cached response",
            severity="high",
            verification="confirmed",
            verification_note=(
                "A duplicated X-Forwarded-Host header plus a unique "
                "cache-busting parameter produced a response that "
                "reflects the attacker host AND shows a cache "
                "differential (Vary/Age/X-Cache) vs baseline — the "
                "cache distinguishes the poisoned variant."),
            manual_check=("curl -sS -i -H 'X-Forwarded-Host: %s' "
                          "-H 'X-Forwarded-Host: %s' \"%s/?%s=1\""
                          % (evil, evil, base_url.rstrip("/"), uniq)),
            location=url,
            evidence={"baseline_status": st0, "probe_status": st1,
                      "vary_baseline": low0.get("vary"),
                      "vary_probe": low1.get("vary"),
                      "age_probe": low1.get("age")},
            source="omega-deep/cache_poison_deception")]
    if reflected:
        return [Finding(
            title="X-Forwarded-Host reflected but no cache differential",
            severity="low",
            verification="candidate",
            verification_note=(
                "The duplicated X-Forwarded-Host value is reflected "
                "differentially, but the response shows no Vary/Age/"
                "X-Cache signal that the cache distinguishes the "
                "variant. Not confirmed as cache poisoning."),
            manual_check=("curl -sS -i -H 'X-Forwarded-Host: %s' "
                          "\"%s/?%s=1\"" % (evil, base_url.rstrip("/"),
                                            uniq)),
            location=url,
            evidence={"baseline_status": st0, "probe_status": st1},
            source="omega-deep/cache_poison_deception")]
    return []


def _graphql_endpoints(path_info):
    if isinstance(path_info, dict) and path_info.get("paths"):
        # When discovery already ran, POST ONLY to graphql paths it
        # found — never blind-guess other endpoints.
        found = []
        for p in _path_info_paths(path_info):
            pl = p.lower()
            if "graphql" in pl:
                found.append(p if p.startswith("/") else "/" + p)
        return found
    return list(GRAPHQL_PATHS)


def graphql_introspection(base_url, fetch=default_fetch, path_info=None):
    """POST { __schema } ONLY to graphql endpoints (documented safe
    read). Enabled introspection = candidate HIGH."""
    findings = []
    body = json.dumps({"query": "{ __schema { types { name } } }"})
    headers = {"Content-Type": "application/json"}
    for path in _graphql_endpoints(path_info):
        url = base_url.rstrip("/") + path
        st, _h, resp = _post(fetch, url, headers, body)
        text = resp.decode("latin-1")
        if st == 200 and "__schema" in text:
            findings.append(Finding(
                title="GraphQL introspection enabled at %s" % path,
                severity="high",
                verification="candidate",
                verification_note=(
                    "A read-only introspection query ({ __schema { "
                    "types { name } } }) returned the schema — full "
                    "type/graph disclosure. Introspection itself is a "
                    "read; exploitation requires manual review."),
                manual_check=("curl -sS -X POST -H 'Content-Type: "
                              "application/json' -d '%s' \"%s\""
                              % (body, url)),
                location=url,
                evidence={"status": st, "introspection": True},
                source="omega-deep/graphql_introspection",
                confidence="high"))
    return findings


def graphql_batch_dos_hint(base_url, fetch=default_fetch, path_info=None):
    """Batch array of 2 identical safe reads; differential response
    shape only (array vs object vs error) — candidate."""
    query = json.dumps({"query": "{ __typename }"})
    findings = []
    for path in _graphql_endpoints(path_info):
        url = base_url.rstrip("/") + path
        st1, _h1, single = _post(fetch, url, {"Content-Type":
                                              "application/json"}, query)
        batch = json.dumps([json.loads(query), json.loads(query)])
        st2, _h2, resp = _post(fetch, url, {"Content-Type":
                                            "application/json"}, batch)
        try:
            one = json.loads(single.decode("latin-1"))
            many = json.loads(resp.decode("latin-1"))
        except ValueError:
            continue
        if isinstance(many, list) and isinstance(one, dict):
            findings.append(Finding(
                title="GraphQL batch queries accepted (array response "
                      "shape) at %s" % path,
                severity="low",
                verification="candidate",
                verification_note=(
                    "A batch array of 2 identical read-only queries "
                    "produced an array-shaped response while a single "
                    "query returned an object — batching is enabled, "
                    "which is a known amplification vector. No load "
                    "was generated (2 harmless reads)."),
                manual_check=("curl -sS -X POST -H 'Content-Type: "
                              "application/json' -d '%s' \"%s\"" % (batch,
                                                                    url)),
                location=url,
                evidence={"single_status": st1, "batch_status": st2,
                          "batch_len": len(many)},
                source="omega-deep/graphql_batch_dos_hint"))
    return findings


def _b64url_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def jwt_flaw_scan(base_url, fetch=default_fetch, path_info=None, token=None,
                  secrets=None):
    """alg=none / weak-HMAC-secret check on a discovered JWT.

    Verify-only: the signature is checked LOCALLY against a 20-word
    common-secret list. CONFIRMED only if a common secret verifies the
    signature. alg=none structure yields a candidate note only.
    """
    token = token or (
        path_info.get("jwt") if isinstance(path_info, dict) else None) \
        or os.environ.get("OMEGA_JWT")
    if not token:
        return []
    parts = token.split(".")
    if len(parts) != 3:
        return []
    findings = []
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("latin-1"))
    except Exception:
        return []
    alg = str(header.get("alg", ""))
    if alg.lower() == "none" or not parts[2]:
        findings.append(Finding(
            title="JWT uses alg=none structure",
            severity="high",
            verification="candidate",
            verification_note=(
                "The token header declares alg=none (or carries an "
                "empty signature). Server acceptance of unsigned "
                "tokens requires manual verification — no crafted "
                "token was sent to the target."),
            manual_check=("Inspect the token offline: %s" % token[:64]),
            location=base_url,
            evidence={"alg": alg},
            source="omega-deep/jwt_flaw_scan"))
    signing_input = (parts[0] + "." + parts[1]).encode("latin-1")
    try:
        sig = _b64url_decode(parts[2])
    except Exception:
        sig = b""
    for secret in (secrets or JWT_COMMON_SECRETS):
        if hmac.new(secret.encode(), signing_input,
                    hashlib.sha256).digest() == sig:
            findings.append(Finding(
                title="JWT signature verifies with a common weak secret",
                severity="high",
                verification="confirmed",
                verification_note=(
                    "The token's HMAC-SHA256 signature was locally "
                    "recomputed with the common secret %r and matched "
                    "exactly — the signing secret is a known weak "
                    "value. Token forgery is therefore possible."
                    % secret),
                manual_check=("Offline verify: recompute HMAC-SHA256 "
                              "over the header.payload with secret %r "
                              "and compare to the signature." % secret),
                location=base_url,
                evidence={"alg": alg, "secret": secret,
                          "secret_list_size": len(secrets
                                                  or JWT_COMMON_SECRETS)},
                source="omega-deep/jwt_flaw_scan",
                confidence="high"))
            break
    return findings


def idor_heuristic(base_url, fetch=default_fetch, path_info=None,
                   params=None):
    """Sequential param +1/-1 differential: one value returns 200 while
    another is refused (403/401) — candidate only."""
    params = params or ["id", "user_id", "uid", "account", "order_id"]
    if isinstance(path_info, dict) and path_info.get("params"):
        params = list(path_info["params"]) + params
    for param in params:
        base_url_ = base_url.rstrip("/")
        results = {}
        for val in ("1", "2"):
            url = "%s/?%s=%s" % (base_url_, param, val)
            st, _h, _b = fetch("GET", url)
            results[val] = st
        ok_vals = [v for v, s in results.items() if s == 200]
        denied = [v for v, s in results.items() if s in (401, 403)]
        if ok_vals and denied:
            url = "%s/?%s=%s" % (base_url_, param, ok_vals[0])
            return [Finding(
                title="IDOR heuristic: sequential values treated "
                      "differently (param '%s')" % param,
                severity="medium",
                verification="candidate",
                verification_note=(
                    "Parameter '%s' value %s returns HTTP 200 while "
                    "value %s is refused (%s) — consistent with "
                    "object-level authorization gaps, but the 200 may "
                    "simply be the caller's own object. Candidate "
                    "only; requires authenticated manual verification."
                    % (param, ok_vals[0], denied[0],
                       results[denied[0]])),
                manual_check=_curl(base_url_, "/?%s=%s" % (param,
                                                           ok_vals[0])),
                location=url,
                evidence={"param": param, "statuses": results},
                source="omega-deep/idor_heuristic")]
    return []


def debug_endpoints(base_url, fetch=default_fetch, path_info=None):
    """/.env /debug /phpinfo /actuator /trace /console discovery.
    INFO when found; HIGH for /.env with real content markers."""
    findings = []
    base = base_url.rstrip("/")
    for path, markers in DEBUG_ENDPOINTS:
        url = base + path
        st, _h, body = fetch("GET", url)
        text = body.decode("latin-1")
        hits = [m for m in markers if m.lower() in text.lower()]
        if st == 200 and hits:
            if path == "/.env":
                findings.append(Finding(
                    title="Exposed .env file with real content markers",
                    severity="high",
                    verification="confirmed",
                    verification_note=(
                        "GET /.env returned HTTP 200 with real "
                        "environment-file content markers (%s) — "
                        "credential/secret disclosure." % hits[:3]),
                    manual_check=_curl(base_url, path),
                    location=url,
                    evidence={"status": st, "markers": hits[:5]},
                    source="omega-deep/debug_endpoints",
                    confidence="high"))
            else:
                findings.append(Finding(
                    title="Debug/diagnostic endpoint exposed: %s" % path,
                    severity="info",
                    verification="confirmed",
                    verification_note=(
                        "The endpoint answered HTTP 200 with content "
                        "markers (%s) — informational discovery."
                        % hits[:3]),
                    manual_check=_curl(base_url, path),
                    location=url,
                    evidence={"status": st, "markers": hits[:5]},
                    source="omega-deep/debug_endpoints"))
    return findings


def admin_panel_discovery(base_url, fetch=default_fetch, path_info=None):
    """/admin /wp-admin /manager /dashboard fingerprinted by title
    markers — INFO."""
    paths = ["/admin", "/wp-admin", "/manager", "/dashboard"]
    for p in _path_info_paths(path_info):
        pl = p.lower()
        if any(m in pl for m in ("admin", "manager", "dashboard")) \
                and p not in paths:
            paths.append(p if p.startswith("/") else "/" + p)
    findings = []
    for path in paths:
        url = base_url.rstrip("/") + path
        st, _h, body = fetch("GET", url)
        if st != 200:
            continue
        text = body.decode("latin-1").lower()
        title_m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        title = title_m.group(1) if title_m else text[:200]
        hits = [m for m in ADMIN_MARKERS if m in title or m in text[:2000]]
        if hits:
            findings.append(Finding(
                title="Admin panel discovered at %s" % path,
                severity="info",
                verification="confirmed",
                verification_note=(
                    "The path returned HTTP 200 with admin-panel title "
                    "markers (%s) — informational discovery."
                    % hits[:3]),
                manual_check=_curl(base_url, path),
                location=url,
                evidence={"status": st, "markers": hits[:5],
                          "title": title.strip()[:120]},
                source="omega-deep/admin_panel_discovery"))
    return findings


def default_page_fingerprint(base_url, fetch=default_fetch, path_info=None):
    """Web-server default pages and default-credential page markers —
    INFO."""
    st, _h, body = fetch("GET", base_url.rstrip("/") + "/")
    if st != 200:
        return []
    text = body.decode("latin-1")
    for _name, label, marker in DEFAULT_PAGE_MARKERS:
        if marker.lower() in text.lower():
            return [Finding(
                title="Web server default page still served (%s)" % label,
                severity="info",
                verification="confirmed",
                verification_note=(
                    "The root document matches the known default page "
                    "of the server (%s) — suggests an unconfigured or "
                    "default installation." % label),
                manual_check=_curl(base_url, "/"),
                location=base_url.rstrip("/") + "/",
                evidence={"marker": marker, "status": st},
                source="omega-deep/default_page_fingerprint")]
    if re.search(r"default credentials|admin/admin|password:\s*admin",
                 text, re.I):
        return [Finding(
            title="Default-credentials text on landing page",
            severity="info",
            verification="candidate",
            verification_note=(
                "The landing page advertises default credentials — "
                "informational; verify manually before relying on it."),
            manual_check=_curl(base_url, "/"),
            location=base_url.rstrip("/") + "/",
            evidence={"status": st},
            source="omega-deep/default_page_fingerprint")]
    return []


def subdomain_takeover_hint(base_url, fetch=default_fetch, path_info=None,
                            dns_fn=None):
    """CNAME to a known-vulnerable service (from the DNS answer) plus a
    404 body fingerprint — candidate. Both signals required."""
    host = _host_of(base_url)
    if not host:
        return []
    if dns_fn is None:
        def dns_fn(h):
            try:
                return socket.gethostbyname_ex(h)[1]
            except OSError:
                return []
    try:
        aliases = list(dns_fn(host))
    except Exception:
        return []
    vuln = [a for a in aliases
            if any(fp in a.lower() for fp in TAKEOVER_FINGERPRINTS)]
    if not vuln:
        return []
    st, _h, body = fetch("GET", base_url if "://" in base_url
                         else "http://" + base_url)
    text = body.decode("latin-1").lower()
    markers = [m for m in TAKEOVER_404_MARKERS if m.lower() in text]
    if st in (404, 400) and markers:
        return [Finding(
            title="Subdomain takeover hint: CNAME to %s with unclaimed "
                  "404 body" % vuln[0],
            severity="high",
            verification="candidate",
            verification_note=(
                "DNS for %s points at %s (a service known to allow "
                "dangling claims) and the endpoint answers 404 with a "
                "fingerprint (%s) typical of an unclaimed resource. "
                "Takeover requires a manual claim test — candidate."
                % (host, vuln[0], markers[0])),
            manual_check=("dig CNAME %s; curl -sS -i \"%s\""
                          % (host, base_url)),
            location=host,
            evidence={"cname": vuln[0], "status": st,
                      "body_markers": markers[:3]},
            source="omega-deep/subdomain_takeover_hint")]
    return []


def rate_limit_detect(base_url, fetch=default_fetch, path_info=None):
    """6 rapid GETs; detect 429/backoff. INFO either way."""
    statuses = []
    retry_after = None
    for _ in range(6):
        st, h, _b = fetch("GET", base_url.rstrip("/") + "/")
        statuses.append(st)
        retry_after = retry_after or (h.get("Retry-After")
                                      or h.get("retry-after"))
    throttled = any(s in (429, 503) for s in statuses)
    if throttled or retry_after:
        return [Finding(
            title="Rate limiting detected on rapid requests",
            severity="info",
            verification="confirmed",
            verification_note=(
                "Six rapid GETs produced statuses %s%s — the server "
                "throttles or backs off." % (
                    statuses, " with Retry-After: %s" % retry_after
                    if retry_after else "")),
            manual_check=("for i in $(seq 1 6); do curl -sS -o /dev/null "
                          "-w '%%{http_code}\\n' \"%s/\"; done"
                          % base_url.rstrip("/")),
            location=base_url.rstrip("/") + "/",
            evidence={"statuses": statuses, "retry_after": retry_after},
            source="omega-deep/rate_limit_detect")]
    return [Finding(
        title="No rate limiting detected on 6 rapid requests",
        severity="info",
        verification="confirmed",
        verification_note=(
            "Six rapid GETs all completed without 429/503 or "
            "Retry-After (statuses: %s) — no rate limiting observed "
            "at this intensity (not proof of absence under load)."
            % statuses),
        manual_check=("for i in $(seq 1 6); do curl -sS -o /dev/null "
                      "-w '%%{http_code}\\n' \"%s/\"; done"
                      % base_url.rstrip("/")),
        location=base_url.rstrip("/") + "/",
        evidence={"statuses": statuses},
        source="omega-deep/rate_limit_detect")]


def open_bucket_hint(base_url, fetch=default_fetch, path_info=None):
    """Guess bucket names from the target hostname and probe S3/GCS/
    Azure public endpoints. Candidate LOW when an error shape indicates
    an existing-but-protected bucket; NoSuchBucket shapes are silent."""
    host = _host_of(base_url)
    if not host or _is_loopback(host):
        return []
    bare = host.lower()
    for part in ("www.",):
        if bare.startswith(part):
            bare = bare[len(part):]
    names = sorted({bare, bare.replace(".", "-"),
                    "www-" + bare.replace(".", "-")})
    probes = []
    for n in names:
        probes += [
            ("s3", "http://%s.s3.amazonaws.com/" % n),
            ("gcs", "https://storage.googleapis.com/%s/" % n),
            ("azure", "https://%s.blob.core.windows.net/" % n),
        ]
    EXISTS_SHAPES = {
        "s3": ["accessdenied", "listbucketresult"],
        "gcs": ["accessdenied", "listbucketresult"],
        "azure": ["accessdenied", "publicaccessnotpermitted",
                  "authorizationfailure"],
    }
    DEAD_SHAPES = ("nosuchbucket", "bucketnamenotfound",
                   "containernotfound", "blobnotfound", "no such bucket")
    for provider, url in probes:
        try:
            st, _h, body = fetch("GET", url)
        except Exception:
            continue
        text = body.decode("latin-1").lower()
        if any(d in text for d in DEAD_SHAPES):
            continue  # bucket does not exist: no finding
        if st in (200, 301, 403) and any(s in text
                                         for s in EXISTS_SHAPES[provider]):
            return [Finding(
                title="Existing cloud storage bucket guessed from "
                      "hostname (%s)" % provider,
                severity="low",
                verification="candidate",
                verification_note=(
                    "A bucket/container name derived from the target "
                    "hostname (%s) resolves to an EXISTING %s resource "
                    "(error shape indicates existence, not absence). "
                    "Manual review of its permissions is required."
                    % (url, provider.upper())),
                manual_check="curl -sS -i \"%s\"" % url,
                location=url,
                evidence={"provider": provider, "status": st},
                source="omega-deep/open_bucket_hint")]
    return []


def cmdi_echo_probe(base_url, fetch=default_fetch, path_info=None):
    """Probe GET params for command-injection echo behavior.

    Appends a unique marker via ; / backtick / $() separators to
    discovered path+param pairs and flags HIGH/candidate when the raw
    marker is echoed back (baseline response checked first). The
    payload is a benign 'echo MARKER' — nothing destructive.
    """
    import urllib.parse as _up
    marker = "OMEGACMD%04x" % (abs(hash(base_url)) % 0xFFFF)
    pi = path_info or {}
    params = list(dict.fromkeys(
        list(pi.get("params") or []) + ["q", "arg", "cmd", "host", "ip"]))
    pairs = [(base_url.rstrip("/") + "/", p) for p in params[:6]]
    for path in (pi.get("paths") or [])[:15]:
        if not isinstance(path, str) or not path:
            continue
        for p in params[:6]:
            pairs.append((base_url.rstrip("/") + path, p))
    findings = []
    seen = set()
    for probe_path, param in pairs:
        key = (probe_path, param)
        if key in seen:
            continue
        seen.add(key)
        url0 = probe_path + ("&" if "?" in probe_path else "?") + \
            _up.urlencode({param: "1"})
        try:
            _st, _h, base_body = fetch("GET", url0)
        except Exception:
            continue
        if marker.encode() in base_body:
            continue  # page reflects marker anyway -> not evidence
        # Reflection control: if the bare marker (no separators) is also
        # echoed, the page reflects arbitrary input — fall back to an
        # arithmetic probe, since plain reflection cannot evaluate
        # $((a*b)) but a real shell does.
        arithmetic = False
        try:
            _st, _h, ctrl_body = fetch(
                "GET", probe_path + ("&" if "?" in probe_path else "?") +
                _up.urlencode({param: marker}))
        except Exception:
            continue
        if marker.encode() in ctrl_body:
            arithmetic = True
        hit = None
        if arithmetic:
            a, b = 123, 2
            lit = "%d*%d" % (a, b)
            for sep in (";echo $((", "`echo $((", "$((", "| echo $(( "):
                payload = sep + lit + "))"
                url = probe_path + ("&" if "?" in probe_path else "?") + \
                    _up.urlencode({param: payload})
                try:
                    _st, _h, body = fetch("GET", url)
                except Exception:
                    continue
                # evaluated result present, literal form absent
                if str(a * b).encode() in body and lit.encode() not in body:
                    hit = (param, payload)
                    break
        else:
            for sep in (";echo %s", "`echo %s`", "$(echo %s)", "| echo %s"):
                payload = sep % marker
                url = probe_path + ("&" if "?" in probe_path else "?") + \
                    _up.urlencode({param: payload})
                try:
                    _st, _h, body = fetch("GET", url)
                except Exception:
                    continue
                if marker.encode() in body and \
                        marker.encode() not in base_body:
                    hit = (param, payload)
                    break
        if hit:
            param, payload = hit
            findings.append(Finding(
                title=("Command output echoed in response (param '%s')"
                       % param),
                severity="high",
                verification="candidate",
                verification_note=(
                    "Marker from a benign echo command appeared in the "
                    "response after appending separators to param '%s'. "
                    "Manual confirmation required before treating as "
                    "confirmed command injection." % param),
                manual_check=(
                    "curl --get --data-urlencode '%s=%s' '%s' | grep -F %s"
                    % (param, payload, probe_path, marker)),
                location=probe_path,
                evidence={"param": param, "payload": payload,
                          "marker": marker, "probe_url": probe_path},
                source="omega-deep/cmdi_echo_probe"))
    return findings


# -------------------------------------------------------------- registry

# Ordered registry: name -> check callable. Read-only evidence
# collection; the ONLY POSTs in the whole module are the two graphql
# checks' documented safe reads (introspection + 2x { __typename }).
registry = [
    ("path_traversal_reflection", path_traversal_reflection),
    ("xss_reflection_diff", xss_reflection_diff),
    ("sqli_error_diff", sqli_error_diff),
    ("prototype_pollution_client", prototype_pollution_client),
    ("cache_poison_deception", cache_poison_deception),
    ("graphql_introspection", graphql_introspection),
    ("graphql_batch_dos_hint", graphql_batch_dos_hint),
    ("jwt_flaw_scan", jwt_flaw_scan),
    ("idor_heuristic", idor_heuristic),
    ("debug_endpoints", debug_endpoints),
    ("admin_panel_discovery", admin_panel_discovery),
    ("default_page_fingerprint", default_page_fingerprint),
    ("subdomain_takeover_hint", subdomain_takeover_hint),
    ("rate_limit_detect", rate_limit_detect),
    ("cmdi_echo_probe", cmdi_echo_probe),
    ("open_bucket_hint", open_bucket_hint),
]


# ---------------------------------------------------------- run_deepchecks

def run_deepchecks(target, fetch=None, budget=None, log=None,
                   allowlist=None, path_info=None):
    """Run all registered deep checks against ``target``.

    Never raises: every check error becomes a skip entry. Returns
    {findings, ran, skipped}.
    """
    result = {"findings": [], "ran": [], "skipped": {}}
    base_url = target if "://" in target else "https://" + target
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = (
            "target %r not in allowlist" % target)
        if log:
            log("deepchecks skipped: target not in allowlist: %r" % target)
        return result
    fetch = fetch or default_fetch
    has_graphql_path = (path_info is None) or bool(_graphql_endpoints(
        path_info))
    jwt_token = None
    if isinstance(path_info, dict):
        jwt_token = path_info.get("jwt")
    for name, check in registry:
        if budget is not None and len(result["ran"]) >= budget:
            result["skipped"][name] = "budget exhausted"
            continue
        if name in ("graphql_introspection", "graphql_batch_dos_hint") \
                and not has_graphql_path:
            result["skipped"][name] = \
                "no graphql endpoint in path_info"
            continue
        if name == "jwt_flaw_scan" and not jwt_token \
                and not os.environ.get("OMEGA_JWT"):
            result["skipped"][name] = "no JWT discovered (path_info/env)"
            continue
        try:
            found = check(base_url, fetch, path_info=path_info)
        except Exception as exc:  # never raise
            result["skipped"][name] = "error: %s" % exc
            if log:
                log("deepcheck %s failed: %s" % (name, exc))
            continue
        result["ran"].append(name)
        result["findings"].extend(found)
        if log:
            log("deepcheck %s: %d finding(s)" % (name, len(found)))
    return result
