"""OMEGA safe differential verification probes.

Python-only, non-destructive, read-only evidence collection. Every probe
sends only GET (and OPTIONS for http_methods_probe) requests — no payload
execution on the target, no exploitation.

Design:
- Each probe is a function ``<name>_probe(base_url, fetch, ...)`` where
  ``fetch`` is an injectable callable ``fetch(method, url, headers) ->
  (status, headers_dict, body_bytes)``. The default implementation uses
  stdlib ``urllib`` with short timeouts.
- A finding is labeled ``confirmed`` ONLY when the documented differential
  condition is fully met; otherwise it is ``candidate`` (or omitted).
- Finding shape matches the ENGINE convention (plain dict):
  title / severity / confidence / verification / verification_note /
  manual_check / location / evidence / source=omega-probe/<name>.
- ``run_probes`` never raises; it returns {findings, ran, skipped}.
"""

import ipaddress
import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

__all__ = [
    "FETCH_TIMEOUT",
    "Finding",
    "allowlist_ok",
    "crlf_probe",
    "cors_misconfig_probe",
    "default_fetch",
    "header_injection_probe",
    "host_header_poison_probe",
    "http_methods_probe",
    "open_redirect_probe",
    "registry",
    "run_probes",
    "security_headers_probe",
    "ssrf_probe_blind",
    "tls_info_probe",
    "version_banner_probe",
]

FETCH_TIMEOUT = 5.0

DANGEROUS_VERBS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

SECURITY_HEADERS = {
    "Content-Security-Policy": "content-security-policy",
    "Strict-Transport-Security": "strict-transport-security",
    "X-Frame-Options": "x-frame-options",
    "X-Content-Type-Options": "x-content-type-options",
    "Referrer-Policy": "referrer-policy",
}

COMMON_REDIRECT_PARAMS = ["next", "url", "redirect", "return", "returnTo",
                          "goto", "dest", "continue"]
COMMON_URL_PARAMS = ["url", "uri", "path", "src", "target", "fetch",
                     "proxy", "link", "callback", "remote"]


class Finding(dict):
    """ENGINE-convention finding dict with safe construction defaults."""

    def __init__(self, title, severity, verification, verification_note,
                 manual_check, location, evidence, source, confidence="high"):
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

import os as _os

# Bounded response cap: 1MB default, operator-overridable. Never unbounded.
MAX_BODY = int(_os.environ.get("OMEGA_MAX_BODY", 1048576))


def _read_bounded(reader, limit=None):
    """Read up to `limit` bytes from `reader`; return (body, truncated).

    A body of exactly `limit` bytes is complete, not truncated: after
    the cap we probe one extra byte to see whether the stream really
    continues before flagging truncation.
    """
    limit = MAX_BODY if limit is None else limit
    chunks, total = [], 0
    while total < limit:
        chunk = reader.read(min(65536, limit - total))
        if not chunk:
            return b"".join(chunks), False
        chunks.append(chunk)
        total += len(chunk)
    extra = reader.read(1)      # exactly-at-cap probe
    if not extra:
        return b"".join(chunks), False
    return b"".join(chunks), True


def fetch_detailed(method, url, headers=None):
    """Like default_fetch but returns (status, headers, body, meta) where
    meta = {"truncated": bool, "limit": int}. Callers that need to know
    whether the body was cut at the cap use this; default_fetch keeps
    the historical 3-tuple contract for compatibility.
    """
    req = urllib.request.Request(url, method=method, headers=headers or {})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=FETCH_TIMEOUT) as resp:
            body, truncated = _read_bounded(resp)
            return (resp.status, dict(resp.headers.items()), body,
                    {"truncated": truncated, "limit": MAX_BODY})
    except urllib.error.HTTPError as exc:
        body, truncated = b"", False
        if hasattr(exc, "read"):
            body, truncated = _read_bounded(exc)
        return (exc.code, dict(exc.headers.items() if exc.headers else {}),
                body, {"truncated": truncated, "limit": MAX_BODY})


def default_fetch(method, url, headers=None):
    """Stdlib-urllib fetch. Returns (status:int, headers:dict, body:bytes).

    Body is bounded to MAX_BODY (1MB default); use fetch_detailed when
    the caller needs to know whether truncation occurred. Raises on
    network errors (probes/run_probes translate that to skips).
    """
    st, hd, body, _meta = fetch_detailed(method, url, headers)
    return st, hd, body


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: probes need the raw Location header."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _mk_opener():
    return urllib.request.build_opener(_NoRedirect())


# ---------------------------------------------------------------- helpers

def _is_off_origin(location, base_url):
    """True if ``location`` points to a different host than base_url."""
    try:
        loc = urllib.parse.urlparse(location)
        base = urllib.parse.urlparse(base_url)
        if not loc.netloc:
            return False
        return loc.netloc.lower() != base.netloc.lower()
    except ValueError:
        return False


def allowlist_ok(target, allowlist=None):
    """Scope check: target host must be in allowlist (None means allowed).

    ``target`` may be a URL or bare host; allowlist entries may be hosts,
    CIDRs or URLs.
    """
    if allowlist is None:
        return True
    host = urllib.parse.urlparse(
        target if "://" in target else "//" + target, scheme="http").hostname
    if not host:
        return False
    for entry in allowlist:
        entry = str(entry)
        if "://" in entry:
            eh = urllib.parse.urlparse(entry).hostname
        elif "/" in entry:
            # CIDR
            try:
                if ipaddress.ip_address(host.split("%")[0]) in \
                        ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                eh = None
            else:
                continue
        else:
            eh = entry
        if eh and host.lower() == eh.lower():
            return True
    return False


def _curl(base_url, path_and_query, method="curl -sS -i"):
    """Concrete manual-check command with the REAL target substituted."""
    return '%s "%s%s"' % (method, base_url.rstrip("/"), path_and_query)


# ----------------------------------------------------------------- probes

def open_redirect_probe(base_url, fetch=default_fetch):
    """Differential: baseline GET / vs GET /?next=//evil.example.

    CONFIRMED only if Location header actually points off-origin AND the
    attacker value is reflected in that Location. Otherwise no finding.
    """
    attacker = "//evil.example"
    st0, h0, _ = fetch("GET", base_url + "/")
    loc0 = h0.get("Location") or h0.get("location")
    url = base_url + "/?" + urllib.parse.urlencode({"next": attacker})
    st1, h1, _ = fetch("GET", url)
    loc1 = h1.get("Location") or h1.get("location")
    if loc1 and loc1 != loc0 and _is_off_origin(loc1, base_url) \
            and attacker in loc1:
        return [Finding(
            title="Open redirect via 'next' parameter",
            severity="medium",
            verification="confirmed",
            verification_note=("Location header redirects off-origin to the "
                               "attacker-controlled value //evil.example "
                               "while baseline request did not redirect "
                               "there."),
            manual_check=_curl(base_url, "/?next=//evil.example"),
            location=url,
            evidence={"baseline_status": st0, "baseline_location": loc0,
                      "probe_status": st1, "probe_location": loc1},
            source="omega-probe/open_redirect_probe")]
    return []


def ssrf_probe_blind(base_url, fetch=default_fetch, hook_url=None):
    """Blind SSRF probe: set a URL param to a canary pointing at the
    operator-supplied hook.

    Evidence only when the hook reports a hit (``hook_url`` callable or
    object with ``.hits()`` returning non-empty). Without a hook (None)
    the probe yields at most a candidate finding.
    """
    if not hook_url:
        return []
    canary = hook_url if isinstance(hook_url, str) else \
        getattr(hook_url, "url", None)
    hits = getattr(hook_url, "hits", None)
    findings = []
    for param in COMMON_URL_PARAMS:
        url = base_url + "/?" + urllib.parse.urlencode({param: canary})
        try:
            fetch("GET", url)
        except Exception:
            pass
        raw_hits = hits() if callable(hits) else hits
        if hits and raw_hits:
            findings.append(Finding(
                title="Blind SSRF: server requested attacker-supplied URL "
                      "(param '%s')" % param,
                severity="high",
                verification="confirmed",
                verification_note=("The canary URL pointing at the "
                                   "operator-supplied hook received a hit "
                                   "after the server fetched the "
                                   "parameter-supplied URL."),
                manual_check=_curl(base_url, "/?%s=%s" % (param, canary)),
                location=url,
                evidence={"param": param, "canary": canary,
                          "hook_hits": list(raw_hits) if raw_hits else []},
                source="omega-probe/ssrf_probe_blind"))
            break
    if not findings and canary:
        url = base_url + "/?" + urllib.parse.urlencode({"url": canary})
        findings.append(Finding(
            title="Possible blind SSRF: URL parameter accepts canary URL "
                  "(unverified)",
            severity="low",
            verification="candidate",
            verification_note=("A URL-typed parameter was set to a canary "
                               "pointing at the operator hook, but the hook "
                               "received no hit (or no hook was reachable). "
                               "Weak evidence — not confirmed."),
            manual_check=_curl(base_url, "/?url=%s" % canary),
            location=url,
            evidence={"param": "url", "canary": canary},
            source="omega-probe/ssrf_probe_blind"))
    return findings


def crlf_probe(base_url, fetch=default_fetch):
    """Inject a %0d%0a marker in the path; differential on headers echo."""
    marker = "X-OMEGA-CRLF-MARKER: 1"
    url = base_url + "/%0d%0a" + urllib.parse.quote(marker)
    st, headers, body = fetch("GET", url)
    header_hit = any("X-OMEGA-CRLF-MARKER" in k or marker in v
                     for k, v in headers.items())
    body_hit = marker.encode() in body
    if header_hit:
        return [Finding(
            title="CRLF injection reflected into response headers",
            severity="high",
            verification="confirmed",
            verification_note=("The injected %0d%0a sequence caused the "
                               "marker to appear as a new response header, "
                               "proving header injection."),
            manual_check=_curl(base_url,
                               "/%0d%0a" + urllib.parse.quote(marker)),
            location=url,
            evidence={"status": st, "reflected_in": "headers"},
            source="omega-probe/crlf_probe")]
    if body_hit:
        return [Finding(
            title="CRLF marker echoed in response body (potential "
                  "reflection)",
            severity="low",
            verification="candidate",
            verification_note=("The CRLF marker was reflected in the body "
                               "only; no header injection demonstrated. "
                               "Weak evidence — not confirmed."),
            manual_check=_curl(base_url,
                               "/%0d%0a" + urllib.parse.quote(marker)),
            location=url,
            evidence={"status": st, "reflected_in": "body"},
            source="omega-probe/crlf_probe")]
    return []


def header_injection_probe(base_url, fetch=default_fetch):
    """Differential: X-Forwarded-Host / X-Original-URL reflection vs
    baseline."""
    fwd = "evil.example"
    xfurl = "/admin"
    probe_headers = {"X-Forwarded-Host": fwd, "X-Original-URL": xfurl}
    st0, h0, b0 = fetch("GET", base_url + "/")
    st1, h1, b1 = fetch("GET", base_url + "/", headers=probe_headers)
    findings = []
    refl_fwd = fwd.encode() in b1 and fwd.encode() not in b0
    if refl_fwd:
        findings.append(Finding(
            title="X-Forwarded-Host reflected in response body",
            severity="medium",
            verification="confirmed",
            verification_note=("The X-Forwarded-Host value appears in the "
                               "response body only when the header is set "
                               "(differential vs baseline)."),
            manual_check=("curl -sS -i -H 'X-Forwarded-Host: %s' \"%s/\""
                          % (fwd, base_url)),
            location=base_url + "/",
            evidence={"baseline_status": st0, "probe_status": st1,
                      "reflected": "X-Forwarded-Host"},
            source="omega-probe/header_injection_probe"))
    refl_url = xfurl.encode() in b1 and xfurl.encode() not in b0
    if refl_url:
        findings.append(Finding(
            title="X-Original-URL reflected in response body",
            severity="medium",
            verification="confirmed",
            verification_note=("The X-Original-URL value appears in the "
                               "response body only when the header is set "
                               "(differential vs baseline)."),
            manual_check=("curl -sS -i -H 'X-Original-URL: %s' \"%s/\""
                          % (xfurl, base_url)),
            location=base_url + "/",
            evidence={"baseline_status": st0, "probe_status": st1,
                      "reflected": "X-Original-URL"},
            source="omega-probe/header_injection_probe"))
    return findings


def host_header_poison_probe(base_url, fetch=default_fetch):
    """Host override differential; evidence = reflected absolute URL in
    body or Location."""
    host = "evil.example"
    st0, h0, b0 = fetch("GET", base_url + "/")
    st1, h1, b1 = fetch("GET", base_url + "/", headers={"Host": host})
    loc1 = h1.get("Location") or h1.get("location")
    loc0 = h0.get("Location") or h0.get("location")
    refl_loc = loc1 and host in loc1 and loc1 != loc0
    refl_body = host.encode() in b1 and host.encode() not in b0
    if refl_loc or refl_body:
        return [Finding(
            title="Host header reflected in server-generated absolute URL",
            severity="medium",
            verification="confirmed",
            verification_note=("Overriding the Host header changed the "
                               "server's absolute URL generation (Location "
                               "header or body links) to the attacker "
                               "value, differing from baseline."),
            manual_check="curl -sS -i -H 'Host: %s' \"%s/\"" % (host,
                                                                base_url),
            location=base_url + "/",
            evidence={"baseline_status": st0, "probe_status": st1,
                      "baseline_location": loc0, "probe_location": loc1,
                      "reflected_in": "location" if refl_loc else "body"},
            source="omega-probe/host_header_poison_probe")]
    return []


def cors_misconfig_probe(base_url, fetch=default_fetch):
    """Origin: evil.example; CONFIRMED only when ACAO echoes the arbitrary
    origin AND Access-Control-Allow-Credentials is true."""
    origin = "https://evil.example"
    st, headers, _ = fetch("GET", base_url + "/",
                           headers={"Origin": origin})
    acao = headers.get("Access-Control-Allow-Origin")
    acac = headers.get("Access-Control-Allow-Credentials")
    if acao == origin and str(acac).lower() == "true":
        return [Finding(
            title="CORS misconfiguration: arbitrary origin reflected with "
                  "credentials",
            severity="high",
            verification="confirmed",
            verification_note=("Access-Control-Allow-Origin echoes the "
                               "arbitrary attacker origin AND "
                               "Access-Control-Allow-Credentials is true; "
                               "cross-origin credentialed reads are "
                               "possible."),
            manual_check=("curl -sS -i -H 'Origin: %s' \"%s/\"" % (origin,
                                                                  base_url)),
            location=base_url + "/",
            evidence={"acao": acao, "acac": acac, "status": st},
            source="omega-probe/cors_misconfig_probe")]
    if acao == origin:
        return [Finding(
            title="CORS: arbitrary origin reflected without credentials",
            severity="low",
            verification="candidate",
            verification_note=("ACAO echoes an arbitrary origin but "
                               "credentials are not allowed; impact is "
                               "limited. Not confirmed as exploitable."),
            manual_check=("curl -sS -i -H 'Origin: %s' \"%s/\"" % (origin,
                                                                  base_url)),
            location=base_url + "/",
            evidence={"acao": acao, "acac": acac, "status": st},
            source="omega-probe/cors_misconfig_probe")]
    return []


def tls_info_probe(base_url, fetch=default_fetch, ssl_ctx=None):
    """INFO finding: TLS certificate subject/issuer/SANs.

    ``ssl_ctx`` injectable for hermetic tests (object with
    get_server_certificate(host, port)). Read-only.
    """
    parsed = urllib.parse.urlparse(
        base_url if "://" in base_url else "https://" + base_url)
    if parsed.scheme != "https":
        return []
    host = parsed.hostname
    port = parsed.port or 443
    ctx = ssl_ctx or ssl.create_default_context()
    try:
        pem = ctx.get_server_certificate((host, port))
    except Exception as exc:
        return [Finding(
            title="TLS certificate could not be retrieved",
            severity="info",
            verification="candidate",
            verification_note=("Retrieving the server certificate failed "
                               "(%s); manual inspection required." % exc),
            manual_check="curl -sS -vI \"%s\" 2>&1 | grep -i -E "
                         "'subject:|issuer:|SSL cert'" % base_url,
            location="%s:%d" % (host, port),
            evidence={"error": str(exc)},
            source="omega-probe/tls_info_probe")]
    info = {}
    try:
        from ssl import PEM_cert_to_DER_cert  # noqa: F401
        import base64
        der = base64.b64decode(
            "".join(l for l in pem.splitlines() if "-----" not in l))
        info = _parse_cert_x509(der)
    except Exception:
        info = {"pem_sha256_note": "x509 parse unavailable; raw PEM kept"}
        info["pem"] = pem
    return [Finding(
        title="TLS certificate details disclosed (informational)",
        severity="info",
        verification="confirmed",
        verification_note=("Certificate subject/issuer/SANs parsed from the "
                           "live TLS handshake — informational only."),
        manual_check="curl -sS -vI \"%s\" 2>&1 | grep -i -E "
                     "'subject:|issuer:|SSL cert'" % base_url,
        location="%s:%d" % (host, port),
        evidence=info,
        source="omega-probe/tls_info_probe")]


def _parse_cert_x509(der):
    """Minimal DER walk for subject/issuer/SANs (stdlib only)."""
    out = {"subject": None, "issuer": None, "sans": []}
    # Cheap approach: regex over the DER for CN/O strings and dNSName IA5s.
    text = der.decode("latin-1")
    cns = re.findall(r"\x03\x55\x04\x03[\x0c\x13](.)", text)
    if cns:
        out["subject_cn"] = cns[0]
    orgs = re.findall(r"\x55\x04\x0a[\x0c\x13](.)", text)
    if orgs:
        out["organization"] = orgs[0]
    # SAN dNSName: IA5String (0x16) after 2.5.29.17 SAN OID context tag
    for m in re.finditer(r"\x16([\x01-\x20])([\x20-\x7e]{1,32})",
                         text[text.find("3.1.7"):]):
        length = m.group(1)[0]
        val = m.group(2)[:length]
        if "." in val or val.isalnum():
            out["sans"].append(val)
    out["sans"] = sorted(set(out["sans"]))[:20]
    return out


def security_headers_probe(base_url, fetch=default_fetch):
    """Audit presence of CSP/HSTS/XFO/XCTO/Referrer-Policy; reports the
    exact missing list."""
    st, headers, body = fetch("GET", base_url + "/")
    lower = {k.lower(): v for k, v in headers.items()}
    missing = [name for name in SECURITY_HEADERS if name.lower() not in lower]
    if not missing:
        return []
    empty_body = (st == 204 or
                  (isinstance(body, bytes) and not body) or
                  (isinstance(body, str) and not body))
    if empty_body:
        # 204/empty responses CAN carry headers: keep the config finding
        # (do not hide a proven absence) but downgrade — absence against
        # an empty-body response is weaker evidence than against content
        return [Finding(
            title="Missing security response headers",
            severity="low",
            verification="candidate",
            verification_note=(
                "Security headers absent on a %d empty-body response; "
                "evidence is weaker than on a content response — manual "
                "check against a normal content-bearing request "
                "recommended. Missing: %s" % (st, ", ".join(missing))),
            manual_check=_curl(base_url, "/"),
            location=base_url + "/",
            evidence={"missing": missing,
                      "present": [n for n in SECURITY_HEADERS
                                  if n not in missing],
                      "status": st, "empty_body": True},
            source="omega-probe/security_headers_probe")]
    return [Finding(
        title="Missing security response headers",
        severity="medium" if len(missing) >= 3 else "low",
        verification="confirmed",
        verification_note=("The following security headers are absent "
                           "from the baseline response: "
                           + ", ".join(missing)),
        manual_check=_curl(base_url, "/"),
        location=base_url + "/",
        evidence={"missing": missing,
                  "present": [n for n in SECURITY_HEADERS
                              if n not in missing]},
        source="omega-probe/security_headers_probe")]


def http_methods_probe(base_url, fetch=default_fetch):
    """OPTIONS: report only dangerous verbs actually listed in Allow. No
    destructive testing."""
    st, headers, _ = fetch("OPTIONS", base_url + "/")
    allow = headers.get("Allow") or headers.get("allow") or ""
    listed = {v.strip().upper() for v in allow.split(",") if v.strip()}
    dangerous = sorted(listed & DANGEROUS_VERBS)
    if dangerous:
        return [Finding(
            title="Potentially dangerous HTTP methods advertised via "
                  "OPTIONS",
            severity="low",
            verification="candidate",
            verification_note=("The server's OPTIONS Allow header lists: %s. "
                               "No destructive method was attempted; "
                               "whether the methods actually work requires "
                               "manual (authorized) verification." %
                               ", ".join(dangerous)),
            manual_check="curl -sS -i -X OPTIONS \"%s/\"" % base_url,
            location=base_url + "/",
            evidence={"allow": allow, "dangerous_listed": dangerous,
                      "status": st},
            source="omega-probe/http_methods_probe")]
    return []


def version_banner_probe(base_url, fetch=default_fetch):
    """INFO: Server / X-Powered-By banner disclosure."""
    st, headers, _ = fetch("GET", base_url + "/")
    lower = {k.lower(): v for k, v in headers.items()}
    banners = {}
    for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
        if lower.get(h.lower()):
            banners[h] = lower[h.lower()]
    if banners:
        return [Finding(
            title="Version banner disclosure",
            severity="info",
            verification="confirmed",
            verification_note=("Server/X-Powered-By headers disclose "
                               "software and version information."),
            manual_check=_curl(base_url, "/"),
            location=base_url + "/",
            evidence=banners,
            source="omega-probe/version_banner_probe")]
    return []


# -------------------------------------------------------------- registry

# Ordered registry: name -> probe callable. All probes are read-only;
# they issue only GET (OPTIONS for http_methods_probe) requests.
registry = [
    ("open_redirect_probe", open_redirect_probe),
    ("ssrf_probe_blind", ssrf_probe_blind),
    ("crlf_probe", crlf_probe),
    ("header_injection_probe", header_injection_probe),
    ("host_header_poison_probe", host_header_poison_probe),
    ("cors_misconfig_probe", cors_misconfig_probe),
    ("tls_info_probe", tls_info_probe),
    ("security_headers_probe", security_headers_probe),
    ("http_methods_probe", http_methods_probe),
    ("version_banner_probe", version_banner_probe),
]


# ------------------------------------------------------------ run_probes

def run_probes(target, fetch=None, budget=None, log=None, allowlist=None):
    """Run all registered read-only probes against ``target``.

    Never raises: every probe error is swallowed and reported as a skip.
    Returns {"findings": [...], "ran": [names], "skipped": {name: reason}}.
    """
    result = {"findings": [], "ran": [], "skipped": {}}
    base_url = target if "://" in target else "https://" + target
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = (
            "target %r not in allowlist" % target)
        if log:
            log("probes skipped: target not in allowlist: %r" % target)
        return result
    for name, probe in registry:
        if budget is not None and len(result["ran"]) >= budget:
            result["skipped"][name] = "budget exhausted"
            continue
        if name == "ssrf_probe_blind":
            # Needs an operator-supplied hook; skip without one rather
            # than emit weak candidate noise in a full run.
            result["skipped"][name] = "no operator-supplied hook"
            continue
        if name == "tls_info_probe" and \
                not base_url.lower().startswith("https"):
            result["skipped"][name] = "target is not https"
            continue
        try:
            found = probe(base_url, fetch or default_fetch)
        except Exception as exc:  # never raise
            result["skipped"][name] = "error: %s" % exc
            if log:
                log("probe %s failed: %s" % (name, exc))
            continue
        result["ran"].append(name)
        result["findings"].extend(found)
        if log:
            log("probe %s: %d finding(s)" % (name, len(found)))
    return result
