"""Hermetic tests for omega.probes.

Local ThreadingHTTPServer fixtures per probe; fetch injectable so no real
network is touched (except none at all — TLS probe uses an ssl stub).
"""

import json
import ssl
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.probes import (
    allowlist_ok,
    crlf_probe,
    cors_misconfig_probe,
    header_injection_probe,
    host_header_poison_probe,
    http_methods_probe,
    open_redirect_probe,
    registry,
    run_probes,
    security_headers_probe,
    ssrf_probe_blind,
    tls_info_probe,
    version_banner_probe,
    _NoRedirect,
)

import urllib.request


# ------------------------------------------------------------ fixtures

class _Handler(BaseHTTPRequestHandler):
    """Configurable handler: subclass and override do_GET/do_OPTIONS."""

    def log_message(self, *a):  # silence
        pass

    def _send(self, status, headers, body=b""):
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


def _serve(handler, methods=("GET",)):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


@pytest.fixture
def server_factory():
    made = []

    def make(handler_cls):
        srv, url = _serve(handler_cls)
        made.append(srv)
        return url

    yield make
    for srv in made:
        srv.shutdown()


# A real-fetch via urllib against the local server, never following
# redirects (same policy as the probe default).
def real_fetch(method, url, headers=None):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=5) as resp:
            return resp.status, dict(resp.headers.items()), resp.read(65536)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items() if exc.headers else {}), \
            (exc.read(65536) if hasattr(exc, "read") else b"")


import urllib.error  # noqa: E402  (after helper definition use)


# ------------------------------------------------------- open_redirect

class RedirectHandler(_Handler):
    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if "next" in qs:
            self._send(302, {"Location": qs["next"][0]})
        else:
            self._send(200, {"Content-Type": "text/plain"}, b"home")


def test_open_redirect_confirmed(server_factory):
    base = server_factory(RedirectHandler)
    findings = open_redirect_probe(base, real_fetch)
    assert len(findings) == 1
    f = findings[0]
    assert f["verification"] == "confirmed"
    assert f["source"] == "omega-probe/open_redirect_probe"
    assert "curl" in f["manual_check"]
    assert base in f["manual_check"]  # real target substituted
    assert "//evil.example" in f["manual_check"]


class SafeRedirectHandler(_Handler):
    """Redirects but only to same-origin paths (ignore the param)."""

    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if "next" in qs:
            self._send(302, {"Location": "/login"})
        else:
            self._send(200, {}, b"home")


def test_open_redirect_candidate_guard(server_factory):
    """FP guard: same-origin redirect yields NO finding at all."""
    base = server_factory(SafeRedirectHandler)
    assert open_redirect_probe(base, real_fetch) == []


class NoRedirectHandler(_Handler):
    def do_GET(self):
        self._send(200, {}, b"home")


def test_open_redirect_no_location_no_finding(server_factory):
    base = server_factory(NoRedirectHandler)
    assert open_redirect_probe(base, real_fetch) == []


# ------------------------------------------------------------ ssrf

class Hook:
    url = "http://canary-hook.invalid/abc"
    hits = []


def test_ssrf_confirmed_with_hook_hit(server_factory):
    class SSRFHandler(_Handler):
        def do_GET(self):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if "url" in qs:
                Hook.hits.append(qs["url"][0])
            self._send(200, {}, b"ok")

    base = server_factory(SSRFHandler)
    Hook.hits = []
    findings = ssrf_probe_blind(base, real_fetch, hook_url=Hook)
    assert findings and findings[0]["verification"] == "confirmed"
    assert findings[0]["evidence"]["param"] == "url"


def test_ssrf_candidate_without_hook(server_factory):
    base = server_factory(NoRedirectHandler)
    findings = ssrf_probe_blind(base, real_fetch, hook_url=None)
    # No hook at all: no evidence, no finding.
    assert findings == []


def test_ssrf_candidate_when_hook_silent(server_factory):
    class SilentHook:
        url = "http://canary-hook.invalid/x"
        hits = []

    base = server_factory(NoRedirectHandler)
    findings = ssrf_probe_blind(base, real_fetch, hook_url=SilentHook)
    assert len(findings) == 1
    assert findings[0]["verification"] == "candidate"


# ------------------------------------------------------------ crlf

class CRLFHeaderHandler(_Handler):
    """Echoes the marker as a real response header."""

    def do_GET(self):
        marker = self.path.lstrip("/").split("%0d%0a")[0]  # unused
        raw = urllib.parse.unquote(self.path)
        if "X-OMEGA-CRLF-MARKER" in raw:
            self._send(200, {"X-OMEGA-CRLF-MARKER": "1",
                             "Content-Type": "text/plain"}, b"ok")
        else:
            self._send(200, {}, b"ok")


def test_crlf_confirmed_header_echo(server_factory):
    base = server_factory(CRLFHeaderHandler)
    findings = crlf_probe(base, real_fetch)
    assert findings and findings[0]["verification"] == "confirmed"


class CRLFBodyHandler(_Handler):
    def do_GET(self):
        raw = urllib.parse.unquote(self.path)
        if "X-OMEGA-CRLF-MARKER" in raw:
            self._send(200, {}, b"echo " + raw.encode())
        else:
            self._send(200, {}, b"ok")


def test_crlf_candidate_body_only(server_factory):
    """FP guard: body echo alone stays candidate."""
    base = server_factory(CRLFBodyHandler)
    findings = crlf_probe(base, real_fetch)
    assert findings and findings[0]["verification"] == "candidate"
    assert findings[0]["evidence"]["reflected_in"] == "body"


# ------------------------------------------------- header_injection

class HeaderReflectHandler(_Handler):
    def do_GET(self):
        xfh = self.headers.get("X-Forwarded-Host")
        xou = self.headers.get("X-Original-URL")
        body = b"home"
        if xfh:
            body += ("" + xfh).encode()
        if xou:
            body += ("" + xou).encode()
        self._send(200, {}, body)


def test_header_injection_confirmed_differential(server_factory):
    base = server_factory(HeaderReflectHandler)
    findings = header_injection_probe(base, real_fetch)
    assert len(findings) == 2
    assert all(f["verification"] == "confirmed" for f in findings)


def test_header_injection_no_finding_when_not_reflected(server_factory):
    base = server_factory(NoRedirectHandler)
    assert header_injection_probe(base, real_fetch) == []


# ------------------------------------------- host_header_poison

class HostPoisonHandler(_Handler):
    def do_GET(self):
        host = self.headers.get("Host", "")
        if "evil.example" in host:
            self._send(302, {"Location": "http://evil.example/login"})
        else:
            self._send(200, {}, b"home")


def test_host_header_poison_confirmed(server_factory):
    base = server_factory(HostPoisonHandler)
    findings = host_header_poison_probe(base, real_fetch)
    assert findings and findings[0]["verification"] == "confirmed"


def test_host_header_poison_no_finding_when_ignored(server_factory):
    base = server_factory(NoRedirectHandler)
    assert host_header_poison_probe(base, real_fetch) == []


# ------------------------------------------------------------- cors

class CorsEchoHandler(_Handler):
    def do_GET(self):
        origin = self.headers.get("Origin")
        h = {}
        if origin:
            h["Access-Control-Allow-Origin"] = origin
            h["Access-Control-Allow-Credentials"] = "true"
        self._send(200, h, b"ok")


def test_cors_confirmed_echo_with_credentials(server_factory):
    base = server_factory(CorsEchoHandler)
    findings = cors_misconfig_probe(base, real_fetch)
    assert findings and findings[0]["verification"] == "confirmed"
    assert findings[0]["severity"] == "high"


class CorsNoCredsHandler(_Handler):
    def do_GET(self):
        origin = self.headers.get("Origin")
        h = {}
        if origin:
            h["Access-Control-Allow-Origin"] = origin  # no ACAC
        self._send(200, h, b"ok")


def test_cors_candidate_without_credentials(server_factory):
    """FP guard: origin echo without ACAC stays candidate."""
    base = server_factory(CorsNoCredsHandler)
    findings = cors_misconfig_probe(base, real_fetch)
    assert findings and findings[0]["verification"] == "candidate"


# -------------------------------------------------------- security_headers

class InsecureHeadersHandler(_Handler):
    def do_GET(self):
        self._send(200, {"Content-Type": "text/plain"}, b"ok")


def test_security_headers_exact_missing_list(server_factory):
    base = server_factory(InsecureHeadersHandler)
    findings = security_headers_probe(base, real_fetch)
    assert len(findings) == 1
    assert findings[0]["evidence"]["missing"] == [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]


class SecureHeadersHandler(_Handler):
    def do_GET(self):
        self._send(200, {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }, b"ok")


def test_security_headers_all_present_no_finding(server_factory):
    base = server_factory(SecureHeadersHandler)
    assert security_headers_probe(base, real_fetch) == []


def test_security_headers_partial_missing(server_factory):
    class Partial(_Handler):
        def do_GET(self):
            self._send(200, {"X-Frame-Options": "DENY"}, b"ok")

    base = server_factory(Partial)
    findings = security_headers_probe(base, real_fetch)
    assert findings[0]["evidence"]["missing"] == [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]


# ------------------------------------------------------ http_methods

class OptionsHandler(_Handler):
    def do_OPTIONS(self):
        self._send(200, {"Allow": "GET, POST, PUT, DELETE"}, b"")

    def do_GET(self):
        self._send(200, {}, b"ok")


def test_http_methods_lists_dangerous_verbs_only(server_factory):
    base = server_factory(OptionsHandler)
    findings = http_methods_probe(base, real_fetch)
    assert len(findings) == 1
    assert findings[0]["evidence"]["dangerous_listed"] == ["DELETE", "PUT"]
    assert findings[0]["verification"] == "candidate"


class SafeOptionsHandler(_Handler):
    def do_OPTIONS(self):
        self._send(200, {"Allow": "GET, HEAD, OPTIONS"}, b"")

    def do_GET(self):
        self._send(200, {}, b"ok")


def test_http_methods_safe_allowlist_no_finding(server_factory):
    base = server_factory(SafeOptionsHandler)
    assert http_methods_probe(base, real_fetch) == []


# ------------------------------------------------- version_banner

class BannerHandler(_Handler):
    def do_GET(self):
        self._send(200, {"Server": "nginx/1.18.0",
                         "X-Powered-By": "PHP/7.4.3"}, b"ok")


def test_version_banner_info(server_factory):
    base = server_factory(BannerHandler)
    findings = version_banner_probe(base, real_fetch)
    assert len(findings) == 1
    assert findings[0]["verification"] == "confirmed"
    assert findings[0]["severity"] == "info"
    assert findings[0]["evidence"]["Server"] == "nginx/1.18.0"


def test_version_banner_no_banner_no_finding():
    """Hermetic: a stub fetch returning no banner headers -> no finding."""
    def stub_fetch(method, url, headers=None):
        return 200, {"Content-Type": "text/plain"}, b"ok"
    assert version_banner_probe("http://stub.example", stub_fetch) == []


# ------------------------------------------------------- tls (stubbed)

class FakeSSLContext:
    """ssl stub: returns a fixed PEM certificate."""

    def get_server_certificate(self, hostport, timeout=None):
        host, port = hostport
        return ("-----BEGIN CERTIFICATE-----\n"
                "MIIBtestcn=stub-echoserver.example\n"
                "-----END CERTIFICATE-----\n")


def test_tls_info_probe_stub():
    findings = tls_info_probe("https://stub.example",
                              fetch=real_fetch,
                              ssl_ctx=FakeSSLContext())
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "info"
    assert f["source"] == "omega-probe/tls_info_probe"
    assert "stub.example" in f["location"]


def test_tls_info_probe_skips_http():
    assert tls_info_probe("http://plain.example",
                          fetch=real_fetch, ssl_ctx=FakeSSLContext()) == []


def test_tls_info_probe_error_is_candidate():
    class FailCtx:
        def get_server_certificate(self, hostport, timeout=None):
            raise ssl.SSLError("handshake failed")

    findings = tls_info_probe("https://dead.example", fetch=real_fetch,
                              ssl_ctx=FailCtx())
    assert findings and findings[0]["verification"] == "candidate"


# ------------------------------------------------------- allowlist

def test_allowlist_matches_host():
    assert allowlist_ok("http://app.local:8080/", ["app.local"])
    assert not allowlist_ok("http://app.local/", ["other.local"])
    assert allowlist_ok("http://10.0.0.5/", ["10.0.0.0/8"])
    assert not allowlist_ok("http://10.9.9.9/", ["10.0.0.0/30"])
    assert allowlist_ok("http://anything/", None)  # None = unrestricted


# ------------------------------------------------------- run_probes

def test_run_probes_happy_path(server_factory):
    base = server_factory(NoRedirectHandler)
    logs = []
    res = run_probes(base, fetch=real_fetch, log=logs.append)
    assert "error" not in str(res["skipped"])
    assert len(res["ran"]) == len(registry) - 2  # ssrf+tls skipped
    # BaseHTTP emits a Server banner and no security headers, so the
    # security-headers and version-banner probes both legitimately fire.
    srcs = {f["source"] for f in res["findings"]}
    assert srcs == {"omega-probe/security_headers_probe",
                    "omega-probe/version_banner_probe"}
    assert any("ssrf_probe_blind" in s for s in res["skipped"])
    assert any("tls_info_probe" in s for s in res["skipped"])
    assert logs  # log callable used


def test_run_probes_budget(server_factory):
    base = server_factory(NoRedirectHandler)
    res = run_probes(base, fetch=real_fetch, budget=3)
    assert len(res["ran"]) == 3
    # ssrf_probe_blind is skipped for lack of a hook, so the budget is
    # consumed by other probes and later ones are marked exhausted.
    assert res["skipped"]["ssrf_probe_blind"] == "no operator-supplied hook"
    assert "budget exhausted" in res["skipped"]["host_header_poison_probe"]


def test_run_probes_allowlist_blocks_all(server_factory):
    base = server_factory(NoRedirectHandler)
    res = run_probes(base, fetch=real_fetch,
                     allowlist=["not-the-target.example"])
    assert res["ran"] == []
    assert res["findings"] == []
    assert "__all__" in res["skipped"]


def test_run_probes_never_raises_on_dead_target():
    res = run_probes("http://127.0.0.1:1/", fetch=real_fetch)
    assert res["ran"] == []
    assert res["findings"] == []
    # every non-network-reachable probe is skipped (error or not-https)
    assert len(res["skipped"]) == len(registry)


def test_run_probes_records_findings(server_factory):
    base = server_factory(RedirectHandler)
    res = run_probes(base, fetch=real_fetch)
    srcs = {f["source"] for f in res["findings"]}
    assert "omega-probe/open_redirect_probe" in srcs
    for f in res["findings"]:
        assert f["verification"] in ("candidate", "confirmed")
        assert base in f["manual_check"]  # real target, never placeholder


# ------------------------------------------------- registry audit

def test_registry_has_at_least_nine_probes():
    assert len(registry) >= 9


def test_registry_probes_are_read_only_methods():
    """Every probe only ever issues GET (OPTIONS for methods probe): use a
    recording fetch across all fixtures and assert no POST bodies, no
    subprocess/shell calls."""
    import subprocess as _sub
    recorded = []

    def recording_fetch(method, url, headers=None):
        recorded.append((method, url, headers))
        return 200, {"Allow": "GET, PUT"}, b"ok"

    # Dead-https target: tls probe path also exercised via stub-free error
    for name, probe in registry:
        kwargs = {}
        if name == "ssrf_probe_blind":
            kwargs["hook_url"] = "http://hook.invalid/x"
        if name == "tls_info_probe":
            kwargs["ssl_ctx"] = FakeSSLContext()
        probe("http://target.example", recording_fetch, **kwargs)
    methods = {m for m, _, _ in recorded}
    assert methods <= {"GET", "OPTIONS"}, methods
    # no POST/PUT bodies ever sent
    assert all(m not in ("POST", "PUT", "DELETE", "PATCH")
               for m, _, _ in recorded)
    # no shell-out: registry functions reference no subprocess/os.system
    import inspect
    from omega import probes as probes_mod
    for fname, probe in registry:
        src = inspect.getsource(probe)
        for bad in ("subprocess", "os.system", "os.popen", "pty.spawn",
                    "eval(", "exec("):
            assert bad not in src, (fname, bad)
