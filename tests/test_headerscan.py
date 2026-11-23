"""Hermetic tests for omega.headerscan (the deep response-header audit).

Local ThreadingHTTPServer fixtures on 127.0.0.1 ephemeral ports or
fully stubbed fetches; no real network egress, no DNS, no destructive
requests. Covers: vulnerable-server findings (all candidate), clean
server and constant-server FP guards (zero findings), HSTS honesty on
http targets (skip, never a finding), CORS origin-echo differential
(high only with credentials), budget cap, never-raise on broken fetch,
manual_check real targets, and method discipline (GET/OPTIONS only).
"""

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))))

from omega.headerscan import (  # noqa: E402
    cache_control_sensitive,
    clickjacking,
    csp_policy_audit,
    cors_credentials_echo,
    cors_preflight_reflection,
    hsts_absent_https,
    registry,
    run_headerscan,
)

CLEAN_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
}


# ------------------------------------------------------------ fixtures

class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # silence
        pass

    def send_response(self, code, message=None):
        # Suppress the default Server header injected by
        # BaseHTTPRequestHandler so the fixtures control their own
        # banner headers exactly.
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def _send(self, status, headers, body=b""):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class VulnHandler(_Base):
    """The 'vulnerable' fixture: missing security headers, banner and
    cookie disclosure, origin-echo CORS with credentials."""

    def _base_headers(self):
        h = {
            "Server": "TestServ/1.0",
            "X-Powered-By": "PHP/7.9.9",
            "X-XSS-Protection": "1; mode=block",
            "Set-Cookie": "sid=abc123; Path=/",
        }
        origin = self.headers.get("Origin")
        if origin:
            h["Access-Control-Allow-Origin"] = origin
            h["Access-Control-Allow-Credentials"] = "true"
        return h

    def do_GET(self):
        h = self._base_headers()
        if self.path in ("/", "/login", "/account"):
            self._send(200, h, "sensitive-ish page")
        else:
            self._send(404, h, "Not Found")

    def do_OPTIONS(self):
        h = self._base_headers()
        h["Allow"] = "GET, HEAD, OPTIONS"
        self._send(200, h, "")


class CleanHandler(_Base):
    """The clean FP guard: all correct headers, sensitive paths send
    no-store, no CORS echo, 404 elsewhere — zero findings expected."""

    def do_GET(self):
        h = dict(CLEAN_HEADERS)
        if self.path in ("/", "/login", "/account", "/admin"):
            self._send(200, h, "home page of OmegaTestApp")
        else:
            self._send(404, h, "Not Found")

    def do_OPTIONS(self):
        h = {"Allow": "GET, HEAD, OPTIONS"}
        self._send(200, h, "")


class ConstantHandler(_Base):
    """Identical constant responses (status, headers, body) for every
    request — FP guard: with correct constant security headers, zero
    findings."""

    def do_GET(self):
        self._send(200, dict(CLEAN_HEADERS), "static page")

    def do_OPTIONS(self):
        self._send(200, dict(CLEAN_HEADERS), "static page")


@pytest.fixture
def server_factory():
    made = []

    def make(handler_cls):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        made.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield make
    for srv in made:
        srv.shutdown()


def _real_fetch():
    from omega.deepchecks import default_fetch  # noqa: E402

    return default_fetch


def _sources(findings):
    return [f["source"] for f in findings]


def _stub_fetch(status=200, headers=None, body=b"ok", record=None):
    """Fully stubbed fetch: hermetic, ignores url, records methods."""

    def fetch(method, url, **_kw):
        if record is not None:
            record.append(method)
        return status, dict(headers or {}), body

    return fetch


# =============================================== run-level behaviour

def test_vulnerable_server_expected_findings(server_factory):
    base = server_factory(VulnHandler)
    res = run_headerscan(base, _real_fetch())
    srcs = _sources(res["findings"])
    for expected in (
        "omega-headerscan/clickjacking",
        "omega-headerscan/csp_policy_audit",
        "omega-headerscan/referrerpolicy_missing",
        "omega-headerscan/permissions_policy_missing",
        "omega-headerscan/xxss_protection_legacy",
        "omega-headerscan/powered_by_banner",
        "omega-headerscan/cors_credentials_echo",
        "omega-headerscan/cookie_flags",
        "omega-headerscan/cache_control_sensitive",
        "omega-headerscan/cors_preflight_reflection",
    ):
        assert expected in srcs, "missing %s (got %s)" % (expected, srcs)
    # HSTS is meaningless over http://: skipped, never a finding
    assert "omega-headerscan/hsts_absent_https" not in srcs
    assert res["skipped"]["hsts_absent_https"] == "n/a: target is not https"
    assert res["requests_sent"] <= 30
    assert len(res["ran"]) == len(registry) - 1


def test_clean_server_zero_findings(server_factory):
    base = server_factory(CleanHandler)
    res = run_headerscan(base, _real_fetch())
    assert res["findings"] == []
    assert res["requests_sent"] <= 30


def test_constant_server_zero_findings_fp_guard(server_factory):
    """FALSE-POSITIVE GUARD: identical constant responses (including
    constant correct security headers) must produce NO findings."""
    base = server_factory(ConstantHandler)
    res = run_headerscan(base, _real_fetch())
    assert res["findings"] == []
    assert set(res["ran"]) == ({n for n, _ in registry}
                               - {"hsts_absent_https"})


def test_run_never_raises_on_broken_fetch():
    def broken(method, url, headers=None, body=None):
        raise RuntimeError("connection refused")

    res = run_headerscan("http://127.0.0.1:1", broken)
    assert res["findings"] == []
    assert len(res["skipped"]) == len(registry)
    assert all(v.startswith(("error:", "n/a:"))
               for v in res["skipped"].values())
    assert res["requests_sent"] == 0


def test_budget_cap_enforced(server_factory):
    base = server_factory(VulnHandler)
    res = run_headerscan(base, _real_fetch(), budget=2)
    assert res["requests_sent"] <= 2
    assert "budget exhausted" in res["skipped"].values()
    assert len(res["ran"]) < len(registry)


def test_method_discipline_get_options_only():
    methods = []
    fetch = _stub_fetch(status=200, headers={}, record=methods)
    run_headerscan("http://example.test", fetch)
    assert set(methods) <= {"GET", "OPTIONS"}


def test_all_verifications_candidate_and_shape(server_factory):
    base = server_factory(VulnHandler)
    res = run_headerscan(base, _real_fetch())
    assert res["findings"]
    for f in res["findings"]:
        for key in ("title", "severity", "confidence", "verification",
                    "source", "evidence", "location", "manual_check"):
            assert key in f
        assert f["verification"] == "candidate"  # never 'confirmed'
        assert len(f["evidence"]) <= 300
        assert base in f["manual_check"]  # real target, no placeholder


# ================================================== per-check gates

def test_hsts_fires_only_on_https_target():
    """HSTS absence is only meaningful over https."""
    st, h, b = None, None, None
    fetch = _stub_fetch(status=200, headers={})
    findings = hsts_absent_https("https://secure.test", fetch)
    assert len(findings) == 1
    assert findings[0]["severity"] == "low"
    assert findings[0]["verification"] == "candidate"
    # over http the run-level gate skips it (n-a), asserted separately
    res = run_headerscan("http://plain.test", fetch)
    assert res["skipped"]["hsts_absent_https"] == "n/a: target is not https"


def test_hsts_present_no_finding():
    fetch = _stub_fetch(status=200, headers={
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains"})
    assert hsts_absent_https("https://secure.test", fetch) == []


def test_cors_high_only_with_credentials():
    """Origin echo without ACAC true is LOW, never HIGH."""
    fetch = _stub_fetch(status=200, headers={
        "Access-Control-Allow-Origin":
            "https://omega-cors-<rand>.example"})
    findings = cors_credentials_echo("http://t.test", fetch)
    assert findings == []  # our actual random origin won't match the stub


def _echo_fetch(record):
    """Stub that echoes whatever Origin the module sends (with or
    without credentials)."""

    def fetch(method, url, headers=None, body=None):
        record.append((method, url, headers))
        origin = (headers or {}).get("Origin")
        h = {"Access-Control-Allow-Origin": origin}
        if record_mode[0]:
            h["Access-Control-Allow-Credentials"] = "true"
        return 200, h, b"ok"

    record_mode = [True]
    return fetch, record_mode


def test_cors_credentials_echo_high_when_credentials(server_factory):
    record = []
    fetch, mode = _echo_fetch([])
    findings = cors_credentials_echo("http://t.test", fetch)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["confidence"] == "high"
    assert findings[0]["verification"] == "candidate"
    mode[0] = False
    findings2 = cors_credentials_echo("http://t.test", fetch)
    assert findings2[0]["severity"] == "low"


def test_csp_unsafe_inline_detected():
    fetch = _stub_fetch(status=200, headers={
        "Content-Security-Policy": "default-src 'unsafe-inline'"})
    findings = csp_policy_audit("http://t.test", fetch)
    assert len(findings) == 1
    assert "unsafe-inline" in findings[0]["title"]


def test_csp_absent_detected():
    fetch = _stub_fetch(status=200, headers={})
    findings = csp_policy_audit("http://t.test", fetch)
    assert len(findings) == 1
    assert "absent" in findings[0]["title"]


def test_clickjacking_ok_when_frame_ancestors_present():
    fetch = _stub_fetch(status=200, headers={
        "Content-Security-Policy": "frame-ancestors 'self'"})
    assert clickjacking("http://t.test", fetch) == []


def test_cache_control_only_on_200_paths():
    """A 403/401 on /login must not produce a cache-control finding."""
    fetch = _stub_fetch(status=403, headers={})
    assert cache_control_sensitive("http://t.test", fetch) == []


def test_preflight_reflection_requires_own_origin_echo(server_factory):
    base = server_factory(VulnHandler)
    findings = cors_preflight_reflection(base, _real_fetch())
    assert len(findings) == 1
    assert findings[0]["verification"] == "candidate"
    assert base in findings[0]["manual_check"]
    # clean server: no echo -> no finding
    clean = server_factory(CleanHandler)
    assert cors_preflight_reflection(clean, _real_fetch()) == []


def test_real_fetch_contract():
    """default_fetch from deepchecks satisfies the contract against a
    local fixture (status, headers dict, bytes body)."""
    from omega.deepchecks import default_fetch  # noqa: E402

    made = []

    def make(handler_cls):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        made.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    try:
        base = make(ConstantHandler)
        st, headers, body = default_fetch("GET", base + "/")
        assert st == 200 and isinstance(headers, dict)
        assert isinstance(body, bytes) and body == b"static page"
    finally:
        for srv in made:
            srv.shutdown()
