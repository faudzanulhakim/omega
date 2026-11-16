"""Hermetic tests for omega.scanning.cspanalyze.

Loopback ThreadingHTTPServer fixtures (weak-CSP + clean-CSP + no-CSP)
only; no egress. Covers parse_csp, every weakness rule, per-location
dedup, candidate contract and never-raise behavior.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.cspanalyze import csp_weaknesses, parse_csp, \
    run_cspanalyze
from omega.scanning.deepchecks import default_fetch

WEAK_CSP = ("default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' "
            "*.cdn.example.com data: http:; style-src 'self'")

NO_REPORT_CSP = "default-src 'self'; script-src 'self'; object-src 'none'"

GOOD_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; "
            "object-src 'none'; frame-ancestors 'self'; report-to csp-end")


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, body=b"", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class WeakHandler(_Base):
    def do_GET(self):
        self._send(200, "page", headers={
            "Content-Security-Policy": WEAK_CSP})


class CleanHandler(_Base):
    def do_GET(self):
        self._send(200, "page", headers={
            "Content-Security-Policy": GOOD_CSP})


class NoCspHandler(_Base):
    def do_GET(self):
        self._send(200, "page")


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture(scope="module")
def weak_base():
    srv = _serve(WeakHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def clean_base():
    srv = _serve(CleanHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def nocsp_base():
    srv = _serve(NoCspHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_parse_csp_directives():
    d = parse_csp(WEAK_CSP)
    assert d["default-src"] == ["'self'"]
    assert "'unsafe-inline'" in d["script-src"]
    assert "*.cdn.example.com" in d["script-src"]
    assert "data:" in d["script-src"]
    assert parse_csp("") == {}


def test_unsafe_inline_eval_medium():
    d = parse_csp(WEAK_CSP)
    issues = {k: (sev, title) for k, sev, title, _n in csp_weaknesses(d)}
    assert issues["script-unsafe"][0] == "medium"
    assert "unsafe-inline" in issues["script-unsafe"][1]
    assert issues["script-wildcard"][0] == "medium"
    assert issues["script-scheme"][0] == "medium"


def test_missing_and_weak_directives():
    d = parse_csp("default-src 'self'")
    issues = {k: sev for k, sev, _t, _n in csp_weaknesses(d)}
    assert issues.get("no-script-src") == "medium"
    assert issues.get("object-src") == "low"
    assert issues.get("frame-ancestors") == "low"
    assert issues.get("no-reporting") == "info"


def test_frame_ancestors_star_low():
    d = parse_csp("script-src 'self'; frame-ancestors *; report-uri /r")
    issues = {k: sev for k, sev, _t, _n in csp_weaknesses(d)}
    assert issues.get("frame-ancestors-star") == "low"
    # report-uri present -> no reporting finding
    assert "no-reporting" not in issues


def test_weak_server_finding_contract(weak_base):
    found = run_cspanalyze(weak_base, default_fetch,
                           path_info={"paths": ["/main"]})
    assert found, "expected CSP weakness findings"
    for f in found:
        assert f["source"] == "omega-cspanalyze"
        assert f["verification"] == "candidate"
        assert f["severity"] in ("low", "medium", "info")
        assert f["location"].startswith(weak_base)
    locs = [(f["location"], f["title"]) for f in found]
    # no duplicate (location, issue) pairs
    assert len(locs) == len(set(locs))


def test_clean_policy_no_medium_findings(clean_base):
    found = run_cspanalyze(clean_base, default_fetch)
    assert all(f["severity"] not in ("medium", "high") for f in found)


def test_no_csp_header_no_findings(nocsp_base):
    assert run_cspanalyze(nocsp_base, default_fetch) == []


def test_never_raises_on_dead_target():
    assert run_cspanalyze("http://127.0.0.1:1", default_fetch) == []
    assert run_cspanalyze("", lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("boom"))) == []
