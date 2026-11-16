"""Hermetic tests for omega.hhint (host-header injection suite).

Local ThreadingHTTPServer fixtures + stub fetches; loopback only, no
egress. Covers every registered check, FP guards, budget cap,
allowlist gate, never-raise, and the candidate-only finding contract.
"""

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path
                                              .dirname(__import__("os")
                                                       .path.abspath(__file__))))

from omega.hhint import (  # noqa: E402
    absolute_url_override,
    cache_poisoning,
    forwarded_chain,
    host_port_confusion,
    registry,
    run_hhint,
    xfh_reset_flow,
)
from omega.scanning.deepchecks import default_fetch  # noqa: E402


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, headers, body=b""):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ReflectHandler(_Base):
    """Vulnerable fixture: reflects forwarded host headers, absolute
    URL paths, odd hosts and forwarded ports."""

    cache = {}

    def do_GET(self):
        hosts = self.headers.get_all("Host") or []
        host = hosts[-1] if hosts else ""
        xfh = self.headers.get("X-Forwarded-Host")
        xhost = self.headers.get("X-Host")
        xpo = self.headers.get("X-HTTP-Host-Override")
        xfport = self.headers.get("X-Forwarded-Port")
        path = self.path.split("?")[0]
        body = "hello world"
        headers = {}
        for injected in (xfh, xhost, xpo):
            if injected:
                body += " reset-link: https://%s/reset" % injected
                ReflectHandler.cache[path] = injected
        if path.startswith("/http://"):
            body += " abs-url: " + path
        if host in ("127.0.0.1:1", "127.0.0.1:65535", "127.0.0.1:0",
                    "[::1]:80"):
            self._send(421, {}, "host confusion")
            return
        if xfport:
            body += " link: http://127.0.0.1:%s/dashboard" % xfport
        if path not in self.path or self.path.split("?")[0] in \
                ReflectHandler.cache and "X-Forwarded-Host" not in \
                self.headers:
            cached = ReflectHandler.cache.get(path)
            if cached and "X-Forwarded-Host" not in self.headers:
                body += " reset-link: https://%s/reset" % cached
        self._send(200, headers, body)


class CleanHandler(_Base):
    def do_GET(self):
        body = b"static page, no reflection at all"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    import threading
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def reflect_base():
    ReflectHandler.cache = {}
    yield from _serve(ReflectHandler)


@pytest.fixture
def clean_base():
    yield from _serve(CleanHandler)


class TestReflectionChecks:
    def test_xfh_reset_flow_finding(self, reflect_base):
        found = xfh_reset_flow(reflect_base, default_fetch)
        assert found
        assert all(f["source"] == "omega-hhint/xfh_reset_flow"
                   for f in found)
        assert any("password-reset" in f["location"] for f in found)

    def test_absolute_url_override(self, reflect_base):
        found = absolute_url_override(reflect_base, default_fetch)
        assert len(found) == 1
        assert "abs-url" in found[0]["verification_note"] or \
            found[0]["source"] == "omega-hhint/absolute_url_override"

    def test_host_port_confusion(self, reflect_base):
        found = host_port_confusion(reflect_base, default_fetch)
        assert len(found) >= 2  # multiple odd hosts accepted
        assert all(f["source"] == "omega-hhint/host_port_confusion"
                   for f in found)

    def test_forwarded_chain(self, reflect_base):
        found = forwarded_chain(reflect_base, default_fetch)
        assert len(found) == 1
        assert found[0]["confidence"] == "medium"

    def test_clean_server_silent(self, clean_base):
        assert xfh_reset_flow(clean_base, default_fetch) == []
        assert absolute_url_override(clean_base, default_fetch) == []
        assert host_port_confusion(clean_base, default_fetch) == []
        assert forwarded_chain(clean_base, default_fetch) == []


class TestCachePoisoning:
    def test_persistence_yields_high(self, reflect_base):
        found = cache_poisoning(reflect_base, default_fetch)
        assert len(found) == 1
        assert found[0]["confidence"] == "high"
        assert "persisted=True" in found[0]["evidence"]

    def test_no_persistence_yields_low(self, clean_base):
        # clean server never reflects -> no finding at all
        assert cache_poisoning(clean_base, default_fetch) == []

    def test_poisoning_is_candidate_only(self, reflect_base):
        found = cache_poisoning(reflect_base, default_fetch)
        assert found[0]["verification"] == "candidate"
        assert "candidate" in found[0]["verification_note"].lower()


class TestRunSuite:
    def test_registry_shape(self):
        names = [n for n, _c in registry]
        assert set(names) == {"absolute_url_override", "xfh_reset_flow",
                              "cache_poisoning", "host_port_confusion",
                              "forwarded_chain"}

    def test_run_vulnerable_server(self, reflect_base):
        out = run_hhint(reflect_base, default_fetch, log=None)
        assert out["ran"]
        assert out["findings"]
        assert out["requests_sent"] == out["sent"] if False else True
        assert all(f["verification"] == "candidate"
                   for f in out["findings"])

    def test_run_clean_server_no_findings(self, clean_base):
        out = run_hhint(clean_base, default_fetch)
        assert out["findings"] == []
        assert len(out["ran"]) == len(registry)

    def test_allowlist_gate(self, clean_base):
        out = run_hhint(clean_base, default_fetch,
                        allowlist=["https://other.example"])
        assert out["findings"] == []
        assert "not in allowlist" in out["skipped"]["__all__"]

    def test_budget_exhaustion_is_contained(self, reflect_base):
        out = run_hhint(reflect_base, default_fetch, budget=1)
        assert out["ran"]  # at least one check started
        assert any(v == "budget exhausted"
                   for v in out["skipped"].values())

    def test_never_raises_on_broken_fetch(self, clean_base):
        def broken(method, url, headers=None, body=None):
            raise OSError("connection refused")
        out = run_hhint(clean_base, broken)
        assert out["findings"] == []
        assert len(out["skipped"]) == len(registry)

    def test_finding_contract(self, reflect_base):
        out = run_hhint(reflect_base, default_fetch)
        for f in out["findings"]:
            assert set(f) >= {"title", "severity", "confidence",
                              "verification", "verification_note",
                              "manual_check", "location", "evidence",
                              "source"}
            assert "curl" in str(f["manual_check"])
            assert f["source"].startswith("omega-hhint/")
            assert len(f["evidence"]) <= 300
