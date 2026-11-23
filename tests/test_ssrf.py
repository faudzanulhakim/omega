"""Hermetic tests for omega.scanning.ssrf.

Loopback servers: one that fetches/echoes the url parameter back
(SSRF-vulnerable), one that sleeps on same-host url requests (timing
differential), and a clean server. Covers HIGH candidates from echo,
timing, HTML shapes, clean targets, bounds and never-raise behavior.
"""

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from omega.scanning.deepchecks import default_fetch
from omega.scanning.ssrf import URLISH_PARAMS, html_shape, run_ssrf, \
    ssrf_params


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, body=b"", ctype="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class EchoHandler(_Base):
    """Vulnerable: the server-side 'fetches' the url param value and
    embeds the response body (marker) in its own response."""

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        url = (q.get("url") or q.get("redirect") or [""])[0]
        if url:
            self._send(200, "<html>fetched: %s</html>" % url)
        else:
            self._send(200, "<html>plain page</html>")


class TimingHandler(_Base):
    """Vulnerable via timing: sleeps when the url param points at the
    same host (simulating a server-side fetch of the marker)."""

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        url = (q.get("url") or [""])[0]
        if url and ("127.0.0.1" in url or "localhost" in url):
            time.sleep(0.4)
            self._send(200, "<html>done</html>")
        else:
            self._send(200, "<html>fast page</html>")


class CleanHandler(_Base):
    def do_GET(self):
        self._send(200, "<html>plain page</html>")


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture(scope="module")
def echo_base():
    srv = _serve(EchoHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def timing_base():
    srv = _serve(TimingHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def clean_base():
    srv = _serve(CleanHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_echo_high_candidate(echo_base):
    found = run_ssrf(echo_base, default_fetch)
    assert found
    f = found[0]
    assert f["severity"] == "high"
    assert f["verification"] == "candidate"
    assert f["source"] == "omega-ssrf"
    assert "omega-ssrf" in f["evidence"] or "marker" in f["title"].lower()


def test_timing_high_candidate(timing_base):
    found = run_ssrf(timing_base, default_fetch)
    assert found
    assert any(f["severity"] == "high" and
               ("timing" in f["verification_note"] or
                "marker" in f["title"].lower()) for f in found)


def test_urls_only_point_at_scanned_host_or_loopback():
    """Defense contract: the module only builds marker URLs for the
    scanned host / 127.0.0.1. Inspect built shapes."""
    shape = html_shape("meta-refresh", "http", "example.test", 8080,
                       "omega-ssrf-abc")
    assert "example.test:8080" in shape
    assert "127.0.0.1" not in shape
    loop = html_shape("link-href", "https", "127.0.0.1", 443, "mk")
    assert loop.startswith("<link") and "127.0.0.1:443" in loop
    # URL-ish parameter list is fixed and internal-only semantics.
    assert "url" in URLISH_PARAMS and "callback" in URLISH_PARAMS


def test_param_discovery_from_path_info(echo_base):
    pairs = ssrf_params("/fetch", ["url", "q", "redirect", "name"])
    assert ("/fetch", "url") in pairs
    assert ("/fetch", "redirect") in pairs
    assert ("/fetch", "q") not in pairs
    assert len(pairs) <= 3


def test_clean_target_no_findings(clean_base):
    assert run_ssrf(clean_base, default_fetch) == []


def test_never_raises_on_dead_target():
    assert run_ssrf("http://127.0.0.1:1", default_fetch) == []


def test_never_raises_on_bad_fetch():
    def boom(*a, **kw):
        raise RuntimeError("boom")
    assert run_ssrf("http://127.0.0.1:1", boom) == []
