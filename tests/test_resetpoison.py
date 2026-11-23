"""Hermetic tests for omega.scanning.resetpoison.

Loopback servers: one reflecting injected Host/X-Forwarded-Host into a
reset link, one clean. Plus token-in-URL, budget and never-raise cases.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.deepchecks import default_fetch
from omega.scanning.resetpoison import (
    INJECT_HOST,
    run_resetpoison,
)


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

    def do_GET(self):
        raise NotImplementedError

    def do_POST(self):
        raise NotImplementedError


class VulnHandler(_Base):
    def do_GET(self):
        # emulate a cached poisoned page
        if VulnHandler.poisoned:
            self._send(200, "<a href='https://%s/reset?token=abc'>"
                            "password reset link</a>" % INJECT_HOST)
            return
        self._send(200, "password reset page")

    def do_POST(self):
        host = self.headers.get("Host") or ""
        xfh = self.headers.get("X-Forwarded-Host") or ""
        if INJECT_HOST in host or INJECT_HOST in xfh:
            VulnHandler.poisoned = True
            link = "https://%s/reset-password?token=deadbeef1234" \
                   % (INJECT_HOST if INJECT_HOST in host else xfh)
            self._send(200, "password reset: <a href=\"%s\">reset</a>"
                            % link)
            return
        self._send(200, "password reset requested")

    @classmethod
    def reset(cls):
        cls.poisoned = False


class TokenLeakHandler(_Base):
    """Reset page that embeds the token in the URL (Location header)."""

    def do_GET(self):
        self._send(302, "", {"Location": "/reset?token=abcdef1234567890"})

    def do_POST(self):
        self._send(200, "ok")


class RejectPostHandler(_Base):
    def do_GET(self):
        self._send(200, "reset page")

    def do_POST(self):
        self._send(405, "no post")


class CleanHandler(_Base):
    def do_GET(self):
        self._send(200, "reset page, nothing injected")

    def do_POST(self):
        self._send(200, "reset requested")


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture(scope="module")
def vuln_base():
    VulnHandler.reset()
    srv = _serve(VulnHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def token_base():
    srv = _serve(TokenLeakHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def reject_base():
    srv = _serve(RejectPostHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def clean_base():
    srv = _serve(CleanHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_poisoning_finding_on_vulnerable_server(vuln_base):
    VulnHandler.reset()
    found = run_resetpoison(vuln_base, default_fetch,
                            path_info={"paths": ["/forgot-password"]})
    assert found
    assert any(f["severity"] == "high"
               and f["verification"] == "candidate"
               and f["source"] == "omega-resetpoison" for f in found)
    assert any(INJECT_HOST in f["title"] or INJECT_HOST in f["evidence"]
               for f in found)


def test_token_in_url_low_candidate(token_base):
    found = run_resetpoison(token_base, default_fetch,
                            path_info={"paths": ["/reset"]})
    assert any(f["severity"] == "low" and "token" in f["title"].lower()
               for f in found)


def test_non_post_endpoint_skipped(reject_base):
    assert run_resetpoison(reject_base, default_fetch) == []


def test_clean_server_yields_nothing(clean_base):
    assert run_resetpoison(clean_base, default_fetch) == []


def test_default_reset_paths_probed(vuln_base):
    VulnHandler.reset()
    # no path_info: the default /forgot-password path is exercised
    found = run_resetpoison(vuln_base, default_fetch)
    assert any("forgot-password" in f["location"] for f in found)


def test_budget_cap_respected(vuln_base):
    VulnHandler.reset()
    counter = {"n": 0}
    orig = default_fetch

    def counting(method, url, headers=None, body=None):
        counter["n"] += 1
        return orig(method, url, headers=headers, body=body)

    run_resetpoison(vuln_base, counting, budget=8)
    assert counter["n"] <= 8


def test_never_raises_on_broken_fetch():
    def boom(*a, **k):
        raise RuntimeError("boom")

    assert run_resetpoison("http://127.0.0.1:1", boom) == []


def test_probe_emails_are_benign(vuln_base):
    VulnHandler.reset()
    bodies = []

    def spy(method, url, headers=None, body=None):
        if method == "POST" and body:
            bodies.append(body)
        return default_fetch(method, url, headers=headers, body=body)

    run_resetpoison(vuln_base, spy)
    assert bodies
    assert all("omegaprobe.invalid" in b for b in bodies)
