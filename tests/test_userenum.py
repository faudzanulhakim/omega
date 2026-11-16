"""Hermetic tests for omega.scanning.userenum.

Loopback servers: one responding with distinct messages per profile
(vulnerable), one uniform (clean), one timing-differential server.
Plus budget, never-raise and no-real-user guarantee cases.
"""

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.deepchecks import default_fetch
from omega.scanning.userenum import (
    ENUM_MARKER,
    PROBE_EMAILS,
    run_userenum,
)


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, body=b""):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, "login page")

    def do_POST(self):
        raise NotImplementedError


class VulnHandler(_Base):
    """Distinct message for bad-password vs nonexistent-user."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("latin-1")
        if "password=x&" in body + "&" or body.endswith("password=x"):
            self._send(200, "invalid password format")
            return
        self._send(200, "no such user, check your email")


class UniformHandler(_Base):
    """Identical response for every probe — healthy behavior."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self._send(200, "if the account exists we sent an email")


class TimingHandler(_Base):
    """Uniform messages but a deliberate ~250ms delay for the bad-
    password profile (timing side-channel)."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("latin-1")
        if "password=x&" in body or body.endswith("password=x"):
            time.sleep(0.25)
        self._send(200, "if the account exists we sent an email")


class NoPostHandler(_Base):
    def do_GET(self):
        self._send(200, "login page")

    def do_POST(self):
        self._send(405, "nope")


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture(scope="module")
def vuln_base():
    srv = _serve(VulnHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def uniform_base():
    srv = _serve(UniformHandler)
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
def nopost_base():
    srv = _serve(NoPostHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_probe_values_are_fake_and_benign():
    assert all(e.endswith("@omegaprobe.invalid") for e in PROBE_EMAILS)


def test_structural_enumeration_finding(vuln_base):
    found = run_userenum(vuln_base, default_fetch,
                         path_info={"paths": ["/login"]})
    assert found
    f = found[0]
    assert f["source"] == "omega-userenum"
    assert f["severity"] == "medium"
    assert f["verification"] == "candidate"
    assert ENUM_MARKER in f["verification_note"]


def test_uniform_responses_yield_nothing(uniform_base):
    assert run_userenum(uniform_base, default_fetch) == []


def test_timing_differential_low_candidate(timing_base):
    found = run_userenum(timing_base, default_fetch,
                         path_info={"paths": ["/login"]})
    assert found
    assert any(f["severity"] == "low" and "timing" in f["title"].lower()
               for f in found)


def test_non_post_endpoint_skipped(nopost_base):
    assert run_userenum(nopost_base, default_fetch) == []


def test_budget_cap_respected(vuln_base):
    counter = {"n": 0}
    orig = default_fetch

    def counting(method, url, headers=None, body=None):
        counter["n"] += 1
        return orig(method, url, headers=headers, body=body)

    run_userenum(vuln_base, counting, path_info={"paths": ["/login"]},
                 budget=12)
    assert counter["n"] <= 12


def test_never_raises_on_broken_fetch():
    def boom(*a, **k):
        raise RuntimeError("boom")

    assert run_userenum("http://127.0.0.1:1", boom) == []


def test_no_real_user_values_submitted(vuln_base):
    bodies = []

    def spy(method, url, headers=None, body=None):
        if method == "POST" and body:
            bodies.append(body)
        return default_fetch(method, url, headers=headers, body=body)

    run_userenum(vuln_base, spy, path_info={"paths": ["/login"]})
    assert bodies
    assert all("omegaprobe.invalid" in b for b in bodies)
