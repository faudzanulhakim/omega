"""Hermetic tests for omega.scanning.authbypass.

Loopback ThreadingHTTPServer fixtures (vulnerable + clean) only; no
egress. Covers the bypass matrix, budget cap, candidate contract and
never-raise behavior.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.authbypass import (
    BYPASS_HEADERS,
    BYPASS_METHODS,
    BYPASS_PATH_MUTATIONS,
    run_authbypass,
)
from omega.scanning.deepchecks import default_fetch


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
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        raise NotImplementedError


class VulnHandler(_Base):
    """Baseline /admin is 401 with a tiny body; classic bypass vectors
    (double-slash, %2e, X-Original-URL, X-Forwarded-For) return the
    secret page with a much larger body."""

    SECRET = "TOPSECRETADMINPANEL" + "A" * 200

    def do_GET(self):
        path = self.path
        if self.headers.get("X-Original-URL"):
            self._send(200, VulnHandler.SECRET)
            return
        if self.headers.get("X-Forwarded-For") == "127.0.0.1" and \
                path.startswith("/admin"):
            self._send(200, VulnHandler.SECRET)
            return
        if path in ("/admin//", "/admin/%2e", "/admin/.", "/admin/./"):
            self._send(200, VulnHandler.SECRET)
            return
        if path.startswith("/admin"):
            self._send(401, "denied")
            return
        self._send(200, "public index")

    def do_HEAD(self):
        self._send(401, "denied")

    def do_POST(self):
        self._send(401, "denied")


class CleanHandler(_Base):
    """Everything is 403 with an identical body — no bypass possible."""

    def do_GET(self):
        self._send(403, "denied")

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_PATCH = do_GET
    do_OPTIONS = do_GET


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
def clean_base():
    srv = _serve(CleanHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_vector_tables_are_bounded():
    assert len(BYPASS_METHODS) == 5
    assert len(BYPASS_PATH_MUTATIONS) == 7
    assert len(BYPASS_HEADERS) == 4


def test_bypass_finding_on_vulnerable_server(vuln_base):
    found = run_authbypass(vuln_base, default_fetch,
                           path_info={"paths": ["/admin"]})
    assert found, "expected at least one bypass candidate"
    for f in found:
        assert f["source"] == "omega-authbypass"
        assert f["severity"] == "high"
        assert f["verification"] == "candidate"
        assert f["location"].startswith(vuln_base)


def test_clean_server_yields_nothing(clean_base):
    assert run_authbypass(clean_base, default_fetch) == []


def test_public_paths_never_reported(vuln_base):
    # only /admin is protected on the vuln fixture; the public paths
    # themselves must never appear in findings (defaults may still
    # probe the protected /admin)
    found = run_authbypass(vuln_base, default_fetch,
                           path_info={"paths": ["/", "/public"]})
    assert all(f["location"] not in (vuln_base + "/",
                                     vuln_base + "/public")
               for f in found)


def test_budget_cap_respected(vuln_base):
    counter = {"n": 0}
    orig = default_fetch

    def counting(method, url, headers=None, body=None):
        counter["n"] += 1
        return orig(method, url, headers=headers, body=body)

    run_authbypass(vuln_base, counting, path_info={"paths": ["/admin"]},
                   budget=10)
    assert counter["n"] <= 10


def test_never_raises_on_broken_fetch():
    def boom(*a, **k):
        raise RuntimeError("boom")

    assert run_authbypass("http://127.0.0.1:1", boom) == []


def test_accepts_path_info_and_gate(vuln_base):
    found = run_authbypass(vuln_base, default_fetch,
                           path_info={"paths": ["/admin"], "params": []},
                           gate=True)
    assert isinstance(found, list)
