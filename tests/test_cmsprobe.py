"""Hermetic tests for omega.scanning.cmsprobe.

Loopback ThreadingHTTPServer fixtures (WordPress-vulnerable + clean)
only; no egress. Covers the fingerprint markers, the wp-json user
enumeration HIGH candidate, version disclosures, candidate contract
and never-raise behavior.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.cmsprobe import CMS_PROBES, run_cmsprobe
from omega.scanning.deepchecks import default_fetch

USERS = json.dumps([{"id": 1, "name": "admin", "slug": "admin"}])


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


class WpHandler(_Base):
    def do_GET(self):
        p = self.path
        if p == "/wp-login.php":
            self._send(200, "<form id=\"loginform\">wp-admin user_login"
                            "</form>")
        elif p == "/wp-json/wp/v2/users":
            self._send(200, USERS, ctype="application/json")
        elif p == "/xmlrpc.php":
            self._send(200, "XML-RPC server accepts POST requests only.")
        elif p == "/wp-content/uploads/":
            self._send(200, "<title>Index of /wp-content/uploads/</title>")
        elif p == "/readme.html":
            self._send(200, "WordPress 5.8.1 readme")
        elif p == "/LICENSE.txt":
            self._send(200, "GNU GENERAL PUBLIC LICENSE Version 2")
        else:
            self._send(404, "nope")


class CleanHandler(_Base):
    def do_GET(self):
        self._send(404, "not found")


class BrokenHandler(_Base):
    def do_GET(self):
        raise RuntimeError("handler exploded")

    def _send(self, *a, **k):  # pragma: no cover
        pass


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture(scope="module")
def wp_base():
    srv = _serve(WpHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def clean_base():
    srv = _serve(CleanHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_probe_table_expected_shape():
    paths = [p for _n, p, _c, _s in CMS_PROBES]
    assert "/wp-json/wp/v2/users" in paths
    assert "/xmlrpc.php" in paths
    assert "/user/login" in paths
    assert "/core/install.php" in paths
    assert "/administrator/" in paths
    assert "/language/en-GB/en-GB.xml" in paths
    assert "/readme.html" in paths and "/LICENSE.txt" in paths
    assert len(CMS_PROBES) <= 12  # bounded


def test_user_enumeration_high_candidate(wp_base):
    found = run_cmsprobe(wp_base, default_fetch)
    enum = [f for f in found if f["severity"] == "high"]
    assert len(enum) == 1
    assert enum[0]["verification"] == "candidate"
    assert "enumeration" in enum[0]["title"].lower()
    assert enum[0]["location"].endswith("/wp-json/wp/v2/users")
    assert "admin" in enum[0]["evidence"]


def test_fingerprint_markers_detected(wp_base):
    found = run_cmsprobe(wp_base, default_fetch)
    titles = " ".join(f["title"] for f in found)
    for marker in ("wp-login", "wp-xmlrpc", "wp-uploads", "readme",
                   "license"):
        assert marker in titles, marker
    for f in found:
        assert f["source"] == "omega-cmsprobe"
        assert f["severity"] in ("low", "medium", "high")


def test_version_disclosures_are_low(wp_base):
    found = run_cmsprobe(wp_base, default_fetch)
    low = [f for f in found if f["severity"] == "low"]
    assert len(low) >= 2  # readme + license
    assert all(f["verification"] == "candidate" for f in low)


def test_clean_server_yields_nothing(clean_base):
    assert run_cmsprobe(clean_base, default_fetch) == []


def test_budget_cap_respected(wp_base):
    counter = {"n": 0}
    orig = default_fetch

    def counting(method, url, headers=None, body=None):
        counter["n"] += 1
        return orig(method, url, headers=headers, body=body)

    run_cmsprobe(wp_base, counting, budget=4)
    assert counter["n"] <= 4


def test_never_raises_on_dead_target():
    assert run_cmsprobe("http://127.0.0.1:1", default_fetch) == []
    assert run_cmsprobe("", lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("boom"))) == []


def test_wp_json_error_body_not_reported():
    from omega.scanning.cmsprobe import _json_user_list
    assert _json_user_list(200, '{"code":"rest_no_route"}',
                           "application/json") is False
    assert _json_user_list(404, USERS, "application/json") is False
