"""Hermetic tests for omega.scanning.backupfiles.

Loopback ThreadingHTTPServer fixtures (vulnerable + clean) only; no
egress. Covers the 25-request cap, random-404 baseline differential,
directory-listing medium, candidate contract and never-raise behavior.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.backupfiles import (
    HIGH_VALUE_PATHS,
    MAX_REQUESTS,
    run_backupfiles,
)
from omega.scanning.deepchecks import default_fetch

SECRET_ENV = "DB_PASSWORD=hunter2\nAPI_KEY=abcd1234abcd1234\n"


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


class VulnHandler(_Base):
    """Real content at /backup.sql, /.git/config and a directory
    listing at /wp-content/uploads/; everything else is a generic 404
    page (simulating a soft-404 SPA)."""

    def do_GET(self):
        if self.path == "/backup.sql":
            self._send(200, "CREATE TABLE users (...);\n" * 3)
            return
        if self.path == "/.git/config":
            self._send(200, "[core]\n\trepositoryformatversion = 0\n")
            return
        if self.path == "/.env.local":
            self._send(200, SECRET_ENV)
            return
        if self.path == "/wp-content/uploads/":
            self._send(200, "<html><title>Index of /wp-content/uploads/"
                            "</title></html>")
            return
        self._send(404, "not found at all")


class SoftHandler(_Base):
    """Soft-404 server: EVERY path returns 200 with the same body —
    the baseline differential must suppress all findings."""

    def do_GET(self):
        self._send(200, "catch-all page body")


class CleanHandler(_Base):
    def do_GET(self):
        self._send(404, "nope")


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
def soft_base():
    srv = _serve(SoftHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def clean_base():
    srv = _serve(CleanHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_path_list_bounded():
    assert MAX_REQUESTS == 25
    assert len(HIGH_VALUE_PATHS) <= MAX_REQUESTS
    assert "/.git/config" in HIGH_VALUE_PATHS
    assert "/dump.sql" in HIGH_VALUE_PATHS
    assert "/.env.bak" in HIGH_VALUE_PATHS


def test_backup_finding_on_vulnerable_server(vuln_base):
    found = run_backupfiles(vuln_base, default_fetch,
                            path_info={"paths": ["/wp-content/uploads/"]})
    high = [f for f in found if f["severity"] == "high"]
    assert any(f["location"].endswith("/backup.sql") for f in high)
    assert any(f["location"].endswith("/.git/config") for f in high)
    for f in found:
        assert f["source"] == "omega-backupfiles"
        assert f["verification"] == "candidate"


def test_directory_listing_is_medium(vuln_base):
    found = run_backupfiles(vuln_base, default_fetch,
                            path_info={"paths": ["/wp-content/uploads/"]})
    listings = [f for f in found if f["severity"] == "medium"]
    assert any("listing" in f["title"].lower() for f in listings)


def test_soft_404_baseline_suppresses_findings(soft_base):
    # soft-404 bodies identical to the baseline must not be reported
    assert run_backupfiles(soft_base, default_fetch) == []


def test_clean_server_yields_nothing(clean_base):
    assert run_backupfiles(clean_base, default_fetch) == []


def test_request_budget_respected(vuln_base):
    counter = {"n": 0}
    orig = default_fetch

    def counting(method, url, headers=None, body=None):
        counter["n"] += 1
        return orig(method, url, headers=headers, body=body)

    run_backupfiles(vuln_base, counting, budget=6)
    assert counter["n"] <= 6


def test_never_raises_on_garbage_input():
    # connection refused + malformed URL must not raise
    assert run_backupfiles("http://127.0.0.1:1",
                           default_fetch) == []
    assert run_backupfiles("", lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("boom"))) == []


def test_path_info_bak_suffix_probed(vuln_base):
    # a known path gets .bak/.old suffix probes; expose /admin.php.bak
    # via a dedicated fixture check on the suffix machinery instead:
    from omega.scanning.backupfiles import _probe_paths
    paths = _probe_paths({"paths": ["/admin", "/admin", ""]})
    assert "/admin.bak" in paths and "/admin.old" in paths
    assert len(paths) <= MAX_REQUESTS
    # duplicates removed
    assert paths.count("/admin.bak") == 1
