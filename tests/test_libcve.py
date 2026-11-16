"""Hermetic tests for omega.scanning.libcve.

Loopback server serving an old jquery bundle; fixture CVE index JSON
written to tmp and pointed at via OMEGA_CVE_INDEX. Covers signature
findings, missing-index note, clean targets, page bounds and
never-raise behavior.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.deepchecks import default_fetch
from omega.scanning.libcve import run_libcve


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

    def do_GET(self):
        raise NotImplementedError


class VulnHandler(_Base):
    INDEX_HTML = ("<html><head>"
                  "<script src='/js/jquery-3.2.1.min.js'></script>"
                  "</head><body>hi</body></html>")
    JQUERY = ("/*! jQuery v3.2.1 | (c) JS Foundation */"
              "// sourceMappingURL=jquery.min.map")

    def do_GET(self):
        if self.path == "/js/jquery-3.2.1.min.js":
            self._send(200, VulnHandler.JQUERY,
                       ctype="application/javascript")
            return
        if self.path == "/old.html":
            self._send(200, VulnHandler.INDEX_HTML)
            return
        self._send(200, VulnHandler.INDEX_HTML)


class ModernHandler(_Base):
    def do_GET(self):
        if self.path == "/js/modern.js":
            self._send(200, "console.log('no libraries here');",
                       ctype="application/javascript")
            return
        self._send(200, "<html><script src='/js/modern.js'>"
                        "</script></html>")


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
def modern_base():
    srv = _serve(ModernHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def cve_index(tmp_path, monkeypatch):
    idx = tmp_path / "cve_index.json"
    idx.write_text(json.dumps({
        "generated": "2026-11-01T00:00:00Z",
        "source_feed": "fixture",
        "entries": [{
            "cve_id": "CVE-2020-11023",
            "product": "jquery",
            "version_ranges": [{"start": "1.2.0", "end": "3.5.0",
                                "start_incl": True, "end_incl": True}],
            "severity": "medium",
            "summary": "XSS in jquery htmlPrefilter",
        }],
    }))
    monkeypatch.setenv("OMEGA_CVE_INDEX", str(idx))
    return idx


def test_signature_finding_with_index(vuln_base, cve_index):
    found = run_libcve(vuln_base, default_fetch)
    assert found
    f = found[0]
    assert f["source"] == "omega-libcve"
    assert f["verification"] == "signature"
    assert f["severity"] == "medium"
    assert "CVE-2020-11023" in f["title"]
    assert "jquery" in f["evidence"].lower()


def test_missing_index_info_note(vuln_base, tmp_path, monkeypatch):
    monkeypatch.setenv("OMEGA_CVE_INDEX",
                       str(tmp_path / "missing.json"))
    found = run_libcve(vuln_base, default_fetch)
    assert found
    assert any(f["severity"] == "info"
               and "index" in f["title"].lower() for f in found)
    assert not any("CVE-" in f["title"] for f in found)


def test_clean_target_no_findings(modern_base, cve_index):
    assert run_libcve(modern_base, default_fetch) == []


def test_asset_and_page_bounds(vuln_base):
    counter = {"n": 0}
    orig = default_fetch

    def counting(method, url, headers=None, body=None):
        counter["n"] += 1
        return orig(method, url, headers=headers, body=body)

    run_libcve(vuln_base, counting,
               path_info={"paths": ["/p%d" % i for i in range(20)]})
    # 10 pages max + 10 assets max
    assert counter["n"] <= 20


def test_fingerprint_from_url_and_body():
    from omega.scanning.libcve import _fingerprint
    assert _fingerprint("/js/lodash-4.17.15.min.js")
    assert _fingerprint("/*! jQuery v3.2.1 */")
    hits = _fingerprint("angular.min.js v1.2.32 angular 1.2.32")
    assert any(p == "angular" for (p, _v) in hits)


def test_never_raises_on_broken_fetch():
    def boom(*a, **k):
        raise RuntimeError("boom")

    assert run_libcve("http://127.0.0.1:1", boom) == []


def test_no_external_assets_fetched(vuln_base, cve_index):
    urls = []

    def spy(method, url, headers=None, body=None):
        urls.append(url)
        return default_fetch(method, url, headers=headers, body=body)

    run_libcve(vuln_base, spy)
    assert all(u.startswith(vuln_base) for u in urls)
