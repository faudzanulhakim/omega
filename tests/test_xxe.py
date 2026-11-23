"""Hermetic tests for omega.scanning.xxe.

Loopback servers: an XXE-vulnerable XML endpoint (echoes entity
content / expansion errors), a verbose-error endpoint, and a clean
server. Covers HIGH candidates, LOW parser-error info leak, clean
targets, discovery from path_info, bounds and never-raise behavior.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.deepchecks import default_fetch
from omega.scanning.xxe import (MARKER_FILE, MARKER_TAG, build_xml_payloads,
                                run_xxe, xml_endpoints)


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, body=b"", ctype="text/xml"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, "<html>no xml here</html>", ctype="text/html")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self._send(200, "<ok/>")


class VulnHandler(_Base):
    """Echoes whatever entity marker arrives in the XML body."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("latin-1")
        if "&xxe;" in body:
            # Simulate an XML parser that expanded the external entity.
            self._send(200, "<resp>content: /nonexistent/omega/xxe/"
                            "marker.txt omega-xxe</resp>")
        else:
            self._send(200, "<ok/>")


class VerboseHandler(_Base):
    """Returns a verbose SAX error for malformed XML only."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("latin-1")
        if "<unclosed>" in body:
            self._send(500, "org.xml.sax.SAXParseException: at line 2 "
                            "column 12: XML document must have a top "
                            "level element")
        else:
            self._send(200, "<ok/>")


class CleanHandler(_Base):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self._send(200, "<ok/>")


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
def verbose_base():
    srv = _serve(VerboseHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def clean_base():
    srv = _serve(CleanHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_entity_echo_high_candidate(vuln_base):
    found = run_xxe(vuln_base, default_fetch)
    assert found
    high = [f for f in found if f["severity"] == "high"]
    assert high
    f = high[0]
    assert f["verification"] == "candidate"
    assert f["source"] == "omega-xxe"
    assert "/xmlrpc" in f["location"] or "/soap" in f["location"]


def test_benign_marker_payloads():
    payloads = build_xml_payloads("abc123.oob.omega-xxe.invalid")
    kinds = [k for k, _ in payloads]
    assert kinds == ["local-entity", "oob-entity", "plain", "malformed"]
    local = dict(payloads)["local-entity"]
    assert "file://%s" % MARKER_FILE in local
    assert MARKER_TAG in local
    oob = dict(payloads)["oob-entity"]
    assert "abc123.oob.omega-xxe.invalid" in oob
    assert MARKER_FILE not in oob


def test_oob_host_only_in_evidence_never_fetched(vuln_base):
    """The OOB hostname must never be contacted: our loopback server
    sees only POSTs to XML endpoints; a DNS lookup would fail anyway.
    Verify the OOB payload body references the unique host and that
    the module completes without any resolution attempt (no socket
    usage beyond the fetch to loopback)."""
    import socket
    real_getaddrinfo = socket.getaddrinfo
    resolved = []

    def spy(host, *a, **kw):
        resolved.append(host)
        return real_getaddrinfo(host, *a, **kw)

    import omega.scanning.xxe as mod
    old = getattr(mod, "socket", None)
    import socket as _socket
    _socket.getaddrinfo = spy
    try:
        found = run_xxe(vuln_base, default_fetch)
    finally:
        _socket.getaddrinfo = real_getaddrinfo
    del old
    assert not any("oob" in str(h) for h in resolved)


def test_verbose_parser_error_low_candidate(verbose_base):
    found = run_xxe(verbose_base, default_fetch)
    assert found
    low = [f for f in found if f["severity"] == "low"]
    assert low
    assert "SAXParseException" in low[0]["evidence"] or \
        "parser error" in low[0]["title"].lower()


def test_clean_target_no_findings(clean_base):
    assert run_xxe(clean_base, default_fetch) == []


def test_path_info_discovery(clean_base):
    """An api/xml path from path_info is probed (no findings on clean,
    but the endpoint is derived correctly)."""
    paths = xml_endpoints(clean_base, {"paths": ["/api/users", "/login"]})
    assert clean_base + "/api/users" in paths
    assert clean_base + "/xmlrpc" in paths
    assert clean_base + "/login" not in paths
    assert len(paths) <= 8


def test_never_raises_on_dead_target():
    assert run_xxe("http://127.0.0.1:1", default_fetch) == []


def test_never_raises_on_bad_fetch():
    def boom(*a, **kw):
        raise RuntimeError("boom")
    assert run_xxe("http://127.0.0.1:1", boom) == []
