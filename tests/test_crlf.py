"""Hermetic tests for omega.scanning.crlf (CRLF injection / response
splitting). Loopback ThreadingHTTPServer fixtures emulate the vulnerable
behaviors; clean server reflects nothing. Inert markers only."""

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(
    __import__("os").path.abspath(__file__))))

from omega.scanning.crlf import (  # noqa: E402
    PROBE_HEADER,
    candidate_pairs,
    crlf_path_probe,
    run_crlf,
)


class CrlfHandler(BaseHTTPRequestHandler):
    """Knobs:
    inject_header (bool): decode the query/path; if it carries a CRLF
      followed by X-Omega-Probe, emit that header (response splitting).
    reflect_body (bool): echo the decoded value into the body.
    """
    inject_header = True
    reflect_body = False

    def log_message(self, *a):
        pass

    def _respond(self, extra_headers=None, body=b"page"):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _decoded(self):
        raw = self.path
        return unquote(raw)

    def do_GET(self):
        decoded = self._decoded()
        split = ("\r\n" in decoded and PROBE_HEADER in decoded)
        if self.inject_header and split:
            self._respond({PROBE_HEADER: "1"},
                           body=b"page " + decoded.encode("latin-1"))
        elif self.reflect_body and PROBE_HEADER in decoded:
            self._respond(body=("reflected " + decoded).encode("latin-1"))
        else:
            self._respond()


@pytest.fixture
def crlf_server():
    made = []

    def make(**attrs):
        handler = type("H", (CrlfHandler,), attrs)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        made.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield make
    for srv in made:
        srv.shutdown()


def test_injected_header_verified(crlf_server):
    base = crlf_server()
    out = run_crlf(base, path_info={"paths": ["/search"],
                                    "params": ["q"]})
    hits = [f for f in out if f["source"] == "omega-crlf/injected_header"]
    assert hits
    f = hits[0]
    assert f["severity"] == "medium"
    assert f["verification"] == "verified"
    assert PROBE_HEADER in f["evidence"]


def test_path_variant_injected_header(crlf_server):
    base = crlf_server()
    out = run_crlf(base, path_info={"paths": ["/search"],
                                    "params": ["q"]})
    hits = [f for f in out
            if f["source"] == "omega-crlf/path_injected_header"]
    assert hits
    assert hits[0]["verification"] == "verified"


def test_body_reflection_low_candidate(crlf_server):
    base = crlf_server(inject_header=False, reflect_body=True)
    out = run_crlf(base, path_info={"paths": ["/search"],
                                    "params": ["q"]})
    hits = [f for f in out if f["source"] == "omega-crlf/reflected_crlf"]
    assert hits
    f = hits[0]
    assert f["severity"] == "low"
    assert f["verification"] == "candidate"


def test_clean_server_no_findings(crlf_server):
    base = crlf_server(inject_header=False, reflect_body=False)
    assert run_crlf(base, path_info={"paths": ["/search"],
                                     "params": ["q"]}) == []


def test_candidate_pairs_shape():
    pi = {"paths": ["/a", "/b"], "params": ["x"]}
    pairs = candidate_pairs(pi)
    assert ("/a", "x") in pairs and ("/b", "x") in pairs
    # no params -> falls back to ("q",) on root
    assert candidate_pairs({"paths": [], "params": []}) == [("/", "q")]


def test_crlf_path_probe_direct(crlf_server):
    base = crlf_server()
    f = crlf_path_probe(base, "/search")
    assert f is not None
    assert f["verification"] == "verified"
    assert f["source"] == "omega-crlf/path_injected_header"


def test_never_raises_on_dead_target():
    import socket as _s
    s = _s.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert run_crlf("http://127.0.0.1:%d" % port,
                    path_info={"paths": ["/a"], "params": ["q"]}) == []
    assert crlf_path_probe("http://127.0.0.1:%d" % port) is None
    assert run_crlf("") == []


def test_finding_shape(crlf_server):
    base = crlf_server()
    for f in run_crlf(base):
        for key in ("title", "severity", "verification",
                    "verification_note", "location", "evidence", "source"):
            assert key in f
        assert len(f["evidence"]) <= 300
