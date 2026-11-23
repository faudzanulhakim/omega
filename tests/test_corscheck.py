"""Hermetic tests for omega.scanning.corscheck (CORS matrix).
Loopback ThreadingHTTPServer fixtures; benign origins only."""

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(
    __import__("os").path.abspath(__file__))))

from omega.scanning.corscheck import (  # noqa: E402
    candidate_paths,
    run_corscheck,
)


class CorsHandler(BaseHTTPRequestHandler):
    """Knobs: acao (str|None), acac (str|None)."""
    acao = None
    acac = None

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        if self.acao is not None:
            self.send_header("Access-Control-Allow-Origin", self.acao)
        if self.acac is not None:
            self.send_header("Access-Control-Allow-Credentials", self.acac)
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def cors_server():
    made = []

    def make(**attrs):
        handler = type("H", (CorsHandler,), attrs)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        made.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield make
    for srv in made:
        srv.shutdown()


def test_clean_no_cors_no_findings(cors_server):
    base = cors_server()
    assert run_corscheck(base) == []


def test_reflects_arbitrary_origin_high(cors_server):
    base = cors_server(acao="https://evil.example", acac="false")
    out = run_corscheck(base)
    hits = [f for f in out if f["source"] ==
            "omega-corscheck/acao_reflects_arbitrary"]
    assert hits
    assert hits[0]["severity"] == "high"
    assert hits[0]["verification"] == "candidate"


def test_reflection_with_credentials_high(cors_server):
    base = cors_server(acao="https://evil.example", acac="true")
    out = run_corscheck(base)
    hits = [f for f in out if f["source"] ==
            "omega-corscheck/acao_reflect_with_credentials"]
    assert hits
    assert hits[0]["severity"] == "high"


def test_wildcard_info(cors_server):
    base = cors_server(acao="*")
    out = run_corscheck(base)
    hits = [f for f in out if f["source"] == "omega-corscheck/acao_wildcard"]
    assert hits
    assert hits[0]["severity"] == "info"
    assert hits[0]["verification"] == "verified"


def test_null_origin_with_credentials_high(cors_server):
    base = cors_server(acao="null", acac="true")
    out = run_corscheck(base)
    hits = [f for f in out if f["source"] ==
            "omega-corscheck/acao_null_with_credentials"]
    assert hits
    assert hits[0]["severity"] == "high"


def test_acao_null_without_credentials_no_finding(cors_server):
    base = cors_server(acao="null", acac="false")
    assert run_corscheck(base) == []


def test_candidate_paths_dedupe_and_cap():
    pi = {"paths": ["/", "/api", "/api", "/a", "/b", "/c", "/d"]}
    paths = candidate_paths(pi)
    assert paths[0] == "/"
    assert paths == ["/", "/api", "/a", "/b", "/c", "/d"]


def test_probes_path_info_paths(cors_server):
    base = cors_server(acao="https://evil.example")
    out = run_corscheck(base, path_info={"paths": ["/api/x"]})
    assert any("/api/x" in f["location"] for f in out)


def test_never_raises_on_dead_target():
    import socket as _s
    s = _s.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert run_corscheck("http://127.0.0.1:%d" % port) == []
    assert run_corscheck("") == []
