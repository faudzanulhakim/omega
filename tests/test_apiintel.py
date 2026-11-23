"""Hermetic tests for omega/apiintel.py — API spec discovery + intel.

Covers: exposed-spec candidate (HIGH when authenticated endpoints are
listed), the clean FP guard (404 for every spec path -> no findings),
parsing of a fixture spec (endpoints / params / risky), compare_specs
drift (added/removed), sensitive-field detection, and never-raises.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.apiintel import (
    SPEC_PATHS,
    compare_specs,
    discover_specs,
    parse_spec,
    run_apiintel,
)

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Thing API", "version": "1.0"},
    "paths": {
        "/v1/users/{user_id}": {
            "get": {"parameters": [
                {"name": "user_id", "in": "path", "schema":
                    {"type": "string"}}],
                "responses": {"200": {"description": "ok"}}}},
        "/v1/users/{id}/profile": {
            "get": {"security": [{"bearer": []}],
                    "parameters": [{"name": "id", "in": "path"}],
                    "responses": {"200": {"content": {
                        "application/json": {"schema": {
                            "type": "object",
                            "properties": {"password": {"type":
                                                "string"}}}}}}}}},
        "/v2/users/{user_id}": {
            "get": {"parameters": [{"name": "user_id", "in": "path"}],
                    "responses": {"200": {"description": "ok"}}}},
    },
}


# ------------------------------------------------------------- fixtures

@pytest.fixture
def spec_server():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            if self.path in ("/openapi.json", "/swagger.json"):
                body = json.dumps(SPEC).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def _get(method, url, headers=None):
    import urllib.error
    import urllib.request
    assert method == "GET"
    req = urllib.request.Request(url, method="GET",
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers.items()), r.read(65536)
    except urllib.error.HTTPError as exc:
        return exc.code, {}, exc.read(65536) if hasattr(exc, "read") \
            else b""


# -------------------------------------------------------------- parsing

def test_spec_paths_list():
    assert SPEC_PATHS == [
        "/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs",
        "/swagger/v1/swagger.json", "/.well-known/openapi.json"]


def test_parse_spec_fixture():
    parsed = parse_spec(json.dumps(SPEC))
    assert "/v1/users/{user_id}" in parsed["endpoints"]
    assert len(parsed["endpoints"]) == 3
    params = {(p["path"], p["param"]) for p in parsed["params"]}
    assert ("/v1/users/{user_id}", "user_id") in params
    assert parsed["auth"] is True  # bearer security + per-op security
    # id-like params without security are risky; the secured one is not
    risky = {(r["path"], r["param"]) for r in parsed["risky"]}
    assert ("/v1/users/{user_id}", "user_id") in risky
    assert ("/v1/users/{id}/profile", "id") not in risky


def test_parse_spec_garbage():
    for junk in (b"", b"not json", None, 42, {}, b"[]"):
        out = parse_spec(junk)
        assert out["endpoints"] == [] and out["risky"] == []


# ----------------------------------------------------------- discovery

def test_discover_specs_finds_openapi(spec_server):
    found = discover_specs(spec_server, fetch=_get)
    paths = [f["path"] for f in found]
    assert paths == ["/openapi.json", "/swagger.json"]
    assert found[0]["spec"]["endpoints"]


def test_discover_specs_clean_404():
    found = discover_specs("http://127.0.0.1:1/", fetch=_get)
    assert found == []


# ------------------------------------------------------------- findings

def test_exposed_spec_candidate_high(spec_server):
    out = run_apiintel(spec_server, fetch=_get)
    exposed = [f for f in out["findings"]
               if f["source"] == "omega-apiintel/exposed-spec"]
    assert exposed
    assert exposed[0]["verification"] == "candidate"
    assert exposed[0]["severity"] == "high"  # authenticated endpoints
    # unauthenticated risky id-like endpoints
    risky = [f for f in out["findings"]
             if f["source"] == "omega-apiintel/risky-endpoint"]
    assert risky and risky[0]["severity"] == "high"
    # version drift /v1 vs /v2
    drift = [f for f in out["findings"]
             if f["source"] == "omega-apiintel/version-drift"]
    assert drift
    # sensitive field 'password' in a response schema
    sens = [f for f in out["findings"]
            if f["source"] == "omega-apiintel/sensitive-field"]
    assert sens and any(f["evidence"]["field"] == "password"
                        for f in sens)


def test_fp_guard_clean_server_no_findings():
    class Clean(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            body = b"plain web app"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Clean)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        out = run_apiintel(base, fetch=_get)
        assert out["findings"] == []
        assert out["specs"] == []
    finally:
        srv.shutdown()
        srv.server_close()


def test_run_apiintel_allowlist_and_never_raises():
    out = run_apiintel("http://stub.invalid", fetch=_get,
                       allowlist=["example.invalid"])
    assert out["findings"] == []
    assert "not in allowlist" in out["skipped"]["__all__"]
    # broken transport never raises
    def boom(_m, _u, _h=None):
        raise OSError("refused")
    out2 = run_apiintel("http://stub.invalid", fetch=boom)
    assert isinstance(out2, dict)


# -------------------------------------------------------- compare_specs

def test_compare_specs_added_removed():
    old = {"endpoints": ["/a", "/b", "/c"]}
    new = {"endpoints": ["/b", "/c", "/d", "/e"]}
    diff = compare_specs(old, new)
    assert diff == {"added": ["/d", "/e"], "removed": ["/a"]}
    # raw spec dicts also accepted
    diff2 = compare_specs({"paths": {"/x": {}}}, {"paths": {"/x": {},
                                                            "/y": {}}})
    assert diff2 == {"added": ["/y"], "removed": []}
