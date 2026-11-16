"""Hermetic tests for omega.scanning.apidocs.

Loopback servers: one exposing an OpenAPI spec with two endpoints
(one open, one auth-gated), one exposing a YAML-flavored spec, one
with no spec. Covers exposed-spec findings, unauthenticated endpoint
candidates, YAML parsing, endpoint fetch bound, clean targets and
never-raise behavior.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.apidocs import (SPEC_PATHS, extract_endpoints,
                                    parse_spec, run_apidocs)
from omega.scanning.deepchecks import default_fetch

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "paths": {
        "/items": {"get": {"summary": "list"}},
        "/admin/users": {"get": {"summary": "users"}},
    },
}


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, body=b"", ctype="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class OpenApiHandler(_Base):
    def do_GET(self):
        if self.path == "/openapi.json":
            self._send(200, json.dumps(SPEC))
        elif self.path == "/items":
            self._send(200, json.dumps({"items": [1, 2]}))
        elif self.path == "/admin/users":
            self._send(401, json.dumps({"error": "auth required"}))
        else:
            self._send(404, "{}")


class YamlApiHandler(_Base):
    YAML_SPEC = (
        "openapi: 3.0.0\n"
        "info:\n"
        "  title: yaml api\n"
        "paths:\n"
        "  /widgets:\n"
        "    get:\n"
        "      summary: list\n"
        "  /secrets:\n"
        "    get:\n"
        "      summary: leak\n"
    )

    def do_GET(self):
        if self.path == "/openapi.yaml":
            self._send(200, YamlApiHandler.YAML_SPEC,
                       ctype="application/yaml")
        elif self.path == "/widgets":
            self._send(200, json.dumps({"widgets": []}))
        else:
            self._send(404, "nope", ctype="text/plain")


class NoSpecHandler(_Base):
    def do_GET(self):
        self._send(404, "not found", ctype="text/plain")


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture(scope="module")
def api_base():
    srv = _serve(OpenApiHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def yaml_base():
    srv = _serve(YamlApiHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def bare_base():
    srv = _serve(NoSpecHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_spec_paths_constant():
    for p in ("/openapi.json", "/swagger.json", "/api-docs",
              "/swagger/v1/swagger.json", "/openapi.yaml"):
        assert p in SPEC_PATHS


def test_exposed_spec_finding(api_base):
    found = run_apidocs(api_base, default_fetch)
    spec_f = [f for f in found if "exposed" in f["title"].lower()]
    assert spec_f
    f = spec_f[0]
    assert f["severity"] == "medium"
    assert f["verification"] == "candidate"
    assert "/items" in f["evidence"] and "/admin/users" in f["evidence"]
    assert f["location"].endswith("/openapi.json")


def test_unauthenticated_endpoint_finding(api_base):
    found = run_apidocs(api_base, default_fetch)
    unauth = [f for f in found if "unauthenticated" in f["title"].lower()]
    assert unauth
    f = unauth[0]
    assert f["severity"] == "medium"
    assert "/items" in f["evidence"]
    assert "/admin/users" not in f["evidence"]  # 401 -> not open


def test_yaml_spec_discovery(yaml_base):
    found = run_apidocs(yaml_base, default_fetch)
    assert found
    assert any("/widgets" in f["evidence"] for f in found)
    unauth = [f for f in found if "unauthenticated" in f["title"].lower()]
    assert unauth and "/widgets" in unauth[0]["evidence"]


def test_parse_and_extract_units():
    spec = parse_spec(json.dumps(SPEC))
    assert spec["openapi"] == "3.0.0"
    assert extract_endpoints(spec) == ["/items", "/admin/users"]
    yspec = parse_spec("paths:\n  /a:\n  /b:\n", is_yaml=True)
    eps = extract_endpoints(yspec)
    assert "/a" in eps and "/b" in eps


def test_no_spec_no_findings(bare_base):
    assert run_apidocs(bare_base, default_fetch) == []


def test_never_raises_on_dead_target():
    assert run_apidocs("http://127.0.0.1:1", default_fetch) == []


def test_never_raises_on_bad_fetch():
    def boom(*a, **kw):
        raise RuntimeError("boom")
    assert run_apidocs("http://127.0.0.1:1", boom) == []
