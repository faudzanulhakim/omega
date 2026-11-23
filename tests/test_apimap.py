"""Hermetic loopback tests for omega/scanning/apimap.py.

A local ThreadingHTTPServer serves a fake OpenAPI document, a fake
GraphQL endpoint with introspection, an undocumented live path and a
documented-but-dead path. Safe probing only (OPTIONS/GET) is asserted.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.apimap import (
    fetch_openapi,
    introspect_graphql,
    mass_assignment_hints,
    probe_endpoint,
    run_apimap,
    spec_endpoints,
)

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Fake API", "version": "1.0"},
    "paths": {
        "/pets": {"get": {"summary": "List pets", "responses": {}}},
        "/pets/{id}": {"get": {"summary": "Get pet", "responses": {}}},
        "/ghost": {"get": {"summary": "Documented but dead", "responses": {}}},
    },
    "components": {"schemas": {
        "User": {"properties": {
            "id": {"type": "integer", "readOnly": True},
            "email": {"type": "string"},
            "role": {"type": "string"},
            "name": {"type": "string"},
        }},
    }},
}

INTROSPECTION_RESULT = {
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "kind": "OBJECT"},
            {"name": "Mutation", "kind": "OBJECT"},
            {"name": "Pet", "kind": "OBJECT"},
            {"name": "__Type", "kind": "OBJECT"},
        ],
    }},
}


def make_server():
    class Handler(BaseHTTPRequestHandler):
        def _json(self, obj, status=200):
            body = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/openapi.json":
                self._json(SPEC)
            elif path == "/graphql":
                if "__schema" in self.path:
                    self._json(INTROSPECTION_RESULT)
                else:
                    self._json({"data": {}})
            elif path == "/metrics":
                self._json({"uptime": 42})
            elif path in ("/pets", "/pets/1"):
                self._json({"ok": True})
            else:
                self.send_error(404)

        do_OPTIONS = do_GET

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture()
def server():
    srv = make_server()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def by_source(findings):
    return {f["source"]: f for f in findings}


# ------------------------------------------------------------------ units
def test_fetch_openapi_finds_spec(server):
    url, spec = fetch_openapi(server)
    assert url == server + "/openapi.json"
    assert spec["openapi"] == "3.0.0"


def test_fetch_openapi_none_on_plain_server(monkeypatch):
    # no doc paths exist on the fake fetch -> (None, None)
    def fake(method, url):
        return 404, {}, b"not found"
    assert fetch_openapi("http://bare.local", fetch=fake) == (None, None)


def test_spec_endpoints_extracts_methods():
    eps = spec_endpoints(SPEC)
    assert ("/pets", "get") in eps
    assert ("/pets/{id}", "get") in eps
    assert ("/ghost", "get") in eps


def test_probe_endpoint_safe_methods_only(server):
    st, method = probe_endpoint(server + "/metrics")
    assert method in ("OPTIONS", "GET")
    assert st == 200


def test_mass_assignment_hints_flags_sensitive_fields():
    hints = mass_assignment_hints(SPEC)
    user = next(h for h in hints if h["schema"] == "User")
    assert "email" in user["fields"]
    assert "role" in user["fields"]
    assert "id" not in user["fields"]          # readOnly excluded
    assert "name" not in user["fields"]        # not sensitive


def test_introspect_graphql(server):
    url, summary = introspect_graphql(server)
    assert url == server + "/graphql"
    assert summary["query_type"] == "Query"
    assert summary["type_count"] >= 3
    assert "__Type" not in summary["types"]    # builtins filtered


def test_introspect_graphql_disabled(monkeypatch):
    def fake(method, url):
        return 200, {}, json.dumps({"errors": [{"msg": "no introspection"}]})
    assert introspect_graphql("http://g.local", fetch=fake) == (None, None)


# ---------------------------------------------------------------- run
def test_run_apimap_undocumented_live(server):
    result = run_apimap(server)
    f = by_source(result["findings"]).get("omega-apimap/undocumented_live")
    assert f is not None
    assert f["verification"] == "candidate"
    assert f["evidence"]["path"] == "/metrics"
    assert result["spec_url"] == server + "/openapi.json"


def test_run_apimap_spec_dead_path(server):
    result = run_apimap(server)
    f = by_source(result["findings"]).get("omega-apimap/spec_dead_path")
    assert f is not None
    assert f["severity"] == "info"
    paths = [d["path"] for d in f["evidence"]["paths"]]
    assert "/ghost" in paths


def test_run_apimap_graphql_introspection_medium(server):
    result = run_apimap(server)
    f = by_source(result["findings"]).get("omega-apimap/graphql_introspection")
    assert f is not None
    assert f["severity"] == "medium"
    assert "types" in f["evidence"]


def test_run_apimap_mass_assignment_info(server):
    result = run_apimap(server)
    f = by_source(result["findings"]).get("omega-apimap/mass_assignment")
    assert f is not None
    assert f["severity"] == "info"
    assert "role" in f["evidence"]["fields"]


def test_run_apimap_no_spec(monkeypatch):
    def fake(method, url):
        return 404, {}, b"nope"
    result = run_apimap("http://bare.local", fetch=fake)
    sources = {f["source"] for f in result["findings"]}
    assert "omega-apimap/no_spec" in sources
    assert result["spec"] is None


def test_run_apimap_never_raises_on_dead_target():
    result = run_apimap("http://127.0.0.1:1")  # closed port
    assert "findings" in result
    assert result["spec"] is None
