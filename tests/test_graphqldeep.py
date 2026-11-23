"""Hermetic tests for omega/graphqldeep.py — GraphQL deep checks.

Covers: field-suggestion leak (candidate), 5-deep query accepted
(candidate 'no depth limit'), malformed-query error disclosure
(candidate HIGH), aliased bulk acceptance, false-positive guards
(depth-limited / rate-limited / clean servers produce no findings),
allowlist gate and never-raises containment.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.graphqldeep import (
    error_disclosure,
    field_suggestion_probe,
    query_depth_probe,
    run_graphqldeep,
)


class _Srv(ThreadingHTTPServer):
    allow_reuse_address = True


def _serve(handler):
    srv = _Srv(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


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


def _query_from(url):
    import urllib.parse
    q = urllib.parse.urlparse(url).query
    return urllib.parse.parse_qs(q).get("query", [""])[0]


def _handler_for(responder):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            q = _query_from(self.path)
            status, body = responder(q, self.path)
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    return Handler


VULN = _handler_for(lambda q, p: (
    200,
    '{"errors":[{"message":"Cannot query field \'heros\'. '
    'Did you mean \'heroes\'?"}]}'
    if "heros" in q and "aliased" not in q else
    '{"errors":[{"message":"syntax error, malformed query. '
    'Traceback (most recent call last): sqlite3. OperationalError"}]}'
    if "{{" in q else
    '{"data":{"a1":{"id":1},"a2":{"id":1},"a3":{"id":1},'
    '"a4":{"id":1},"a5":{"id":1},"a6":{"id":1},"a7":{"id":1},'
    '"a8":{"id":1},"a9":{"id":1},"a10":{"id":1}}}'
    if "a1: hero" in q else
    '{"data":{"a":{"b":{"c":{"d":{"e":"deep"}}}}}}'))


@pytest.fixture
def vuln_server():
    srv = _serve(VULN)
    yield "http://127.0.0.1:%d/graphql" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_field_suggestion_candidate(vuln_server):
    f = field_suggestion_probe(vuln_server, _get)
    assert f is not None
    assert f["verification"] == "candidate"
    assert f["evidence"]["suggestion"] == "heroes"
    assert f["source"] == "omega-graphql/field_suggestion"


def test_query_depth_no_limit_candidate(vuln_server):
    f = query_depth_probe(vuln_server, _get, depth=5)
    assert f is not None
    assert f["verification"] == "candidate"
    assert "no depth limit" in f["title"]
    assert f["evidence"]["depth"] == 5


def test_error_disclosure_candidate_high(vuln_server):
    f = error_disclosure(vuln_server, _get)
    assert f is not None
    assert f["severity"] == "high"
    assert f["verification"] == "candidate"
    assert f["evidence"]["markers"]


def test_run_graphqldeep_full(vuln_server):
    base = vuln_server.rsplit("/", 1)[0]
    out = run_graphqldeep(base, fetch=_get)
    sources = {f["source"] for f in out["findings"]}
    assert "omega-graphql/field_suggestion" in sources
    assert "omega-graphql/query_depth" in sources
    assert "omega-graphql/error_disclosure" in sources
    assert "omega-graphql/aliased_bulk" in sources


# -------------------------------------------------------- FP guards

def test_fp_guard_depth_limited_server():
    safe = _handler_for(lambda q, p: (
        400, '{"errors":[{"message":"maximum query depth exceeded: '
             'query is too deep"}]}'))
    srv = _serve(safe)
    try:
        base = "http://127.0.0.1:%d/graphql" % srv.server_address[1]
        assert query_depth_probe(base, _get) is None
    finally:
        srv.shutdown()
        srv.server_close()


def test_fp_guard_rate_limited_server():
    safe = _handler_for(lambda q, p: (
        429, '{"errors":[{"message":"too many aliases: rate limit '
             'exceeded"}]}'))
    srv = _serve(safe)
    try:
        base = "http://127.0.0.1:%d/graphql" % srv.server_address[1]
        from omega.graphqldeep import aliased_bulk_probe
        assert aliased_bulk_probe(base, _get) is None
    finally:
        srv.shutdown()
        srv.server_close()


def test_fp_guard_clean_server_no_error_finding():
    safe = _handler_for(lambda q, p: (
        200, '{"errors":[{"message":"Cannot query field: syntax '
             'error"}],"data":null}'))
    srv = _serve(safe)
    try:
        base = "http://127.0.0.1:%d/graphql" % srv.server_address[1]
        assert error_disclosure(base, _get) is None
        assert field_suggestion_probe(base, _get) is None
    finally:
        srv.shutdown()
        srv.server_close()


def test_no_graphql_endpoint_skipped():
    out = run_graphqldeep("http://127.0.0.1:1/", fetch=_get)
    assert out["findings"] == []
    assert "no GraphQL endpoint found" in out["skipped"]["__all__"]


def test_allowlist_and_never_raises():
    out = run_graphqldeep("http://stub.invalid", fetch=_get,
                          allowlist=["example.invalid"])
    assert "not in allowlist" in out["skipped"]["__all__"]

    def boom(_m, _u, _h=None):
        raise OSError("refused")
    out2 = run_graphqldeep("http://stub.invalid", fetch=boom)
    assert isinstance(out2, dict) and out2["findings"] == []
