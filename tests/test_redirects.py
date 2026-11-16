"""Hermetic tests for omega/redirects.py — open-redirect + chain auditor.

All servers are ThreadingHTTPServer instances bound to 127.0.0.1 on an
ephemeral port. No internet access; the probe domain
omega-redirect-check.example never resolves and is never fetched.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.redirects import (
    PROBE_HOST,
    discover_redirect_params,
    run_redirects,
)

BASE = "http://omega-target.example"


# ------------------------------------------------------------ fixtures

class _Handler(BaseHTTPRequestHandler):
    def _handle(self):
        srv = self.server.omega_behavior
        parsed = self.path
        status, headers, body = srv(parsed)
        self.send_response(status)
        for key, val in headers.items():
            self.send_header(key, val)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):      # noqa: N802 (http.server API)
        self._handle()

    def do_HEAD(self):     # noqa: N802
        self._handle()

    def log_message(self, fmt, *args):   # silence
        pass


def _make_server(behavior):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.omega_behavior = behavior
    t = threading.Thread(target=srv.serve_forever,
                         kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    return srv


def _q(path):
    from urllib.parse import parse_qs, urlsplit
    qs = parse_qs(urlsplit(path).query, keep_blank_values=True)
    return {k: v[0] for k, v in qs.items()}


def _resp(status, body=b"ok", headers=None):
    return status, (headers or {}), body


@pytest.fixture
def open_redirect_server():
    """Redirects externally ONLY when the url param is an absolute URL;
    a same-origin value like /dashboard just 200s (differential holds)."""
    def behavior(path):
        q = _q(path)
        val = q.get("url", "")
        if val.startswith("http"):
            return _resp(302, headers={"Location": val})
        return _resp(200, b"home")
    srv = _make_server(behavior)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def unconditional_redirect_server():
    """Redirects to an external host for ANY param value — the
    differential control also redirects, so findings must stay
    'candidate'."""
    def behavior(path):
        return _resp(302, headers={"Location": "http://evil.example/x"})
    srv = _make_server(behavior)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def echo_server():
    """Reflects every query value into the body, never redirects."""
    def behavior(path):
        q = _q(path)
        body = ("echo: " + json.dumps(q, sort_keys=True)).encode()
        return _resp(200, body)
    srv = _make_server(behavior)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def client_redirect_server():
    """200 with meta-refresh AND window.location to the url param."""
    def behavior(path):
        q = _q(path)
        val = q.get("url", "")
        body = (
            "<html><meta http-equiv='refresh' content='0;url=%s'>"
            "<script>window.location='%s'</script></html>"
            % (val, val)).encode()
        return _resp(200, body)
    srv = _make_server(behavior)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def constant_server():
    def behavior(_path):
        return _resp(200, b"ok")
    srv = _make_server(behavior)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def chain_server():
    """/h1..h4 same-origin hops then hop 5 crosses to another host
    (INFO long-chain + MEDIUM boundary); /c1../c2 is a short chain."""
    def behavior(path):
        route = {
            "/h1": (302, "/h2"), "/h2": (302, "/h3"),
            "/h3": (302, "/h4"), "/h4": (302, "/h5"),
            "/h5": (302, "http://elsewhere.example/"),
            "/c1": (302, "/c2"), "/c2": (302, "/c3"),
            "/c3": (200, None),
            "/b1": (302, "http://auth.example/login"),
        }.get(path.split("?")[0], (200, None))
        status, loc = route
        headers = {"Location": loc} if loc else {}
        return _resp(status, b"hop", headers)
    srv = _make_server(behavior)
    yield srv
    srv.shutdown()
    srv.server_close()


def _url(srv, path="/"):
    return "http://127.0.0.1:%d%s" % (srv.server_address[1], path)


# -------------------------------------------------------------- tests

def test_discover_redirect_params_suspects_and_url_values():
    params = {"url": "x", "q": "plain", "custom": "http://a.example/",
              "weird": "b://c"}
    found = discover_redirect_params(params)
    assert "url" in found
    assert "custom" in found
    assert "weird" in found
    assert "q" not in found


def test_open_redirect_confirmed_via_differential(open_redirect_server):
    res = run_redirects(_url(open_redirect_server),
                        params={"url": "http://start"})
    assert res["ran"] == ["redirects"]
    hits = [f for f in res["findings"]
            if f["title"].startswith("Open redirect")]
    assert len(hits) == 1
    f = hits[0]
    assert f["severity"] == "high"
    assert f["verification"] == "confirmed"
    assert f["source"] == "omega-redirects/open_redirect_param"
    assert "/dashboard" in f["verification_note"]
    assert f["evidence"]["param"] == "url"


def test_open_redirect_unconditional_stays_candidate(
        unconditional_redirect_server):
    res = run_redirects(_url(unconditional_redirect_server),
                        params={"url": "http://start"})
    f = [x for x in res["findings"]
         if x["title"].startswith("Open redirect")][0]
    assert f["verification"] == "candidate"


def test_client_side_redirect_medium_candidate(client_redirect_server):
    res = run_redirects(_url(client_redirect_server),
                        params={"url": "http://start"})
    f = [x for x in res["findings"]
         if x["title"].startswith("Client-side open redirect")][0]
    assert f["severity"] == "medium"
    assert f["verification"] == "candidate"
    assert PROBE_HOST in f["evidence"]["client_target"]


def test_reflected_param_low_echo_server(echo_server):
    res = run_redirects(_url(echo_server),
                        params={"next": "http://start"})
    f = [x for x in res["findings"]
         if x["title"].startswith("Reflected redirect param")][0]
    assert f["severity"] == "low"
    assert f["verification"] == "candidate"


def test_constant_server_zero_findings(constant_server):
    res = run_redirects(_url(constant_server),
                        params={"url": "http://start", "next": "/x"})
    assert res["findings"] == []
    assert res["ran"] == ["redirects"]


def test_clean_param_no_finding(open_redirect_server):
    """A param that echoes/redirects internally leaves no finding."""
    res = run_redirects(_url(open_redirect_server),
                        params={"return": "/dashboard"})
    assert res["findings"] == []
    assert res["probed"] == ["return"]


def test_chain_long_and_crosses_boundary(chain_server):
    res = run_redirects(_url(chain_server, "/h1"))
    titles = [f["title"] for f in res["findings"]]
    assert "Redirect chain crosses trust boundary" in titles
    assert "Redirect chain longer than 3 hops" in titles
    boundary = [f for f in res["findings"]
                if f["title"] == "Redirect chain crosses trust boundary"][0]
    assert boundary["severity"] == "medium"
    assert boundary["verification"] == "candidate"
    assert boundary["evidence"]["crossed_to"] == "http://elsewhere.example/"
    info = [f for f in res["findings"]
            if f["title"] == "Redirect chain longer than 3 hops"][0]
    assert info["severity"] == "info"
    assert info["evidence"]["hops"] == 5


def test_short_chain_no_findings(chain_server):
    res = run_redirects(_url(chain_server, "/c1"))
    assert res["findings"] == []


def test_chain_boundary_single_hop(chain_server):
    res = run_redirects(_url(chain_server, "/b1"))
    boundary = [f for f in res["findings"]
                if f["title"] == "Redirect chain crosses trust boundary"]
    assert len(boundary) == 1
    assert boundary[0]["evidence"]["hops"] == 1


def test_request_cap_40_and_accounting(open_redirect_server):
    params = {"p%d" % i: "http://x/%d" % i for i in range(30)}
    res = run_redirects(_url(open_redirect_server), params=params)
    assert res["requests_sent"] <= 40
    assert res["budget"] == 40


def test_budget_exhaustion_skips(open_redirect_server):
    res = run_redirects(_url(open_redirect_server),
                        params={"url": "http://a", "next": "http://b"},
                        budget=2)
    assert res["requests_sent"] <= 2
    assert res["skipped"].get("chain") == "budget exhausted"
    assert any("next" in k for k in res["skipped"])


def test_dedupe_per_param(open_redirect_server):
    """Each param is probed exactly once even with duplicate names."""
    res = run_redirects(_url(open_redirect_server),
                        params={"url": "http://a", "url": "http://b"})
    assert res["probed"].count("url") == 1


def test_never_raises_on_broken_fetch(open_redirect_server):
    def broken(method, url, headers=None, body=None):
        raise RuntimeError("network down")
    res = run_redirects(_url(open_redirect_server),
                        fetch=broken, params={"url": "http://a"})
    assert res["ran"] == ["redirects"]
    assert res["findings"] == []
    assert res["skipped"]  # contained, not raised
    assert res["requests_sent"] == 0


def test_finding_shape_and_evidence_cap(open_redirect_server):
    res = run_redirects(_url(open_redirect_server),
                        params={"url": "http://a"})
    for f in res["findings"]:
        for key in ("title", "severity", "confidence", "verification",
                    "manual_check", "location", "evidence", "source"):
            assert key in f
        assert f["manual_check"].startswith("curl ")
        assert len(json.dumps(f["evidence"])) <= 300


def test_result_keys(open_redirect_server):
    res = run_redirects(_url(open_redirect_server))
    assert set(["findings", "skipped", "requests_sent", "ran"]) <= set(res)
    assert res["ran"] == ["redirects"]
