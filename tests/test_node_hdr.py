"""Hermetic tests for omega/adapters/node_hdr.py + node/hdrscore.mjs.

All network is local (ThreadingHTTPServer on 127.0.0.1); the node
scorer subprocess only reads stdin. Fail-closed behavior (skip entries)
is asserted for every error mode; findings are never 'confirmed'.
"""
import json
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.adapters import node_hdr

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
    "X-Content-Type-Options": "nosniff",
    "Set-Cookie": "sid=1; Path=/; Secure; HttpOnly; SameSite=Strict",
}


def make_server(headers, cookie=None):
    """Build a local ThreadingHTTPServer with the given headers."""
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html>omega node-hdr fixture</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            for k, v in headers.items():
                self.send_header(k, v)
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()

        def log_message(self, *a):  # silence
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    import threading
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


@pytest.fixture()
def gate(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")


@pytest.fixture()
def bad_server():
    srv = make_server({}, cookie="session=abc123; Path=/")
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture()
def good_server():
    srv = make_server(GOOD_HEADERS)
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def real_fetch(method, url, headers=None, body=None):
    return node_hdr._default_fetch(method, url, headers, body)


# ------------------------------------------------------ scorer (real node)
def test_scorer_bad_server_zero_score(bad_server):
    proc = subprocess.run(
        ["node", node_hdr.HDRSCORE_MJS],
        input=json.dumps({"headers": {"set-cookie": "session=abc; Path=/"},
                          "url": bad_server + "/"}),
        capture_output=True, text=True, timeout=30)
    rep = json.loads(proc.stdout)
    # http:// endpoint: HSTS is n-a, so all other deductions apply (80)
    assert rep["score"] == 20
    assert rep["grade"] == "F"
    ids = {i["id"] for i in rep["issues"]}
    assert {"hsts-missing", "csp-missing", "frame-deny-missing",
            "referrer-missing", "permissions-missing", "cto-missing",
            "cookie-flags"} <= ids


def test_scorer_good_server_high_score(good_server):
    proc = subprocess.run(
        ["node", node_hdr.HDRSCORE_MJS],
        input=json.dumps({"headers": dict(GOOD_HEADERS),
                          "url": good_server + "/"}),
        capture_output=True, text=True, timeout=30)
    rep = json.loads(proc.stdout)
    assert rep["score"] >= 90
    assert rep["grade"] == "A"
    assert all("n-a" in i["detail"] for i in rep["issues"]
               if i["id"] == "hsts-missing")


def test_scorer_https_deducts_hsts():
    hdrs = {k: v for k, v in GOOD_HEADERS.items()
            if k != "Strict-Transport-Security"}
    proc = subprocess.run(
        ["node", node_hdr.HDRSCORE_MJS],
        input=json.dumps({"headers": hdrs,
                          "url": "https://example.test/"}),
        capture_output=True, text=True, timeout=30)
    rep = json.loads(proc.stdout)
    assert rep["score"] == 80  # only HSTS deducted (20)
    assert rep["grade"] == "B"


# ------------------------------------------------------ runner: gate/skips
def test_gate_skips_without_env(bad_server, monkeypatch):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    res = node_hdr.run_hdrscore(bad_server, real_fetch)
    assert res["findings"] == []
    assert res["requests_sent"] == 0
    assert res["skipped"][0]["reason"].startswith("PTK_POLYGLOT")


def test_node_missing_contained_skip(bad_server, gate, monkeypatch):
    res = node_hdr.run_hdrscore(bad_server, real_fetch,
                                which_fn=lambda name: None)
    assert res["findings"] == []
    assert res["skipped"] == [{"suite": "node-hdr",
                               "reason": "node unavailable"}]


def test_malformed_output_contained_skip(bad_server, gate, monkeypatch):
    class FakeProc:
        returncode = 0
        stdout = "this is not json <<<"

    def fake_run(*a, **kw):
        return FakeProc()

    monkeypatch.setattr(node_hdr.subprocess, "run", fake_run)
    res = node_hdr.run_hdrscore(bad_server, real_fetch)
    assert res["findings"] == []
    assert res["skipped"][0]["suite"] == "node-hdr"
    assert "malformed" in res["skipped"][0]["reason"]


def test_timeout_contained_skip(bad_server, gate, monkeypatch):
    def fake_run(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="node", timeout=30)

    monkeypatch.setattr(node_hdr.subprocess, "run", fake_run)
    res = node_hdr.run_hdrscore(bad_server, real_fetch)
    assert res["findings"] == []
    assert res["skipped"][0]["reason"] == "hdrscore.mjs timed out"


def test_unreachable_target_contained_skip(gate):
    res = node_hdr.run_hdrscore("http://127.0.0.1:1", real_fetch)
    assert res["findings"] == []
    assert any("unreachable" in s["reason"] for s in res["skipped"])


# ------------------------------------------------------ runner: real path
def test_bad_server_findings_and_request_cap(bad_server, gate):
    counted = []

    def counting_fetch(method, url, headers=None, body=None):
        counted.append((method, url))
        return real_fetch(method, url, headers, body)

    res = node_hdr.run_hdrscore(bad_server, counting_fetch)
    assert res["requests_sent"] <= 3
    assert len(counted) == res["requests_sent"]
    assert "node-hdr.hdrscore" in res["ran"]
    srcs = [f["source"] for f in res["findings"]]
    assert any(s.startswith("node-hdr/") for s in srcs)
    inventory = [f for f in res["findings"]
                 if f["source"] == "node-hdr/inventory"]
    assert len(inventory) == 1
    assert inventory[0]["severity"] == "info"
    for f in res["findings"]:
        for key in ("title", "severity", "confidence", "verification",
                    "source", "evidence", "location", "manual_check"):
            assert key in f
        assert f["verification"] == "candidate"
        assert f["confidence"] == "candidate"
        assert len(f["evidence"]) <= 300
        assert f["manual_check"].startswith("curl -sI ")
        assert bad_server in f["manual_check"] or bad_server in f["location"]
    assert any(f["severity"] == "high" for f in res["findings"]
               )  # hsts/csp missing => high


def test_good_server_minimal_issues(good_server, gate):
    res = node_hdr.run_hdrscore(good_server, real_fetch)
    # only the n-a hsts issue (info) + inventory => no medium/high findings
    assert not [f for f in res["findings"] if f["severity"] in
                ("low", "medium", "high")]
    inv = [f for f in res["findings"]
           if f["source"] == "node-hdr/inventory"][0]
    assert "grade=A" in inv["evidence"]


def test_verification_never_confirmed(bad_server, gate):
    res = node_hdr.run_hdrscore(bad_server, real_fetch)
    for f in res["findings"]:
        assert f["verification"] != "confirmed"
