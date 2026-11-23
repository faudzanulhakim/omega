"""Hermetic tests for omega/oobscan.py — blind-interaction scanner.

All servers are ThreadingHTTPServer instances on 127.0.0.1 ephemeral
ports; the OOB collector is the real omega.oob.OOBCallbackServer (also
127.0.0.1). No internet: the canary host TOKEN.oobhost never resolves,
so reflection alone can never produce a false OOB positive.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import urlopen

import pytest

from omega.oob import OOBCallbackServer
from omega.oobscan import (
    NO_CALLBACK_NOTE,
    OOBSCAN_SUSPECT_PARAMS,
    run_oobscan,
)


# ------------------------------------------------------------ fixtures

class _Handler(BaseHTTPRequestHandler):
    def _handle(self):
        status, headers, body = self.server.omega_behavior(self.path)
        self.send_response(status)
        for key, val in headers.items():
            self.send_header(key, val)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):      # noqa: N802 (http.server API)
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


@pytest.fixture
def echo_server():
    """Echoes any param value into the body. Reflected canary values
    must NEVER produce an OOB positive (no real callback happens)."""
    def behavior(path):
        q = _q(path)
        body = ("echo: " + json.dumps(q, sort_keys=True)).encode()
        return 200, {}, body
    srv = _make_server(behavior)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def ssrf_vulnerable_server():
    """'Vulnerable' fixture: fetches the url param server-side via
    urllib (1s timeout) and embeds the fetched body — the differential
    confirm path with REAL local HTTP."""
    def behavior(path):
        q = _q(path)
        val = q.get("url", "")
        fetched = b""
        if val.startswith("http"):
            try:
                with urlopen(val, timeout=1.0) as resp:
                    fetched = resp.read(65536)
            except Exception:
                fetched = b"fetch-error"
        body = b"page | internal: " + fetched
        return 200, {}, body
    srv = _make_server(behavior)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def constant_server():
    def behavior(_path):
        return 200, {}, b"ok"
    srv = _make_server(behavior)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def oob():
    with OOBCallbackServer() as srv:
        yield srv


class _StubOOB:
    """Duck-typed OOB handle whose exact tokens always 'receive a
    callback' — lets us exercise the interaction-hit classification
    hermetically."""

    running = True

    def new_token(self):
        import secrets
        return secrets.token_hex(16)

    def hits(self, token=None):
        if token is None:
            return []
        return [{"token": token, "path": "/" + token, "method": "GET",
                 "remote": "127.0.0.1", "ts": 0.0}]


def _url(srv, path="/"):
    return "http://127.0.0.1:%d%s" % (srv.server_address[1], path)


# -------------------------------------------------------------- tests

def test_oob_interaction_hit_candidate(oob, echo_server):
    res = run_oobscan(_url(echo_server), params={"url": "x"},
                      oob_server=_StubOOB(), internal_ports=[])
    assert res["ran"] == ["oobscan"]
    f = [x for x in res["findings"]
         if x["title"] == "Out-of-band interaction via parameter 'url'"]
    assert len(f) == 1
    assert f[0]["severity"] in ("medium", "high")
    assert f[0]["verification"] == "candidate"  # never auto-confirmed
    assert f[0]["evidence"]["token"] == res["tokens"][0]["token"]
    assert f[0]["evidence"]["path"] == "/" + res["tokens"][0]["token"]


def test_oob_tokens_unique_across_runs(oob, echo_server):
    r1 = run_oobscan(_url(echo_server), params={"url": "x"},
                     oob_server=oob, internal_ports=[])
    r2 = run_oobscan(_url(echo_server), params={"url": "x"},
                     oob_server=oob, internal_ports=[])
    t1 = [t["token"] for t in r1["tokens"]]
    t2 = [t["token"] for t in r2["tokens"]]
    assert t1 and t2
    assert set(t1).isdisjoint(t2)


def test_no_callback_is_no_finding_and_inconclusive(oob, echo_server):
    """Reflected canary + real OOB server: no callback -> NO finding,
    and the result explicitly says absence is inconclusive."""
    res = run_oobscan(_url(echo_server), params={"url": "x", "host": "h"},
                      oob_server=oob, internal_ports=[])
    oob_findings = [f for f in res["findings"]
                    if f["title"].startswith("Out-of-band")]
    assert oob_findings == []
    assert res["tokens"]  # canaries were planted and polled
    assert "inconclusive" in res["note"].lower()
    assert NO_CALLBACK_NOTE  # documented honest-label constant exists


def test_reflection_never_false_oob_positive(oob, echo_server):
    """The echo server reflects 'TOKEN.oobhost' verbatim; the OOB
    collector must still record zero hits and the scan zero findings."""
    res = run_oobscan(_url(echo_server), params={"url": "x"},
                      oob_server=oob, internal_ports=[])
    assert res["findings"] == []
    assert oob.hits() == []


def test_ssrf_internal_reflection_confirmed(oob, ssrf_vulnerable_server):
    """Real differential: the vulnerable fixture fetches our own local
    OOB server server-side and embeds its body; the fingerprint match
    + clean control => the one 'confirmed' finding the module allows."""
    res = run_oobscan(_url(ssrf_vulnerable_server), params={"url": "x"},
                      oob_server=oob)
    f = [x for x in res["findings"]
         if x["title"] == "Internal service response reflected "
                          "(SSRF evidence)"]
    assert len(f) == 1
    assert f[0]["severity"] == "high"
    assert f[0]["verification"] == "confirmed"
    assert f[0]["evidence"]["internal_port"] == oob.port
    assert "differential" in f[0]["evidence"]


def test_echo_server_no_ssrf_evidence(oob, echo_server):
    """Reflection of the URL string is NOT fingerprint content -> no
    SSRF finding."""
    res = run_oobscan(_url(echo_server), params={"url": "x"},
                      oob_server=oob)
    ssrf = [f for f in res["findings"]
            if "SSRF" in f["title"] or "SSRF" in f["title"].upper()]
    assert ssrf == []


def test_constant_server_zero_findings(oob, constant_server):
    res = run_oobscan(_url(constant_server), params={"url": "x"},
                      oob_server=oob)
    assert res["findings"] == []


def test_oob_server_unavailable_skip(echo_server, monkeypatch):
    """No handle + omega.oob import blocked => skipped, never raises."""
    import sys
    monkeypatch.setitem(sys.modules, "omega.oob", None)
    res = run_oobscan(_url(echo_server), params={"url": "x"})
    assert res["findings"] == []
    assert "oob server unavailable" in res["skipped"].get("oobscan", "")


def test_stopped_server_handle_skips(echo_server):
    dead = OOBCallbackServer()  # never started
    res = run_oobscan(_url(echo_server), params={"url": "x"},
                      oob_server=dead)
    assert res["skipped"].get("oobscan") == "oob server unavailable"


def test_default_suspect_params_used(oob, echo_server):
    res = run_oobscan(_url(echo_server), oob_server=oob,
                      internal_ports=[])
    planted = {t["param"] for t in res["tokens"]}
    assert planted == set(OOBSCAN_SUSPECT_PARAMS)


def test_url_shaped_vs_host_shaped_values(oob, echo_server):
    res = run_oobscan(_url(echo_server), params={"url": "x", "host": "h"},
                      oob_server=oob, internal_ports=[])
    by_param = {t["param"]: t["value"] for t in res["tokens"]}
    assert by_param["url"].startswith("http://")
    assert by_param["url"].endswith(".oobhost/")
    assert not by_param["host"].startswith("http")
    assert by_param["host"].endswith(".oobhost")


def test_request_cap_and_accounting(oob, echo_server):
    res = run_oobscan(_url(echo_server), oob_server=oob)
    assert res["requests_sent"] <= 20
    assert res["budget"] == 20


def test_budget_exhaustion_skips(oob, echo_server):
    res = run_oobscan(_url(echo_server), oob_server=oob, budget=1)
    assert res["requests_sent"] <= 1
    assert any("budget exhausted" in v for v in res["skipped"].values())


def test_never_raises_on_broken_fetch(oob, echo_server):
    def broken(method, url, headers=None, body=None):
        raise RuntimeError("network down")
    res = run_oobscan(_url(echo_server), fetch=broken, oob_server=oob,
                      internal_ports=[])
    assert res["ran"] == ["oobscan"]
    assert res["findings"] == []
    assert res["skipped"]
    assert res["requests_sent"] == 0


def test_no_confirmed_without_differential(oob, echo_server):
    """Every non-SSRF finding must be 'candidate'; the module never
    claims 'confirmed' without the documented fingerprint differential."""
    res = run_oobscan(_url(echo_server), oob_server=_StubOOB(),
                      internal_ports=[])
    for f in res["findings"]:
        if f["source"] == "omega-oobscan/oob_interaction":
            assert f["verification"] == "candidate"


def test_finding_shape_and_evidence_cap(oob, ssrf_vulnerable_server):
    res = run_oobscan(_url(ssrf_vulnerable_server), oob_server=oob)
    for f in res["findings"]:
        for key in ("title", "severity", "confidence", "verification",
                    "manual_check", "location", "evidence", "source"):
            assert key in f
        assert f["manual_check"].startswith("curl ")
        assert f["location"].startswith("http")
        assert len(json.dumps(f["evidence"])) <= 300


def test_result_keys(oob, echo_server):
    res = run_oobscan(_url(echo_server), oob_server=oob, internal_ports=[])
    assert set(["findings", "skipped", "requests_sent", "ran"]) <= set(res)
    assert res["ran"] == ["oobscan"]
