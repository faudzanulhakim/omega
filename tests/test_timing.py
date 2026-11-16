"""Hermetic tests for omega/scanning/timing.py.

All servers are ThreadingHTTPServer instances on 127.0.0.1 ephemeral
ports with CONTROLLABLE artificial delay. No internet, no real sleep
payloads: the delay is injected by the fixture itself.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from omega.timing import (
    DEFAULT_ROUNDS,
    DEFAULT_SAMPLES,
    MAX_SAMPLES,
    MIN_MARGIN_S,
    env_samples,
    mad,
    median,
    run_timing,
    time_url,
    timing_differential,
)


# ------------------------------------------------------------ fixtures

class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):      # noqa: N802 (http.server API)
        q = {k: v[0] for k, v in
             parse_qs(urlsplit(self.path).query, keep_blank_values=True).items()}
        delay = float(self.server.omega_delay(q, self.path))
        if delay:
            time.sleep(delay)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):   # silence
        pass


def _make_server(delay_fn):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.omega_delay = delay_fn
    t = threading.Thread(target=srv.serve_forever,
                         kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    return srv


@pytest.fixture
def slow_admin_server():
    """Sleeps 0.25s only for username=admin; 5ms otherwise."""
    srv = _make_server(lambda q, p: 0.25 if q.get("username") == "admin"
                       else 0.005)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def constant_server():
    srv = _make_server(lambda q, p: 0.005)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def slow_token_server():
    """Sleeps 0.25s for token=known-token; 5ms otherwise."""
    srv = _make_server(lambda q, p: 0.25 if q.get("token") == "known-token"
                       else 0.005)
    yield srv
    srv.shutdown()
    srv.server_close()


def _url(srv, path="/"):
    return "http://127.0.0.1:%d%s" % (srv.server_address[1], path)


# -------------------------------------------------------------- helpers

def test_median_and_mad_basics():
    assert median([1.0, 2.0, 3.0]) == 2.0
    assert median([1.0, 2.0, 3.0, 4.0]) == 2.5
    assert median([]) == 0.0
    assert mad([1.0, 1.0, 1.0]) == 0.0
    assert mad([]) == 0.0
    assert mad([1.0, 1.0, 1.0, 11.0]) == 0.0  # median 1.0, deviations 0,0,0,10
    assert mad([2.0, 4.0]) == 1.0


def test_env_samples_default_and_clamp(monkeypatch):
    monkeypatch.delenv("OMEGA_TIMING_SAMPLES", raising=False)
    assert env_samples() == DEFAULT_SAMPLES == 5
    monkeypatch.setenv("OMEGA_TIMING_SAMPLES", "50")
    assert env_samples() == MAX_SAMPLES == 20
    monkeypatch.setenv("OMEGA_TIMING_SAMPLES", "0")
    assert env_samples() == 1
    monkeypatch.setenv("OMEGA_TIMING_SAMPLES", "not-a-number")
    assert env_samples() == DEFAULT_SAMPLES


def test_env_samples_configures_probe(monkeypatch, constant_server):
    monkeypatch.setenv("OMEGA_TIMING_SAMPLES", "3")
    samples = time_url(_url(constant_server), samples=None)
    assert len(samples) == 3


def test_time_url_counts_failed_samples(constant_server, monkeypatch):
    def bad_fetch(method, url, headers=None):
        raise OSError("boom")
    out = time_url(_url(constant_server), fetch=bad_fetch, samples=4)
    assert len(out) == 4
    assert all(v is None for v in out)


# -------------------------------------------------------- differential

def test_differential_flags_slow_candidate(slow_admin_server):
    base = _url(slow_admin_server) + "/login?username=nope123&password=x"
    cand = _url(slow_admin_server) + "/login?username=admin&password=x"
    res = timing_differential(base, cand, samples=3, rounds=2)
    assert res["flagged"] and res["confirmed"]
    assert res["samples"] == 3
    assert res["candidate_median"] > res["baseline_median"]


def test_differential_not_flagged_on_constant(constant_server):
    url = _url(constant_server) + "/login?username=a&password=x"
    res = timing_differential(url, url, samples=3, rounds=2)
    assert not res["flagged"] and not res["confirmed"]
    assert not res["candidate_median"] > res["baseline_median"] * 2.5


def test_differential_evidence_fields(slow_admin_server):
    base = _url(slow_admin_server) + "/?username=nope&password=x"
    cand = _url(slow_admin_server) + "/?username=admin&password=x"
    res = timing_differential(base, cand, samples=3, rounds=1)
    for key in ("samples", "baseline_median", "baseline_mad",
                "candidate_median", "candidate_mad", "rounds", "factor"):
        assert key in res
    assert res["rounds"] == 1


# -------------------------------------------------------- entrypoints

def test_login_timing_probe_detects(slow_admin_server):
    res = run_timing(_url(slow_admin_server), login_url="/login",
                     samples=3, rounds=2)
    assert res["ran"] == ["login_timing"]
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["severity"] == "medium"
    assert f["verification"] == "candidate"   # never auto-confirmed
    ev = f["evidence"]
    assert ev["samples"] == 3 and ev["rounds"] == 2
    assert ev["candidate_median"] > ev["baseline_median"]


def test_login_timing_probe_no_false_positive(constant_server):
    res = run_timing(_url(constant_server), login_url="/login",
                     samples=3, rounds=2)
    assert res["findings"] == []
    assert res["ran"] == ["login_timing"]


def test_token_timing_probe_detects(slow_token_server):
    res = run_timing(_url(slow_token_server),
                     known_values={"token": "known-token"},
                     samples=3, rounds=2)
    assert res["ran"] == ["token_timing:token"]
    assert len(res["findings"]) == 1
    assert res["findings"][0]["title"].startswith(
        "Timing differential for parameter 'token'")


def test_token_timing_probe_no_false_positive(constant_server):
    res = run_timing(_url(constant_server),
                     known_values={"token": "whatever"}, samples=3, rounds=2)
    assert res["findings"] == []


def test_run_timing_never_raises_on_bad_fetch(slow_admin_server):
    def bad_fetch(method, url, headers=None):
        raise OSError("boom")
    res = run_timing(_url(slow_admin_server), login_url="/login",
                     known_values={"token": "x"}, fetch=bad_fetch,
                     samples=2, rounds=1)
    assert res["findings"] == []
    # transport errors become failed samples (never exceptions)
    assert res["ran"] == ["login_timing", "token_timing:token"]


def test_constants_documented():
    assert DEFAULT_SAMPLES == 5
    assert DEFAULT_ROUNDS >= 2
    assert MIN_MARGIN_S > 0
