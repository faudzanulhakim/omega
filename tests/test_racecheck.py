"""Hermetic tests for omega/racecheck.py — GET-only race probe.

Covers: stable server -> no findings, alternating-status server ->
candidate LOW + serialization INFO, non-GET refusal (ValueError),
the hard request cap (<=20), and never-raises containment.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.racecheck import MAX_REQUESTS, race_probe, run_racecheck

COUNT = {"n": 0}


def _stable(_method, _url, _h=None):
    return 200, {}, b"consistent body"


def _alternating(_method, _url, _h=None):
    COUNT["n"] += 1
    if COUNT["n"] % 2:
        return 200, {}, b"version A body"
    return 500, {}, b"version B body"


@pytest.fixture(autouse=True)
def _reset_count():
    COUNT["n"] = 0


def test_stable_server_no_finding():
    out = race_probe("http://stub.invalid", fetch=_stable, n=5)
    assert out["findings"] == []
    assert out["consistent"] is True
    assert out["requests_sent"] == 5
    assert out["serialization"].startswith("info:")


def test_alternating_server_candidate_low_and_info():
    out = race_probe("http://stub.invalid", fetch=_alternating, n=5)
    severities = sorted(f["severity"] for f in out["findings"])
    assert severities == ["info", "low"]
    low = [f for f in out["findings"] if f["severity"] == "low"][0]
    assert low["verification"] == "candidate"
    assert low["source"] == "omega-race/probe"
    assert out["consistent"] is False
    assert len(set(out["statuses"])) == 2


def test_non_get_refused():
    for method in ("POST", "PUT", "DELETE", "PATCH", "TRACE", "HEAD"):
        with pytest.raises(ValueError):
            race_probe("http://stub.invalid", fetch=_stable,
                       method=method)
    # GET (any case) is accepted
    out = race_probe("http://stub.invalid", fetch=_stable, method="GET")
    assert out["findings"] == []


def test_request_cap_20():
    sent = {"n": 0}

    def counting(_m, _u, _h=None):
        sent["n"] += 1
        return 200, {}, b"same"

    out = race_probe("http://stub.invalid", fetch=counting, n=500)
    assert out["requests_sent"] <= MAX_REQUESTS == 20
    assert sent["n"] <= MAX_REQUESTS


def test_run_racecheck_allowlist_and_never_raises():
    out = run_racecheck("http://stub.invalid", fetch=_stable,
                        allowlist=["example.invalid"])
    assert out["findings"] == []
    assert "not in allowlist" in out["skipped"]["__all__"]
    # failing transport: contained, never raises
    def boom(_m, _u, _h=None):
        raise OSError("refused")
    out2 = run_racecheck("http://stub.invalid", fetch=boom, n=3)
    assert isinstance(out2, dict)
    assert out2["findings"] == []
    assert out2["serialization"] is None or isinstance(
        out2["serialization"], str)


def test_run_racecheck_happy_path():
    out = run_racecheck("http://stub.invalid", fetch=_alternating)
    assert out["ran"] == ["race_probe"]
    assert len(out["findings"]) == 2
    assert out["requests_sent"] <= MAX_REQUESTS
