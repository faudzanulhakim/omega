"""Hermetic tests for omega/adapters/jqdiff.py + jq/diffstat.jq.

All network is local (ThreadingHTTPServer on 127.0.0.1); jq runs only
on stdin/stdout. Fail-closed quarantine behavior is asserted; findings
are never 'confirmed'.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.adapters import jqdiff


def make_server(responder):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            responder(self)

        def log_message(self, *a):  # silence
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


@pytest.fixture()
def gate(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")


@pytest.fixture()
def leaking_server():
    """Reflects any query param value 6 times => >=5 new tokens."""
    def responder(handler):
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(handler.path).query)
        if "_omega_marker" in qs:
            # baseline: inert marker must NOT be reflected
            body = b"<html>static baseline content 1234567890abcdef</html>"
        else:
            marker = next(iter(qs.values()))[0] if qs else "static"
            body = " ".join(f"k{i}={marker}" for i in range(6)).encode()
        handler.send_response(200)
        handler.send_header("Content-Type", "text/html")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    srv = make_server(responder)
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture()
def static_server():
    """Constant body regardless of params (FP guard => no leak findings)."""
    def responder(handler):
        body = b"<html>constant baseline page body</html>"
        handler.send_response(200)
        handler.send_header("Content-Type", "text/html")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    srv = make_server(responder)
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def real_fetch(method, url, headers=None, body=None):
    return jqdiff._default_fetch(method, url, headers, body)


# ------------------------------------------------------------ diffstat.jq
def test_diffstat_filter_basic(tmp_path):
    import subprocess
    payload = {
        "baseline": {"status": 200, "headers": {}, "body": "aa bb cc"},
        "probe": {"status": 404, "headers": {},
                  "body": "aa bb somereallynewtoken123 extra9999xx"},
    }
    proc = subprocess.run(
        ["jq", "-c", "-f", jqdiff.DIFFSTAT_JQ],
        input=json.dumps(payload), capture_output=True, text=True, timeout=30)
    out = json.loads(proc.stdout)
    assert out["body_len_delta"] > 0
    assert out["status_delta"] is True
    assert "somereallynewtoken123" in out["new_tokens"]
    assert "extra9999xx" in out["new_tokens"]
    assert "aa" not in out["new_tokens"]      # short + present in baseline
    assert "bb" not in out["new_tokens"]


def test_diffstat_filter_no_new_tokens():
    import subprocess
    payload = {
        "baseline": {"status": 200, "headers": {}, "body": "sharedtoken12345"},
        "probe": {"status": 200, "headers": {}, "body": "sharedtoken12345"},
    }
    proc = subprocess.run(
        ["jq", "-c", "-f", jqdiff.DIFFSTAT_JQ],
        input=json.dumps(payload), capture_output=True, text=True, timeout=30)
    out = json.loads(proc.stdout)
    assert out["body_len_delta"] == 0
    assert out["status_delta"] is False
    assert out["new_tokens"] == []


# ------------------------------------------------------------------- gate
def test_gate_skips_without_env(static_server, monkeypatch):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    res = jqdiff.run_jqdiff(static_server, real_fetch)
    assert res["findings"] == []
    assert res["requests_sent"] == 0
    assert res["skipped"][0]["reason"].startswith("PTK_POLYGLOT")


def test_jq_missing_contained_skip(static_server, gate):
    res = jqdiff.run_jqdiff(static_server, real_fetch,
                            which_fn=lambda name: None)
    assert res["findings"] == []
    assert res["skipped"] == [{"suite": "jq-diff",
                               "reason": "jq binary not found"}]


def test_unreachable_target_contained_skip(gate):
    res = jqdiff.run_jqdiff("http://127.0.0.1:1", real_fetch)
    assert res["findings"] == []
    assert any("unreachable" in s["reason"] for s in res["skipped"])
    assert res["requests_sent"] == 1


# --------------------------------------------------------- real jq runs
def test_leak_detected_with_caps(leaking_server, gate):
    counted = []

    def counting_fetch(method, url, headers=None, body=None):
        counted.append(url)
        return real_fetch(method, url, headers, body)

    res = jqdiff.run_jqdiff(leaking_server, counting_fetch)
    assert res["requests_sent"] <= 6
    assert len(counted) == res["requests_sent"]
    leaks = [f for f in res["findings"] if f["source"].startswith("jq-diff/q")]
    assert len(leaks) == 1
    leak = leaks[0]
    assert leak["severity"] == "low"
    assert leak["verification"] == "candidate"
    assert leak["confidence"] == "candidate"
    for key in ("title", "severity", "confidence", "verification",
                "source", "evidence", "location", "manual_check"):
        assert key in leak
    assert len(leak["evidence"]) <= 300
    assert leak["manual_check"].startswith("curl -s ")
    assert leaking_server in leak["manual_check"]


def test_constant_server_no_leak_fp_guard(static_server, gate):
    res = jqdiff.run_jqdiff(static_server, real_fetch)
    assert not [f for f in res["findings"]
                if f["severity"] != "info"]  # INFO inventory only
    inv = [f for f in res["findings"]
           if f["source"] == "jq-diff/inventory"]
    assert len(inv) == 1
    assert inv[0]["severity"] == "info"
    assert all(c < 5 for c in
               json.loads(inv[0]["evidence"].split("new_token_counts=")[1]
                          .rsplit(" baseline=", 1)[0]).values())


def test_baseline_path_offline(tmp_path, leaking_server, gate):
    # reuse the live server body as a pre-recorded baseline file
    res0 = jqdiff.run_jqdiff(leaking_server, real_fetch)
    # the baseline fetch uses an inert marker; grab a recorded response
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps({
        "status": 200, "headers": {},
        "body": "constantbaseline12345 sharedcontent6789"}))
    res = jqdiff.run_jqdiff(leaking_server, real_fetch,
                            baseline_path=str(baseline_file))
    assert res["requests_sent"] == res0["requests_sent"] - 1  # no baseline GET
    assert any(f["source"] == "jq-diff/q" for f in res["findings"])


def test_broken_baseline_quarantined(tmp_path, gate):
    baseline_file = tmp_path / "bad.json"
    baseline_file.write_text("{not json at all")
    res = jqdiff.run_jqdiff("http://127.0.0.1:59999", real_fetch,
                            baseline_path=str(baseline_file))
    assert res["findings"] == []
    assert res["skipped"][0]["reason"].startswith("baseline file")


def test_quarantine_on_bad_pair(leaking_server, gate, monkeypatch):
    """Monkeypatched jq run producing garbage => pair quarantined."""
    class FakeProc:
        returncode = 0
        stdout = "not-json-garbage"
        stderr = ""

    monkeypatch.setattr(jqdiff.subprocess, "run", lambda *a, **kw: FakeProc())
    res = jqdiff.run_jqdiff(leaking_server, real_fetch)
    assert res["ran"] == []          # no pair ran successfully
    assert not [f for f in res["findings"]
                if f["source"].startswith("jq-diff/q")]
    quarantined = [s for s in res["skipped"] if "quarantined" in s["reason"]]
    assert quarantined               # every pair fail-closed
    for f in res["findings"]:
        assert f["verification"] != "confirmed"
