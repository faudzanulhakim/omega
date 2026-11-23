"""Hermetic tests for omega/scanning/anomaly.py.

Baseline-vs-deviation fixtures on 127.0.0.1 ephemeral ports; the
stack-trace fingerprint path is exercised with a real Python traceback
line served by the fixture.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.anomaly import (
    LENGTH_BUCKET,
    SENSITIVE_HEADERS,
    STACK_TRACE_FINGERPRINTS,
    check_path,
    learn_baseline,
    run_anomaly,
)

TRACEBACK_BODY = (
    "internal error\n"
    "Traceback (most recent call last):\n"
    '  File "app.py", line 1, in <module>\n'
    "ZeroDivisionError: division by zero\n"
).encode()

DEBUG_BODY = (
    "<h1>Technical details</h1>"
    "django.views.debug.ExceptionReporter\n"
    "Exception Value: bad\n"
).encode()

FIVEXX_BODY = b"oops"

PLAIN_BODY = b"ok"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):      # noqa: N802 (http.server API)
        status, headers, body = self.server.omega_behavior(self.path)
        body = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        for key, val in (headers or {}).items():
            self.send_header(key, val)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):   # silence
        pass


def _make_server(behavior):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.omega_behavior = behavior
    t = threading.Thread(target=srv.serve_forever,
                         kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    return srv


@pytest.fixture
def anomaly_server():
    """/ is healthy; /crash 500s with a traceback; /debug shows Django
    debug markers; /hdr adds a sensitive header; /ctype flips type."""
    def behavior(path):
        if path == "/crash":
            return 500, {}, TRACEBACK_BODY
        if path == "/debug":
            return 200, {}, DEBUG_BODY
        if path == "/hdr":
            return 200, {"X-Debug-Token": "abc123"}, PLAIN_BODY
        if path == "/ctype":
            return 200, {"Content-Type": "application/json"}, b"{}"
        return 200, {"Content-Type": "text/html"}, PLAIN_BODY
    srv = _make_server(behavior)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def broken_server():
    srv = _make_server(lambda path: (_ for _ in ()).throw(OSError("dead")))
    yield srv
    srv.shutdown()
    srv.server_close()


def _url(srv, path="/"):
    return "http://127.0.0.1:%d%s" % (srv.server_address[1], path)


# ------------------------------------------------------------- baseline

def test_learn_baseline_profiles(anomaly_server):
    base = learn_baseline(_url(anomaly_server), ["/", "/ctype"])
    assert set(base) == {"/", "/ctype"}
    p = base["/"]
    assert p["status"] == 200
    assert "content-type" in p["headers"]
    assert p["content_type"].startswith("text/html")
    assert p["length_bucket"] == len(PLAIN_BODY) // LENGTH_BUCKET


def test_learn_baseline_never_raises(broken_server):
    base = learn_baseline(_url(broken_server), ["/"])
    assert base["/"]["status"] == 0
    assert base["/"]["length_bucket"] == 0


# ---------------------------------------------------------- fingerprints

def test_stack_trace_fingerprints_exist():
    labels = [label for label, _rx in STACK_TRACE_FINGERPRINTS]
    assert "python traceback" in labels
    assert "asp.net yellow screen" in labels
    assert "java stack trace" in labels


def test_check_path_confirms_stack_trace(anomaly_server):
    profile = {"status": 200, "headers": ["content-type"],
               "length_bucket": 0, "content_type": "text/html"}
    res = check_path(_url(anomaly_server, "/crash"), profile)
    stack = [f for f in res["findings"]
             if f["source"] == "omega-anomaly/stack-trace"]
    assert len(stack) == 1
    f = stack[0]
    assert f["severity"] == "high"
    assert f["verification"] == "confirmed"    # unambiguous fingerprint
    ev = f["evidence"]
    assert "Traceback (most recent call last)" in ev["fingerprint"]
    assert len(ev["fingerprint"]) <= 300


def test_fingerprint_evidence_capped_at_300_chars():
    long_line = "Traceback (most recent call last): " + "x" * 1000
    import re
    rx = dict(STACK_TRACE_FINGERPRINTS)["python traceback"]
    from omega.anomaly import _match_line
    line = _match_line(long_line, rx)
    assert line is not None and len(line) <= 300


def test_check_path_flags_debug_flag_as_candidate(anomaly_server):
    profile = {"status": 200, "headers": [], "length_bucket": 0,
               "content_type": "text/html"}
    res = check_path(_url(anomaly_server, "/debug"), profile)
    dbg = [f for f in res["findings"]
           if f["source"] == "omega-anomaly/debug-flag"]
    assert dbg and dbg[0]["verification"] == "candidate"
    assert dbg[0]["severity"] == "medium"


def test_check_path_flags_unexpected_5xx(anomaly_server):
    profile = {"status": 200, "headers": ["content-type"],
               "length_bucket": 0, "content_type": "text/html"}
    res = check_path(_url(anomaly_server, "/crash"), profile)
    fivexx = [f for f in res["findings"] if f["source"] == "omega-anomaly/5xx"]
    assert fivexx and fivexx[0]["severity"] == "medium"
    assert fivexx[0]["verification"] == "candidate"


def test_check_path_flags_new_sensitive_header(anomaly_server):
    profile = {"status": 200, "headers": ["content-type"],
               "length_bucket": 0, "content_type": "text/html"}
    res = check_path(_url(anomaly_server, "/hdr"), profile)
    hdr = [f for f in res["findings"]
           if f["source"] == "omega-anomaly/headers"]
    assert hdr and hdr[0]["severity"] == "low"
    assert "x-debug-token" in hdr[0]["evidence"]["headers"]
    assert "x-debug-token" in SENSITIVE_HEADERS


def test_check_path_flags_content_type_deviation(anomaly_server):
    profile = {"status": 200, "headers": ["content-type"],
               "length_bucket": 0, "content_type": "text/html"}
    res = check_path(_url(anomaly_server, "/ctype"), profile)
    ct = [f for f in res["findings"]
          if f["source"] == "omega-anomaly/content-type"]
    assert ct and ct[0]["verification"] == "candidate"


def test_check_path_no_deviations_on_healthy(anomaly_server):
    base = learn_baseline(_url(anomaly_server), ["/"])
    res = check_path(_url(anomaly_server, "/"), base["/"])
    assert res["findings"] == []
    assert res["deviations"] == []


# ----------------------------------------------------------- entrypoint

def test_run_anomaly_full_flow(anomaly_server):
    res = run_anomaly(_url(anomaly_server),
                      ["/", "/crash", "/debug", "/hdr"])
    assert res["ran"] == ["/", "/crash", "/debug", "/hdr"]
    assert not res["skipped"]
    sources = {f["source"] for f in res["findings"]}
    assert "omega-anomaly/stack-trace" in sources
    assert "omega-anomaly/debug-flag" in sources
    # NOTE: /crash's own baseline was learned on the same 500 endpoint,
    # so the 5xx is NOT a deviation there — the 5xx rule fires when the
    # learned baseline is healthy (see test_check_path_flags_unexpected_5xx).
    stack = [f for f in res["findings"]
             if f["source"] == "omega-anomaly/stack-trace"]
    assert stack[0]["verification"] == "confirmed"


def test_run_anomaly_never_raises(broken_server):
    res = run_anomaly(_url(broken_server), ["/"])
    assert res["findings"] == []
    assert res["skipped"] == {}      # never raises, failures recorded
    assert "transport-error" in res["deviations"]
