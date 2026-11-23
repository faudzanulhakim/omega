"""Hermetic tests for omega/payloadmatrix.py — WAF-evasion matrix.

Covers: the encodings audit (12 encodings x 8 placements per the
module's own API), survival detection with a fixture server that
normalizes ONE layer of URL-encoding (single-encoded markers survive ->
candidate finding; the double-encoded marker also travels through the
single normalization layer), the false-positive guard (a server that
strips/never reflects anything -> no findings), the request-rate cap,
and the never-raises containment on a failing transport.
"""

import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.payloadmatrix import (
    DEFAULT_BUDGET,
    ENCODINGS,
    PLACEMENTS,
    encodings_audit,
    matrix_runner,
)

MARKER = "o<>&%\u00e9"  # non-ASCII exercises the unicode layers


# ------------------------------------------------------------- fixtures

@pytest.fixture
def reflecting_server():
    """Server that applies exactly ONE layer of percent-decoding to the
    q parameter and echoes the decoded value back (server-side
    normalization). Single-encoded markers survive via the direct
    reflection, double-encoded ones after the single normalize."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(parsed.query,
                                      keep_blank_values=True).get("q", [""])
            decoded = urllib.parse.unquote(q[0]) if q else ""
            body = ("echo:%s" % decoded).encode("latin-1", "replace")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


# --------------------------------------------------------- encodings audit

def test_encodings_audit_12x8():
    n_enc, n_place, problems = encodings_audit()
    assert n_enc == 12
    assert n_place == 8
    assert problems == []
    assert len(ENCODINGS) == 12
    assert len(PLACEMENTS) == 8


def test_each_encoding_pure_and_distinct():
    for name, fn in ENCODINGS:
        out1 = fn(MARKER)
        out2 = fn(MARKER)
        assert isinstance(out1, str) and out1, name
        assert out1 == out2, "encoding %s not deterministic" % name
        if name not in ("plain", "base64"):
            assert out1 != MARKER, \
                "encoding %s is identity on the marker" % name


def test_placement_names_disjoint_from_encodings():
    enc = {n for n, _f in ENCODINGS}
    for pname, _fn in PLACEMENTS:
        assert pname not in enc


# ------------------------------------------------------------ survival

def test_survival_detection_yields_findings(reflecting_server):
    base = reflecting_server
    out = matrix_runner(base, MARKER, lambda m, u, headers=None: _get(m, u, headers),
                        budget=96)
    assert out["findings"], "expected survival findings"
    encs = {f["evidence"]["encoding"] for f in out["findings"]}
    # the server normalizes a single URL-encode layer, so both the
    # single- and double-encoded markers travel through and survive
    assert "url_single" in encs
    assert "url_double" in encs
    for f in out["findings"]:
        assert f["verification"] == "candidate"
        assert f["source"] == "omega-matrix/reflect"
    # multi-encoding survival on the same param aggregates to HIGH
    assert any(f["severity"] == "high" for f in out["findings"])
    assert out["requests_sent"] <= DEFAULT_BUDGET


def _get(method, url, headers=None):
    """Minimal stdlib GET (fetch contract: (method, url, headers))."""
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


def test_double_encode_survives_single_normalization():
    """Model check: one server decode layer passes the double-encoded
    marker through as the single-encoded form, which still reflects."""
    from omega.payloadmatrix import _url_double, _reflected
    double = _url_double(MARKER)
    server_body = urllib.parse.unquote(double)  # one normalization layer
    assert _reflected(MARKER, server_body.encode("latin-1"))


# --------------------------------------------------------- FP guard

def test_stripping_server_no_findings():
    """Server that strips/never reflects anything -> no findings."""

    class Stripper(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            body = b"static page with no user content at all"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Stripper)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        out = matrix_runner(base, MARKER, lambda m, u, headers=None:
                            _get(m, u, headers), budget=96)
        assert out["findings"] == []
        assert out["requests_sent"] == 96
    finally:
        srv.shutdown()
        srv.server_close()


# ------------------------------------------------------- rate cap etc.

def test_rate_cap_budget():
    sent = {"n": 0}

    def fetch(_m, _url, headers=None):
        sent["n"] += 1
        return 200, {}, b"echo:o<>&%"

    out = matrix_runner("http://stub.invalid", MARKER, fetch, budget=7)
    assert out["requests_sent"] <= 7
    assert sent["n"] <= 7
    assert "budget exhausted" in "".join(
        str(v) for v in out["skipped"].values())


def test_never_raises_on_failing_fetch():
    def boom(_m, _url, headers=None):
        raise OSError("connection refused")

    out = matrix_runner("http://stub.invalid", MARKER, boom, budget=10)
    assert isinstance(out, dict)
    assert out["findings"] == []
    assert out["skipped"]


def test_empty_marker_skipped():
    out = matrix_runner("http://stub.invalid", "  ",
                        lambda m, u, h=None: (200, {}, b""), budget=4)
    assert out["findings"] == []
    assert "empty marker" in out["skipped"]["__all__"]
