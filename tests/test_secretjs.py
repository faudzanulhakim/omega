"""Hermetic tests for omega.scanning.secretjs.

Loopback ThreadingHTTPServer fixtures (leaky + clean) only; no egress.
Covers the asset-collection bound, each regex family, REDACTED
evidence, dedup, candidate contract and never-raise behavior.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.secretjs import (
    MAX_JS_ASSETS,
    redact,
    run_secretjs,
    SECRET_PATTERNS,
)
from omega.scanning.deepchecks import default_fetch

BUNDLE = (
    'var a="AKIAIOSFODNN7EXAMPLE";'
    'var g="AIzaSyA-1234567890abcdefghijklmnopqrstuv";'
    'var j="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4";'
    'var s="xoxb-123456789-abcdefghij";'
    'var st="sk_live_abcdefghijklmnop1234";'
    'var p="-----BEGIN RSA PRIVATE KEY-----\\nMIIB";'
    'var q={api_key:"sup3rs3cretvalue"};'
)

BUNDLE_CLEAN = "console.log('nothing to see here');\n"

SOURCemap = ('{"version":3,"sources":'
             '["http://10.0.0.5/internal/app.js"],'
             '"names":[],"mappings":"AAAA"}')


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, body=b"", ctype="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class LeakyHandler(_Base):
    def do_GET(self):
        p = self.path
        if p == "/":
            self._send(200, '<html><script src="/app.js"></script>'
                            '<script src="/sourcemap.js"></script></html>')
        elif p == "/app.js":
            self._send(200, BUNDLE, ctype="application/javascript")
        elif p == "/sourcemap.js":
            self._send(200, BUNDLE_CLEAN + "//# sourceMappingURL="
                            "/app.js.map",
                       ctype="application/javascript")
        elif p == "/app.js.map":
            self._send(200, SOURCemap, ctype="application/json")
        else:
            self._send(404, "nope")


class CleanHandler(_Base):
    def do_GET(self):
        if self.path == "/":
            self._send(200, '<html><script src="/clean.js"></script>'
                            '</html>')
        else:
            self._send(200, BUNDLE_CLEAN, ctype="application/javascript")


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture(scope="module")
def leaky_base():
    srv = _serve(LeakyHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def clean_base():
    srv = _serve(CleanHandler)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_pattern_table_covers_required_families():
    keys = [k for k, _rx, _d in SECRET_PATTERNS]
    for k in ("aws-access-key", "private-key-block", "google-api-key",
              "jwt-token", "generic-secret", "slack-token", "stripe-key"):
        assert k in keys, k
    assert MAX_JS_ASSETS == 10


def test_redact_truncates():
    assert redact("AKIAIOSFODNN7EXAMPLE") == "AKIAIOSF..."
    assert redact("short") == "short"


def test_secrets_found_in_bundle(leaky_base):
    found = run_secretjs(leaky_base, default_fetch,
                         path_info={"paths": []})
    titles = " ".join(f["title"] for f in found)
    for marker in ("AWS access key", "private key block",
                   "Google API key", "JWT token", "Slack token",
                   "Stripe secret key", "generic secret"):
        assert marker in titles, marker
    for f in found:
        assert f["source"] == "omega-secretjs"
        assert f["severity"] == "high"
        assert f["verification"] == "candidate"
        assert f["evidence"].endswith("...")
        assert "AKIAIOSFODNN7EXAMPLE" not in f["evidence"]


def test_dedup_per_url_pattern(leaky_base):
    found = run_secretjs(leaky_base, default_fetch)
    keys = [(f["location"], f["title"]) for f in found]
    assert len(keys) == len(set(keys))


def test_sourcemap_internal_url_flagged(leaky_base):
    found = run_secretjs(leaky_base, default_fetch)
    maps = [f for f in found if ".map" in f["location"]]
    assert any("internal URLs" in f["title"] for f in maps)


def test_clean_server_yields_nothing(clean_base):
    assert run_secretjs(clean_base, default_fetch) == []


def test_asset_collection_bounded(leaky_base):
    from omega.scanning.secretjs import _collect_assets
    js, maps = _collect_assets(leaky_base, default_fetch, ["/", "/x"])
    assert len(js) <= MAX_JS_ASSETS
    assert len(maps) <= MAX_JS_ASSETS


def test_never_raises_on_dead_target():
    assert run_secretjs("http://127.0.0.1:1", default_fetch) == []
    assert run_secretjs("", lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("boom"))) == []
