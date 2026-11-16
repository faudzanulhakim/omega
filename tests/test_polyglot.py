"""Hermetic tests for the omega polyglot native adapters.

Real `go build` is exercised when the toolchain exists (tests skip
gracefully otherwise).  All network is local: a listening socket for
portspeed and a ThreadingHTTPServer for htsweep.
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.adapters import native

GO_AVAILABLE = subprocess.run(["which", "go"], capture_output=True
                             ).returncode == 0
needs_go = pytest.mark.skipif(not GO_AVAILABLE, reason="go toolchain missing")


HIGH_ENTROPY = "a7Xk2Qp9Lm4Rt8Wz3Yb6Nd"   # 23 chars, high entropy
FIXTURE_JS = """
const API = "https://example.com";
fetch("/api/v1/users");
axios.get("/api/v2/orders");
const url = "https://cdn.example.com/data";
const path = "/static/assets/app.js";
axios.post("/api/login", {token: "%s"});
const plain = "this is just plain english text, not a secret at all";
fetch(`https://example.com/api/${id}`);
""" % HIGH_ENTROPY


@pytest.fixture()
def listening_port():
    """A real TCP listener plus a definitely-closed port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    # closed port: try to grab one that nothing is listening on
    closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    yield port, closed_port
    srv.close()


@pytest.fixture()
def http_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><head><title>Omega Polyglot Test Page</title>" \
                   b"</head><body>hi</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "omega-test-httpd/1.0")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # silence
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture()
def cache_dir(tmp_path):
    return str(tmp_path / "bin")


@pytest.fixture()
def gate(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")


@pytest.fixture()
def fixture_js(tmp_path):
    p = tmp_path / "app.js"
    p.write_text(FIXTURE_JS)
    return str(p)


# ------------------------------------------------------------ gate tests
def test_gate_refuses_without_env(monkeypatch, cache_dir):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    with pytest.raises(PermissionError):
        native.ensure_native(cache_dir)
    with pytest.raises(PermissionError):
        native.run_portspeed("127.0.0.1", "80", allow=False)
    with pytest.raises(PermissionError):
        native.run_jsanalyze("/nonexistent.js")
    # suite is contained, not raising
    suite = native.run_native_suite("example.com", ["portspeed"])
    assert suite["ran"] == []
    assert suite["skipped"] and "PTK_POLYGLOT" in suite["skipped"][0]["reason"]


def test_gate_allows_explicit(monkeypatch, cache_dir):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    res = native.ensure_native(cache_dir, allow=True) if GO_AVAILABLE \
        else None
    # either built (go present) or skipped with reason — never raised
    assert res is None or set(res) == {"built", "skipped"}


# ------------------------------------------------------- compile manager
@needs_go
def test_ensure_native_builds_and_caches(gate, cache_dir):
    res = native.ensure_native(cache_dir)
    assert "portspeed" in res["built"]
    assert "htsweep" in res["built"]
    bin_path = os.path.join(cache_dir, "portspeed")
    assert os.path.exists(bin_path)
    mtime1 = os.path.getmtime(bin_path)
    # second call: fresh binary reused (no rebuild)
    res2 = native.ensure_native(cache_dir)
    assert "portspeed" in res2["built"]
    assert os.path.getmtime(bin_path) == mtime1
    # source change triggers rebuild
    src = os.path.join(os.path.dirname(native.__file__), "go",
                       "portspeed.go")
    os.utime(src, (time.time() + 10, time.time() + 10))
    res3 = native.ensure_native(cache_dir)
    assert "portspeed" in res3["built"]
    assert os.path.getmtime(bin_path) > mtime1


@needs_go
def test_ensure_native_never_raises_on_broken_cache(gate, tmp_path):
    # unwritable cache dir -> contained skip
    bad = str(tmp_path / "afile")
    open(bad, "w").close()
    res = native.ensure_native(bad)   # not a dir -> makedirs fails
    assert res["skipped"]


# ------------------------------------------------------------ runners
@needs_go
def test_portspeed_open_and_closed(gate, cache_dir, listening_port):
    open_port, closed_port = listening_port
    res = native.run_portspeed("127.0.0.1",
                               f"{open_port},{closed_port}",
                               timeout_s=10, cache_dir=cache_dir)
    assert res["error"] is None
    ports = {p["port"] for p in res["open"]}
    assert open_port in ports
    assert closed_port not in ports


@needs_go
def test_htsweep_local_server(gate, cache_dir, http_server):
    res = native.run_htsweep([http_server, "http://127.0.0.1:1/"],
                             timeout_s=10, cache_dir=cache_dir)
    assert res["error"] is None
    alive = {a["url"]: a for a in res["alive"]}
    assert http_server + "/" in alive or http_server in alive
    entry = list(alive.values())[0]
    assert entry["status"] == 200
    assert "Omega Polyglot Test Page" in entry["title"]
    assert entry["server"] != ""  # Server header captured


def test_jsanalyze(fixture_js, gate):
    res = native.run_jsanalyze(fixture_js)
    assert res["error"] is None
    assert "/api/v1/users" in res["endpoints"]
    assert "/api/v2/orders" in res["endpoints"]
    assert "/api/v1/users" in res["api_routes"] or \
        any("/api" in r for r in res["api_routes"])
    # high-entropy secret flagged
    assert any(HIGH_ENTROPY[:8] in s["value"] for s in res["secrets"])
    # plain English text NOT flagged (fails entropy + length/charset)
    assert not any("plain" in s["value"] for s in res["secrets"])


def test_jsanalyze_never_raises_missing_file(gate):
    res = native.run_jsanalyze("/does/not/exist.js")
    # node prints an empty-but-valid JSON result; contained, no raise
    assert res["endpoints"] == [] and res["secrets"] == []


def test_runners_never_raise_missing_binary(gate, tmp_path, monkeypatch):
    # empty cache dir without go -> contained error, no raise
    monkeypatch.setenv("PATH", "/nonexistent-bin-dir")
    res = native.run_portspeed("127.0.0.1", "80", timeout_s=5,
                               cache_dir=str(tmp_path / "bin"))
    assert res["open"] == []
    assert res["error"]


# ------------------------------------------------------------- suite glue
@needs_go
def test_run_native_suite_portspeed(gate, cache_dir, listening_port):
    open_port, closed_port = listening_port
    suite = native.run_native_suite(
        "127.0.0.1", ["portspeed"], budget=5, cache_dir=cache_dir,
        ports=f"{open_port},{closed_port}")
    assert suite["ran"] == ["portspeed"]
    assert suite["skipped"] == []
    assert any(f"127.0.0.1:{open_port}" in f["location"]
               for f in suite["findings"])
    assert all(f["source"].startswith("omega-native/")
               for f in suite["findings"])
    assert all(f["confidence"] == "candidate" and
               f["verification"] == "signature"
               for f in suite["findings"])


def test_run_native_suite_budget(gate, cache_dir, fixture_js):
    suite = native.run_native_suite(fixture_js, ["jsanalyze"],
                                    budget=0, cache_dir=cache_dir)
    assert suite["ran"] == []
    assert any(s["reason"].startswith("budget exhausted")
               for s in suite["skipped"])


def test_run_native_suite_contained(gate, tmp_path, cache_dir,
                                    monkeypatch):
    # unknown kind + missing binaries -> all contained skips, no raise
    suite = native.run_native_suite(
        "127.0.0.1", ["portspeed", "bogus"], budget=3,
        cache_dir=str(tmp_path / "c"),
        allow=False)
    assert suite["ran"] == []
