"""Hermetic tests for omega.pytools / omega.pytools_scan.

No external binaries, no external network: HTTP tools run against a
local ThreadingHTTPServer, DNS tools against stubbed resolvers, and the
archive/CT clients against a stubbed urlopen. The async port scanner is
tested against a real local listening socket.
"""
import asyncio
import json
import socket
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import omega.pytools as pt
import omega.pytools_scan as pts
from omega.pytools_scan import AsyncPortScanner, run_py_suite


@pytest.fixture(autouse=True)
def _fresh_osint_cache():
    """Isolate the module-level OSINT TTL cache between tests."""
    pt._OSINT_CACHE.clear()
    yield
    pt._OSINT_CACHE.clear()


# ------------------------------------------------------------ HTTP server

def _build_handler(state):
    """Build a request handler with per-test fixture behavior."""

    class FixtureHandler(BaseHTTPRequestHandler):
        server_version = "FixtureHTTP/1.0"
        sys_version = ""
        DEFAULTS = {
            "/": "<html><title>Fixture Site</title>"
                 "<script src='/app.js'></script></html>",
            "/app.js": "fetch('/api/v1/users');"
                       "var api_key='k9Xm2LpQ7vR4wZ8sT3bY6nJ1cF5dH0';"
                       "var short='x';",
            "/robots.txt": "User-agent: *\nDisallow: /admin\n",
            "/sitemap.xml": "<urlset><url><loc>/</loc></url></urlset>",
            "/.well-known/security.txt": "Contact: mailto:sec@example.com\n",
            "/favicon.ico": "favicon-bytes",
            "/humans.txt": "/* humans */\n",
            "/login": "<html>login page</html>",
            "/admin": "<html>login page</html>",
        }

        def log_message(self, fmt, *args):  # silence
            pass

        def _respond(self):
            path = urllib.parse.urlparse(self.path).path
            state.setdefault("hits", []).append((self.command, path))
            custom404 = state.get("custom404", False)
            if path in self.DEFAULTS:
                status, body = 200, self.DEFAULTS[path]
            elif custom404:
                status, body = 200, "<html>soft 404</html>"
            else:
                status, body = 404, "not found"
            if state.get("set_cookie"):
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                for ck in state["set_cookie"]:
                    self.send_header("Set-Cookie", ck)
                if state.get("headers"):
                    for k, v in state["headers"].items():
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len((body or "").encode())))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write((body or "").encode())
                return
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            for k, v in (state.get("headers") or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len((body or "").encode())))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write((body or "").encode())

        do_GET = _respond
        do_HEAD = _respond
        do_POST = _respond

    return FixtureHandler


@pytest.fixture
def fixture_server():
    """Start a local ThreadingHTTPServer; yields (state, base_url)."""
    state = {}
    handler = _build_handler(state)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield state, f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        srv.server_close()


# ------------------------------------------------------------- registry

def test_registry_audit():
    """Registry: >= 10 tools, correct shape, read-only, no exploits."""
    assert len(pt.PY_REGISTRY) >= 10
    for name, spec in pt.PY_REGISTRY.items():
        assert spec["name"] == name
        assert spec["stage"] in ("recon", "enum", "verify")
        assert spec["output"] in ("json", "text")
        assert callable(spec["parser"])
        assert spec["safety"] in ("passive", "active-recon")
        assert callable(spec["fn"])
    # safety contract: read-only tools only, no exploit/intrusive entries
    forbidden = ("exploit", "brute", "attack", "shell", "inject")
    for name in pt.PY_REGISTRY:
        assert not any(w in name.lower() for w in forbidden)
    assert all(spec["safety"] in ("passive", "active-recon")
               for spec in pt.PY_REGISTRY.values())


# ---------------------------------------------------- http_fingerprint

def test_http_fingerprint(fixture_server):
    state, base = fixture_server
    state["headers"] = {"X-Powered-By": "FixturePHP/8.2"}
    findings, surface = pt.fn_http_fingerprint(base)
    assert surface["server"].strip() == "FixtureHTTP/1.0"
    assert surface["x_powered_by"] == "FixturePHP/8.2"
    assert "Fixture Site" in surface["title"]
    titles = [f for f in findings if "X-Powered-By" in f["title"]]
    assert titles
    f = findings[0]
    assert f["confidence"] == "candidate"
    assert f["verification"] == "signature"
    assert f["manual_check"] is True
    assert f["source"] == "omega-py/http_fingerprint"


# ---------------------------------------------------------- tech_probe

def test_tech_probe(fixture_server):
    _, base = fixture_server
    findings, surface = pt.fn_tech_probe(base)
    paths = {p["path"] for p in surface["present"]}
    assert "/robots.txt" in paths
    assert "/favicon.ico" in paths
    assert "/.well-known/security.txt" in paths
    # each present entry carries a sha256 hash
    assert all(p["sha256_16"] for p in surface["present"])


# -------------------------------------------------- js_endpoint_miner

def test_js_endpoint_miner(fixture_server):
    _, base = fixture_server
    findings, surface = pt.fn_js_endpoint_miner(base)
    assert "/api/v1/users" in surface["endpoints"]
    # differential care: 32-char high-entropy token reported,
    # short 'x' value not reported
    tokens = surface["secret_candidates"]
    assert tokens and all("k9Xm2LpQ7vR4wZ8sT3bY6nJ1" in t
                          for t in tokens)
    assert not any(t.strip("'\"") == "x" for t in tokens)


# --------------------------------------------------------- dirfind_py

def test_dirfind_py_baseline_differential(fixture_server):
    _, base = fixture_server
    findings, surface = pt.fn_dirfind_py(base)
    paths = {h["path"] for h in surface["hits"]}
    # /login and /admin return 200 while random baselines 404 -> hits
    assert "/login" in paths and "/admin" in paths
    # every reported hit differs from the 404 baseline
    assert all(h["status"] != 404 for h in surface["hits"])


def test_dirfind_py_custom404_noise_rejected(fixture_server):
    state, base = fixture_server
    state["custom404"] = True  # soft-404: unknown paths return 200
    findings, surface = pt.fn_dirfind_py(base)
    # baseline is 200, so NOTHING should differ -> no false hits
    assert surface["hits"] == []
    assert all("login page" not in f["evidence"] for f in findings)


# --------------------------------------------------- cookie_flag_audit

def test_cookie_flag_audit(fixture_server):
    state, base = fixture_server
    state["set_cookie"] = [
        "sessionid=abc123; Path=/",
        "good=1; Secure; HttpOnly; SameSite=Lax; Path=/",
    ]
    findings, surface = pt.fn_cookie_flag_audit(base)
    by_name = {c["name"]: c for c in surface["cookies"]}
    assert by_name["sessionid"]["secure"] is False
    assert by_name["sessionid"]["httponly"] is False
    assert by_name["good"]["secure"] and by_name["good"]["httponly"] \
        and by_name["good"]["samesite"]
    low = [f for f in findings if f["param"] == "sessionid"]
    assert low and low[0]["severity"] == "LOW"


# --------------------------------------------- subdomain sweep (stubbed)

def test_subdomain_sweep_stubbed(monkeypatch):
    calls = []

    def fake_gethostbyname(host):
        calls.append(host)
        if host.startswith(("www.", "mail.")):
            return "203.0.113.10"
        raise socket.gaierror(8, "nodename nor servname")

    monkeypatch.setattr(pt.socket, "gethostbyname", fake_gethostbyname)
    findings, surface = pt.fn_subdomain_sweep("example.com")
    assert sorted(surface["hosts"]) == ["mail.example.com",
                                        "www.example.com"]
    assert len(calls) >= 200  # full common wordlist probed
    assert all("example.com" in f["evidence"] for f in findings)


def test_subdomain_sweep_skips_ips():
    findings, surface = pt.fn_subdomain_sweep("203.0.113.5")
    assert findings == [] and surface["hosts"] == []


# --------------------------------------------- dns_records (stubbed)

def test_dns_records_stubbed(monkeypatch):
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, port, family=0, type_=0):
        if host == "example.com":
            if family == socket.AF_INET6:
                return [(socket.AF_INET6, socket.SOCK_STREAM, 0, "",
                         ("2001:db8::1", 0, 0, 0))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "",
                     ("93.184.216.34", 0))]
        raise socket.gaierror(8, "nodename")

    def fake_gethostbyname_ex(host):
        if host == "example.com":
            return ("cdn.example.com", [], ["93.184.216.34"])
        raise socket.gaierror(8, "nodename")

    monkeypatch.setattr(pt.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(pt.socket, "gethostbyname_ex", fake_gethostbyname_ex)
    monkeypatch.setattr(pt.socket, "gethostbyname",
                        lambda h: "93.184.216.34")
    findings, surface = pt.fn_dns_records("example.com")
    types = {r["type"] for r in surface["records"]}
    assert "A" in types and "AAAA" in types and "CNAME-candidate" in types


def test_dns_records_unresolvable(monkeypatch):
    monkeypatch.setattr(pt.socket, "gethostbyname",
                        lambda h: (_ for _ in ()).throw(socket.gaierror(8, "x")))
    findings, surface = pt.fn_dns_records("nxdomain.invalid")
    assert surface["records"] == []
    assert any("no DNS records" in f["title"] for f in findings)


# ------------------------------------- wayback / crtsh (stubbed urlopen)

class _FakeResponse:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode() \
            if not isinstance(payload, bytes) else payload

    def read(self, n=-1):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_wayback_client_stubbed(monkeypatch):
    rows = [["urlkey", "timestamp", "original", "mimetype", "status"],
            ["com,example)/", "20200101", "http://example.com/", "text/html",
             "200"],
            ["com,example)/old", "20200102", "http://example.com/old",
             "text/html", "200"]]
    captured = {}

    def fake_urlopen(req, timeout=0):
        captured["url"] = req.full_url if hasattr(req, "full_url") else req
        return _FakeResponse(rows)

    monkeypatch.setattr(pt.urllib.request, "urlopen", fake_urlopen)
    findings, surface = pt.fn_wayback_client("example.com")
    assert "http://example.com/old" in surface["urls"]
    assert "web.archive.org/cdx" in captured["url"]


def test_wayback_client_network_failure_tolerated(monkeypatch):
    def boom(req, timeout=0):
        raise OSError("no network in hermetic test")

    monkeypatch.setattr(pt.urllib.request, "urlopen", boom)
    findings, surface = pt.fn_wayback_client("example.com")
    assert surface["urls"] == []
    assert any("unavailable" in f["title"] or "tolerated" in f["evidence"]
               for f in findings)


def test_crtsh_client_stubbed(monkeypatch):
    data = [{"name_value": "www.example.com\n*.example.com\nother.net"},
            {"name_value": "api.example.com"}]

    def fake_urlopen(req, timeout=0):
        return _FakeResponse(data)

    monkeypatch.setattr(pt.urllib.request, "urlopen", fake_urlopen)
    findings, surface = pt.fn_crtsh_client("example.com")
    assert "api.example.com" in surface["names"]
    assert "other.net" not in surface["names"]
    assert any("CT-log name: api.example.com" in f["title"] for f in findings)


def test_crtsh_client_network_failure_tolerated(monkeypatch):
    def boom(req, timeout=0):
        raise OSError("no network in hermetic test")

    monkeypatch.setattr(pt.urllib.request, "urlopen", boom)
    findings, surface = pt.fn_crtsh_client("example.com")
    assert surface["names"] == []
    assert all("tolerated" in f["verification_note"] or
               "unavailable" in f["title"] for f in findings)


# ------------------------------------------------------------ httpx_py

def test_httpx_py(fixture_server):
    state, base = fixture_server
    findings, surface = pt.fn_httpx_py([base, "http://127.0.0.1:1/"])
    live = {l["url"] for l in surface["live"]}
    assert base in live
    assert surface["live"][0]["status"] == 200
    assert "Fixture Site" in surface["live"][0]["title"]
    assert any("unreachable" in f["title"] for f in findings)


# --------------------------------------------------- async port scanner

def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    return s, port


def test_async_scanner_open_and_closed():
    srv_sock, port = _free_port()
    srv_sock.listen(5)
    stop = threading.Event()

    def acceptor():
        while not stop.is_set():
            try:
                srv_sock.settimeout(0.2)
                conn, _ = srv_sock.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    t = threading.Thread(target=acceptor, daemon=True)
    t.start()
    try:
        # pick a port that is (almost certainly) closed on localhost
        closed_sock, closed_port = _free_port()
        closed_sock.close()
        ports = sorted({port, closed_port, 1})
        scanner = AsyncPortScanner(concurrency=3, timeout=1.0)
        result = scanner.scan("127.0.0.1", ports=ports)
        open_ports = {e["port"] for e in result["open"]}
        assert port in open_ports, f"open port missed: {result}"
        assert closed_port not in open_ports, "closed port reported open"
        assert 1 not in open_ports
        entry = next(e for e in result["open"] if e["port"] == port)
        assert "banner_guess" in entry
    finally:
        stop.set()
        srv_sock.close()


def test_async_scanner_http_guess():
    """A tiny HTTP server on a non-80 port is guessed as http."""
    state = {}
    handler = _build_handler(state)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = srv.server_port
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        scanner = AsyncPortScanner(concurrency=2, timeout=2.0)
        result = scanner.scan("127.0.0.1", ports=[port])
        entry = result["open"][0]
        assert entry["port"] == port
        assert entry["banner_guess"].startswith("http")
    finally:
        srv.shutdown()
        srv.server_close()


def test_async_scanner_cancellable():
    srv_sock, port = _free_port()
    srv_sock.listen(5)
    scanner = AsyncPortScanner(concurrency=2, timeout=1.0)
    scanner.cancel()
    result = scanner.scan("127.0.0.1", ports=[port])
    assert result["cancelled"] is True
    srv_sock.close()


def test_async_scanner_open_connection_called():
    """Scan uses asyncio.open_connection under the hood."""
    import inspect
    src = inspect.getsource(AsyncPortScanner)
    assert "asyncio.open_connection" in src


# ------------------------------------------------------- run_py_suite

def test_run_py_suite_budget_and_stages(monkeypatch, fixture_server):
    _, base = fixture_server
    ran_order = []

    real_registry = dict(pt.PY_REGISTRY)
    staged = {}
    for i, (name, spec) in enumerate(real_registry.items()):
        def make_fn(n):
            def fn(target, log=None):
                ran_order.append(n)
                return [{"title": f"hit from {n}", "severity": "INFO",
                         "confidence": "candidate",
                         "verification": "signature",
                         "manual_check": True,
                         "location": target, "param": "",
                         "evidence": "x", "source": f"omega-py/{n}"}], \
                    {"count": 1}
            return fn
        staged[name] = dict(spec, fn=make_fn(name))
    monkeypatch.setattr(pt, "PY_REGISTRY", staged)

    # budget: only 2 tools execute, rest skipped with reason
    out = run_py_suite(base, stages=["recon", "enum", "verify"], budget=2,
                       log=lambda m: None)
    assert len(out["ran"]) == 2
    assert out["ran"] == ran_order
    assert len(out["skipped"]) == len(staged) - 2
    assert all(s["reason"] == "budget exhausted" for s in out["skipped"])
    assert out["findings"] and out["surface"]

    # stage filter: only recon-stage tools run
    recon_names = {n for n, s in staged.items() if s["stage"] == "recon"}
    out2 = run_py_suite(base, stages=["recon"], budget=None)
    assert set(out2["ran"]) == recon_names

    # allowlist: only allowed names run
    out3 = run_py_suite(base, stages=None, allowlist=["dns_records",
                                                      "httpx_py"])
    assert set(out3["ran"]) == {"dns_records", "httpx_py"}


def test_run_py_suite_never_raises(monkeypatch):
    def boom(target, log=None):
        raise RuntimeError("hermetic explosion")

    def fine(target, log=None):
        return [{"title": "ok", "severity": "INFO",
                 "confidence": "candidate", "verification": "signature",
                 "manual_check": True, "location": target, "param": "",
                 "evidence": "e", "source": "omega-py/fine"}], {}

    monkeypatch.setattr(pt, "PY_REGISTRY", {
        "dns_records": {"name": "dns_records", "stage": "recon",
                        "output": "json", "parser": lambda v: v,
                        "safety": "passive", "fn": fine},
        "boom_tool": {"name": "boom_tool", "stage": "enum",
                      "output": "json", "parser": lambda v: v,
                      "safety": "active-recon", "fn": boom},
    })
    out = run_py_suite("example.com", stages=None)
    assert out["ran"] == ["dns_records"]
    assert "boom_tool" in [s["tool"] for s in out["skipped"]]
    assert "explosion" in out["skipped"][0]["reason"]
    assert out["findings"][0]["source"].startswith("omega-py/")


def test_run_py_suite_finding_shape():
    out = run_py_suite("203.0.113.5", stages=["recon"], allowlist=None)
    for f in out["findings"]:
        assert f["confidence"] == "candidate"
        assert f["verification"] == "signature"
        assert f["manual_check"] is True
        assert f["source"].startswith("omega-py/")
        assert isinstance(f["title"], str) and f["title"]
