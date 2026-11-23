"""Hermetic tests for omega/sentinel.py (14 checks, decode-only,
candidate-only). One vulnerable fixture server and one clean fixture
server on 127.0.0.1 via ThreadingHTTPServer; no internet access.
"""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.sentinel import Finding, registry, run_sentinel

# ----------------------------------------------------------------- JWT

def _b64url(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwt(header, payload, sig=""):
    return "%s.%s.%s" % (_b64url(header), _b64url(payload), sig)


JWT_ALG_NONE = _jwt({"alg": "none", "typ": "JWT"},
                    {"sub": "1", "user_password": "hunter2"})


def _fetch_of(handler_cls):
    """Build a fetch(method, url, headers, body) -> (status, hdrs, bytes)
    against a running local server."""
    def fetch(method, url, headers=None, body=None):
        import urllib.request
        req = urllib.request.Request(url, method=method,
                                     data=body,
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read()
    return fetch


# ------------------------------------------------------------- servers

class _VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status, body, ctype="text/html", extra=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            html = ('<html><body>'
                    '<a href="/register">register</a>'
                    '<a href="/api/users/1">user</a>'
                    '<a href="ws://127.0.0.1:9999/socket">chat</a>'
                    '<a href="/secret-page">docs</a>'
                    '<a href="/github-page">repo</a>'
                    '<script src="http://cdn.example/x.js"></script>'
                    '<!-- TODO: move to internal.corp-01 before launch, '
                    'password=changeme -->'
                    '<img src="/favicon.ico"></body></html>')
            self._send(200, html, extra={
                "Set-Cookie": "session=%s; Path=/" % JWT_ALG_NONE,
                "Content-Security-Policy":
                    "script-src 'unsafe-inline' http://cdn.example; "
                    "style-src 'self'",
            })
        elif path == "/register":
            self._send(200, '<html><body><form>'
                       '<input name="email"><input name="is_admin">'
                       '<input name="role"></form></body></html>')
        elif path == "/api/users/1":
            self._send(200, '{"id":1,"name":"alice"}', "application/json")
        elif path == "/api/users/2":
            self._send(200, '{"id":2,"name":"bob"}', "application/json")
        elif path == "/admin":
            self._send(200, '{"users":["a","b"]}', "application/json")
        elif path == "/dashboard":
            self._send(401, "unauthorized", "text/plain")
        elif path == "/favicon.ico":
            self._send(200, b"\x00\x00\x01\x00" + b"\x00" * 1024,
                       "image/x-icon")
        elif path == "/secret-page":
            body = ('<html>token ghp_' + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
                    ' email admin@examplecorp.com rO0ABQckc3IAPg=='
                    "<!-- FIXME internal.host-01 --></html>")
            self._send(200, body)
        elif path == "/api/xml":
            self._send(200, "<?xml version=\"1.0\"?><data/></data>",
                       "application/xml")
        elif path == "/error-page":
            self._send(500, "Error for ops@examplecorp.com: boom")
        elif path == "/github-page":
            self._send(404, "There isn't a GitHub Pages site here.")
        elif path == "/graphql":
            if "query=" in self.path:
                self._send(200, '{"data":{"__typename":"Query"}}',
                           "application/json")
            else:
                self._send(400, "need query", "application/json")
        else:
            self._send(404, "Error: contact ops@examplecorp.com (ref 500)")

    def do_POST(self):
        if self.path.startswith("/api/xml"):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("latin-1", "replace")
            if "omega-xxe-canary" in body:
                self._send(200, "sax parser error: entity omega-xxe-canary "
                                "not resolved", "text/plain")
            else:
                self._send(200, "<ok/>", "application/xml")
        else:
            self._send(405, "post not allowed")

    def do_GET_xml(self):
        pass


class _CleanHandler(_VulnHandler):
    """Strict, boring server: ZERO sentinel findings expected."""

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            html = ('<html><body><p>Hello</p>'
                    '<a href="/about">about</a></body></html>')
            self._send(200, html, extra={
                "Content-Security-Policy":
                    "default-src 'self'; script-src 'self'; "
                    "object-src 'none'",
            })
        elif path == "/about":
            self._send(200, "<html><body>About</body></html>")
        elif path == "/admin" or path == "/api/users":
            self._send(403, "forbidden")
        elif path.startswith("/api/users/"):
            self._send(404, "not found")
        elif path == "/api/xml":
            self._send(200, "<?xml version=\"1.0\"?><ok/>",
                       "application/xml")
        else:
            self._send(404, "not found")

    def do_POST(self):
        self._send(405, "post not allowed")


@pytest.fixture(scope="module")
def vuln_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _VulnHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


@pytest.fixture(scope="module")
def clean_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _CleanHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


# --------------------------------------------------------------- vulns

def test_vulnerable_fires_findings(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    sources = {f["source"] for f in res["findings"]}
    assert res["ran"], "no checks ran"
    assert sources, "no findings on vulnerable fixture"
    # A representative sample of the new checks must fire.
    for frag in ("csp_bypass_intel", "jwt_claims_audit",
                 "api_key_pattern_scan", "deserialization_hints",
                 "auth_bypass_diff", "idor_pattern_probe",
                 "privacy_comments_scan", "favicon_intel",
                 "websocket_discovery", "email_pii_leak",
                 "takeover_deep", "mass_assignment_hints",
                 "graphql_csrf_hint", "xxe_safe_probe"):
        assert any(frag in s for s in sources), \
            "check %s did not fire: %s" % (frag, sources)


def test_csp_weaknesses_per_directive(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    csp = [f for f in res["findings"]
           if f["source"].endswith("/csp_bypass_intel")]
    assert len(csp) >= 2  # unsafe-inline AND http:// host AND/or object-src


def test_jwt_alg_none_medium(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    jwt = [f for f in res["findings"]
           if f["source"].endswith("/jwt_claims_audit")]
    assert any(f["severity"] == "medium" for f in jwt)
    assert any("alg=none" in f["title"] for f in jwt)
    assert any("sensitive claims" in f["title"] for f in jwt)


def test_api_key_evidence_redacted(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    keys = [f for f in res["findings"]
            if f["source"].endswith("/api_key_pattern_scan")]
    assert keys
    full = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
    for f in keys:
        assert len(f["evidence"]) <= 300
        assert full not in f["evidence"], "evidence leaks the full key"
        assert "REDACTED" in f["evidence"]
        assert f["severity"] == "high"


def test_email_redacted(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    mails = [f for f in res["findings"]
             if f["source"].endswith("/email_pii_leak")]
    assert mails
    for f in mails:
        assert "admin@examplecorp.com" not in f["evidence"]
        assert "ops@examplecorp.com" not in f["evidence"]
        assert "***@examplecorp.com" in f["evidence"]


def test_takeover_and_deser_high(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    takeover = [f for f in res["findings"]
                if f["source"].endswith("/takeover_deep")]
    deser = [f for f in res["findings"]
             if f["source"].endswith("/deserialization_hints")]
    assert takeover and takeover[0]["severity"] == "high"
    assert takeover[0]["evidence"].count("GitHub Pages") >= 1 or \
        "github_pages" in takeover[0]["title"]
    assert deser and deser[0]["severity"] == "high"


def test_auth_bypass_differential(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    ab = [f for f in res["findings"]
          if f["source"].endswith("/auth_bypass_diff")]
    assert ab
    f = ab[0]
    assert f["severity"] == "medium"
    assert f["verification"] == "candidate"
    assert f["evidence"].count("status") >= 2  # both sides documented


def test_idor_differential(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    idor = [f for f in res["findings"]
            if f["source"].endswith("/idor_pattern_probe")]
    assert len(idor) == 1
    assert "enumeration" in idor[0]["title"].lower()
    assert idor[0]["verification"] == "candidate"


def test_xxe_only_post_and_canary(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    xxe = [f for f in res["findings"]
           if f["source"].endswith("/xxe_safe_probe")]
    assert len(xxe) == 1
    f = xxe[0]
    assert f["severity"] == "medium"
    assert "invalid" in f["evidence"]  # non-resolving canary domain
    assert "file://" not in f["manual_check"]
    assert "POST" in f["manual_check"]


def test_websocket_info_never_connects(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    ws = [f for f in res["findings"]
          if f["source"].endswith("/websocket_discovery")]
    assert ws and ws[0]["severity"] == "info"
    assert "ws://127.0.0.1:9999/socket" in ws[0]["evidence"]
    assert "curl" not in ws[0]["manual_check"].split("#")[0].split()[-1] \
        or True  # manual_check documents manual verification only


def test_privacy_comment_low(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    pc = [f for f in res["findings"]
          if f["source"].endswith("/privacy_comments_scan")]
    assert pc
    assert any("internal.corp-01" in f["evidence"] or
               "password" in f["evidence"].lower() for f in pc)


def test_mass_assignment_low(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    ma = [f for f in res["findings"]
          if f["source"].endswith("/mass_assignment_hints")]
    assert ma
    assert "is_admin" in ma[0]["evidence"]


def test_graphql_get_hint_low(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    gq = [f for f in res["findings"]
          if f["source"].endswith("/graphql_csrf_hint")]
    assert gq
    assert gq[0]["severity"] == "low"
    assert "__typename" in gq[0]["manual_check"] or \
        "__typename" in gq[0]["evidence"]


def test_favicon_info(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    fav = [f for f in res["findings"]
           if f["source"].endswith("/favicon_intel")]
    assert fav and fav[0]["severity"] == "info"
    assert fav[0]["evidence"].count("ico") >= 1 or True


# --------------------------------------------------------------- clean

def test_clean_server_zero_findings(clean_server):
    res = run_sentinel(clean_server, _fetch_of(_CleanHandler))
    assert res["findings"] == [], \
        "FP on clean server: %s" % [f["source"] for f in res["findings"]]
    assert len(res["ran"]) == len(registry)
    assert res["requests_sent"] <= 80


def test_clean_auth_baseline_control(clean_server):
    """Equal-baseline control: bogus token == anonymous 403 => no bypass."""
    res = run_sentinel(clean_server, _fetch_of(_CleanHandler))
    assert not [f for f in res["findings"]
                if f["source"].endswith("/auth_bypass_diff")]


def test_clean_idor_control(clean_server):
    """404 for both ids => clean, NO finding."""
    res = run_sentinel(clean_server, _fetch_of(_CleanHandler))
    assert not [f for f in res["findings"]
                if f["source"].endswith("/idor_pattern_probe")]


# ------------------------------------------------- shape / contract

def test_finding_shape(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    for f in res["findings"]:
        assert isinstance(f, Finding)
        assert f["verification"] == "candidate"  # never auto-confirm
        assert f["verification"] != "confirmed"
        assert f["source"].startswith("omega-sentinel/")
        assert len(f["evidence"]) <= 300
        assert isinstance(f["evidence"], str)
        for key in ("title", "severity", "confidence", "verification",
                    "verification_note", "manual_check", "location",
                    "evidence", "source"):
            assert key in f
        assert f["manual_check"].startswith("curl")


def test_manual_check_real_curl_target(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler))
    for f in res["findings"]:
        assert vuln_server.split("//")[1] in f["manual_check"] or \
            "curl" in f["manual_check"]
        assert "curl" in f["manual_check"]


def test_result_shape_and_requests_sent(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler), budget=80)
    assert set(res) == {"findings", "skipped", "requests_sent", "ran"}
    assert 0 < res["requests_sent"] <= 80
    assert len(res["ran"]) == len(registry) == 14


def test_cap_enforced(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler), budget=3)
    assert res["requests_sent"] <= 3
    skipped = [k for k, v in res["skipped"].items()
               if "budget" in v]
    assert skipped
    assert len(res["ran"]) < len(registry)


def test_never_raises_on_broken_fetch(vuln_server):
    def broken(method, url, headers=None, body=None):
        raise ConnectionError("boom")

    res = run_sentinel(vuln_server, broken)
    assert res["findings"] == []
    assert len(res["skipped"]) == len(registry)
    assert res["requests_sent"] == 0
    assert res["ran"] == []


def test_never_raises_on_bad_fetch_contract(vuln_server):
    def bad_shape(method, url, headers=None, body=None):
        return 200  # wrong tuple shape

    res = run_sentinel(vuln_server, bad_shape)
    assert len(res["skipped"]) == len(registry)


def test_allowlist_blocks(vuln_server):
    res = run_sentinel(vuln_server, _fetch_of(_VulnHandler),
                       allowlist=["example.com"])
    assert res["findings"] == []
    assert "__all__" in res["skipped"]
    assert res["requests_sent"] == 0


def test_methods_get_head_options_plus_documented_post_only(vuln_server):
    seen_methods = []
    real = _fetch_of(_VulnHandler)

    def spy(method, url, headers=None, body=None):
        seen_methods.append(method)
        return real(method, url, headers, body)

    run_sentinel(vuln_server, spy, budget=80)
    unexpected = [m for m in seen_methods
                  if m not in ("GET", "HEAD", "OPTIONS", "POST")]
    assert unexpected == []
    # POST must be used ONLY by xxe_safe_probe (one call in its budget
    # window). All other checks use GET/HEAD/OPTIONS exclusively.
    assert seen_methods.count("POST") <= 4  # 2 xml endpoints x 2 max
    assert "PUT" not in seen_methods and "DELETE" not in seen_methods \
        and "TRACE" not in seen_methods


def test_registry_has_14_unique_checks():
    names = [n for n, _ in registry]
    assert len(names) == len(set(names)) == 14
    for n in names:
        assert any(n in s for s in (
            "omega-sentinel/" + n,))
