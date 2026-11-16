"""Hermetic tests for omega.scanning.csrf. Loopback
ThreadingHTTPServer fixtures; benign inert values only."""

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(
    __import__("os").path.abspath(__file__))))

from omega.scanning.csrf import (  # noqa: E402
    extract_forms,
    parse_cookies,
    run_csrf,
)

VULN_PAGE = (
    "<html><body>"
    '<form action="/settings/save" method="post">'
    '<input type="text" name="display_name">'
    '<input type="submit" value="Save">'
    "</form></body></html>")

CLEAN_PAGE = (
    "<html><body>"
    '<form action="/settings/save" method="post">'
    '<input type="hidden" name="csrf_token" value="abc123">'
    '<input type="text" name="display_name">'
    "</form></body></html>")


class CsrfHandler(BaseHTTPRequestHandler):
    """Knobs: token (bool: include hidden csrf token), samesite (bool:
    emit SameSite on the session cookie), state_change (bool: POST body
    alters the response)."""
    token = False
    samesite = False
    state_change = True

    def log_message(self, *a):
        pass

    def _respond(self, text, status=200, cookie=True):
        body = text.encode("latin-1")
        self.send_response(status)
        if cookie:
            sc = "sess=abcdef0123456789; Path=/; HttpOnly"
            if self.samesite:
                sc += "; SameSite=Lax"
            self.send_header("Set-Cookie", sc)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        page = CLEAN_PAGE if self.token else VULN_PAGE
        self._respond(page)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("latin-1", "replace")
        origin = self.headers.get("Origin") or ""
        if self.state_change:
            payload = sorted(parse_qs(body).items())
            self._respond("saved:%s:origin=%s" % (payload, origin))
        else:
            self._respond("static-ok")


@pytest.fixture
def csrf_server():
    made = []

    def make(**attrs):
        handler = type("H", (CsrfHandler,), attrs)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        made.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield make
    for srv in made:
        srv.shutdown()


def test_extract_forms_parses_action_method_inputs():
    forms = extract_forms(VULN_PAGE)
    assert len(forms) == 1
    f = forms[0]
    assert f["action"] == "/settings/save"
    assert f["method"] == "post"
    assert "display_name" in f["fields"]
    assert f["has_token"] is False
    clean = extract_forms(CLEAN_PAGE)
    assert clean[0]["has_token"] is True


def test_parse_cookies_samesite_detection():
    assert parse_cookies({"Set-Cookie": "sess=abc; SameSite=Lax"}) == [
        ("sess", True)]
    assert parse_cookies({"Set-Cookie": "sess=abc; Path=/"}) == [
        ("sess", False)]


def test_missing_token_finding(csrf_server):
    base = csrf_server(state_change=False)
    out = run_csrf(base, path_info={"paths": ["/settings"]})
    hits = [f for f in out if f["source"] == "omega-csrf/missing_token"]
    assert hits
    f = hits[0]
    assert f["severity"] == "medium"
    assert f["verification"] == "candidate"
    assert "no hidden CSRF token field" in f["verification_note"]
    # claim gate ran: verified claims carry the gate note
    assert "claim gate: verified" in f["verification_note"]


def test_samesite_missing_note(csrf_server):
    base = csrf_server(state_change=False)
    out = run_csrf(base, path_info={"paths": ["/settings"]})
    hits = [f for f in out if f["source"] == "omega-csrf/samesite_missing"]
    assert hits
    assert hits[0]["severity"] == "low"
    assert "SameSite" in hits[0]["title"]


def test_clean_server_no_findings(csrf_server):
    base = csrf_server(token=True, samesite=True, state_change=False)
    assert run_csrf(base, path_info={"paths": ["/settings"]}) == []


def test_non_state_action_ignored(csrf_server):
    """Only /login exists, and its POST action is a non-state action."""
    class Handler(CsrfHandler):
        def do_GET(self):
            if self.path != "/login":
                self._respond("not found", status=404, cookie=False)
                return
            self._respond('<form action="/login" method="post">'
                          '<input name="user"></form>', cookie=False)

    base2 = Handler  # noqa: F841 (clarity)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        assert run_csrf(base, path_info={"paths": ["/login"]}) == []
    finally:
        srv.shutdown()


def test_cross_origin_state_change_high(csrf_server):
    base = csrf_server()
    out = run_csrf(base, path_info={"paths": ["/settings"]})
    hits = [f for f in out if f["source"] == "omega-csrf/cross_origin_post"]
    assert hits
    f = hits[0]
    assert f["severity"] == "high"
    assert f["verification"] == "candidate"
    assert "claim gate: verified" in f["verification_note"]


def test_no_cross_origin_when_no_state_change(csrf_server):
    base = csrf_server(state_change=False)
    out = run_csrf(base, path_info={"paths": ["/settings"]})
    assert not [f for f in out
                if f["source"] == "omega-csrf/cross_origin_post"]


def test_never_raises_on_dead_target():
    assert run_csrf("http://127.0.0.1:1", path_info={"paths": ["/x"]}) == []
    assert run_csrf("") == []
