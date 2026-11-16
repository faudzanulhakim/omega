"""Hermetic tests for omega.scanning.secondorder. Loopback
ThreadingHTTPServer fixtures; benign inert marker values only."""

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(
    __import__("os").path.abspath(__file__))))

from omega.scanning.secondorder import (  # noqa: E402
    make_marker,
    pick_write_paths,
    run_secondorder,
)

SETTINGS_PAGE = (
    '<html><form action="/settings" method="post">'
    '<input type="text" name="display_name">'
    '<input type="submit"></form></html>')

NOFORM_PAGE = "<html><p>nothing here</p></html>"

PROFILE_VIEW = "<html><h1>Profile: </h1></html>"
HOME = "<html><h1>Welcome home</h1></html>"


class SecondOrderHandler(BaseHTTPRequestHandler):
    """Knobs: store (bool: the POSTed display_name is echoed on
    /profile and /), serve_form (bool: /settings serves a form)."""
    store = True
    serve_form = True
    stored = ""  # class-level: shared across request handler instances

    def log_message(self, *a):
        pass

    def _respond(self, text, status=200):
        body = text.encode("latin-1")
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/settings":
            self._respond(SETTINGS_PAGE if self.serve_form
                          else NOFORM_PAGE)
        elif path == "/profile":
            self._respond(PROFILE_VIEW + self.stored)
        elif path == "/":
            self._respond(HOME + self.stored)
        else:
            self._respond("not found", status=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("latin-1", "replace")
        if self.store:
            vals = parse_qs(body)
            self.__class__.stored = (vals.get("display_name") or [""])[-1]
        self._respond("saved")


@pytest.fixture
def so_server():
    made = []

    def make(**attrs):
        handler = type("H", (SecondOrderHandler,), attrs)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        made.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield make
    for srv in made:
        srv.shutdown()


def test_make_marker_unique_benign():
    a, b = make_marker(), make_marker()
    assert a.startswith("omegasecond") and b.startswith("omegasecond")
    assert a != b
    assert a.isalnum()


def test_pick_write_paths_from_path_info():
    writes = pick_write_paths({"paths": ["/", "/user/comment", "/about"]})
    assert writes[0] == "/user/comment"
    assert len(writes) <= 2
    defaults = pick_write_paths(None)
    assert "/settings" in defaults and "/profile" in defaults


def test_stored_echo_found(so_server):
    base = so_server(store=True)
    out = run_secondorder(base, path_info={
        "paths": ["/settings", "/profile", "/"]})
    hits = [f for f in out
            if f["source"] == "omega-secondorder/stored_echo"]
    assert hits
    f = hits[0]
    assert f["severity"] == "high"
    assert f["verification"] == "candidate"
    assert "claim gate: verified" in f["verification_note"]
    assert "omegasecond" in f["evidence"]
    # write + read locations both appear in the note
    assert "/settings" in f["verification_note"]
    assert f["location"].startswith("http://127.0.0.1:")
    assert "/settings" not in f["location"].replace(
        f["verification_note"], "")


def test_clean_server_no_findings(so_server):
    base = so_server(store=False)
    assert run_secondorder(base, path_info={
        "paths": ["/settings", "/profile", "/"]}) == []


def test_no_form_no_findings(so_server):
    base = so_server(serve_form=False)
    assert run_secondorder(base, path_info={
        "paths": ["/settings", "/profile", "/"]}) == []


def test_marker_not_echoed_in_own_write_page(so_server):
    """A marker echoed only in the write response (not another page) is
    not a second-order finding."""
    base = so_server(store=False)

    class Handler(SecondOrderHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("latin-1", "replace")
            self._respond("accepted:%s" % body)

    # handler above still doesn't store; no other page should echo
    out = run_secondorder(base, path_info={
        "paths": ["/settings", "/profile", "/"]})
    assert out == []


def test_never_raises_on_dead_target():
    assert run_secondorder("http://127.0.0.1:1",
                           path_info={"paths": ["/settings"]}) == []
    assert run_secondorder("") == []


def test_budget_caps_requests(so_server):
    """With a tiny fetch budget the suite stops cleanly (no raise,
    bounded requests)."""
    base = so_server(store=True)
    calls = {"n": 0}

    def fetch(method, url, headers=None, body=None):
        calls["n"] += 1
        from omega.scanning.deepchecks import default_fetch
        return default_fetch(method, url, headers=headers, body=body)

    run_secondorder(base, fetch=fetch, path_info={
        "paths": ["/settings", "/profile", "/", "/a", "/b", "/c"]})
    assert calls["n"] <= 24 + 2  # REQUEST_BUDGET headroom
