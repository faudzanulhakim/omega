"""Hermetic tests for omega.scanning.secops (hygiene bundle).
Local ThreadingHTTPServer fixtures; GET-only checks; findings are
info/low/medium candidate — never confirmed exploits.
"""

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(
    __import__("os").path.abspath(__file__))))

from omega.scanning.secops import (  # noqa: E402
    INTERESTING_DISALLOWS,
    parse_robots,
    run_secops,
    security_txt_check,
    robots_interesting_paths,
    autocomplete_scan,
)

VALID_SEC_TXT = (b"Contact: mailto:security@example.com\n"
                 b"Expires: 2030-01-01T00:00:00Z\n")
LOGIN_FORM = (b"<html><form action=\"/login\" method=\"post\">"
              b"<input type=\"password\" name=\"pw\" autocomplete=\"on\">"
              b"</form></html>")


class SecopsHandler(BaseHTTPRequestHandler):
    """Knobs: sec_txt (bytes|None), robots (bytes|None), page (bytes)."""
    sec_txt = None
    robots = None
    page = LOGIN_FORM

    def log_message(self, *a):
        pass

    def _send(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/.well-known/security.txt":
            if self.sec_txt is None:
                self._send(404, b"not found")
            else:
                self._send(200, self.sec_txt)
        elif self.path == "/robots.txt":
            if self.robots is None:
                self._send(404, b"not found")
            else:
                self._send(200, self.robots)
        elif self.path in ("/", "/login", "/signin", "/signup",
                           "/account"):
            self._send(200, self.page)
        else:
            self._send(404, b"nope")


@pytest.fixture
def sec_server():
    made = []

    def make(**attrs):
        handler = type("H", (SecopsHandler,), attrs)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        made.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield make
    for srv in made:
        srv.shutdown()


def _fetch_of(base):
    from omega.deepchecks import default_fetch
    def fetch(method, url, headers=None, body=None):
        return default_fetch(method, url, headers=headers, body=body)
    return fetch


# ------------------------------------------------------------ security.txt

def test_security_txt_missing_is_low_candidate(sec_server):
    base = sec_server()
    findings = security_txt_check(base, _fetch_of(base))
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "low"
    assert f["verification"] == "candidate"
    assert "/.well-known/security.txt" in f["location"]
    assert base in f["manual_check"]


def test_security_txt_valid_no_finding(sec_server):
    base = sec_server(sec_txt=VALID_SEC_TXT)
    assert security_txt_check(base, _fetch_of(base)) == []


def test_security_txt_malformed_missing_contact_is_low(sec_server):
    base = sec_server(sec_txt=b"Expires: 2030-01-01T00:00:00Z\n")
    findings = security_txt_check(base, _fetch_of(base))
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "low"
    assert "contact" in f["title"].lower()
    assert "contact" in f["evidence"].lower() or \
        "contact" in f["verification_note"]


# ------------------------------------------------------------- robots.txt

def test_parse_robots_extracts_disallow_paths():
    body = ("User-agent: *\nDisallow: /admin\n"
            "Disallow: /backup.zip\nDisallow: /\n"
            "# comment\nAllow: /public\n")
    assert parse_robots(body) == ["/admin", "/backup.zip"]


def test_robots_interesting_paths_info_finding(sec_server):
    base = sec_server(robots=b"User-agent: *\nDisallow: /admin\n"
                             b"Disallow: /public\n")
    findings = robots_interesting_paths(base, _fetch_of(base))
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "info"
    assert "/admin" in f["evidence"]
    # /public is not interesting -> not flagged
    assert "/public" not in f["evidence"]


def test_robots_benign_no_finding(sec_server):
    base = sec_server(robots=b"User-agent: *\nDisallow: /assets\n")
    assert robots_interesting_paths(base, _fetch_of(base)) == []


def test_robots_missing_no_finding(sec_server):
    base = sec_server()
    assert robots_interesting_paths(base, _fetch_of(base)) == []


# ------------------------------------------------------------ autocomplete

def test_autocomplete_on_password_is_medium_candidate(sec_server):
    base = sec_server()
    findings = autocomplete_scan(base, _fetch_of(base))
    assert len(findings) >= 1
    f = findings[0]
    assert f["severity"] == "medium"
    assert f["verification"] == "candidate"
    assert 'type="password"' in f["title"]
    assert "ASVS" in f["verification_note"]


def test_autocomplete_off_no_finding(sec_server):
    safe = (b"<form action=\"/login\"><input type=\"password\" "
            b"name=\"pw\" autocomplete=\"off\"></form>")
    base = sec_server(page=safe)
    assert autocomplete_scan(base, _fetch_of(base)) == []


def test_autocomplete_ignores_non_sensitive_inputs():
    html = (b"<form action=\"/s\"><input type=\"text\" name=\"q\" "
            b"autocomplete=\"on\"></form>")
    assert autocomplete_scan(
        "http://t.example",
        lambda m, u, headers=None, body=None: (200, {}, html)) == []


# ---------------------------------------------------------------- runner

def test_run_secops_ran_all_three_checks(sec_server):
    base = sec_server()
    res = run_secops(base, _fetch_of(base), budget=20)
    assert set(res["ran"]) == {"security_txt", "robots", "autocomplete"}
    assert res["requests_sent"] >= 3
    for f in res["findings"]:
        assert f["verification"] in ("candidate",)
        assert f["severity"] in ("info", "low", "medium")
        assert f["source"].startswith("omega-secops/")


def test_run_secops_allowlist_blocks_all(sec_server):
    base = sec_server()
    res = run_secops(base, _fetch_of(base),
                     allowlist=["not-the-target.example"])
    assert res["ran"] == [] and res["findings"] == []
    assert "__all__" in res["skipped"]


def test_run_secops_dead_target_never_raises():
    res = run_secops("http://127.0.0.1:1/", _fetch_of("http://127.0.0.1:1"))
    # contained: every check either ran harmlessly or was skipped
    assert set(res["ran"]) | set(res["skipped"]) == \
        {"security_txt", "robots", "autocomplete"}


def test_run_secops_budget_exhaustion_skips_remaining(sec_server):
    base = sec_server()
    res = run_secops(base, _fetch_of(base), budget=1)
    assert "security_txt" in res["ran"]
    assert res["skipped"].get("robots") == "budget exhausted"
