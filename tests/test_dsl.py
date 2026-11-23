"""Hermetic tests for omega/dsl.py — user-writable YAML check DSL.

Covers: loading the shipped dsl_default.yaml (4 example checks, all
valid), running two of them against a fixture server with the
confirmed path (diff_vs_baseline semantics honored) plus a
false-positive guard (404 server -> no findings), malformed YAML ->
skipped with a reason, and the budget + allowlist gates.
"""

import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega import dsl as dsl_mod
from omega.dsl import load_checks, run_dsl_checks


# ------------------------------------------------------------- fixtures

class DslHandler(BaseHTTPRequestHandler):
    def log_message(self, *_a):
        pass

    def do_GET(self):
        echo = self.headers.get("X-Omega-Dsl")
        if self.path == "/.well-known/security.txt":
            body = b"Contact: mailto:security@example.test\n"
            self._reply(200, body)
        elif self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
            self._reply(200, body)
        elif self.path == "/admin/":
            body = b"<html><title>Admin Dashboard</title></html>"
            self._reply(200, body)
        elif echo:
            body = ("echo:%s" % echo).encode()
            self._reply(200, body)
        else:
            self._reply(200, b"plain baseline index body")

    def do_HEAD(self):
        self.do_GET()

    def _reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Omega-Dsl",
                         self.headers.get("X-Omega-Dsl", ""))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


@pytest.fixture
def dsl_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), DslHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def yaml_file(tmp_path):
    def _write(text):
        p = tmp_path / "checks.yaml"
        p.write_text(textwrap.dedent(text))
        return str(p)
    return _write


# ------------------------------------------------------------- loading

def test_default_yaml_loads_4_valid_checks():
    checks, skipped = load_checks(dsl_mod.default_yaml_path())
    assert skipped == {}
    assert len(checks) == 4
    ids = {c["id"] for c in checks}
    assert {"security-txt", "robots-sensitive", "admin-title",
            "custom-header-echo"} == ids
    for c in checks:
        assert c["requests"] and c["severity"] in ("info", "low",
                                                   "medium", "high")


# -------------------------------------------------------------- running

def test_confirmed_checks_with_diff_vs_baseline(dsl_server, yaml_file):
    path = yaml_file("""
        checks:
          - id: security-txt
            title: security.txt present
            severity: info
            requests:
              - method: GET
                path: /.well-known/security.txt
                expect:
                  status: 200
                  body_contains: ["Contact:"]
          - id: custom-header-echo
            title: server echoes custom header
            severity: low
            requests:
              - method: GET
                path: /
                headers:
                  X-Omega-Dsl: "omega-echo-marker"
                expect:
                  header_contains:
                    X-Omega-Dsl: "omega-echo-marker"
                  diff_vs_baseline: true
    """)
    out = run_dsl_checks(dsl_server, path)
    assert out["skipped"] == {}, out["skipped"]
    assert len(out["findings"]) == 2
    for f in out["findings"]:
        assert f["verification"] == "confirmed"
        assert f["source"].startswith("omega-dsl/")
        assert f["evidence"]["matched"] == f["evidence"]["total_expects"]
    echo = [f for f in out["findings"]
            if f["source"] == "omega-dsl/custom-header-echo"][0]
    assert echo["evidence"]["total_expects"] == 2  # header + diff check


def test_candidate_when_only_some_conditions_match(dsl_server,
                                                   yaml_file):
    path = yaml_file("""
        checks:
          - id: admin-title
            title: admin page reachable
            severity: low
            requests:
              - method: GET
                path: /admin/
                expect:
                  status: 200
              - method: GET
                path: /admin/
                expect:
                  body_regex: ["(?i)<title>[^<]*(secret-panel)"]
    """)
    out = run_dsl_checks(dsl_server, path)
    assert len(out["findings"]) == 1
    assert out["findings"][0]["verification"] == "candidate"
    assert out["findings"][0]["evidence"]["matched"] == 1


def test_fp_guard_no_match_no_finding(dsl_server, yaml_file):
    path = yaml_file("""
        checks:
          - id: admin-title
            title: admin page reachable
            severity: low
            requests:
              - method: GET
                path: /admin/
                expect:
                  status: 200
                  body_regex: ["(?i)<title>[^<]*(secret-panel)"]
          - id: security-txt
            title: security.txt present
            severity: info
            requests:
              - method: GET
                path: /.well-known/security.txt
                expect:
                  status: 200
    """)
    # second check matches; add a 404-server run for the pure-FP guard
    out = run_dsl_checks(dsl_server, path)
    assert [f["source"] for f in out["findings"]] == \
        ["omega-dsl/security-txt"]


def test_fp_guard_404_server_no_findings(yaml_file):
    class NotFound(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), NotFound)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        path = yaml_file("""
            checks:
              - id: security-txt
                title: security.txt present
                severity: info
                requests:
                  - method: GET
                    path: /.well-known/security.txt
                    expect:
                      status: 200
        """)
        out = run_dsl_checks(base, path)
        assert out["findings"] == []
    finally:
        srv.shutdown()
        srv.server_close()


# ----------------------------------------------------- malformed yaml

def test_malformed_yaml_skipped_with_reason(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("checks:\n  - { id: x,\n    unclosed: [:\n")
    checks, skipped = load_checks(str(bad))
    assert checks == []
    assert "__all__" in skipped
    assert "cannot load" in skipped["__all__"] or \
        "error" in skipped["__all__"].lower()

    # structurally-invalid (parseable) YAML also skips per-check
    bad2 = tmp_path / "bad2.yaml"
    bad2.write_text(textwrap.dedent("""
        checks:
          - id: BAD-ID-UPPER
            title: bad id
            requests:
              - method: GET
                path: /
                expect:
                  status: 200
    """))
    checks2, skipped2 = load_checks(str(bad2))
    assert checks2 == []
    assert "validation error" in skipped2["BAD-ID-UPPER"]

    # run path never raises on the malformed file
    out = run_dsl_checks("http://stub.invalid", str(bad))
    assert out["findings"] == []
    assert out["skipped"]


# --------------------------------------------------- budget / allowlist

def test_budget_exhaustion_skips_check(dsl_server, yaml_file):
    path = yaml_file("""
        checks:
          - id: security-txt
            title: security.txt present
            severity: info
            requests:
              - method: GET
                path: /.well-known/security.txt
                expect:
                  status: 200
    """)
    out = run_dsl_checks(dsl_server, path, budget=0)
    assert out["findings"] == []
    assert out["skipped"]["security-txt"] == "budget exhausted"


def test_allowlist_gate(dsl_server, yaml_file):
    path = yaml_file("""
        checks:
          - id: security-txt
            title: security.txt present
            severity: info
            requests:
              - method: GET
                path: /.well-known/security.txt
                expect:
                  status: 200
    """)
    out = run_dsl_checks(dsl_server, path, allowlist=["example.invalid"])
    assert out["findings"] == []
    assert "not in allowlist" in out["skipped"]["__all__"]
    # allowed target runs normally
    out2 = run_dsl_checks(dsl_server, path, allowlist=["127.0.0.1"])
    assert len(out2["findings"]) == 1
