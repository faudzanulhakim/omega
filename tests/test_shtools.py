"""Hermetic tests for the bash adapter runner (omega/adapters/shtools.py).

No test requires bash/curl to pass: subprocess.run and shutil.which
are monkeypatched everywhere the tool path is exercised. One optional
integration test runs the real methodcheck.sh against a hermetic
ThreadingHTTPServer on 127.0.0.1 and skips cleanly otherwise.
FP guard: the constant benign fixture (405 on everything, Allow: GET,
HEAD) produces ZERO findings.
"""
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.adapters import shtools

TARGET = "http://127.0.0.1:9999"


class FakeProc:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout = stdout
        self.stderr = b""
        self.returncode = returncode


class FakeRun:
    def __init__(self, canned_rows=None, raise_exc=None, raw_stdout=None):
        self.calls = []
        self.canned_rows = canned_rows if canned_rows is not None else []
        self.raise_exc = raise_exc
        self.raw_stdout = raw_stdout

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        if self.raise_exc is not None:
            raise self.raise_exc
        out = self.raw_stdout
        if out is None:
            out = "".join(json.dumps(r) + "\n"
                          for r in self.canned_rows).encode()
        return FakeProc(stdout=out)


def row(method, status, allow=""):
    return {"method": method, "status": status, "allow": allow,
            "url": TARGET}


# FP-guard baseline: benign fixture -> zero findings
CLEAN_ROWS = [row("GET", 200), row("HEAD", 200),
              row("OPTIONS", 200, "GET, HEAD, POST"),
              row("POST", 405), row("TRACE", 405)]


@pytest.fixture()
def gate(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")


@pytest.fixture()
def fake_bash(monkeypatch):
    monkeypatch.setattr(shtools.shutil, "which",
                        lambda x: "/usr/bin/" + x
                        if x in ("bash", "curl") else None)
    return None


# ------------------------------------------------------------ gate tests
def test_gate_closed_skip_shape(monkeypatch):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    res = shtools.run_methodcheck(TARGET)
    assert res["findings"] == []
    assert res["skipped"] == {"shtools":
                              "polyglot gate closed (PTK_POLYGLOT)"}
    res2 = shtools.run_sh_suite(TARGET)
    assert res2["skipped"] == {"shtools":
                               "polyglot gate closed (PTK_POLYGLOT)"}


def test_bash_missing_skip_shape(gate, monkeypatch):
    monkeypatch.setattr(shtools.shutil, "which", lambda x: None)
    res = shtools.run_methodcheck(TARGET)
    assert res["skipped"] == {"shtools": "bash unavailable"}


def test_curl_missing_skip_shape(gate, monkeypatch):
    monkeypatch.setattr(shtools.shutil, "which",
                        lambda x: "/usr/bin/bash" if x == "bash" else None)
    monkeypatch.delenv("OMEGA_CURL", raising=False)
    res = shtools.run_methodcheck(TARGET)
    assert res["skipped"] == {"shtools": "curl unavailable"}


def test_gate_open_fn_true_overrides_closed_env(monkeypatch, fake_bash):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    monkeypatch.setattr(shtools.subprocess, "run",
                        FakeRun(canned_rows=CLEAN_ROWS))
    res = shtools.run_sh_suite(TARGET, gate_open_fn=lambda: True)
    assert res["skipped"] == {} and res["ran"] == ["methodcheck"]


# ------------------------------------------------- canned execution
def test_trace_enabled_high_finding(gate, fake_bash, monkeypatch):
    monkeypatch.setattr(
        shtools.subprocess, "run",
        FakeRun(canned_rows=CLEAN_ROWS + [row("TRACE", 200)]))
    res = shtools.run_methodcheck(TARGET)
    assert res["findings"][0]["severity"] == "HIGH"
    assert res["findings"][0]["source"] == "sh-methodcheck/trace_enabled"


def test_options_discloses_dangerous_medium(gate, fake_bash, monkeypatch):
    monkeypatch.setattr(
        shtools.subprocess, "run",
        FakeRun(canned_rows=[row("OPTIONS", 200,
                                 "GET, HEAD, PUT, DELETE")]))
    res = shtools.run_methodcheck(TARGET)
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["severity"] == "MEDIUM"
    assert f["source"] == "sh-methodcheck/options_discloses_dangerous"
    assert "PUT" in f["evidence"] and "DELETE" in f["evidence"]


def test_fp_guard_benign_fixture_zero_findings(gate, fake_bash,
                                               monkeypatch):
    """Constant benign fixture (405s, GET/HEAD/POST Allow) -> ZERO
    findings."""
    monkeypatch.setattr(shtools.subprocess, "run",
                        FakeRun(canned_rows=CLEAN_ROWS))
    res = shtools.run_methodcheck(TARGET)
    assert res["findings"] == []
    assert res["requests_sent"] == 5
    assert res["ran"] == ["methodcheck"]


def test_contract_fields_complete(gate, fake_bash, monkeypatch):
    monkeypatch.setattr(
        shtools.subprocess, "run",
        FakeRun(canned_rows=[row("TRACE", 200)]))
    res = shtools.run_methodcheck(TARGET)
    f = res["findings"][0]
    for key in ("title", "severity", "confidence", "verification",
                "source", "evidence", "location", "manual_check",
                "verification_note"):
        assert key in f
    assert len(f["evidence"]) <= 300
    assert "curl" in f["manual_check"] and TARGET in f["manual_check"]


def test_manual_check_real_target_command(gate, fake_bash, monkeypatch):
    monkeypatch.setattr(
        shtools.subprocess, "run",
        FakeRun(canned_rows=[row("OPTIONS", 200, "GET, PUT")]))
    res = shtools.run_methodcheck(TARGET)
    mc = res["findings"][0]["manual_check"]
    assert "-X OPTIONS" in mc and TARGET in mc


def test_url_scheme_defaulted(gate, fake_bash, monkeypatch):
    fake = FakeRun(canned_rows=CLEAN_ROWS)
    monkeypatch.setattr(shtools.subprocess, "run", fake)
    shtools.run_methodcheck("example.internal")
    assert fake.calls[0] == ["bash", shtools.METHODCHECK_SCRIPT,
                             "http://example.internal"]


def test_malformed_json_contained(gate, fake_bash, monkeypatch):
    monkeypatch.setattr(shtools.subprocess, "run",
                        FakeRun(raw_stdout=b"{not json\n"))
    res = shtools.run_methodcheck(TARGET)
    assert res["findings"] == []
    assert "invalid JSON" in res["skipped"]["shtools"]


def test_timeout_contained(gate, fake_bash, monkeypatch):
    monkeypatch.setattr(
        shtools.subprocess, "run",
        FakeRun(raise_exc=subprocess.TimeoutExpired(cmd="bash",
                                                   timeout=90)))
    res = shtools.run_methodcheck(TARGET)
    assert res["findings"] == []
    assert "timeout" in res["skipped"]["shtools"]


def test_script_argv_records_url(gate, fake_bash, monkeypatch):
    fake = FakeRun(canned_rows=CLEAN_ROWS)
    monkeypatch.setattr(shtools.subprocess, "run", fake)
    shtools.run_methodcheck(TARGET)
    assert fake.calls[0][:2] == ["bash", shtools.METHODCHECK_SCRIPT]
    assert fake.calls[0][2] == TARGET


@pytest.mark.skipif(not __import__("shutil").which("bash")
                    or not __import__("shutil").which("curl"),
                    reason="bash/curl not installed")
def test_integration_real_script_benign_server():
    """End-to-end against a hermetic constant server: a server that
    405s methods and discloses only GET/HEAD yields ZERO findings."""
    class Benign(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _resp(self, allow=None):
            self.send_response(405 if allow is None else 200)
            if allow:
                self.send_header("Allow", allow)
            self.end_headers()

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def do_HEAD(self):
            self.send_response(200)
            self.end_headers()

        def do_OPTIONS(self):
            self._resp(allow="GET, HEAD, POST")

        def do_POST(self):
            self.send_response(405)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Benign)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        res = shtools.run_methodcheck(
            f"http://127.0.0.1:{srv.server_address[1]}/",
            gate_open_fn=lambda: True)
        assert res["skipped"] == {}
        assert res["findings"] == []
        assert res["requests_sent"] == 5
    finally:
        srv.shutdown()
