"""Hermetic tests for omega.smuggle (request-smuggling differential).

Loopback raw-socket fixture server that deliberately mishandles
CL/TE framing per mode; no real network egress, no body smuggling
(the module itself never smuggles — this suite proves that contract
too). The Go path is only exercised through its compile/gate logic,
never against external targets.
"""

import json
import socket
import socketserver
import sys
import threading

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path
                                              .dirname(__import__("os")
                                                       .path.abspath(__file__))))

from omega.smuggle import (  # noqa: E402
    build_cases,
    classify,
    run_smuggle,
)
from omega.scanning.smuggle import _python_send, _gate_open  # noqa: E402


# ------------------------------------------------------------ fixtures
class SmuggleHandler(socketserver.BaseRequestHandler):
    """Raw-socket HTTP server with configurable framing mishandling.

    mode 'vuln': any conflicting/duplicated framing header -> respond
    HTTP 400 (differentially rejecting framing the baseline accepts)
    and, for obfuscated TE variants, append extra bytes (size diff).
    mode 'clean': always 200, identical body.
    """

    mode = "clean"

    def handle(self):
        buf = b""
        self.request.settimeout(2)
        try:
            while b"\r\n\r\n" not in buf:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                buf += chunk
        except socket.timeout:
            pass
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        names = [l.split(b":")[0].strip(b" \t").lower() for l in lines[1:]]
        cl_count = names.count(b"content-length")
        te_count = names.count(b"transfer-encoding")
        weird = any(n != n.strip() for n in names)
        # body framing: use CL if present, else chunked terminator scan
        payload = body
        if body.startswith(b"q="):
            payload = body
        conflicting = (cl_count > 1 or
                       (cl_count >= 1 and te_count >= 1) or weird)
        if self.mode == "vuln" and conflicting:
            out = b"HTTP/1.1 400 Bad Framing\r\nContent-Length: 12\r\n" \
                  b"Connection: close\r\n\r\nframing-fault" + b"Z" * 64
        elif self.mode == "vuln" and te_count >= 1:
            out = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n" \
                  b"Connection: close\r\n\r\nchunk" + b"Y" * 96
        else:
            out = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n" \
                  b"Connection: close\r\n\r\nok" + body[:8]
        try:
            self.request.sendall(out)
        except OSError:
            pass
        self.request.close()


class _ThreadedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture(params=["vuln", "clean"])
def smuggle_server(request):
    SmuggleHandler.mode = request.param
    srv = _ThreadedServer(("127.0.0.1", 0), SmuggleHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d/" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


# ------------------------------------------------------------- builders
class TestCaseBuilder:
    def test_eight_cases_present(self):
        cases = build_cases("127.0.0.1")
        names = [n for n, _raw, _d in cases]
        for expected in ("baseline", "duplicate_cl", "cl_te", "te_cl",
                         "te_te_space", "te_te_tab", "te_te_x",
                         "space_colon_cl"):
            assert expected in names

    def test_cases_are_safe_read(self):
        # SAFETY CONTRACT: no case body contains a smuggled second
        # request (no request line beyond the first).
        for _name, raw, _d in build_cases("127.0.0.1"):
            lines = raw.split(b"\r\n")
            assert lines[0].startswith(b"POST / HTTP/1.1")
            for extra in lines[1:]:
                assert not extra.startswith((b"GET ", b"POST ",
                                             b"PUT ", b"HEAD "))

    def test_conflicting_headers_are_exact_bytes(self):
        cases = {n: raw for n, raw, _d in build_cases("127.0.0.1")}
        dup = cases["duplicate_cl"].decode("latin-1").lower()
        assert dup.count("content-length:") == 2
        clte = cases["cl_te"].decode("latin-1").lower()
        assert "content-length:" in clte and "transfer-encoding:" in clte
        assert cases["te_te_space"].split(b"\r\n")[1].startswith(
            b"Transfer-Encoding :")
        assert " Content-Length :" in \
            cases["space_colon_cl"].decode("latin-1")


class TestClassify:
    def _res(self, name, status=200, elapsed=10, size=100, err=""):
        return {"name": name, "status": status, "elapsed_ms": elapsed,
                "size": size, "error": err, "host": "127.0.0.1",
                "port": 8080}

    def test_status_differential_yields_finding(self):
        results = [self._res("baseline"),
                   self._res("cl_te", status=400)]
        findings = classify(results)
        assert len(findings) == 1
        assert findings[0]["source"] == "omega-smuggle/cl_te"
        assert "status differential" in findings[0]["evidence"]

    def test_size_differential_yields_finding(self):
        results = [self._res("baseline"),
                   self._res("te_te_x", size=300)]
        findings = classify(results)
        assert len(findings) == 1
        assert "size differential" in findings[0]["evidence"]

    def test_timing_differential_yields_finding(self):
        from omega.scanning import smuggle as sm
        results = [self._res("baseline"),
                   self._res("te_cl", status=0, elapsed=1500)]
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(sm, "PROBE_TIMEOUT_MS", 1500)
            findings = classify(results)
        assert len(findings) == 1
        assert "timing differential" in findings[0]["evidence"]

    def test_uniform_responses_are_silent(self):
        results = [self._res(n) for n in ("baseline", "cl_te", "te_cl")]
        assert classify(results) == []

    def test_errors_and_missing_baseline_are_silent(self):
        assert classify([self._res("baseline", err="dial fail")]) == []
        assert classify([self._res("baseline"),
                         self._res("cl_te", err="timeout")]) == []

    def test_finding_contract(self):
        findings = classify([self._res("baseline"),
                             self._res("duplicate_cl", status=400)])
        f = findings[0]
        assert f["verification"] == "candidate"
        assert f["confidence"] in ("medium", "high")
        assert f["severity"] in ("low", "medium", "high", "info")
        assert len(f["evidence"]) <= 300
        assert "no body was smuggled" in f["verification_note"]


class TestRunSmuggle:
    def test_vuln_server_produces_findings(self, smuggle_server):
        if "vuln" not in smuggle_server:  # parametrize marker
            pass
        out = run_smuggle(smuggle_server)
        if SmuggleHandler.mode == "vuln":
            assert out["findings"], "vuln server must be flagged"
            assert out["ran"] == ["python-raw"]
        else:
            assert out["findings"] == []

    def test_gate_closed_skips_go_path(self, smuggle_server):
        out = run_smuggle(smuggle_server, gate_open_fn=lambda: False)
        assert "smsweep-go" not in out["ran"]
        assert out["ran"] == ["python-raw"]

    def test_gate_open_invokes_go_path(self, smuggle_server, monkeypatch):
        calls = {}

        def fake_go(host, port, cases, log=None):
            calls["n"] = len(cases)
            return ([{"name": n, "status": 400 if n != "baseline" else 200,
                      "elapsed_ms": 5, "size": 100, "error": "",
                      "host": host, "port": port}
                     for n, _r, _d in cases]), None

        monkeypatch.setattr("omega.scanning.smuggle._go_exec", fake_go)
        out = run_smuggle(smuggle_server, gate_open_fn=lambda: True)
        assert calls.get("n") == 8
        assert out["ran"] == ["smsweep-go"]
        assert out["findings"]

    def test_go_build_failure_falls_back(self, smuggle_server,
                                         monkeypatch):
        monkeypatch.setattr("omega.scanning.smuggle._go_exec",
                            lambda *a, **k: (None, "go build failed"))
        out = run_smuggle(smuggle_server, gate_open_fn=lambda: True)
        assert out["ran"] == ["python-raw"]
        assert out["skipped"]["smsweep-go"] == "go build failed"

    def test_unparseable_target_is_contained(self):
        out = run_smuggle("!!!not a url///")
        assert out["findings"] == []
        assert out["skipped"]  # contained skip, no raise

    def test_gate_env_semantics(self, monkeypatch):
        monkeypatch.delenv("PTK_POLYGLOT", raising=False)
        assert _gate_open() is False
        monkeypatch.setenv("PTK_POLYGLOT", "1")
        assert _gate_open() is True
        assert _gate_open(gate_open_fn=lambda: False) is False

    def test_raw_send_returns_profile(self, smuggle_server):
        host, port = "127.0.0.1", int(smuggle_server.rsplit(":", 1)[1]
                                     .split("/")[0])
        raw = build_cases(host)[0][1]  # baseline case bytes
        status, elapsed, size, err = _python_send(host, port, raw, 3)
        assert status == 200 and err == "" and size > 0
        assert elapsed >= 0

    def test_result_shape(self, smuggle_server):
        out = run_smuggle(smuggle_server)
        for key in ("findings", "skipped", "requests_sent", "ran",
                    "surface"):
            assert key in out
        assert out["requests_sent"] == 8
        assert len(out["surface"]["smuggle"]) == 8
