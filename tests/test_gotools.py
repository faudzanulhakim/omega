"""Hermetic tests for the gotools runner (omega/adapters/gotools.py).

No test requires the go binary to pass: subprocess.run and shutil.which
are monkeypatched everywhere the tool path is exercised. A small optional
integration test exercises the real dirscan binary when Go is installed.
"""
import json
import subprocess

import pytest

from omega.adapters import gotools
from omega.adapters import native

TARGET = "http://127.0.0.1:9999"


# ------------------------------------------------------------ helpers
class FakeProc:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout = stdout
        self.stderr = b""
        self.returncode = returncode


class FakeRun:
    """Monkeypatch target for gotools.subprocess.run: records commands and
    dispatches go-build calls vs binary-exec calls."""

    def __init__(self, binary_name="dirscan", canned=None, raise_exc=None,
                 raw_stdout=None):
        self.calls = []
        self.binary_name = binary_name
        self.canned = canned if canned is not None else {"results": []}
        self.raise_exc = raise_exc
        self.raw_stdout = raw_stdout

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        if self.raise_exc is not None and cmd[0] != "go":
            # build calls are not failed by raise_exc (only tool exec)
            raise self.raise_exc
        if cmd[0] == "go":
            # go build: pretend the compile succeeded (create the binary
            # file so _build_tool's existence check passes)
            out = cmd[cmd.index("-o") + 1]
            open(out, "wb").close()
            return FakeProc()
        if cmd[0].endswith(self.binary_name):
            out = self.raw_stdout
            if out is None:
                out = json.dumps(self.canned).encode()
            return FakeProc(stdout=out)
        return FakeProc()


@pytest.fixture()
def gate(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")


@pytest.fixture()
def fake_go(monkeypatch, tmp_path):
    """Pretend the go toolchain is present; use a fresh cache dir per test."""
    monkeypatch.setattr(gotools.shutil, "which", lambda x: "/usr/bin/go")
    monkeypatch.setattr(native, "DEFAULT_CACHE_DIR", str(tmp_path / "bin"))
    return None


# ------------------------------------------------------------ gate tests
def test_gate_closed_skip_shape(monkeypatch):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    res = gotools.run_dirscan(TARGET, ["/admin"])
    assert res["findings"] == []
    assert res["skipped"] == {"gotools": "polyglot gate closed (PTK_POLYGLOT)"}
    assert res["requests_sent"] == 0
    assert res["ran"] == []
    res2 = gotools.run_dnssweep("example.com", ["www"])
    assert res2["skipped"] == {"gotools": "polyglot gate closed (PTK_POLYGLOT)"}


def test_gate_open_fn_false_overrides_env(gate, monkeypatch):
    res = gotools.run_dirscan(TARGET, ["/admin"], gate_open_fn=lambda: False)
    assert res["skipped"] and "gate closed" in res["skipped"]["gotools"]
    res2 = gotools.run_dnssweep("example.com", ["www"],
                                gate_open_fn=lambda: False)
    assert res2["skipped"] and "gate closed" in res2["skipped"]["gotools"]


def test_gate_open_fn_true_overrides_closed_env(monkeypatch, fake_go):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    monkeypatch.setattr(gotools.subprocess, "run", FakeRun())
    res = gotools.run_dirscan(TARGET, ["/admin"],
                              gate_open_fn=lambda: True)
    assert res["skipped"] == {}
    assert res["ran"] == ["dirscan"]


# ------------------------------------------------------------ go missing
def test_go_missing_skip_shape(gate, monkeypatch):
    monkeypatch.setattr(gotools.shutil, "which", lambda x: None)
    res = gotools.run_dirscan(TARGET, ["/admin"])
    assert res["skipped"] == {"gotools": "go toolchain unavailable"}
    assert res["findings"] == [] and res["requests_sent"] == 0
    res2 = gotools.run_dnssweep("example.com", ["www"])
    assert res2["skipped"] == {"gotools": "go toolchain unavailable"}


# ------------------------------------------------- fake binary execution
def test_dirscan_exists_and_protected_findings(gate, fake_go, monkeypatch):
    canned = {"results": [
        {"path": "/admin", "status": 200, "class": "exists",
         "ctype": "text/html", "snippet": "<html>Admin Panel</html>"},
        {"path": "/private", "status": 403, "class": "protected",
         "ctype": "text/html", "snippet": "Forbidden"},
        {"path": "/nope", "status": 404, "class": "missing",
         "ctype": "text/html", "snippet": "not found"},
    ]}
    fake = FakeRun(canned=canned)
    monkeypatch.setattr(gotools.subprocess, "run", fake)
    res = gotools.run_dirscan(TARGET, ["/admin", "/private", "/nope"])
    assert res["ran"] == ["dirscan"]
    assert res["skipped"] == {}
    sev = {f["location"]: f["severity"] for f in res["findings"]}
    assert sev[TARGET + "/admin"] == "LOW"
    assert sev[TARGET + "/private"] == "INFO"
    assert TARGET + "/nope" not in sev  # missing -> no finding


def test_dirscan_sensitive_path_is_high(gate, fake_go, monkeypatch):
    canned = {"results": [
        {"path": "/backup.sql", "status": 200, "class": "exists",
         "ctype": "application/sql", "snippet": "CREATE TABLE users"},
    ]}
    monkeypatch.setattr(gotools.subprocess, "run", FakeRun(canned=canned))
    res = gotools.run_dirscan(TARGET, ["/backup.sql"])
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["severity"] == "HIGH"
    assert f["source"] == "go-dirscan/backup-sql"


def test_dnssweep_public_and_private_ips(gate, fake_go, monkeypatch):
    canned = {"alive": [
        {"name": "www.example.com", "ip": "93.184.216.34"},
        {"name": "git.example.com", "ip": "10.0.0.5"},
        {"name": "mail.example.com", "ip": "192.168.1.10"},
        {"name": "vpn.example.com", "ip": "172.16.3.4"},
    ], "errors": 2}
    monkeypatch.setattr(gotools.subprocess, "run",
                        FakeRun(binary_name="dnssweep", canned=canned))
    res = gotools.run_dnssweep("example.com",
                               ["www", "git", "mail", "vpn"])
    by_loc = {f["location"]: f for f in res["findings"]}
    assert by_loc["www.example.com"]["severity"] == "INFO"
    for host in ("git.example.com", "mail.example.com", "vpn.example.com"):
        assert by_loc[host]["severity"] == "LOW"
        assert "internal host resolvable" in by_loc[host]["title"]
        assert "dig" in by_loc[host]["manual_check"]
    assert res["requests_sent"] == 4


# ------------------------------------------------------- error containment
def test_malformed_json_contained_skip(gate, fake_go, monkeypatch):
    monkeypatch.setattr(gotools.subprocess, "run",
                        FakeRun(raw_stdout=b"not json at all"))
    res = gotools.run_dirscan(TARGET, ["/admin"])
    assert res["findings"] == [] and res["ran"] == []
    assert "invalid JSON" in res["skipped"]["gotools"]


def test_timeout_contained_skip(gate, fake_go, monkeypatch):
    monkeypatch.setattr(
        gotools.subprocess, "run",
        FakeRun(raise_exc=subprocess.TimeoutExpired(cmd="x", timeout=60)))
    res = gotools.run_dirscan(TARGET, ["/admin"])
    assert res["findings"] == [] and res["ran"] == []
    assert "timeout" in res["skipped"]["gotools"]


def test_malformed_json_dnssweep_contained(gate, fake_go, monkeypatch):
    monkeypatch.setattr(gotools.subprocess, "run",
                        FakeRun(binary_name="dnssweep",
                                raw_stdout=b"{oops"))
    res = gotools.run_dnssweep("example.com", ["www"])
    assert res["findings"] == []
    assert "invalid JSON" in res["skipped"]["gotools"]


def test_build_failure_contained(gate, fake_go, monkeypatch):
    proc = FakeProc()
    proc.returncode = 1
    proc.stderr = b"compile error: whatever"
    monkeypatch.setattr(gotools.subprocess, "run", lambda *a, **kw: proc)
    res = gotools.run_dirscan(TARGET, ["/admin"])
    assert res["findings"] == [] and res["ran"] == []
    assert "build failed" in res["skipped"]["gotools"]


def test_output_capped_before_parse(gate, fake_go, monkeypatch):
    # 3 MB of valid JSON would parse; after the 2 MB cap it is truncated
    # mid-token and must become a contained skip, proving the cap applies.
    big = json.dumps({"results": [
        {"path": "/x" * 500000, "status": 200, "class": "exists",
         "ctype": "t", "snippet": "y" * 500000}]}).encode() * 3
    assert len(big) > gotools.OUTPUT_CAP
    monkeypatch.setattr(gotools.subprocess, "run",
                        FakeRun(raw_stdout=big))
    res = gotools.run_dirscan(TARGET, ["/admin"])
    assert res["findings"] == []
    assert "invalid JSON" in res["skipped"]["gotools"]


def test_subprocess_generic_error_contained(gate, fake_go, monkeypatch):
    monkeypatch.setattr(gotools.subprocess, "run",
                        FakeRun(raise_exc=OSError("spawn failure")))
    res = gotools.run_dnssweep("example.com", ["www"])
    assert res["findings"] == [] and res["ran"] == []
    assert res["skipped"]["gotools"]


# ------------------------------------------------- accounting / FP / shape
def test_request_accounting_counts_paths(gate, fake_go, monkeypatch):
    paths = [f"/p{i}" for i in range(7)]
    monkeypatch.setattr(gotools.subprocess, "run",
                        FakeRun(canned={"results": []}))
    res = gotools.run_dirscan(TARGET, paths)
    assert res["requests_sent"] == len(paths) == 7


def test_fp_guard_all_missing_zero_findings(gate, fake_go, monkeypatch):
    canned = {"results": [
        {"path": f"/p{i}", "status": 404, "class": "missing",
         "ctype": "text/html", "snippet": "not found"} for i in range(5)]}
    monkeypatch.setattr(gotools.subprocess, "run", FakeRun(canned=canned))
    res = gotools.run_dirscan(TARGET, [f"/p{i}" for i in range(5)])
    assert res["findings"] == []
    assert res["ran"] == ["dirscan"]


def test_finding_shape_and_manual_check(gate, fake_go, monkeypatch):
    canned = {"results": [
        {"path": "/backup.sql", "status": 200, "class": "exists",
         "ctype": "application/x-sql", "snippet": "INSERT INTO users"},
        {"path": "/admin", "status": 403, "class": "protected",
         "ctype": "text/html", "snippet": "denied"},
    ]}
    monkeypatch.setattr(gotools.subprocess, "run", FakeRun(canned=canned))
    res = gotools.run_dirscan(TARGET, ["/backup.sql", "/admin"])
    for f in res["findings"]:
        assert set(f) >= {"title", "severity", "confidence", "verification",
                          "source", "evidence", "location", "manual_check"}
        assert f["confidence"] == "candidate"
        assert f["verification"] == "candidate"
        assert f["source"].startswith("go-dirscan/")
        assert len(f["evidence"]) <= 300
        assert f["location"].startswith(TARGET)
        assert f["manual_check"].startswith("curl -s")
        assert TARGET in f["manual_check"]  # REAL target in the command
    # slug derivation: /backup.sql -> backup-sql
    assert any(f["source"] == "go-dirscan/backup-sql"
               for f in res["findings"])


def test_ensure_native_called_and_right_go_source(gate, fake_go,
                                                  monkeypatch):
    """ensure_native is reused (recorded here) and our own go build names
    the correct .go source path."""
    calls = []

    def fake_ensure(cache_dir=None, log=None, allow=None):
        calls.append(cache_dir)
        return {"built": [], "skipped": []}

    monkeypatch.setattr(native, "ensure_native", fake_ensure)
    fake = FakeRun()
    monkeypatch.setattr(gotools.subprocess, "run", fake)
    gotools.run_dirscan(TARGET, ["/admin"])
    assert calls == [native.DEFAULT_CACHE_DIR]
    go_cmds = [c for c in fake.calls if c[0] == "go"]
    assert go_cmds, "expected a go build invocation"
    assert go_cmds[0][-1].endswith("omega/adapters/go/dirscan.go")
    assert "-o" in go_cmds[0]

    calls.clear()
    fake2 = FakeRun(binary_name="dnssweep")
    monkeypatch.setattr(gotools.subprocess, "run", fake2)
    gotools.run_dnssweep("example.com", ["www"])
    assert calls == [native.DEFAULT_CACHE_DIR]
    go_cmds = [c for c in fake2.calls if c[0] == "go"]
    assert go_cmds[0][-1].endswith("omega/adapters/go/dnssweep.go")


def test_stdin_payload_shape(gate, fake_go, monkeypatch):
    """The runner feeds the Go binary the documented JSON contract."""
    captured = {}

    def run_capture(cmd, **kw):
        captured["cmd"] = cmd
        if cmd[0] == "go":
            open(cmd[cmd.index("-o") + 1], "wb").close()
            return FakeProc()
        captured["input"] = kw.get("input")
        return FakeProc(stdout=b'{"results": [], "alive": [], "errors": 0}')

    monkeypatch.setattr(gotools.subprocess, "run", run_capture)
    gotools.run_dirscan(TARGET, ["/admin", "/a b"])
    payload = json.loads(captured["input"])
    assert payload["target"] == TARGET
    assert payload["paths"] == ["/admin", "/a b"]
    assert payload["probe"].startswith("/omega-")


def test_runners_never_raise_on_garbage_input():
    """No exceptions even for nonsense arguments (contained result)."""
    for bad in (None, "", 123):
        r1 = gotools.run_dirscan(TARGET, bad, gate_open_fn=lambda: False)
        r2 = gotools.run_dnssweep(bad, [None], gate_open_fn=lambda: False)
        assert r1["findings"] == [] and r2["findings"] == []
        assert isinstance(r1["skipped"], dict)


# ------------------------------------------------- real-binary integration
def _go_available():
    try:
        return subprocess.run(["which", "go"],
                              capture_output=True).returncode == 0
    except Exception:
        return False


@pytest.mark.skipif(not _go_available(), reason="go toolchain missing")
def test_real_dirscan_binary_against_local_server(gate, monkeypatch):
    """End-to-end: compile + run the real dirscan binary against a local
    ThreadingHTTPServer with a differential fixture."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if "omega-" in self.path:  # probe -> uniform fallback body
                body = b"<html>generic 404 page</html>"
                code = 200
            elif self.path == "/backup.sql":
                body = b"CREATE TABLE users (id INT); INSERT INTO users;"
                code = 200
            elif self.path == "/admin":
                code, body = 403, b"Forbidden"
            else:
                code, body = 404, b"<html>generic 404 page</html>"
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        res = gotools.run_dirscan(
            url, ["/backup.sql", "/admin", "/missing-zz"])
        classes = {r["path"]: r["class"] for r in res["surface"]["dirscan"]}
        assert classes["/backup.sql"] == "exists"
        assert classes["/admin"] == "protected"
        assert classes["/missing-zz"] == "missing"
        sev = {f["location"]: f["severity"] for f in res["findings"]}
        assert sev[url + "/backup.sql"] == "HIGH"
        assert sev[url + "/admin"] == "INFO"
        assert url + "/missing-zz" not in sev
        assert res["requests_sent"] == 3
    finally:
        srv.shutdown()
