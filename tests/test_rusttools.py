"""Hermetic tests for the Rust adapter runner
(omega/adapters/rusttools.py).

No test requires rustc to pass: subprocess.run and shutil.which are
monkeypatched everywhere the tool path is exercised; when rustc is
absent the bridge falls back to the pure-Python normalizer (identical
JSON contract), so tests exercise BOTH paths without rustc. One
optional integration test compiles the real pathscope.rs when rustc
exists and skips cleanly otherwise. FP guard: benign paths produce
ZERO findings.
"""
import json
import os
import subprocess

import pytest

from omega.adapters import rusttools
from omega.adapters import native

TARGET = "http://127.0.0.1:9999"


class FakeProc:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout = stdout
        self.stderr = b""
        self.returncode = returncode


class FakeRun:
    """Dispatch rustc-build calls vs binary-exec calls."""

    def __init__(self, canned_rows=None, raise_exc=None, raw_stdout=None,
                 build_fail=False):
        self.calls = []
        self.canned_rows = canned_rows if canned_rows is not None else []
        self.raise_exc = raise_exc
        self.raw_stdout = raw_stdout
        self.build_fail = build_fail

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        self.last_input = kw.get("input", b"")
        if cmd[0].endswith("rustc") or \
                any(a.endswith("pathscope.rs") for a in cmd):
            if self.build_fail:
                return FakeProc(returncode=1)
            out = cmd[cmd.index("-o") + 1]
            open(out, "wb").close()
            return FakeProc()
        if self.raise_exc is not None:
            raise self.raise_exc
        out = self.raw_stdout
        if out is None:
            out = "".join(json.dumps(r) + "\n"
                          for r in self.canned_rows).encode()
        return FakeProc(stdout=out)


def sample_row(raw="/../../etc/passwd", normalized="../etc/passwd",
               score=70, encoded=False):
    return {"raw": raw, "normalized": normalized,
            "traversal_risk": True, "encoded": encoded,
            "score": score, "escapes_root": True}


BENIGN_PATHS = ["/admin", "/static/app.js", "/api/v1/users?id=3"]


@pytest.fixture()
def gate(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")


@pytest.fixture()
def fake_rustc(monkeypatch, tmp_path):
    monkeypatch.setattr(rusttools.shutil, "which",
                        lambda x: "/usr/bin/rustc" if x == "rustc" else None)
    monkeypatch.setattr(native, "DEFAULT_CACHE_DIR", str(tmp_path / "bin"))
    return None


@pytest.fixture()
def no_rustc(monkeypatch):
    monkeypatch.setattr(rusttools.shutil, "which", lambda x: None)
    return None


# ------------------------------------------------------------ gate tests
def test_gate_closed_skip_shape(monkeypatch, no_rustc):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    res = rusttools.run_pathscope(["/x"])
    assert res["findings"] == []
    assert res["skipped"] == {"rusttools":
                              "polyglot gate closed (PTK_POLYGLOT)"}
    res2 = rusttools.run_rust_suite(TARGET)
    assert res2["skipped"] == {"rusttools":
                               "polyglot gate closed (PTK_POLYGLOT)"}


def test_rustc_absent_python_fallback_still_works(gate, no_rustc):
    """The bridge must still work without rustc: pure-Python fallback
    produces the same findings shape."""
    res = rusttools.run_pathscope(["/../../etc/passwd", "/admin"])
    assert res["skipped"] == {}
    assert res["ran"] == ["pathscope"]
    assert res["surface"]["fallback"] is True
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["source"] == "rust-pathscope/traversal"
    assert "traversal" in f["title"].lower()


def test_rustc_present_builds_and_runs(gate, fake_rustc, monkeypatch):
    monkeypatch.setattr(rusttools.subprocess, "run",
                        FakeRun(canned_rows=[sample_row()]))
    res = rusttools.run_pathscope(["/../../etc/passwd"])
    assert res["skipped"] == {}
    assert res["surface"]["fallback"] is False
    assert len(res["findings"]) == 1
    build = fake_rustc  # sentinel; argv checked below
    res2 = rusttools.run_pathscope(["/../../etc/passwd"])
    assert res2["ran"] == ["pathscope"]


def test_rustc_present_build_failure_falls_back(gate, fake_rustc,
                                                monkeypatch):
    monkeypatch.setattr(rusttools.subprocess, "run",
                        FakeRun(build_fail=True))
    res = rusttools.run_pathscope(["/../../etc/passwd"])
    # bridge must still work via the fallback
    assert res["ran"] == ["pathscope"]
    assert res["surface"]["fallback"] is True
    assert len(res["findings"]) == 1


def test_compile_argv_and_cache_dir_recorded(gate, fake_rustc,
                                             monkeypatch):
    fake = FakeRun(canned_rows=[sample_row()])
    monkeypatch.setattr(rusttools.subprocess, "run", fake)
    rusttools.run_pathscope(["/../../etc/passwd"])
    build = fake.calls[0]
    assert build[0].endswith("rustc") and "-O" in build
    src_idx = next(i for i, a in enumerate(build)
                   if a.endswith("pathscope.rs"))
    assert os.path.isabs(build[src_idx])
    assert build[build.index("-o") + 1].startswith(
        str(native.DEFAULT_CACHE_DIR))


# ------------------------------------------------- fallback semantics
def test_fallback_severity_scores(gate, no_rustc):
    rows = rusttools._pathscope_fallback(
        ["/../a", "/../../../etc/passwd"])
    # single-level escape -> MEDIUM-ish (35), multi-level -> HIGH (100)
    assert rows[0]["score"] == 35
    assert rows[1]["score"] == 100
    assert rows[1]["traversal_risk"] is True


def test_fallback_encoded_detection(gate, no_rustc):
    rows = rusttools._pathscope_fallback(["/%2e%2e/%2e%2e/etc/passwd"])
    assert rows[0]["encoded"] is True
    assert rows[0]["escapes_root"] is True


def test_fp_guard_benign_paths_zero_findings(gate, no_rustc):
    """Constant benign fixture paths produce ZERO findings."""
    res = rusttools.run_pathscope(BENIGN_PATHS)
    assert res["findings"] == []
    assert res["requests_sent"] == 0
    assert res["ran"] == ["pathscope"]


def test_no_network_requests_sent_zero(gate, fake_rustc, monkeypatch):
    """Pure computation adapter: requests_sent is always 0."""
    monkeypatch.setattr(rusttools.subprocess, "run",
                        FakeRun(canned_rows=[sample_row()]))
    res = rusttools.run_pathscope(["/../../etc/passwd"])
    assert res["requests_sent"] == 0


def test_contract_fields_complete(gate, no_rustc):
    res = rusttools.run_pathscope(["/../../etc/passwd"])
    f = res["findings"][0]
    for key in ("title", "severity", "confidence", "verification",
                "source", "evidence", "location", "manual_check",
                "verification_note"):
        assert key in f
    assert len(f["evidence"]) <= 300
    assert "curl" in f["manual_check"]


def test_manual_check_real_target(gate, no_rustc):
    res = rusttools.run_pathscope(["/../../etc/passwd"])
    mc = res["findings"][0]["manual_check"]
    assert "curl" in mc and "/../../etc/passwd" in mc


def test_malformed_json_contained_falls_back(gate, fake_rustc,
                                             monkeypatch):
    monkeypatch.setattr(rusttools.subprocess, "run",
                        FakeRun(raw_stdout=b"{not json\n"))
    res = rusttools.run_pathscope(["/../../etc/passwd"])
    # contained: the bridge degrades to the pure-Python fallback
    assert res["ran"] == ["pathscope"]
    assert len(res["findings"]) == 1


def test_timeout_contained_falls_back(gate, fake_rustc, monkeypatch):
    monkeypatch.setattr(
        rusttools.subprocess, "run",
        FakeRun(raise_exc=subprocess.TimeoutExpired(cmd="pathscope",
                                                   timeout=60)))
    res = rusttools.run_pathscope(["/../../etc/passwd"])
    assert res["ran"] == ["pathscope"]
    assert res["surface"]["fallback"] is True


def test_empty_paths_contained(gate, no_rustc):
    res = rusttools.run_pathscope([])
    assert res["findings"] == []
    assert "no paths" in res["skipped"]["rusttools"]


def test_suite_shape(gate, no_rustc):
    res = rusttools.run_rust_suite(TARGET)
    assert res["ran"] == ["pathscope"]
    assert res["surface"]["fallback"] is True
    # suite includes both benign and traversal candidates
    assert len(res["findings"]) >= 2


@pytest.mark.skipif(not __import__("shutil").which("rustc"),
                    reason="rustc not installed")
def test_integration_real_rust_compile(gate, tmp_path):
    """End-to-end: compile the real pathscope.rs and score paths."""
    binary = rusttools._build_pathscope(str(tmp_path))
    rows, err = rusttools._run_pathscope_binary(
        binary, ["/admin", "/../../etc/passwd", "/%2e%2e/etc/passwd"])
    assert err is None and len(rows) == 3
    assert rows[0]["traversal_risk"] is False
    assert rows[1]["traversal_risk"] is True
    assert rows[1]["normalized"] == "../etc/passwd"
    assert rows[2]["encoded"] is True
