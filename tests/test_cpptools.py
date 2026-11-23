"""Hermetic tests for the C++ adapter runner (omega/adapters/cpptools.py).

No test requires g++ to pass: subprocess.run and shutil.which are
monkeypatched everywhere the tool path is exercised. One optional
integration test compiles the real hdrstruct.cpp when a C++ compiler
exists and skips cleanly otherwise.
"""
import json
import os
import subprocess

import pytest

from omega.adapters import cpptools
from omega.adapters import native

TARGET = "http://127.0.0.1:9999"


# ------------------------------------------------------------ helpers
class FakeProc:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout = stdout
        self.stderr = b""
        self.returncode = returncode


class FakeRun:
    """Monkeypatch target for cpptools.subprocess.run: records commands
    and dispatches g++-build calls vs binary-exec calls."""

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
        if cmd[0].endswith(("g++", "c++", "clang++")) or \
                any(a.endswith("hdrstruct.cpp") for a in cmd):
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


def sample_row(**flag_overrides):
    flags = {"has_csp": True, "has_hsts": True, "has_xcto": True,
             "has_xfo": True, "has_referrer_policy": True,
             "has_permissions_policy": True,
             "cookie_no_httponly": False, "cookie_no_secure": False,
             "server_with_version": False}
    flags.update(flag_overrides)
    return {"url": TARGET + "/", "flags": flags}


# FP-guard baseline: a fully-flagged response must produce ZERO findings.
CLEAN_ROW = sample_row()


@pytest.fixture()
def gate(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")


@pytest.fixture()
def fake_gxx(monkeypatch, tmp_path):
    """Pretend g++ is present; fresh cache dir per test."""
    monkeypatch.setattr(cpptools.shutil, "which",
                        lambda x: "/usr/bin/g++" if x in
                        ("g++", "c++", "clang++") else None)
    monkeypatch.setattr(native, "DEFAULT_CACHE_DIR", str(tmp_path / "bin"))
    return None


# ------------------------------------------------------------ gate tests
def test_gate_closed_skip_shape(monkeypatch):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    res = cpptools.run_hdrstruct([{"url": TARGET, "headers": "x"}])
    assert res["findings"] == []
    assert res["skipped"] == {"cpptools":
                              "polyglot gate closed (PTK_POLYGLOT)"}
    assert res["requests_sent"] == 0 and res["ran"] == []
    res2 = cpptools.run_cpp_suite(TARGET)
    assert res2["skipped"] == {"cpptools":
                               "polyglot gate closed (PTK_POLYGLOT)"}


def test_gate_open_fn_true_overrides_closed_env(monkeypatch, fake_gxx):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    monkeypatch.setattr(cpptools.subprocess, "run",
                        FakeRun(canned_rows=[CLEAN_ROW]))
    res = cpptools.run_cpp_suite(TARGET, fetch=lambda u: None,
                                 gate_open_fn=lambda: True)
    assert res["skipped"] == {} and res["ran"] == ["hdrstruct"]


# ------------------------------------------------- toolchain missing
def test_gxx_missing_skip_shape(gate, monkeypatch):
    monkeypatch.setattr(cpptools.shutil, "which", lambda x: None)
    res = cpptools.run_hdrstruct([{"url": TARGET, "headers": "x"}])
    assert res["skipped"] == {"cpptools": "C++ toolchain unavailable"}
    assert res["findings"] == [] and res["requests_sent"] == 0


def test_build_failure_contained(gate, fake_gxx, monkeypatch):
    monkeypatch.setattr(cpptools.subprocess, "run",
                        FakeRun(build_fail=True))
    res = cpptools.run_hdrstruct([{"url": TARGET, "headers": "x"}])
    assert res["findings"] == []
    assert "build failed" in res["skipped"]["cpptools"]


# ------------------------------------------------- canned execution
def test_missing_csp_medium_finding(gate, fake_gxx, monkeypatch):
    row = sample_row(has_csp=False)
    monkeypatch.setattr(cpptools.subprocess, "run", FakeRun([row]))
    res = cpptools.run_hdrstruct([{"url": row["url"], "headers": "h"}])
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["severity"] == "MEDIUM"
    assert f["source"] == "cpp-hdrstruct/missing_content_security_policy"
    assert f["confidence"] == "candidate"
    assert f["verification"] == "candidate"
    assert len(f["evidence"]) <= 300
    assert "curl" in f["manual_check"] and row["url"] in f["manual_check"]


def test_hsts_https_only(gate, fake_gxx, monkeypatch):
    """missing HSTS fires on https:// but never on plain http (FP guard)."""
    row_http = sample_row(has_hsts=False)
    row_https = dict(sample_row(has_hsts=False),
                     url="https://127.0.0.1:9999/")
    monkeypatch.setattr(
        cpptools.subprocess, "run",
        FakeRun([row_http, row_https]))
    res = cpptools.run_hdrstruct(
        [{"url": row_http["url"], "headers": "h"},
         {"url": row_https["url"], "headers": "h"}])
    sources = [f["source"] for f in res["findings"]]
    assert "cpp-hdrstruct/missing_hsts" in sources


def test_cookie_and_banner_findings(gate, fake_gxx, monkeypatch):
    row = sample_row(cookie_no_httponly=True, server_with_version=True)
    monkeypatch.setattr(cpptools.subprocess, "run", FakeRun([row]))
    res = cpptools.run_hdrstruct([{"url": row["url"], "headers": "h"}])
    sources = [f["source"] for f in res["findings"]]
    assert "cpp-hdrstruct/cookie_no_httponly" in sources
    assert "cpp-hdrstruct/server_banner" in sources


def test_fp_guard_clean_flags_zero_findings(gate, fake_gxx, monkeypatch):
    """Constant clean fixture (all headers, flagged cookies, no
    version banner) produces ZERO findings."""
    monkeypatch.setattr(cpptools.subprocess, "run",
                        FakeRun([CLEAN_ROW]))
    res = cpptools.run_hdrstruct(
        [{"url": CLEAN_ROW["url"], "headers": "h"}])
    assert res["findings"] == []
    assert res["requests_sent"] == 1 and res["ran"] == ["hdrstruct"]


def test_contract_fields_complete(gate, fake_gxx, monkeypatch):
    row = sample_row(has_csp=False)
    monkeypatch.setattr(cpptools.subprocess, "run", FakeRun([row]))
    res = cpptools.run_hdrstruct([{"url": row["url"], "headers": "h"}])
    f = res["findings"][0]
    for key in ("title", "severity", "confidence", "verification",
                "source", "evidence", "location", "manual_check",
                "verification_note"):
        assert key in f
    assert len(f["evidence"]) <= 300


def test_malformed_json_contained(gate, fake_gxx, monkeypatch):
    monkeypatch.setattr(cpptools.subprocess, "run",
                        FakeRun(raw_stdout=b"{not json\n"))
    res = cpptools.run_hdrstruct([{"url": TARGET, "headers": "x"}])
    assert res["findings"] == []
    assert "invalid JSON" in res["skipped"]["cpptools"]


def test_timeout_contained(gate, fake_gxx, monkeypatch):
    monkeypatch.setattr(
        cpptools.subprocess, "run",
        FakeRun(raise_exc=subprocess.TimeoutExpired(cmd="hdrstruct",
                                                   timeout=60)))
    res = cpptools.run_hdrstruct([{"url": TARGET, "headers": "x"}])
    assert res["findings"] == []
    assert "timeout" in res["skipped"]["cpptools"]


def test_compile_argv_and_cache_dir_recorded(gate, fake_gxx, monkeypatch):
    fake = FakeRun(canned_rows=[CLEAN_ROW])
    monkeypatch.setattr(cpptools.subprocess, "run", fake)
    cpptools.run_hdrstruct([{"url": TARGET, "headers": "x"}])
    build = fake.calls[0]
    assert build[0] == "g++" and "-O2" in build
    src_idx = next(i for i, a in enumerate(build)
                   if a.endswith("hdrstruct.cpp"))
    assert os.path.isabs(build[src_idx])
    assert build[build.index("-o") + 1].startswith(
        native.DEFAULT_CACHE_DIR)


def test_suite_without_fetch_contained(gate, fake_gxx):
    res = cpptools.run_cpp_suite(TARGET, fetch=None)
    assert res["findings"] == []
    assert "no fetch callable" in res["skipped"]["cpptools"]


def test_suite_fetch_error_contained(gate, fake_gxx):
    def boom(url):
        raise OSError("conn refused")
    res = cpptools.run_cpp_suite(TARGET, fetch=boom)
    assert res["findings"] == []
    assert "fetch failed" in res["skipped"]["cpptools"]


@pytest.mark.skipif(not (os.environ.get("SKIP_INTEGRATION")
                         or cpptools._find_gxx()),
                    reason="no C++ compiler installed")
def test_integration_real_compile_and_run(gate, tmp_path):
    """End-to-end: compile the real hdrstruct.cpp and classify a raw
    response head. Skips when g++ is unavailable."""
    binary = cpptools._build_hdrstruct(str(tmp_path))
    rows, err = cpptools._run_hdrstruct_binary(binary, [{
        "url": TARGET,
        "headers": ("HTTP/1.1 200 OK\n"
                    "Server: nginx/1.24.0\n"
                    "Content-Type: text/html\n"
                    "Set-Cookie: sid=abc\n\n")}])
    assert err is None and len(rows) == 1
    flags = rows[0]["flags"]
    assert flags["has_csp"] is False
    assert flags["cookie_no_httponly"] is True
    assert flags["server_with_version"] is True
