"""Hermetic tests for the C adapter runner (omega/adapters/ctools.py).

No test requires gcc/cc to pass: subprocess.run and shutil.which are
monkeypatched everywhere the tool path is exercised. One optional
integration test compiles the real urlinfo.c when a C compiler exists
and skips cleanly otherwise.
"""
import json
import os
import subprocess

import pytest

from omega.adapters import ctools
from omega.adapters import native

TARGET = "http://127.0.0.1:9999"


# ------------------------------------------------------------ helpers
class FakeProc:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout = stdout
        self.stderr = b""
        self.returncode = returncode


class FakeRun:
    """Monkeypatch target for ctools.subprocess.run: records commands and
    dispatches cc-build calls vs binary-exec calls."""

    def __init__(self, canned_rows=None, raise_exc=None, raw_stdout=None):
        self.calls = []
        self.canned_rows = canned_rows if canned_rows is not None else []
        self.raise_exc = raise_exc
        self.raw_stdout = raw_stdout

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        self.last_input = kw.get("input", b"")
        if cmd[0] in ("cc", "gcc"):
            # compile: pretend success (create the binary file)
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
    flags = {"default_port": False, "long_path_gt200": False,
             "nonstd_scheme": False, "userinfo_present": False}
    flags.update(flag_overrides)
    return {"url": TARGET + "/", "scheme": "http", "host": "127.0.0.1",
            "port": "", "path": "/", "flags": flags}


@pytest.fixture()
def gate(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")


@pytest.fixture()
def fake_cc(monkeypatch, tmp_path):
    """Pretend a C compiler is present; fresh cache dir per test."""
    monkeypatch.setattr(ctools.shutil, "which",
                        lambda x: "/usr/bin/cc" if x in ("cc", "gcc")
                        else None)
    monkeypatch.setattr(native, "DEFAULT_CACHE_DIR", str(tmp_path / "bin"))
    return None


# ------------------------------------------------------------ gate tests
def test_gate_closed_skip_shape(monkeypatch):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    res = ctools.run_urlinfo([TARGET])
    assert res["findings"] == []
    assert res["skipped"] == {"ctools":
                              "polyglot gate closed (PTK_POLYGLOT)"}
    assert res["requests_sent"] == 0 and res["ran"] == []
    res2 = ctools.run_c_suite(TARGET)
    assert res2["skipped"] == {"ctools":
                               "polyglot gate closed (PTK_POLYGLOT)"}


def test_gate_open_fn_false_overrides_env(gate):
    res = ctools.run_urlinfo([TARGET], gate_open_fn=lambda: False)
    assert "gate closed" in res["skipped"]["ctools"]


def test_gate_open_fn_true_overrides_closed_env(monkeypatch, fake_cc):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    monkeypatch.setattr(ctools.subprocess, "run", FakeRun())
    res = ctools.run_c_suite(TARGET, gate_open_fn=lambda: True)
    assert res["skipped"] == {} and res["ran"] == ["urlinfo"]


# ------------------------------------------------- toolchain missing
def test_cc_missing_skip_shape(gate, monkeypatch):
    monkeypatch.setattr(ctools.shutil, "which", lambda x: None)
    res = ctools.run_urlinfo([TARGET])
    assert res["skipped"] == {"ctools": "C toolchain unavailable"}
    assert res["findings"] == [] and res["requests_sent"] == 0


# ------------------------------------------------- canned execution
def test_userinfo_flag_high_finding(gate, fake_cc, monkeypatch):
    row = sample_row(userinfo_present=True)
    monkeypatch.setattr(ctools.subprocess, "run", FakeRun([row]))
    res = ctools.run_urlinfo([row["url"]])
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["severity"] == "HIGH"
    assert f["source"] == "c-urlinfo/userinfo_present"
    assert f["confidence"] == "candidate"
    assert f["verification"] == "candidate"
    assert len(f["evidence"]) <= 300


def test_long_path_flag_info_finding(gate, fake_cc, monkeypatch):
    row = sample_row(long_path_gt200=True)
    monkeypatch.setattr(ctools.subprocess, "run", FakeRun([row]))
    res = ctools.run_urlinfo([row["url"]])
    assert len(res["findings"]) == 1
    assert res["findings"][0]["severity"] == "INFO"
    assert res["findings"][0]["source"] == "c-urlinfo/long_path_gt200"


def test_nonstd_scheme_flag_low_finding(gate, fake_cc, monkeypatch):
    row = sample_row(nonstd_scheme=True)
    monkeypatch.setattr(ctools.subprocess, "run", FakeRun([row]))
    res = ctools.run_urlinfo([row["url"]])
    assert res["findings"][0]["severity"] == "LOW"
    assert res["findings"][0]["source"] == "c-urlinfo/nonstd_scheme"


def test_fp_guard_all_false_flags_zero_findings(gate, fake_cc, monkeypatch):
    # default_port=True too — it must never produce a finding
    row = sample_row(default_port=True)
    monkeypatch.setattr(ctools.subprocess, "run", FakeRun([row]))
    res = ctools.run_urlinfo([row["url"]])
    assert res["findings"] == []
    assert res["requests_sent"] == 1 and res["ran"] == ["urlinfo"]


def test_request_accounting_and_ran(gate, fake_cc, monkeypatch):
    rows = [sample_row(), sample_row(userinfo_present=True)]
    monkeypatch.setattr(ctools.subprocess, "run", FakeRun(rows))
    res = ctools.run_urlinfo(["http://a/", "http://b/"])
    assert res["requests_sent"] == 2
    assert res["ran"] == ["urlinfo"]
    assert res["skipped"] == {}


def test_manual_check_real_target(gate, fake_cc, monkeypatch):
    row = sample_row(userinfo_present=True)
    monkeypatch.setattr(ctools.subprocess, "run", FakeRun([row]))
    res = ctools.run_urlinfo([row["url"]])
    mc = res["findings"][0]["manual_check"]
    assert "curl" in mc and row["url"] in mc


def test_malformed_json_contained(gate, fake_cc, monkeypatch):
    monkeypatch.setattr(ctools.subprocess, "run",
                        FakeRun(raw_stdout=b"{not json\n"))
    res = ctools.run_urlinfo([TARGET])
    assert res["findings"] == []
    assert "invalid JSON" in res["skipped"]["ctools"]


def test_timeout_contained(gate, fake_cc, monkeypatch):
    monkeypatch.setattr(
        ctools.subprocess, "run",
        FakeRun(raise_exc=subprocess.TimeoutExpired(cmd="urlinfo",
                                                   timeout=60)))
    res = ctools.run_urlinfo([TARGET])
    assert res["findings"] == []
    assert "timeout" in res["skipped"]["ctools"]


def test_output_cap_2mb(gate, fake_cc, monkeypatch):
    """A huge stdout is capped at 2MB before parsing."""
    big = b'{"url":"' + b"a" * (3 * 1024 * 1024) + b'"}\n'
    monkeypatch.setattr(ctools.subprocess, "run", FakeRun(raw_stdout=big))
    res = ctools.run_urlinfo([TARGET])
    # capped/truncated output parses as error, not a crash
    assert res["findings"] == []
    assert "skipped" in res and res["requests_sent"] == 0


def test_compile_argv_and_cache_dir_recorded(gate, fake_cc, monkeypatch):
    fake = FakeRun(canned_rows=[sample_row()])
    monkeypatch.setattr(ctools.subprocess, "run", fake)
    ctools.run_urlinfo([TARGET])
    build = fake.calls[0]
    assert build[0] == "cc" and "-O2" in build
    src_idx = next(i for i, a in enumerate(build)
                   if a.endswith("urlinfo.c"))
    assert os.path.isabs(build[src_idx])
    assert build[build.index("-o") + 1].startswith(
        native.DEFAULT_CACHE_DIR)


def test_suite_builds_variant_urls_and_counts(gate, fake_cc, monkeypatch):
    fake = FakeRun(canned_rows=[sample_row(userinfo_present=True)])
    monkeypatch.setattr(ctools.subprocess, "run", fake)
    res = ctools.run_c_suite(TARGET)
    assert res["skipped"] == {}
    assert res["requests_sent"] == 5  # suite URL variant count
    stdin = fake.last_input.decode()
    # the userinfo variant is present in the suite
    assert "user@" in stdin


# ---------------------------------------- optional real-compiler test
@pytest.mark.skipif(not (ctools._find_cc()), reason="no C compiler")
def test_real_urlinfo_compile_and_parse(monkeypatch, gate, tmp_path):
    monkeypatch.setattr(native, "DEFAULT_CACHE_DIR", str(tmp_path / "bin"))
    res = ctools.run_urlinfo([
        "http://user@127.0.0.1:80/" + "x" * 250,
    ])
    assert res["skipped"] == {}
    flags = [r["flags"] for r in res["surface"]["urlinfo"]]
    assert flags and flags[0]["userinfo_present"] is True
    assert flags[0]["long_path_gt200"] is True
    assert flags[0]["default_port"] is True
    assert res["requests_sent"] == 1
