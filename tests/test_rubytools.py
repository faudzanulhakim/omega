"""Hermetic tests for the Ruby adapter runner (omega/adapters/rubytools.py).

No test requires ruby to pass: subprocess.run and shutil.which are
monkeypatched everywhere the tool path is exercised. One optional
integration test exercises the real urlaudit.rb when ruby is installed
and skips cleanly otherwise.
"""
import json
import subprocess

import pytest

from omega.adapters import rubytools

TARGET = "http://127.0.0.1:9999"


# ------------------------------------------------------------ helpers
class FakeProc:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout = stdout
        self.stderr = b""
        self.returncode = returncode


class FakeRun:
    """Monkeypatch target for rubytools.subprocess.run: records commands."""

    def __init__(self, canned_rows=None, raise_exc=None, raw_stdout=None):
        self.calls = []
        self.canned_rows = canned_rows if canned_rows is not None else []
        self.raise_exc = raise_exc
        self.raw_stdout = raw_stdout

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        self.last_input = kw.get("input", b"")
        if self.raise_exc is not None:
            raise self.raise_exc
        out = self.raw_stdout
        if out is None:
            out = "".join(json.dumps(r) + "\n"
                          for r in self.canned_rows).encode()
        return FakeProc(stdout=out)


def sample_row(**check_overrides):
    checks = {"open_redirect_shape": False, "sqli_shape": False,
              "ssti_shape": False, "xss_shape": False}
    checks.update(check_overrides)
    return {"url": TARGET + "/search?q=x", "checks": checks}


@pytest.fixture()
def gate(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")


@pytest.fixture()
def fake_ruby(monkeypatch):
    """Pretend ruby is present."""
    monkeypatch.setattr(rubytools.shutil, "which",
                        lambda x: "/usr/bin/ruby" if x == "ruby" else None)


# ------------------------------------------------------------ gate tests
def test_gate_closed_skip_shape(monkeypatch):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    res = rubytools.run_ruby_urlaudit([TARGET])
    assert res["findings"] == []
    assert res["skipped"] == {"rubytools":
                              "polyglot gate closed (PTK_POLYGLOT)"}
    assert res["requests_sent"] == 0 and res["ran"] == []
    res2 = rubytools.run_ruby_suite(TARGET)
    assert res2["skipped"] == {"rubytools":
                               "polyglot gate closed (PTK_POLYGLOT)"}


def test_gate_open_fn_false_overrides_env(gate):
    res = rubytools.run_ruby_urlaudit([TARGET], gate_open_fn=lambda: False)
    assert "gate closed" in res["skipped"]["rubytools"]


def test_gate_open_fn_true_overrides_closed_env(monkeypatch, fake_ruby):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    monkeypatch.setattr(rubytools.subprocess, "run", FakeRun())
    res = rubytools.run_ruby_suite(TARGET, gate_open_fn=lambda: True)
    assert res["skipped"] == {} and res["ran"] == ["urlaudit"]


# ------------------------------------------------- toolchain missing
def test_ruby_missing_skip_shape(gate, monkeypatch):
    monkeypatch.setattr(rubytools.shutil, "which", lambda x: None)
    res = rubytools.run_ruby_urlaudit([TARGET])
    assert res["skipped"] == {"rubytools": "ruby unavailable"}
    assert res["findings"] == [] and res["requests_sent"] == 0


# ------------------------------------------------- canned execution
def test_sqli_shape_medium_finding(gate, fake_ruby, monkeypatch):
    row = sample_row(sqli_shape=True)
    monkeypatch.setattr(rubytools.subprocess, "run", FakeRun([row]))
    res = rubytools.run_ruby_urlaudit([row["url"]])
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["severity"] == "MEDIUM"
    assert f["source"] == "ruby-urlaudit/sqli_shape"
    assert f["confidence"] == "candidate"
    assert f["verification"] == "candidate"
    assert f["evidence"] == row["url"]  # evidence = the URL itself


def test_ssti_shape_medium_finding(gate, fake_ruby, monkeypatch):
    row = sample_row(ssti_shape=True)
    monkeypatch.setattr(rubytools.subprocess, "run", FakeRun([row]))
    res = rubytools.run_ruby_urlaudit([row["url"]])
    assert res["findings"][0]["severity"] == "MEDIUM"
    assert res["findings"][0]["source"] == "ruby-urlaudit/ssti_shape"


def test_redirect_and_xss_shape_low_findings(gate, fake_ruby, monkeypatch):
    rows = [sample_row(open_redirect_shape=True),
            sample_row(xss_shape=True)]
    monkeypatch.setattr(rubytools.subprocess, "run", FakeRun(rows))
    res = rubytools.run_ruby_urlaudit([rows[0]["url"], rows[1]["url"]])
    assert {f["severity"] for f in res["findings"]} == {"LOW"}
    assert {f["source"] for f in res["findings"]} == {
        "ruby-urlaudit/open_redirect_shape", "ruby-urlaudit/xss_shape"}


def test_fp_guard_all_false_checks_zero_findings(gate, fake_ruby,
                                                 monkeypatch):
    monkeypatch.setattr(rubytools.subprocess, "run",
                        FakeRun([sample_row()]))
    res = rubytools.run_ruby_urlaudit([TARGET + "/clean"])
    assert res["findings"] == []
    assert res["requests_sent"] == 1 and res["ran"] == ["urlaudit"]


def test_request_accounting_and_ran(gate, fake_ruby, monkeypatch):
    monkeypatch.setattr(rubytools.subprocess, "run",
                        FakeRun([sample_row(sqli_shape=True)]))
    res = rubytools.run_ruby_urlaudit(["http://a/?q=1'", "http://b/?q=2'"])
    assert res["requests_sent"] == 2
    assert res["ran"] == ["urlaudit"]
    assert res["skipped"] == {}


def test_manual_check_real_target(gate, fake_ruby, monkeypatch):
    row = sample_row(xss_shape=True)
    monkeypatch.setattr(rubytools.subprocess, "run", FakeRun([row]))
    res = rubytools.run_ruby_urlaudit([row["url"]])
    mc = res["findings"][0]["manual_check"]
    assert "curl" in mc and row["url"] in mc


def test_malformed_json_contained(gate, fake_ruby, monkeypatch):
    monkeypatch.setattr(rubytools.subprocess, "run",
                        FakeRun(raw_stdout=b"<ruby exception>\n"))
    res = rubytools.run_ruby_urlaudit([TARGET])
    assert res["findings"] == []
    assert "invalid JSON" in res["skipped"]["rubytools"]


def test_timeout_contained(gate, fake_ruby, monkeypatch):
    monkeypatch.setattr(
        rubytools.subprocess, "run",
        FakeRun(raise_exc=subprocess.TimeoutExpired(cmd="ruby",
                                                   timeout=30)))
    res = rubytools.run_ruby_urlaudit([TARGET])
    assert res["findings"] == []
    assert "timeout" in res["skipped"]["rubytools"]


def test_output_cap_1mb(gate, fake_ruby, monkeypatch):
    """A huge stdout is capped at 1MB before parsing."""
    big = b'{"url":"' + b"a" * (2 * 1024 * 1024) + b'"}\n'
    monkeypatch.setattr(rubytools.subprocess, "run", FakeRun(raw_stdout=big))
    res = rubytools.run_ruby_urlaudit([TARGET])
    assert res["findings"] == []
    assert res["requests_sent"] == 0


def test_argv_is_ruby_plus_script_path(gate, fake_ruby, monkeypatch):
    fake = FakeRun([sample_row()])
    monkeypatch.setattr(rubytools.subprocess, "run", fake)
    rubytools.run_ruby_urlaudit([TARGET])
    assert len(fake.calls) == 1
    cmd = fake.calls[0]
    assert cmd[0] == "ruby"
    assert cmd[1].endswith("urlaudit.rb")


def test_suite_variants_and_counting(gate, fake_ruby, monkeypatch):
    fake = FakeRun(canned_rows=[sample_row(ssti_shape=True)])
    monkeypatch.setattr(rubytools.subprocess, "run", fake)
    res = rubytools.run_ruby_suite(TARGET)
    assert res["skipped"] == {}
    assert res["requests_sent"] == 5  # suite URL variant count
    stdin = fake.last_input.decode()
    assert any("OR+" in u or "OR%" in u for u in stdin.splitlines())
    assert any("%7B%7B" in u for u in stdin.splitlines())
    assert "evil.example" in stdin


# -------------------------------------------- optional real-ruby test
@pytest.mark.skipif(not __import__("shutil").which("ruby"),
                    reason="ruby unavailable")
def test_real_urlaudit_shapes(gate, monkeypatch):
    res = rubytools.run_ruby_urlaudit([
        TARGET + "/search?q=1%27+OR+%271%27%3D%271",
        TARGET + "/render?q=%7B%7B7*7%7D%7D",
        TARGET + "/clean?page=1",
    ])
    assert res["skipped"] == {}
    rows = res["surface"]["urlaudit"]
    assert rows[0]["checks"]["sqli_shape"] is True
    assert rows[1]["checks"]["ssti_shape"] is True
    assert not any(rows[2]["checks"].values())
    assert res["requests_sent"] == 3
