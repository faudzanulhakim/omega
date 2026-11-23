"""Hermetic tests for the PHP adapter runner
(omega/adapters/phptools.py).

No test requires php to pass: subprocess.run and shutil.which are
monkeypatched everywhere the tool path is exercised. One optional
integration test runs the real seriscan.php when php exists and skips
cleanly otherwise (php-cli is optional on this machine). FP guard:
benign and commented-out fixtures produce ZERO findings.
"""
import json
import subprocess

import pytest

from omega.adapters import phptools

TARGET = "http://127.0.0.1:9999"


class FakeProc:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout = stdout
        self.stderr = b""
        self.returncode = returncode


class FakeRun:
    def __init__(self, canned_hits=None, raise_exc=None, raw_stdout=None):
        self.calls = []
        self.canned_hits = canned_hits if canned_hits is not None else []
        self.raise_exc = raise_exc
        self.raw_stdout = raw_stdout
        self.last_input = b""

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        self.last_input = kw.get("input", b"")
        if self.raise_exc is not None:
            raise self.raise_exc
        out = self.raw_stdout
        if out is None:
            out = json.dumps({"findings": self.canned_hits}).encode()
        return FakeProc(stdout=out)


def hit(kind, line, match):
    return {"kind": kind, "line": line, "match": match}


# FP-guard baseline: benign/commented fixture -> zero findings
BENIGN_SNIPPET = (
    "<?php\n"
    "// never call unserialize() or eval() here\n"
    "# system('x') is forbidden by policy\n"
    "$safe = htmlspecialchars($input);\n"
)


@pytest.fixture()
def gate(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")


@pytest.fixture()
def fake_php(monkeypatch):
    monkeypatch.setattr(phptools.shutil, "which",
                        lambda x: "/usr/bin/php" if x == "php" else None)
    return None


# ------------------------------------------------------------ gate tests
def test_gate_closed_skip_shape(monkeypatch):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    res = phptools.run_seriscan("<?php eval($x);")
    assert res["findings"] == []
    assert res["skipped"] == {"phptools":
                              "polyglot gate closed (PTK_POLYGLOT)"}
    res2 = phptools.run_php_suite(TARGET)
    assert res2["skipped"] == {"phptools":
                               "polyglot gate closed (PTK_POLYGLOT)"}


def test_php_missing_graceful_skip(gate, monkeypatch):
    """php absent -> contained skip (never raises)."""
    monkeypatch.setattr(phptools.shutil, "which", lambda x: None)
    res = phptools.run_seriscan("<?php eval($x);")
    assert res["skipped"] == {"phptools": "php unavailable"}
    assert res["findings"] == [] and res["requests_sent"] == 0


def test_gate_open_fn_true_overrides_closed_env(monkeypatch, fake_php):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    monkeypatch.setattr(phptools.subprocess, "run", FakeRun())
    res = phptools.run_seriscan("<?php $x=1;",
                                gate_open_fn=lambda: True)
    assert res["skipped"] == {} and res["ran"] == ["seriscan"]


# ------------------------------------------------- canned execution
def test_unserialize_high_finding(gate, fake_php, monkeypatch):
    monkeypatch.setattr(
        phptools.subprocess, "run",
        FakeRun(canned_hits=[hit("unserialize", 3, "unserialize(")]))
    res = phptools.run_seriscan("<?php\n$a = unserialize($b);")
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["severity"] == "HIGH"
    assert f["source"] == "php-seriscan/unserialize"
    assert f["confidence"] == "candidate"
    assert f["verification"] == "candidate"
    assert len(f["evidence"]) <= 300


def test_eval_and_system_findings(gate, fake_php, monkeypatch):
    monkeypatch.setattr(
        phptools.subprocess, "run",
        FakeRun(canned_hits=[hit("eval", 2, "eval("),
                             hit("system", 5, "system(")]))
    res = phptools.run_seriscan("code")
    sources = {f["source"]: f["severity"] for f in res["findings"]}
    assert sources["php-seriscan/eval"] == "HIGH"
    assert sources["php-seriscan/system"] == "HIGH"


def test_line_numbers_in_location_and_evidence(gate, fake_php,
                                               monkeypatch):
    monkeypatch.setattr(
        phptools.subprocess, "run",
        FakeRun(canned_hits=[hit("eval", 7, "eval(")]))
    res = phptools.run_seriscan("code", location="/app/inc.php")
    f = res["findings"][0]
    assert f["location"] == "/app/inc.php:7"
    assert "line 7" in f["evidence"]


def test_manual_check_is_real_grep_command(gate, fake_php, monkeypatch):
    monkeypatch.setattr(
        phptools.subprocess, "run",
        FakeRun(canned_hits=[hit("unserialize", 3, "unserialize(")]))
    res = phptools.run_seriscan("code", location="/app/inc.php")
    mc = res["findings"][0]["manual_check"]
    assert "grep" in mc and "/app/inc.php" in mc and "unserialize" in mc


def test_unknown_kind_ignored(gate, fake_php, monkeypatch):
    monkeypatch.setattr(
        phptools.subprocess, "run",
        FakeRun(canned_hits=[hit("weird", 1, "weird(")]))
    res = phptools.run_seriscan("code")
    assert res["findings"] == []


def test_malformed_json_contained(gate, fake_php, monkeypatch):
    monkeypatch.setattr(phptools.subprocess, "run",
                        FakeRun(raw_stdout=b"{not json\n"))
    res = phptools.run_seriscan("code")
    assert res["findings"] == []
    assert "invalid JSON" in res["skipped"]["phptools"]


def test_unexpected_shape_contained(gate, fake_php, monkeypatch):
    monkeypatch.setattr(phptools.subprocess, "run",
                        FakeRun(raw_stdout=b'{"nope": 1}\n'))
    res = phptools.run_seriscan("code")
    assert res["findings"] == []
    assert "unexpected JSON shape" in res["skipped"]["phptools"]


def test_timeout_contained(gate, fake_php, monkeypatch):
    monkeypatch.setattr(
        phptools.subprocess, "run",
        FakeRun(raise_exc=subprocess.TimeoutExpired(cmd="php", timeout=30)))
    res = phptools.run_seriscan("code")
    assert res["findings"] == []
    assert "timeout" in res["skipped"]["phptools"]


def test_snippet_passed_via_stdin(gate, fake_php, monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(phptools.subprocess, "run", fake)
    phptools.run_seriscan("<?php echo 1;")
    assert fake.calls[0][:2] == ["php", phptools.SERISCAN_SCRIPT]
    assert b"echo 1" in fake.last_input


def test_finding_cap_50(gate, fake_php, monkeypatch):
    monkeypatch.setattr(
        phptools.subprocess, "run",
        FakeRun(canned_hits=[hit("eval", i + 1, "eval(")
                             for i in range(80)]))
    res = phptools.run_seriscan("code")
    assert len(res["findings"]) == 50


def test_suite_without_fetch_contained(gate, fake_php):
    res = phptools.run_php_suite(TARGET, fetch=None)
    assert res["findings"] == []
    assert "no fetch callable" in res["skipped"]["phptools"]


def test_suite_fetch_error_contained(gate, fake_php):
    def boom(url):
        raise OSError("conn refused")
    res = phptools.run_php_suite(TARGET, fetch=boom)
    assert res["findings"] == []
    assert "fetch failed" in res["skipped"]["phptools"]


@pytest.mark.skipif(not __import__("shutil").which("php"),
                    reason="php not installed")
def test_integration_real_php_script(gate):
    """End-to-end with the real seriscan.php: dangerous calls found,
    benign/commented fixture yields zero findings."""
    bad = ("<?php\n"
           "$a = unserialize($_GET['d']);\n"
           "eval($code);\n"
           "system('ls');\n")
    res = phptools.run_seriscan(bad, location="snippet.php")
    kinds = sorted(f["source"] for f in res["findings"])
    assert kinds == ["php-seriscan/eval", "php-seriscan/system",
                     "php-seriscan/unserialize"]
    benign = phptools.run_seriscan(BENIGN_SNIPPET)
    assert benign["findings"] == []
