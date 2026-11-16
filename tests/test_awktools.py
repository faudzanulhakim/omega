"""Hermetic tests for the awk adapter runner (omega/adapters/awktools.py).

No test requires awk to pass: subprocess.run and shutil.which are
monkeypatched everywhere the tool path is exercised. One optional
integration test runs the real urlmine.awk when awk exists and skips
cleanly otherwise. FP guard: a benign constant fixture produces ZERO
findings (baseline diff handled in Python).
"""
import json
import subprocess

import pytest

from omega.adapters import awktools
from omega.adapters import native

TARGET = "http://127.0.0.1:9999"


class FakeProc:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout = stdout
        self.stderr = b""
        self.returncode = returncode


class FakeRun:
    def __init__(self, canned_matches=None, raise_exc=None,
                 raw_stdout=None, baseline_matches=None):
        self.calls = []
        self.canned = canned_matches or []
        self.baseline_matches = baseline_matches
        self.raise_exc = raise_exc
        self.raw_stdout = raw_stdout
        self.inputs = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        self.inputs.append(kw.get("input", b""))
        if self.raise_exc is not None:
            raise self.raise_exc
        if self.raw_stdout is not None:
            return FakeProc(stdout=self.raw_stdout)
        # first call scans the payload; later calls scan baselines
        # (empty unless the test provides explicit baseline matches)
        if len(self.calls) > 1:
            canned = self.baseline_matches or []
        else:
            canned = self.canned
        out = "".join(json.dumps({"kind": k, "value": v}) + "\n"
                      for k, v in canned).encode()
        return FakeProc(stdout=out)


@pytest.fixture()
def gate(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")


@pytest.fixture()
def fake_awk(monkeypatch):
    monkeypatch.setattr(awktools.shutil, "which",
                        lambda x: "/usr/bin/awk" if x == "awk" else None)
    return None


# ------------------------------------------------------------ gate tests
def test_gate_closed_skip_shape(monkeypatch):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    res = awktools.run_urlmine("some text")
    assert res["findings"] == []
    assert res["skipped"] == {"awktools":
                              "polyglot gate closed (PTK_POLYGLOT)"}
    res2 = awktools.run_awk_suite(TARGET)
    assert res2["skipped"] == {"awktools":
                               "polyglot gate closed (PTK_POLYGLOT)"}


def test_awk_missing_skip_shape(gate, monkeypatch):
    monkeypatch.setattr(awktools.shutil, "which", lambda x: None)
    res = awktools.run_urlmine("text")
    assert res["skipped"] == {"awktools": "awk unavailable"}
    assert res["findings"] == []


def test_gate_open_fn_true_overrides_closed_env(monkeypatch, fake_awk):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    monkeypatch.setattr(awktools.subprocess, "run",
                        FakeRun(canned_matches=[]))
    res = awktools.run_urlmine("text", gate_open_fn=lambda: True)
    assert res["skipped"] == {} and res["ran"] == ["urlmine"]


# ------------------------------------------------- canned execution
def test_aws_key_high_finding(gate, fake_awk, monkeypatch):
    monkeypatch.setattr(
        awktools.subprocess, "run",
        FakeRun(canned_matches=[("aws_key", "AKIA1234ABCD5678EF")]))
    res = awktools.run_urlmine("body with key")
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["severity"] == "HIGH"
    assert f["source"] == "awk-urlmine/aws_key"
    assert f["confidence"] == "candidate"
    assert f["verification"] == "candidate"
    assert len(f["evidence"]) <= 300


def test_jwt_medium_api_key_high_findings(gate, fake_awk, monkeypatch):
    monkeypatch.setattr(awktools.subprocess, "run", FakeRun(
        canned_matches=[("jwt", "eyJaa.eyJbb.cc"),
                        ("api_key", "api_key = abcdefghijklmnop")]))
    res = awktools.run_urlmine("body")
    sources = {f["source"]: f["severity"] for f in res["findings"]}
    assert sources["awk-urlmine/jwt"] == "MEDIUM"
    assert sources["awk-urlmine/api_key"] == "HIGH"


def test_private_ip_low_finding(gate, fake_awk, monkeypatch):
    monkeypatch.setattr(
        awktools.subprocess, "run",
        FakeRun(canned_matches=[("private_ip", "10.1.2.3")]))
    res = awktools.run_urlmine("body")
    assert res["findings"][0]["severity"] == "LOW"
    assert res["findings"][0]["source"] == "awk-urlmine/private_ip"


def test_url_matches_are_surface_only(gate, fake_awk, monkeypatch):
    """'url' matches never become findings (surface intel only)."""
    monkeypatch.setattr(
        awktools.subprocess, "run",
        FakeRun(canned_matches=[("url", TARGET + "/admin")]))
    res = awktools.run_urlmine("body")
    assert res["findings"] == []
    assert res["surface"]["urls"] == [TARGET + "/admin"]


def test_fp_guard_baseline_diff_drops_known_values(gate, fake_awk,
                                                   monkeypatch):
    """A match whose value also appears in the benign baseline is
    dropped (FP-safe diff handled in Python)."""
    monkeypatch.setattr(
        awktools.subprocess, "run",
        FakeRun(canned_matches=[("aws_key", "AKIAIOSFODNN7EXAMPLE")],
                baseline_matches=[("aws_key", "AKIAIOSFODNN7EXAMPLE")]))
    res = awktools.run_urlmine(
        "docs sample AKIAIOSFODNN7EXAMPLE placeholder")
    assert res["findings"] == []
    assert res["ran"] == ["urlmine"]


def test_fp_guard_clean_text_zero_findings(gate, fake_awk, monkeypatch):
    """Constant benign fixture (no secret shapes) -> ZERO findings."""
    monkeypatch.setattr(awktools.subprocess, "run", FakeRun([]))
    res = awktools.run_urlmine("plain benign text, nothing here")
    assert res["findings"] == []
    assert res["requests_sent"] == 1


def test_custom_baseline_param_respected(gate, fake_awk, monkeypatch):
    monkeypatch.setattr(
        awktools.subprocess, "run",
        FakeRun(canned_matches=[("jwt", "eyJx.y.z")],
                baseline_matches=[("jwt", "eyJx.y.z")]))
    res = awktools.run_urlmine("body eyJx.y.z",
                               baseline="baseline eyJx.y.z")
    assert res["findings"] == []


def test_manual_check_is_real_command(gate, fake_awk, monkeypatch):
    monkeypatch.setattr(
        awktools.subprocess, "run",
        FakeRun(canned_matches=[("aws_key", "AKIA1234ABCD5678EF")]))
    res = awktools.run_urlmine("body", location="/tmp/src.txt")
    mc = res["findings"][0]["manual_check"]
    assert "grep" in mc and "/tmp/src.txt" in mc


def test_malformed_json_contained(gate, fake_awk, monkeypatch):
    monkeypatch.setattr(awktools.subprocess, "run",
                        FakeRun(raw_stdout=b"{not json\n"))
    res = awktools.run_urlmine("text")
    assert res["findings"] == []
    assert "invalid JSON" in res["skipped"]["awktools"]


def test_timeout_contained(gate, fake_awk, monkeypatch):
    monkeypatch.setattr(
        awktools.subprocess, "run",
        FakeRun(raise_exc=subprocess.TimeoutExpired(cmd="awk", timeout=30)))
    res = awktools.run_urlmine("text")
    assert res["findings"] == []
    assert "timeout" in res["skipped"]["awktools"]


def test_evidence_cap_and_dedupe(gate, fake_awk, monkeypatch):
    long_val = "AKIA" + "A" * 400
    monkeypatch.setattr(
        awktools.subprocess, "run",
        FakeRun(canned_matches=[("aws_key", long_val),
                                ("aws_key", long_val)]))
    res = awktools.run_urlmine("body")
    assert len(res["findings"]) == 1  # deduped
    assert len(res["findings"][0]["evidence"]) <= 300


def test_suite_without_fetch_contained(gate, fake_awk):
    res = awktools.run_awk_suite(TARGET, fetch=None)
    assert res["findings"] == []
    assert "no fetch callable" in res["skipped"]["awktools"]


def test_suite_fetch_error_contained(gate, fake_awk):
    def boom(url):
        raise OSError("conn refused")
    res = awktools.run_awk_suite(TARGET, fetch=boom)
    assert res["findings"] == []
    assert "fetch failed" in res["skipped"]["awktools"]


def test_script_argv(gate, fake_awk, monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(awktools.subprocess, "run", fake)
    awktools.run_urlmine("text")
    assert fake.calls[0][:2] == ["awk", "-f"]
    assert fake.calls[0][2].endswith("urlmine.awk")


@pytest.mark.skipif(not __import__("shutil").which("awk"),
                    reason="awk not installed")
def test_integration_real_awk_script(gate):
    """End-to-end with the real urlmine.awk: secret shapes are found
    and the benign fixture yields zero findings."""
    payload = ("see https://example.com/a AKIA1234ABCD5678EFGH "
               "eyJa.eyJb.ccc 10.0.0.5")
    res = awktools.run_urlmine(payload)
    kinds = {f["source"] for f in res["findings"]}
    assert "awk-urlmine/aws_key" in kinds
    assert "awk-urlmine/private_ip" in kinds
    benign = awktools.run_urlmine("totally harmless body text")
    assert benign["findings"] == []
