"""tests/test_dojo.py — DefectDojo export mapping + never-raise tests."""

import csv
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))

from omega.reporting.dojo import (  # noqa: E402
    CSV_COLUMNS,
    export_dojo,
    map_cwe,
    map_severity,
    map_verified,
    to_csv_rows,
    to_dojo_json,
)


def _finding(**kw):
    base = {
        "id": "F-1",
        "title": "Path traversal in /download",
        "severity": "CRITICAL",
        "verification": "confirmed",
        "cwe": "CWE-22",
        "cvss": 9.1,
        "evidence": {"url": "http://t/x", "why": "traversal confirmed"},
        "manual_check": "verify manually",
        "location": "/download",
        "source": "omega-deepchecks/traversal",
    }
    base.update(kw)
    return base


def test_severity_mapping_all_levels():
    assert map_severity("CRITICAL") == "Critical"
    assert map_severity("HIGH") == "High"
    assert map_severity("MEDIUM") == "Medium"
    assert map_severity("LOW") == "Low"
    assert map_severity("INFO") == "Info"
    assert map_severity("bogus") == "Info"


def test_verified_mapping():
    assert map_verified("confirmed") is True
    assert map_verified("candidate") is False
    assert map_verified(None) is False
    assert map_verified("CONFIRMED") is True


def test_cwe_numeric_mapping():
    assert map_cwe("CWE-79") == 79
    assert map_cwe("79") == 79
    assert map_cwe(89) == 89
    assert map_cwe(None) is None
    assert map_cwe("junk") is None


def test_csv_header_and_row_shape(tmp_path):
    path = str(tmp_path / "dojo.csv")
    out = export_dojo([_finding()], fmt="csv", path=path)
    assert out == path
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == CSV_COLUMNS == [
        "Title", "Severity", "Description", "Mitigation", "Impact",
        "References", "CVE", "Active", "Verified", "Date"]
    assert len(rows) == 2
    row = rows[1]
    assert row[0] == "Path traversal in /download"
    assert row[1] == "Critical"
    assert row[7] == "true"
    assert row[8] == "true"          # confirmed -> Verified true
    assert row[9]                     # date column present


def test_csv_candidate_and_cve_extraction(tmp_path):
    rows = to_csv_rows([
        _finding(title="nginx CVE-2021-41773 mismatch",
                 severity="LOW", verification="candidate", cwe=None)])
    row = rows[1]
    assert row[1] == "Low"
    assert row[8] == "false"          # candidate -> Verified false
    assert row[6] == "CVE-2021-41773"  # extracted from title


def test_json_shape_and_fields(tmp_path):
    path = str(tmp_path / "dojo.json")
    out = export_dojo([_finding()], fmt="json", path=path)
    assert out == path
    doc = json.loads(open(path, encoding="utf-8").read())
    assert doc["test_type"] == "OMEGA Scan"
    assert isinstance(doc["findings"], list) and len(doc["findings"]) == 1
    f = doc["findings"][0]
    for key in ("title", "severity", "description", "mitigation",
                "impact", "references", "cve", "active", "verified",
                "cwe", "date"):
        assert key in f
    assert f["severity"] == "Critical"
    assert f["verified"] is True
    assert f["active"] is True
    assert f["cwe"] == 22
    assert f["cvssv3"] == 9.1


def test_export_default_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = export_dojo([], fmt="json")
    assert isinstance(out, str) and out.endswith(".json")
    assert os.path.exists(out)


def test_never_raises_on_junk_findings(tmp_path):
    path = str(tmp_path / "junk.csv")
    junk = [_finding(), "a string finding", 42,
            {"title": None, "severity": None}, None]
    for fmt in ("csv", "json"):
        out = export_dojo(junk, fmt=fmt, path=path)
        assert isinstance(out, str)
        # junk rows do not crash; header/shape still valid
        if fmt == "csv":
            rows = list(csv.reader(open(path, encoding="utf-8")))
            assert rows[0] == CSV_COLUMNS


def test_never_raises_on_bad_args(tmp_path):
    # None findings -> error dict, never an exception
    out = export_dojo(None, fmt="csv", path=str(tmp_path / "a.csv"))
    assert isinstance(out, dict) and "error" in out
    assert "error" in export_dojo("not-a-list", fmt="csv")
    assert "error" in export_dojo([], fmt="excel")


def test_csv_and_json_run_via_cli_report(monkeypatch, tmp_path):
    """CLI dispatch: omega report - --format dojo-csv/--out <path>."""
    from omega.core import cli
    import omega.core.session as session_mod

    monkeypatch.setattr(session_mod, "load_session", lambda n: {
        "target": "example.com", "timestamp": "t",
        "state": {"findings": [_finding()]}})
    out_csv = str(tmp_path / "cli.csv")
    rc = cli.main(["report", "s1", "--format", "dojo-csv",
                   "--out", out_csv])
    assert rc == 0
    assert os.path.exists(out_csv)
    out_json = str(tmp_path / "cli.json")
    rc = cli.main(["report", "s1", "--format", "dojo-json",
                   "--out", out_json])
    assert rc == 0
    assert json.loads(open(out_json, encoding="utf-8").read())[
        "test_type"] == "OMEGA Scan"
