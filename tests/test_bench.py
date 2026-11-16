"""Hermetic tests for the external bench + regression gate scoring logic.

No network: pure functions from lab/bench_ext.py and lab/regress.py are
exercised with synthetic findings and stubbed fusion results.
"""
import json
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "lab"))

from bench_ext import (  # noqa: E402
    UNREACHABLE_EXIT,
    load_catalog,
    matches_hint,
    render_report,
    score,
)
from regress import CLEAN_PATHS, PLANTED_CLASSES, evaluate  # noqa: E402

CATALOG_PATH = os.path.join(REPO, "lab", "bench_catalog.json")


def mkf(title="x", sev="LOW", loc="/", ev="evidence text", param="", **extra):
    f = {"title": title, "severity": sev, "location": loc,
         "evidence": ev, "param": param}
    f.update(extra)
    return f


# ------------------------------------------------------------ catalog

def test_catalog_loads_and_is_shaped():
    catalog = load_catalog(CATALOG_PATH)
    assert len(catalog) >= 20
    for entry in catalog:
        assert entry.get("id") and entry.get("category")
        assert entry.get("expected_severity")
        assert isinstance(entry.get("check_hint"), list)


def test_catalog_missing_file_returns_empty_never_raises():
    assert load_catalog("/nonexistent/catalog.json") == []


def test_catalog_has_expected_key_categories():
    cats = {e["category"] for e in load_catalog(CATALOG_PATH)}
    for c in ("sqli", "xss_reflected", "path_traversal", "open_redirect",
              "jwt_forgery", "missing_security_headers", "idor"):
        assert c in cats
    assert "xxe" not in cats  # JS SPA: XXE class intentionally skipped


# ------------------------------------------------------------ hint match

def test_matches_hint_hits_title_and_evidence():
    f = mkf(title="SQL Injection in search", ev="sqlite error")
    assert matches_hint(f, ["sqli", "sql injection"])
    assert matches_hint(f, ["SQLITE"])
    assert not matches_hint(f, ["jwt"])


def test_matches_hint_scans_location_param():
    f = mkf(loc="/rest/user/whoami", param="email")
    assert matches_hint(f, ["whoami", "email"])
    assert not matches_hint(f, ["token"])


def test_matches_hint_empty_hints_never_matches():
    assert not matches_hint(mkf(title="anything"), [])


# ------------------------------------------------------------ scoring

def _catalog_entry(eid, cat, sev, hints):
    return {"id": eid, "category": cat, "expected_severity": sev,
            "check_hint": hints}


def test_score_tp_counting():
    catalog = [_catalog_entry("E1", "sqli", "CRITICAL", ["sql injection"]),
               _catalog_entry("E2", "open_redirect", "MEDIUM", ["redirect"])]
    findings = [mkf(title="SQL Injection detected", sev="HIGH"),
                mkf(title="Open redirect on /redirect", sev="MEDIUM"),
                mkf(title="Info: server banner", sev="LOW")]
    res = score(catalog, findings)
    assert res["detected_classes"] == 2
    assert res["total_classes"] == 2
    assert res["missed"] == []
    assert {t["id"] for t in res["tp"]} == {"E1", "E2"}


def test_score_missed_classes():
    catalog = [_catalog_entry("E1", "sqli", "CRITICAL", ["sql injection"]),
               _catalog_entry("E2", "ssrf", "HIGH", ["ssrf"])]
    res = score(catalog, [mkf(title="SQL Injection")])
    assert res["detected_classes"] == 1
    assert [e["id"] for e in res["missed"]] == ["E2"]


def test_score_fp_suspects_high_sev_unmatched():
    catalog = [_catalog_entry("E1", "sqli", "CRITICAL", ["sql injection"])]
    matched = mkf(title="SQL Injection found", sev="HIGH")
    unmatched_high = mkf(title="Totally unexpected thing", sev="CRITICAL")
    low_unmatched = mkf(title="Unmatched but low", sev="LOW")
    res = score(catalog, [matched, unmatched_high, low_unmatched])
    assert res["fp_suspects"] == [unmatched_high]


def test_score_fp_suspect_matching_class_is_not_flagged():
    catalog = [_catalog_entry("E1", "sqli", "CRITICAL", ["sql injection"])]
    res = score(catalog, [mkf(title="SQL Injection", sev="CRITICAL")])
    assert res["fp_suspects"] == []


def test_score_never_marks_confirmed():
    """Findings are carried as detected-signal; no 'confirmed' label added."""
    catalog = [_catalog_entry("E1", "sqli", "CRITICAL", ["sql"])]
    res = score(catalog, [mkf(title="SQL Injection")])
    assert all("confirmed" not in t for t in res["tp"])
    assert all(t["finding"].get("verification") is None for t in res["tp"])


def test_score_empty_inputs():
    res = score([], [])
    assert res["detected_classes"] == 0 and res["fp_suspects"] == []


# ------------------------------------------------------------ report

def test_render_report_contains_coverage_and_fp_section():
    catalog = load_catalog(CATALOG_PATH)
    findings = [mkf(title="Missing security headers", sev="MEDIUM",
                    loc="https://t/")]
    res = score(catalog, findings)
    report = render_report("https://target", {"ran": ["a"], "skipped": []},
                           res, 12.5)
    assert "detected signals" in report.lower()
    assert "FP suspects" in report
    assert "| E" in report or "| EXT" in report
    assert "manual review" in report or "manual verification" in report


def test_render_report_fp_suspects_listed():
    res = {"tp": [], "missed": [], "fp_suspects": [
        mkf(title="Weird high sev", sev="HIGH", loc="/x")],
        "detected_classes": 0, "total_classes": 5}
    report = render_report("t", {}, res, 1.0)
    assert "Weird high sev" in report and "manual review" in report


# ------------------------------------------------------------ regress gate

def test_regress_evaluate_pass_with_stubbed_results():
    findings = [
        mkf(title="SQL injection error diff", sev="HIGH", loc="/login"),
        mkf(title="Reflected XSS payload echo", sev="HIGH", loc="/echo"),
        mkf(title="Path traversal ../ read", sev="HIGH", loc="/file"),
        mkf(title="OS command injection echo", sev="CRITICAL", loc="/exec"),
        mkf(title="SSTI template injection {{7*7}}", sev="HIGH", loc="/ssti"),
        mkf(title="Open redirect Location header", sev="MEDIUM", loc="/go"),
        mkf(title="Exposed .env secrets", sev="HIGH", loc="/.env"),
        mkf(title="Session cookie without Secure flag", sev="MEDIUM",
            loc="/login"),
        mkf(title="Missing security headers CSP HSTS", sev="MEDIUM", loc="/"),
        mkf(title="Directory listing enabled", sev="LOW", loc="/files/"),
    ]
    verdict = evaluate(findings)
    assert verdict["pass"] is True
    assert verdict["detection_count"] == 10
    assert verdict["clean_fps"] == []


def test_regress_evaluate_fails_below_detection_threshold():
    verdict = evaluate([mkf(title=f"Hit {n}", sev="LOW") for n in (1,)])
    assert verdict["pass"] is False
    assert verdict["detection_count"] < 9


def test_regress_evaluate_fails_on_clean_path_high_fp():
    findings = [mkf(t, sev="LOW", loc="/")
                for t, _h in PLANTED_CLASSES]
    # all 10 planted matched, but one HIGH finding on a clean path
    findings.append(mkf(title="SQL error on health", sev="HIGH",
                        loc=f"{CLEAN_PATHS[2]}"))
    verdict = evaluate(findings)
    assert verdict["detection_count"] == 10
    assert verdict["pass"] is False and verdict["clean_fps"]
    assert CLEAN_PATHS[2] in str(verdict["clean_fps"][0]["location"])


def test_regress_planted_class_hints_are_complete():
    """Every planted class has >=1 hint so the gate can't silently no-op."""
    assert len(PLANTED_CLASSES) == 10
    assert all(hints for _n, hints in PLANTED_CLASSES)


def test_json_catalog_is_valid_json(tmp_path):
    with open(CATALOG_PATH, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert isinstance(data, dict) and isinstance(data["classes"], list)
