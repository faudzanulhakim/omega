"""tests/test_cvefeed.py — offline NVD feed refresh + lookup tests.

Hermetic: only tmp files, no network, no real ~/.cache writes (the
index path is redirected via OMEGA_CVE_INDEX / explicit paths).
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))

from omega.scanning import cvefeed  # noqa: E402


FEED_1_1 = {
    "CVE_Items": [
        {
            "cve": {
                "CVE_data_meta": {"ID": "CVE-2021-41773"},
                "description": {"description_data": [
                    {"lang": "en",
                     "value": "A path traversal and remote code "
                              "execution flaw in Apache HTTP Server "
                              "2.4.49 and 2.4.50."}]},
                "affects": {"vendor": {"vendor_data": [
                    {"vendor_name": "apache",
                     "product": {"product_data": [
                         {"product_name": "httpd",
                          "version": {"version_data": [
                              {"version_value": "2.4.49"}]}}]}}]}},
                "impact": {"baseMetricV3": {"cvssV3": {
                    "baseSeverity": "CRITICAL"}}},
            },
        },
        {
            "cve": {
                "CVE_data_meta": {"ID": "CVE-2021-23017"},
                "description": {"description_data": [
                    {"lang": "en",
                     "value": "DNS resolver off-by-one heap write in "
                              "nginx."}]},
                "affects": {"vendor": {"vendor_data": [
                    {"vendor_name": "nginx",
                     "product": {"product_data": [
                         {"product_name": "nginx"}]}}]}},
                "impact": {"baseMetricV2": {"severity": "HIGH"}},
            },
        },
    ]
}

FEED_2_0 = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2022-26134",
                "descriptions": [{"lang": "en",
                                  "value": "OGNL injection "
                                           "vulnerability in "
                                           "Confluence Server."}],
                "configurations": [{"nodes": [{"cpeMatch": [
                    {"criteria": "cpe:2.3:a:atlassian:confluence:"
                                 "7.4.0:*:*:*:*:*:*:*",
                     "versionStartIncluding": "7.0.0",
                     "versionEndExcluding": "7.4.2"},
                ]}]}],
                "metrics": {"cvssMetricV31": [{"cvssData": {
                    "baseSeverity": "HIGH"}}]},
            },
        }
    ]
}


@pytest.fixture()
def tmp_index(tmp_path, monkeypatch):
    monkeypatch.setenv("OMEGA_CVE_INDEX",
                       str(tmp_path / "cve_index.json"))
    return tmp_path / "cve_index.json"


def _write_feed(tmp_path, doc, name="feed.json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def test_refresh_json_1_1_builds_index(tmp_path, tmp_index):
    feed = _write_feed(tmp_path, FEED_1_1)
    out = cvefeed.refresh(feed)
    assert out["ok"] is True
    assert out["cves"] == 2
    doc = json.loads(tmp_index.read_text(encoding="utf-8"))
    entries = [e for e in doc["entries"] if e["cve_id"] == "CVE-2021-41773"]
    assert entries and entries[0]["product"] == "httpd"
    assert entries[0]["severity"] == "critical"
    assert entries[0]["summary"].startswith("A path traversal")
    assert len(entries[0]["summary"]) <= 200


def test_refresh_json_2_0_version_ranges(tmp_path, tmp_index):
    feed = _write_feed(tmp_path, FEED_2_0)
    out = cvefeed.refresh(feed)
    assert out["ok"] is True and out["entries"] >= 1
    doc = json.loads(tmp_index.read_text(encoding="utf-8"))
    e = doc["entries"][0]
    assert e["product"] == "confluence"
    rng = e["version_ranges"][0]
    assert rng["start"] == "7.0.0" and rng["start_incl"] is True
    assert rng["end_excl"] == "7.4.2" and rng["end_incl"] is False


def test_lookup_version_in_range(tmp_path, tmp_index):
    feed = _write_feed(tmp_path, FEED_2_0)
    cvefeed.refresh(feed)
    hits = cvefeed.lookup("confluence", "7.2.1")
    assert len(hits) == 1
    assert hits[0]["cve_id"] == "CVE-2022-26134"
    assert hits[0]["severity"] == "high"


def test_lookup_version_out_of_range(tmp_path, tmp_index):
    feed = _write_feed(tmp_path, FEED_2_0)
    cvefeed.refresh(feed)
    assert cvefeed.lookup("confluence", "9.9.9") == []
    assert cvefeed.lookup("nonexistent-product") == []


def test_refresh_never_raises_on_junk(tmp_path, tmp_index):
    bad = tmp_path / "bad.json"
    bad.write_text("{definitely not json", encoding="utf-8")
    out = cvefeed.refresh(str(bad))
    assert out["ok"] is False and "error" in out
    assert isinstance(out, dict)


def test_refresh_without_feed_reports_error(tmp_path, monkeypatch):
    monkeypatch.delenv("OMEGA_CVE_FEED", raising=False)
    out = cvefeed.refresh()
    assert out["ok"] is False
    assert "no feed" in out["error"]


def test_status_counts_and_staleness(tmp_path, tmp_index):
    feed = _write_feed(tmp_path, FEED_2_0)
    cvefeed.refresh(feed)
    st = cvefeed.status()
    assert st["present"] is True
    assert st["cves"] == 1 and st["entries"] >= 1
    assert st["staleness_days"] == 0
    missing = str(tmp_path / "nope.json")
    st2 = cvefeed.status(missing)
    assert st2["present"] is False and st2["entries"] == 0


def test_brain_capability_registered():
    from omega.brain import DEFAULT_REGISTRY
    cap = DEFAULT_REGISTRY.get("scanning.cvefeed")
    assert cap is not None
    assert cap.risk == "passive"
    assert "cve" in (cap.description or "").lower()


def test_brain_capability_runs(tmp_path, tmp_index, monkeypatch):
    feed = _write_feed(tmp_path, FEED_2_0)
    cvefeed.refresh(feed)
    from omega.brain import _cap_cvefeed_fn

    class _State:
        surface = {"techs": [{"product": "confluence",
                              "version": "7.2.1"}]}

    out = _cap_cvefeed_fn(_State())
    assert isinstance(out, dict)
    assert out["index_status"]["present"] is True
    assert out["index_status"]["staleness_days"] == 0
    assert any(h["cve"] == "CVE-2022-26134" for h in out["enriched_cves"])
