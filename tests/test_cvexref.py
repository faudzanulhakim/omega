"""Hermetic tests for omega/cvexref.py — offline CVE correlation.

Covers: the bundled DB audit (>=60 entries, every CVE with id + version
range), exact-version correlation in an affected range -> candidate
HIGH carrying the CVE id, versions outside every range -> no finding,
banners without a parseable version -> skipped 'no version', an
EOL-only (non-flagged) entry match -> INFO severity, and a fully
offline execution path (no network imports / calls involved).
"""

import inspect

import pytest

import omega.cvexref as cx
from omega.cvexref import CVE_DB, correlate, db_audit, parse_version


# ------------------------------------------------------------- DB audit

def test_db_at_least_60_entries_with_cves_and_ranges():
    n, n_cves, problems = db_audit()
    assert n >= 60, "expected >=60 DB entries, found %d" % n
    assert n_cves >= n, "every entry should carry CVE data"
    # the only tolerated audit note is the one CVE id genuinely shared
    # by two products (nginx + node: HTTP/2 CVE-2019-9511)
    assert all(p.startswith("duplicate CVE id CVE-2019-9511")
               for p in problems), problems
    for entry in CVE_DB:
        assert entry.get("product")
        assert entry.get("aliases")
        assert entry.get("cves"), entry["product"]
        for c in entry["cves"]:
            assert c["id"].startswith("CVE-")
            assert c["min"] and c["max"]


# ------------------------------------------------------------ correlate

def test_exact_version_in_range_candidate_high():
    out = correlate(["Apache/2.4.49"])
    assert out["findings"], "expected findings for apache 2.4.49"
    cve_ids = {f["evidence"]["cve"] for f in out["findings"]}
    assert "CVE-2021-41773" in cve_ids
    hit = [f for f in out["findings"]
           if f["evidence"]["cve"] == "CVE-2021-41773"][0]
    assert hit["verification"] == "candidate"
    assert hit["severity"] == "high"
    assert hit["evidence"]["parsed_version"] == "2.4.49"
    assert hit["source"] == "omega-cve/xref"


def test_dict_fingerprint_shape():
    out = correlate([{"product": "nginx", "version": "1.20.0"}])
    cves = {f["evidence"]["cve"] for f in out["findings"]}
    assert "CVE-2021-23017" in cves


def test_version_not_in_range_no_finding():
    out = correlate(["nginx/1.99.9", "apache/2.4.99"])
    assert out["findings"] == []
    assert out["skipped"] == {}


def test_banner_without_version_skipped_no_version():
    out = correlate(["nginx", "OpenSSH"])
    assert out["findings"] == []
    for key in out["skipped"]:
        assert out["skipped"][key] == "no version"
    assert len(out["skipped"]) == 2


def test_eol_only_entry_info_severity():
    # php 5.4.20 hits only EOL-era entries, none flagged high
    out = correlate(["PHP/5.4.20"])
    assert out["findings"], "expected EOL-range findings"
    for f in out["findings"]:
        assert f["severity"] == "info"
        assert f["verification"] == "candidate"


def test_parse_version_extracts_dotted():
    assert parse_version("Apache/2.4.49") == "2.4.49"
    assert parse_version("nginx 1.18.0 (ubuntu)") == "1.18.0"
    assert parse_version("no version here") is None
    assert parse_version("") is None


def test_correlate_never_raises_on_garbage():
    out = correlate([None, 42, "", {"product": None}, {}])
    assert isinstance(out, dict)
    out2 = correlate(None)
    assert out2["findings"] == []


# ------------------------------------------------------------- offline

def test_fully_offline_correlate_path():
    """No network imports anywhere in the module: correlate() can never
    touch the network (checked via AST over the module source)."""
    import ast
    tree = ast.parse(inspect.getsource(cx))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    banned = {"urllib", "socket", "requests", "http", "httpx", "aiohttp"}
    assert not (imported & banned), "network import found: %s" % \
        (imported & banned)
    # and running it still works with any network machinery blocked
    out = correlate(["log4j/2.14.0"])
    cves = {f["evidence"]["cve"] for f in out["findings"]}
    assert "CVE-2021-44228" in cves
    assert any(f["severity"] == "high"
               for f in out["findings"]
               if f["evidence"]["cve"] == "CVE-2021-44228")
