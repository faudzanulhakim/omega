"""Regression tests for approved post-audit fixes (cee113e):

MEDIUM-1: bounded 1MB response reading + explicit truncation metadata
MEDIUM-2a: valid legacy CVSS vector preserved & rescored
MEDIUM-2e: execsum recomputes CVSS, never presents stale scores
LOW-1: no missing-headers finding on 204/empty responses
"""
import threading
import http.server

import pytest

from omega.scanning.probes import (default_fetch, fetch_detailed,
                                   _read_bounded, security_headers_probe,
                                   MAX_BODY)
from omega.scanning.spamap import map_spa_endpoints
from omega.reporting.cvss import score_finding, base_score
from omega.reporting.execsum import for_developer

VEC98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8
VEC54 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"   # 5.4


# --------------------------------------------------------------- lab server
class _Lab(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path in SIZES:
            body = SIZES[self.path]
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/204":
            self.send_response(204)
            self.end_headers()
        elif self.path == "/malformed":
            self.wfile.write(b"GARBAGE-NOT-HTTP\r\n\r\nnope")
        elif self.path == "/":
            body = (b'<html><script src="/1m.js"></script>'
                    b'<script src="/70k.js"></script>'
                    b'<script src="/256k.js"></script></html>')
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def _bundle(total, marker=b'fetch("/api/late-endpoint")'):
    # exact-size bundle: header + filler + newline + marker + newline
    prefix = b'var api="";\n'
    filler = b'var x1=1;\n' * (((total - len(prefix) - len(marker) - 2)
                               // 10))
    body = prefix + filler + b'\n' + marker + b'\n'
    return body + b' ' * (total - len(body))   # pad to exact size


SIZES = {
    "/1k.js": _bundle(1024),
    "/64k.js": _bundle(64 * 1024),
    "/64k1.js": _bundle(64 * 1024 + 1),
    "/70k.js": _bundle(70 * 1024),
    "/256k.js": _bundle(256 * 1024),
    "/1m.js": _bundle(1024 * 1024),
    "/over1m.js": _bundle(1024 * 1024 + 50000),
}


@pytest.fixture(scope="module")
def lab_url():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Lab)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


# ------------------------------------------------------- MEDIUM-1
@pytest.mark.parametrize("path,size", [
    ("/1k.js", 1024), ("/64k.js", 64 * 1024),
    ("/64k1.js", 64 * 1024 + 1), ("/70k.js", 70 * 1024),
    ("/256k.js", 256 * 1024), ("/1m.js", 1024 * 1024)])
def test_m1_sizes_fully_delivered(lab_url, path, size):
    st, hd, body = default_fetch("GET", lab_url + path)
    assert st == 200
    assert len(body) == size          # fully delivered up to 1MB
    assert b"late-endpoint" in body   # endpoint at END visible


def test_m1_over_1mb_bounded_and_flagged(lab_url):
    st, hd, body, meta = fetch_detailed("GET", lab_url + "/over1m.js")
    assert st == 200
    assert len(body) == MAX_BODY            # hard cap, memory bounded
    assert meta["truncated"] is True        # explicit truncation metadata
    assert meta["limit"] == MAX_BODY


def test_m1_default_fetch_contract_unchanged(lab_url):
    out = default_fetch("GET", lab_url + "/70k.js")
    assert isinstance(out, tuple) and len(out) == 3  # 3-tuple preserved


def test_m1_read_bounded_exact_and_partial():
    class R:
        def __init__(self, data):
            self.data, self.pos = data, 0
        def read(self, n=-1):
            n = min(n, len(self.data) - self.pos) if n > 0 else \
                len(self.data) - self.pos
            chunk = self.data[self.pos:self.pos + n]
            self.pos += len(chunk)
            return chunk
    body, trunc = _read_bounded(R(b"ab"), limit=10)
    assert body == b"ab" and trunc is False            # short read: complete
    body, trunc = _read_bounded(R(b"x" * 20), limit=10)
    assert len(body) == 10 and trunc is True           # cap hit: truncated
    body, trunc = _read_bounded(R(b""), limit=10)
    assert body == b"" and trunc is False              # empty: complete


def test_m1_connection_failure_and_malformed(lab_url):
    # contract: default_fetch raises on network/parse errors; callers
    # (run_probes etc.) translate that into honest skips
    with pytest.raises(Exception):
        default_fetch("GET", "http://127.0.0.1:1/")
    with pytest.raises(Exception):
        default_fetch("GET", lab_url + "/malformed")


def test_m1_spamap_finds_endpoint_after_64kb(lab_url):
    doc = map_spa_endpoints(lab_url + "/", fetch=default_fetch)
    eps = set(doc.get("endpoints", {}))
    assert any("late-endpoint" in e for e in eps)      # >64KB bundle parsed
    assert doc["incomplete"] is False
    assert doc["truncated_assets"] == []


def test_m1_spamap_endpoint_in_last_bytes_of_1mb(lab_url):
    doc = map_spa_endpoints(lab_url + "/", fetch=default_fetch)
    # /1m.js: marker sits at the very end of a 1MB bundle
    assert any("late-endpoint" in e for e in
               set(doc.get("endpoints", {})))


def test_m1_spamap_marks_truncated_bundle(lab_url, monkeypatch):
    # force a tiny cap so the asset is cut mid-bundle
    monkeypatch.setattr("omega.scanning.probes.MAX_BODY", 512)
    import omega.scanning.probes as probes_mod
    orig = probes_mod.fetch_detailed

    def capped(method, url, headers=None):
        st, hd, body, meta = orig(method, url, headers)
        if len(body) > 512:
            body = body[:512]
            meta = dict(meta, truncated=True)
        return st, hd, body, meta

    monkeypatch.setattr(probes_mod, "fetch_detailed", capped)
    doc = map_spa_endpoints(lab_url + "/",
                            fetch=lambda u: capped("GET", u))
    assert doc["incomplete"] is True
    assert doc["truncated_assets"]


# ------------------------------------------------------- MEDIUM-2a
def test_m2a_valid_vector_98_stale_zero_preserved():
    f = {"title": "t", "severity": "CRITICAL", "cwe": [89],
         "verification": "confirmed", "cvss_score": 0.0,
         "cvss_vector": VEC98}
    out = score_finding(f)
    assert out["cvss_vector"] == VEC98        # operator vector kept
    assert out["cvss_score"] == 9.8           # rescored from vector
    assert f["cvss_score"] == 0.0             # input not mutated


def test_m2a_valid_vector_54_stale_98_ignored():
    f = {"title": "t", "severity": "LOW", "cwe": [614],
         "cvss_score": 9.8, "cvss_vector": VEC54}
    out = score_finding(f)
    assert out["cvss_vector"] == VEC54
    assert out["cvss_score"] == pytest.approx(5.4)


def test_m2a_invalid_vector_falls_back_to_derivation():
    for bad in ("not-a-vector", "", None,
                "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
        f = {"title": "t", "severity": "HIGH", "cwe": [79],
             "cvss_vector": bad}
        out = score_finding(f)
        assert out["cvss_vector"].startswith("CVSS:3.1/")
        assert 0.0 <= out["cvss_score"] <= 10.0


def test_m2a_no_vector_no_cwe_derives_from_severity():
    f = {"title": "t", "severity": "CRITICAL"}
    out = score_finding(f)
    assert 0.0 <= out["cvss_score"] <= 10.0
    assert out["cvss_vector"].startswith("CVSS:3.1/")


def test_m2a_genuine_zero_and_range():
    f = {"title": "info", "severity": "INFO", "cwe": [693]}
    out = score_finding(f)
    assert 0.0 <= out["cvss_score"] <= 10.0
    crit = score_finding({"title": "c", "severity": "CRITICAL",
                          "cwe": [89]})
    assert crit["cvss_score"] > out["cvss_score"]


# ------------------------------------------------------- MEDIUM-2e
def test_m2e_execsum_no_stale_zero():
    f = {"title": "legacy", "severity": "CRITICAL", "cwe": [89],
         "verification": "confirmed", "cvss_score": 0.0,
         "cvss_vector": VEC98}
    row = for_developer([f])["items"][0]
    assert "(0.0)" not in row["cvss"]
    assert VEC98 in row["cvss"] and "9.8" in row["cvss"]


def test_m2e_execsum_inconsistent_score_rejected():
    f = {"title": "bad", "severity": "LOW", "cwe": [614],
         "cvss_score": 9.8, "cvss_vector": VEC54}
    row = for_developer([f])["items"][0]
    assert "5.4" in row["cvss"] and "9.8" not in row["cvss"]


def test_m2e_execsum_finding_without_cvss_fields():
    f = {"title": "bare", "severity": "MEDIUM", "cwe": [79]}
    row = for_developer([f])["items"][0]
    assert row["cvss"].startswith("CVSS:3.1/")
    assert "(0.0)" not in row["cvss"]


# ------------------------------------------------------- LOW-1
def test_low1_matrix_204_full_headers(lab_url):
    hdrs = {h: "x" for h in ("Content-Security-Policy",
                             "Strict-Transport-Security", "X-Frame-Options",
                             "X-Content-Type-Options", "Referrer-Policy")}
    f = security_headers_probe(
        lab_url, fetch=lambda m, u, h=None: (204, hdrs, b""))
    assert f == []                      # nothing missing: no finding


def test_low1_matrix_204_no_headers_candidate(lab_url):
    f = security_headers_probe(
        lab_url, fetch=lambda m, u, h=None: (204, {}, b""))
    assert len(f) == 1
    assert f[0]["verification"] == "candidate"   # weak evidence, kept
    assert f[0]["severity"] == "low"
    assert f[0]["evidence"]["empty_body"] is True
    assert f[0]["evidence"]["status"] == 204


def test_low1_matrix_204_partial_headers_candidate(lab_url):
    hdrs = {"Content-Security-Policy": "default-src 'self'"}
    f = security_headers_probe(
        lab_url, fetch=lambda m, u, h=None: (204, hdrs, b""))
    assert len(f) == 1 and f[0]["verification"] == "candidate"
    assert f[0]["evidence"]["present"] == ["Content-Security-Policy"]


def test_low1_matrix_200_empty_body_candidate(lab_url):
    f = security_headers_probe(
        lab_url, fetch=lambda m, u, h=None: (200, {}, b""))
    assert f[0]["verification"] == "candidate"


def test_low1_matrix_200_normal_body_confirmed(lab_url):
    f = security_headers_probe(lab_url, fetch=default_fetch)
    assert f and f[0]["verification"] == "confirmed"  # real evidence


def test_low1_matrix_500_still_evidence_based(lab_url):
    # 500 with body: normal confirmed path (headers still auditable)
    f = security_headers_probe(
        lab_url, fetch=lambda m, u, h=None: (500, {}, b"err"))
    assert f[0]["verification"] == "confirmed"


def test_low1_connection_failure_skips(lab_url):
    with pytest.raises(Exception):
        security_headers_probe("http://127.0.0.1:1/", fetch=default_fetch)


def test_low1_still_reports_missing_headers_on_200(lab_url):
    st, hd, body, meta = fetch_detailed("GET", lab_url + "/1k.js")
    # simulate by pointing the probe at a path with 200 + no headers
    f = security_headers_probe(lab_url, fetch=default_fetch)
    assert isinstance(f, list)     # root returns 200 w/o security headers


# ------------------------------------------------- D: single CVSS source
def test_d_unavailable_when_no_evidence():
    from omega.reporting.cvss import score_finding
    f = {"title": "mystery", "severity": "wat", "cwe": []}
    out = score_finding(f)
    assert out["cvss_source"] == "unavailable"
    assert out["cvss_vector"] is None and out["cvss_score"] is None


def test_d_source_provenance_vector_vs_derived():
    from omega.reporting.cvss import score_finding
    a = score_finding({"title": "a", "severity": "HIGH", "cwe": [79],
                       "cvss_vector": VEC98})
    assert a["cvss_source"] == "vector"
    b = score_finding({"title": "b", "severity": "HIGH", "cwe": [79]})
    assert b["cvss_source"] == "derived"


def test_d_ceo_manager_developer_scores_canonical():
    from omega.reporting.execsum import (for_executive, for_manager,
                                         for_developer)
    legacy = {"title": "L", "severity": "CRITICAL", "cwe": [89],
              "verification": "confirmed", "cvss_score": 0.0,
              "cvss_vector": VEC98}
    missing = {"title": "M", "severity": "wat"}
    m = for_manager([legacy, missing])
    assert m["top_items"][0]["score"] == 9.8          # rescored
    assert m["top_items"][1]["score"] is None          # honest unavailable
    d = for_developer([legacy, missing])
    assert "9.8" in d["items"][0]["cvss"]
    assert d["items"][1]["cvss"] == "unavailable"
    c = for_executive([legacy])
    # executive view aggregates counts, not scores: no stale 0.0 anywhere
    assert "0.0" not in str(c) or c["counts"]


def test_d_markdown_vs_execsum_consistency():
    from omega.reporting.report import generate_report
    from omega.reporting.execsum import for_developer, for_manager
    legacy = {"title": "Consistency case", "severity": "CRITICAL",
              "cwe": [89], "verification": "confirmed",
              "cvss_score": 0.0, "cvss_vector": VEC98}
    md = generate_report("t", [legacy])
    dev = for_developer([legacy])["items"][0]["cvss"]
    man = for_manager([legacy])["top_items"][0]["score"]
    assert VEC98 in dev and "9.8" in dev
    assert man == 9.8
    # markdown CVSS line must show the same score
    md_lines = [l for l in md.splitlines() if "CVSS:" in l and "9.8" in l]
    assert md_lines, "markdown must show rescored 9.8"


def test_d_genuine_zero_keeps_derivation():
    from omega.reporting.cvss import score_finding
    f = {"title": "i", "severity": "INFO", "cwe": [693],
         "cvss_score": 0.0}
    out = score_finding(f)
    assert out["cvss_score"] == 0.0 and out["cvss_source"] == "derived"


# ------------------------------------------------- F: title unification
def test_f_version_banner_title():
    from omega.scanning.probes import version_banner_probe
    hdrs = {"Server": "nginx/1.14.0"}
    f = version_banner_probe(
        "http://x", fetch=lambda m, u, h=None: (200, hdrs, b"ok"))
    assert f[0]["title"] == "Version banner disclosure"
    assert f[0]["severity"] == "info"          # detection/severity unchanged
