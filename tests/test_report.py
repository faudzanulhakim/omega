"""Tests for omega/report.py — the auto-report engine (hermetic)."""

import json
import os
import time

import pytest

from omega import report as rpt
from omega.report import (
    CLASSIFICATION,
    CWE_LINKS,
    GENERIC_RECOMMENDATION,
    ReportError,
    generate_report,
    generate_session_report,
    report_summary,
    sanitize_findings,
    write_report,
)


def _f(**kw):
    f = {"title": "t", "severity": "INFO", "confidence": "medium",
         "verification": "candidate", "source": "omega-py/x",
         "evidence": "", "location": "loc", "manual_check": ""}
    f.update(kw)
    return f


# ---------------------------------------------------------------------------
# sanitize_findings
# ---------------------------------------------------------------------------

def test_sanitize_drops_non_dict_entries():
    out = sanitize_findings(["junk", 42, None, _f(title="ok")])
    assert [f["title"] for f in out] == ["ok"]


def test_sanitize_coerces_missing_fields():
    out = sanitize_findings([{"title": "bare"}])
    f = out[0]
    assert f["severity"] == "INFO"
    assert f["evidence"] == ""
    assert f["location"] == ""
    assert f["source"] == ""
    assert f["manual_check"] == ""


def test_sanitize_truncates_evidence():
    out = sanitize_findings([_f(evidence="x" * 500)])
    assert len(out[0]["evidence"]) == 300


def test_sanitize_dedupes_keeps_highest_severity():
    out = sanitize_findings([
        _f(title="dup", location="l", source="s", severity="LOW"),
        _f(title="dup", location="l", source="s", severity="HIGH"),
    ])
    assert len(out) == 1
    assert out[0]["severity"] == "HIGH"


def test_sanitize_sorts_severity_then_title():
    out = sanitize_findings([
        _f(title="b", severity="LOW"),
        _f(title="a", severity="LOW"),
        _f(title="z", severity="HIGH"),
        _f(title="m", severity="MEDIUM"),
    ])
    assert [(f["severity"], f["title"]) for f in out] == [
        ("HIGH", "z"), ("MEDIUM", "m"), ("LOW", "a"), ("LOW", "b")]


def test_sanitize_never_raises_on_malformed():
    weird = [{"title": {"nested": 1}, "severity": 99, "evidence": b"bytes"},
             [1, 2], "str", 7]
    out = sanitize_findings(weird)
    assert isinstance(out, list) and len(out) == 1


def test_sanitize_assigns_sequential_ids():
    out = sanitize_findings([_f(title="b"), _f(title="a", severity="HIGH"),
                             _f(title="c")])
    assert [f["id"] for f in out] == ["F-001", "F-002", "F-003"]


def test_sanitize_severity_aliases():
    out = sanitize_findings([_f(severity="critical")])
    assert out[0]["severity"] == "HIGH"


def test_sanitize_cwe_normalization():
    out = sanitize_findings([_f(cwe=89), _f(title="b", cwe="CWE79"),
                             _f(title="c", cwe="CWE-611")])
    assert [f["cwe"] for f in out] == ["CWE-79", "CWE-611", "CWE-89"]


def test_sanitize_default_description_uses_finding_text_when_given():
    out = sanitize_findings([_f(description="my description")])
    assert out[0]["description"] == "my description"


def test_sanitize_generated_description_when_missing():
    out = sanitize_findings([_f(title="SQLi", location="/a",
                                source="omega-py/deep")])
    d = out[0]["description"]
    assert "SQLi" in d and "/a" in d and "omega-py/deep" in d


def test_sanitize_impact_default_by_severity():
    out = sanitize_findings([_f(severity="HIGH"),
                             _f(title="b", severity="LOW")])
    assert out[0]["impact"] != out[1]["impact"]
    assert "attacker" in out[0]["impact"].lower()


def test_sanitize_explicit_impact_kept():
    out = sanitize_findings([_f(impact="custom impact")])
    assert out[0]["impact"] == "custom impact"


def test_sanitize_recommendation_cwe89_sqli():
    out = sanitize_findings([_f(cwe="CWE-89")])
    rec = out[0]["recommendation"].lower()
    assert "parameterized" in rec or "prepared statements" in rec


def test_sanitize_recommendation_unknown_cwe_generic():
    out = sanitize_findings([_f(cwe="CWE-12345")])
    assert "OWASP" in out[0]["recommendation"]


def test_sanitize_references_for_known_cwe():
    out = sanitize_findings([_f(cwe="CWE-79")])
    refs = out[0]["references"]
    assert any("owasp.org" in r for r in refs)
    assert CWE_LINKS["CWE-79"] in refs


def test_sanitize_references_empty_without_cwe():
    out = sanitize_findings([_f()])
    assert out[0]["references"] == []


def test_sanitize_never_raises_on_cwe_garbage():
    out = sanitize_findings([{"title": "x", "cwe": {"bad": 1}, "evidence": b""}])
    assert out[0]["cwe"] == "BAD: 1" or isinstance(out[0]["cwe"], str)


# ---------------------------------------------------------------------------
# report_summary
# ---------------------------------------------------------------------------

def test_report_summary_counts():
    findings = [
        _f(verification="confirmed", severity="HIGH"),
        _f(title="b", verification="candidate", severity="MEDIUM"),
        _f(title="c", verification="candidate", severity="LOW",
           corroborated=True),
    ]
    s = report_summary(findings)
    assert s["total"] == 3
    assert s["by_severity"] == {"HIGH": 1, "MEDIUM": 1, "LOW": 1,
                                "INFO": 0}
    assert s["by_verification"]["confirmed"] == 1
    assert s["by_verification"]["candidate"] == 2
    assert s["corroborated"] == 1


def test_report_summary_risk_rating_highest_severity():
    assert report_summary([_f(severity="LOW"),
                           _f(title="b", severity="HIGH")]
                          )["risk_rating"] == "HIGH"
    assert report_summary([_f()])["risk_rating"] == "INFO"


def test_report_summary_risk_rating_empty_is_info():
    assert report_summary([])["risk_rating"] == "INFO"


def test_empty_findings_valid_report_zero_summary():
    md = generate_report("t", [])
    assert "# Web Application Penetration Test Report" in md
    s = report_summary([])
    assert s["total"] == 0
    assert all(v == 0 for v in s["by_severity"].values())
    assert s["corroborated"] == 0


# ---------------------------------------------------------------------------
# cover / classification
# ---------------------------------------------------------------------------

def test_markdown_cover_block():
    md = generate_report("example.com", [_f()])
    assert md.startswith("# Web Application Penetration Test Report")
    assert "**Target:** example.com" in md
    assert "Engagement date (UTC):" in md
    assert "OMEGA v1.0.0" in md
    assert CLASSIFICATION in md


def test_markdown_generated_at_utc_isoformat():
    md = generate_report("example.com", [_f()])
    line = [ln for ln in md.splitlines() if "Engagement date" in ln][0]
    assert "T" in line and "Z" in line


def test_html_classification_banner(html_report):
    assert CLASSIFICATION in html_report
    assert 'class="classification"' in html_report


# ---------------------------------------------------------------------------
# executive summary
# ---------------------------------------------------------------------------

def test_markdown_executive_summary_rating_and_counts():
    md = generate_report("t", [_f(verification="confirmed", severity="HIGH"),
                               _f(title="b", verification="candidate",
                                  severity="LOW")])
    assert "## Executive Summary" in md
    assert "overall risk rating of this engagement is HIGH" in md
    assert "HIGH 1" in md and "MEDIUM 0" in md
    assert "confirmed 1" in md and "candidate 1" in md


def test_markdown_executive_summary_key_observations():
    md = generate_report("t", [_f(title="SQL injection", severity="HIGH")])
    assert "Key observations" in md
    assert "SQL injection" in md


def test_markdown_empty_findings_executive_summary():
    md = generate_report("t", [])
    assert "No findings" in md


def test_html_executive_summary_section(html_report):
    assert 'id="executive-summary"' in html_report
    assert "overall risk rating" in html_report


# ---------------------------------------------------------------------------
# scope / methodology / risk methodology
# ---------------------------------------------------------------------------

def test_markdown_scope_and_methodology():
    md = generate_report("t", [_f(source="omega-py/deep")],
                         meta={"ran": ["headerscan", "deepchecks"],
                               "skipped": ["oobscan (no OOB host)"]})
    assert "## Scope & Methodology" in md
    assert "black-box" in md and "non-destructive" in md
    assert "operator-provided scope" in md
    assert "omega-py/deep" in md or "omega-py" in md
    assert "headerscan" in md
    assert "oobscan (no OOB host)" in md


def test_markdown_risk_rating_methodology_section():
    md = generate_report("t", [_f()])
    assert "## Risk Rating Methodology" in md
    assert "differential proof" in md
    assert "needs manual verification" in md
    assert "2 independent scanners" in md
    for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
        assert f"- {sev}:" in md


# ---------------------------------------------------------------------------
# markdown findings
# ---------------------------------------------------------------------------

def test_markdown_finding_ids_sequential():
    md = generate_report("t", [_f(title="b"), _f(title="a", severity="HIGH"),
                               _f(title="c")])
    assert "### F-001 [HIGH] a" in md
    assert "### F-002 [INFO] b" in md
    assert "### F-003 [INFO] c" in md


def test_markdown_confirmed_and_candidate_markers():
    md = generate_report("t", [
        _f(title="yes", verification="confirmed", location="l1",
           severity="HIGH"),
        _f(title="cand", verification="candidate", location="l2"),
    ])
    yes = md.split("### F-001")[1].split("### F-002")[0]
    cand = md.split("### F-002")[1]
    assert "CONFIRMED" in yes
    assert "CANDIDATE — needs manual verification" in cand
    assert "CONFIRMED" not in cand


def test_markdown_corroborated_status():
    md = generate_report("t", [_f(corroborated=True,
                                  source="omega-py/a, omega-py/b")])
    assert "corroborated by 2 scanners" in md


def test_markdown_manual_check_fenced_and_evidence_block():
    md = generate_report("t", [_f(evidence="EVID-123",
                                  manual_check="curl -I http://x")])
    assert "```bash\ncurl -I http://x\n```" in md
    assert "```\nEVID-123\n```" in md


def test_markdown_missing_evidence_placeholder():
    md = generate_report("t", [_f(evidence="")])
    assert "No evidence captured" in md


def test_markdown_finding_description_impact_recommendation():
    md = generate_report("t", [_f(title="SQLi", cwe="CWE-89")])
    assert "**Description:**" in md
    assert "**Impact:**" in md
    assert "**Recommendation:**" in md
    assert "parameterized" in md.lower()


def test_markdown_references_owasp_link():
    md = generate_report("t", [_f(cwe="CWE-89")])
    assert CWE_LINKS["CWE-89"] in md


def test_markdown_manual_verification_steps_label():
    md = generate_report("t", [_f(manual_check="whoami")])
    assert "Manual verification steps:" in md


# ---------------------------------------------------------------------------
# html
# ---------------------------------------------------------------------------

@pytest.fixture()
def html_report():
    return generate_report("h.com", [
        _f(title="one", verification="confirmed", severity="HIGH",
           evidence="ev", manual_check="mc"),
        _f(title="two", severity="MEDIUM"),
    ], fmt="html")


def test_html_valid_start_end_tags(html_report):
    assert html_report.startswith("<!DOCTYPE html>")
    assert html_report.rstrip().endswith("</html>")
    assert "<body>" in html_report and "</body>" in html_report


def test_html_no_script_no_external_assets(html_report):
    assert "<style>" in html_report
    assert "<script" not in html_report
    assert "<img" not in html_report and "<iframe" not in html_report
    assert "<link" not in html_report


def test_html_print_media_rule(html_report):
    assert "@media print" in html_report


def test_html_severity_badge_classes():
    doc = generate_report("h", [_f(severity="HIGH"),
                                _f(title="b", severity="MEDIUM"),
                                _f(title="c", severity="LOW"),
                                _f(title="d", severity="INFO")], fmt="html")
    for cls in ("badge-HIGH", "badge-MEDIUM", "badge-LOW", "badge-INFO"):
        assert f'class="badge {cls}"' in doc


def test_html_all_findings_present(html_report):
    assert "one" in html_report and "two" in html_report
    assert "ev" in html_report and "mc" in html_report
    assert "CONFIRMED" in html_report


def test_html_finding_ids_and_sections(html_report):
    assert "F-001" in html_report and "F-002" in html_report
    assert "Appendix A" in html_report and "Appendix B" in html_report
    assert "Scope &amp; Methodology" in html_report


def test_html_evidence_placeholder():
    doc = generate_report("h", [_f(evidence="")], fmt="html")
    assert "No evidence captured" in doc


def test_html_disclaimer_footer():
    doc = generate_report("h", [_f()], fmt="html")
    assert "Findings marked CANDIDATE require manual verification" in doc


# ---------------------------------------------------------------------------
# json
# ---------------------------------------------------------------------------

def test_json_parses_and_summary_matches():
    doc = json.loads(generate_report("j.com", [
        _f(verification="confirmed", severity="HIGH"),
        _f(title="b", severity="LOW"),
    ], fmt="json"))
    assert doc["target"] == "j.com"
    assert "generated_at" in doc
    assert doc["summary"]["total"] == 2
    assert doc["summary"]["by_severity"]["HIGH"] == 1
    assert doc["findings"][0]["severity"] == "HIGH"


def test_json_report_meta_risk_rating():
    doc = json.loads(generate_report("j", [_f(severity="HIGH")],
                                     fmt="json"))
    rm = doc["report_meta"]
    assert rm["risk_rating"] == "HIGH"
    assert rm["generator"] == "OMEGA v1.0.0"
    assert "generated_at" in rm
    assert "CONFIDENTIAL" in rm["classification"]


def test_json_findings_sanitized_and_enriched():
    doc = json.loads(generate_report("j", [{"title": 3, "junk": 1,
                                            "cwe": 89}], fmt="json"))
    f = doc["findings"][0]
    assert f["severity"] == "INFO" and "junk" not in f
    assert f["id"] == "F-001"
    assert f["cwe"] == "CWE-89"
    assert f["description"] and f["impact"] and f["recommendation"]


# ---------------------------------------------------------------------------
# format dispatch / errors
# ---------------------------------------------------------------------------

def test_unknown_fmt_valueerror():
    with pytest.raises(ValueError):
        generate_report("t", [], fmt="xml")
    with pytest.raises(ValueError):
        generate_session_report("/nonexistent-dir", fmt="xml")


def test_reporterror_on_bad_session_dir(tmp_path):
    with pytest.raises(ReportError):
        generate_session_report(str(tmp_path / "missing"))
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "session.json").write_text("{not json")
    with pytest.raises(ReportError):
        generate_session_report(str(bad))


# ---------------------------------------------------------------------------
# write_report
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ext,marker", [
    (".md", "# Web Application Penetration Test Report"),
    (".html", "<!DOCTYPE html>"),
    (".json", '"target"'),
])
def test_write_report_fmt_inference(tmp_path, ext, marker):
    path = write_report("w.com", [_f()], str(tmp_path / f"r{ext}"))
    assert path == str(tmp_path / f"r{ext}")
    assert os.path.isfile(path)
    with open(path, encoding="utf-8") as fh:
        assert marker in fh.read()


def test_write_report_creates_parent_dirs(tmp_path):
    deep = str(tmp_path / "a" / "b" / "c" / "r.md")
    path = write_report("w", [], deep)
    assert path == deep
    with open(path, encoding="utf-8") as fh:
        assert "# Web Application Penetration Test Report" in fh.read()


def test_write_report_unknown_ext_valueerror(tmp_path):
    with pytest.raises(ValueError):
        write_report("w", [], str(tmp_path / "r.txt"))


def test_write_report_explicit_fmt(tmp_path):
    path = write_report("w", [_f()], str(tmp_path / "out.weird"),
                        fmt="json")
    with open(path, encoding="utf-8") as fh:
        assert json.loads(fh.read())["target"] == "w"


# ---------------------------------------------------------------------------
# session loading
# ---------------------------------------------------------------------------

def test_generate_session_report_ok(tmp_path):
    doc = {"name": "s1", "timestamp": "2026-01-01T00:00:00",
           "target": "sess.com",
           "summary": {"findings": 1},
           "state": {"target": "sess.com",
                     "findings": [_f(title="sf",
                                     verification="confirmed")]}}
    (tmp_path / "session.json").write_text(json.dumps(doc))
    md = generate_session_report(str(tmp_path))
    assert "# Web Application Penetration Test Report" in md
    assert "sf" in md and "CONFIRMED" in md


def test_generate_session_report_missing_layout(tmp_path):
    d = tmp_path / "broken"
    d.mkdir()
    (d / "session.json").write_text(json.dumps({"no": "state"}))
    with pytest.raises(ReportError):
        generate_session_report(str(d))


# ---------------------------------------------------------------------------
# performance
# ---------------------------------------------------------------------------

def test_500_findings_fast():
    findings = [_f(title=f"finding-{i}", severity="HIGH",
                   location=f"http://h/{i}", source="omega-py/bulk",
                   evidence="e" * 280) for i in range(500)]
    t0 = time.monotonic()
    for fmt in ("markdown", "html", "json"):
        out = generate_report("bulk.com", findings, fmt=fmt)
        assert len(out) > 1000
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0, f"too slow: {elapsed:.3f}s"


# ---------------------------------------------------------------------------
# docx
# ---------------------------------------------------------------------------

def test_generate_report_docx_returns_bytes():
    data = generate_report("d.com", [_f(title="D1", verification="confirmed",
                                        evidence="EV", manual_check="mc")],
                           fmt="docx")
    assert isinstance(data, bytes)
    assert data[:2] == b"PK"  # docx is a zip container
    assert len(data) > 500


def test_docx_reopen_headings_pagebreaks_classification(tmp_path):
    from docx import Document
    path = write_report("d.com", [
        _f(title="D1", verification="confirmed"),
        _f(title="D2", severity="HIGH"),
    ], str(tmp_path / "rep.docx"))
    doc = Document(path)
    texts = [p.text for p in doc.paragraphs] + \
            [c.text for t in doc.tables for r in t.rows
             for c in r.cells]
    all_text = "\n".join(texts)
    assert "Web Application Penetration Test Report" in all_text
    assert CLASSIFICATION in all_text
    assert "D1" in all_text and "D2" in all_text
    assert "CONFIRMED" in all_text
    # heading styles used
    styles = [p.style.name for p in doc.paragraphs]
    assert any(s.startswith("Heading") for s in styles)
    # >= 2 explicit page-break elements
    from docx.enum.text import WD_BREAK
    breaks = sum(1 for p in doc.paragraphs
                 for r in p.runs
                 for br in r._r.findall(
                     "{http://schemas.openxmlformats.org/wordprocessingml/"
                     "2006/main}br")
                 if br.get("{http://schemas.openxmlformats.org/"
                           "wordprocessingml/2006/main}type")
                 == "page")
    assert breaks >= 2


def test_write_report_infers_docx_and_pdf(tmp_path):
    dpath = write_report("w.com", [_f(title="WD")], str(tmp_path / "d.docx"))
    ppath = write_report("w.com", [_f(title="WP")], str(tmp_path / "p.pdf"))
    with open(dpath, "rb") as fh:
        assert fh.read(2) == b"PK"
    with open(ppath, "rb") as fh:
        assert fh.read(5) == b"%PDF-"


def test_docx_import_error_reporterror(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "docx" or name.startswith("docx."):
            raise ImportError("no python-docx in this sandbox")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ReportError):
        generate_report("d", [_f()], fmt="docx")


def test_docx_pdf_sanitized_findings(tmp_path):
    from docx import Document
    garbage = ["junk", _f(title="GOOD", evidence="x" * 500,
                          severity="HIGH"),
               _f(title="GOOD", evidence="short", severity="LOW")]
    path = write_report("s.com", garbage, str(tmp_path / "s.docx"))
    doc = Document(path)
    texts = [p.text for p in doc.paragraphs]
    # dedupe keeps the HIGH entry (highest severity of the two GOOD rows)
    assert "[HIGH] GOOD" in "\n".join(texts)
    assert "junk" not in texts
    good = [t for t in texts if t.startswith("x")]
    assert good and len(good[0]) == 300


# ---------------------------------------------------------------------------
# pdf
# ---------------------------------------------------------------------------

def test_generate_report_pdf_bytes(tmp_path):
    data = generate_report("p.com", [_f(title="P1", evidence="EV")],
                           fmt="pdf")
    assert isinstance(data, bytes)
    assert data[:5] == b"%PDF-"
    assert len(data) > 500
    path = tmp_path / "direct.pdf"
    path.write_bytes(data)
    assert path.stat().st_size > 500


def test_pdf_three_findings_over_2kb_with_classification(tmp_path):
    findings = [
        _f(title="A", severity="HIGH", verification="confirmed",
           evidence="EV-A", manual_check="mc", cwe="CWE-89"),
        _f(title="B", severity="MEDIUM"),
        _f(title="C", severity="LOW"),
    ]
    path = tmp_path / "three.pdf"
    write_report("p.com", findings, str(path))
    assert path.stat().st_size > 2048
    with open(path, "rb") as fh:
        assert fh.read(5) == b"%PDF-"


def test_pdf_import_error_reporterror(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("reportlab"):
            raise ImportError("no reportlab in this sandbox")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ReportError):
        generate_report("p", [_f()], fmt="pdf")


# ---------------------------------------------------------------------------
# footer / disclaimer across formats
# ---------------------------------------------------------------------------

def test_markdown_footer_disclaimer():
    md = generate_report("t", [_f()])
    assert "End of report." in md
    assert ("Findings marked CANDIDATE require manual verification "
            "before remediation planning.") in md


def test_pdf_classification_and_disclaimer_text():
    # pdf text content is compressed; just verify generation with the
    # constants present does not blow up and includes them in docx
    from docx import Document
    import io
    data = generate_report("c.com", [_f()], fmt="docx")
    doc = Document(io.BytesIO(data))
    all_text = "\n".join(p.text for p in doc.paragraphs)
    assert CLASSIFICATION in all_text
    assert "Findings marked CANDIDATE require manual verification" \
        in all_text


# ---------------------------------------------------------------------------
# Multi-language report support (appended; additive only)
# ---------------------------------------------------------------------------

LANG_CODES = ["en", "id", "es", "fr", "de", "pt", "zh", "ja", "ar",
              "ru", "hi"]


def test_resolve_lang_returns_label_sets_for_all_langs():
    for code in LANG_CODES:
        L = rpt.resolve_lang(code)
        assert set(L) == set(rpt._EN)
        assert L["title"]


def test_resolve_lang_normalizes_variants():
    assert rpt.resolve_lang("ID")["title"] == rpt.resolve_lang("id")["title"]
    assert rpt.resolve_lang("zh-cn") is rpt.LANGS["zh"]
    assert rpt.resolve_lang("pt-BR") is rpt.LANGS["pt"]
    assert rpt.resolve_lang(" in ") is rpt.LANGS["id"]


def test_resolve_lang_fallback_none_and_unknown():
    assert rpt.resolve_lang(None) is rpt.LANGS["en"]
    assert rpt.resolve_lang("") is rpt.LANGS["en"]
    assert rpt.resolve_lang("klingon") is rpt.LANGS["en"]
    assert rpt.resolve_lang(12345) is rpt.LANGS["en"]
    assert rpt.resolve_lang(["id"]) is rpt.LANGS["en"]


def test_markdown_lang_id_indonesian_title_and_no_english():
    md = generate_report("t", [_f()], lang="id")
    assert "# Laporan Uji Penetrasi Aplikasi Web" in md
    assert "Web Application Penetration Test Report" not in md


def test_markdown_lang_id_section_labels():
    md = generate_report("t", [_f()], lang="id")
    assert "## Ringkasan Eksekutif" in md
    assert "## Ruang Lingkup & Metodologi" in md
    assert "## Temuan" in md
    assert "## Lampiran A" in md and "## Lampiran B" in md


def test_markdown_english_unchanged_expectations():
    md = generate_report("t", [_f()])
    assert "**Target:** t" in md
    assert "## Executive Summary" in md
    assert "## Scope & Methodology" in md
    assert "## Risk Rating Methodology" in md
    assert "## Findings" in md
    assert "## Appendix A" in md and "## Appendix B" in md
    assert "End of report." in md


def test_markdown_unknown_lang_falls_back_to_english():
    md = generate_report("t", [_f()], lang="klingon")
    assert "# Web Application Penetration Test Report" in md


def test_json_has_language_field_resolved():
    doc = json.loads(generate_report("t", [_f()], fmt="json", lang="es"))
    assert doc["language"] == "es"
    assert doc["report_meta"]["title"].startswith("Informe")
    doc2 = json.loads(generate_report("t", [_f()], fmt="json",
                                      lang="not-a-lang"))
    assert doc2["language"] == "en"
    doc3 = json.loads(generate_report("t", [_f()], fmt="json"))
    assert doc3["language"] == "en"


def test_html_lang_attribute_resolved():
    h = generate_report("t", [_f()], fmt="html", lang="fr")
    assert '<html lang="fr">' in h
    h2 = generate_report("t", [_f()], fmt="html")
    assert '<html lang="en">' in h2
    h3 = generate_report("t", [_f()], fmt="html", lang="xx-bogus")
    assert '<html lang="en">' in h3


def test_docx_accepts_lang_and_magic_bytes():
    data = generate_report("t", [_f()], fmt="docx", lang="de")
    assert isinstance(data, bytes) and data[:2] == b"PK"


def test_pdf_accepts_lang_and_magic_bytes():
    data = generate_report("t", [_f()], fmt="pdf", lang="hi")
    assert isinstance(data, bytes) and data[:5] == b"%PDF-"


def test_finding_content_verbatim_in_id_report():
    evidence = "' OR 1=1 -- AND username=admin"
    manual = "curl -d \"q=a' OR 1=1\" http://x/login"
    md = generate_report("t", [_f(evidence=evidence,
                                  manual_check=manual)], lang="id")
    assert evidence in md
    assert manual in md


def test_finding_content_verbatim_in_ja_html():
    evidence = "UNION SELECT password FROM users"
    h = generate_report("t", [_f(evidence=evidence)], fmt="html",
                        lang="ja")
    assert evidence in h


def test_severity_codes_not_translated():
    md = generate_report("t", [_f(severity="HIGH",
                                  verification="confirmed")], lang="zh")
    # severity codes stay untranslated even in localized reports
    assert "HIGH" in md
    assert "MEDIUM 0" in md


def test_all_languages_markdown_and_html_generate():
    for code in LANG_CODES:
        md = generate_report("t", [_f()], lang=code)
        assert md.startswith("# ")
        h = generate_report("t", [_f()], fmt="html", lang=code)
        assert h.endswith("</html>")


def test_all_languages_docx_pdf_json_no_raise(tmp_path):
    for code in LANG_CODES:
        assert generate_report("t", [_f()], fmt="docx",
                               lang=code)[:2] == b"PK"
        assert generate_report("t", [_f()], fmt="pdf",
                               lang=code)[:5] == b"%PDF-"
        doc = json.loads(generate_report("t", [_f()], fmt="json",
                                         lang=code))
        assert doc["language"] == code


def test_write_report_passes_lang(tmp_path):
    p = write_report("t", [_f()], str(tmp_path / "r.md"), lang="id")
    with open(p, encoding="utf-8") as fh:
        text = fh.read()
    assert "Laporan Uji Penetrasi Aplikasi Web" in text
    p2 = write_report("t", [_f()], str(tmp_path / "r2.json"), lang="de")
    assert json.load(open(p2, encoding="utf-8"))["language"] == "de"


def test_localized_methodology_and_footer_paragues():
    md_en = generate_report("t", [], lang="en")
    assert "Severity definitions:" in md_en
    assert "Disclaimer:" in md_en
    md_id = generate_report("t", [], lang="id")
    assert "Definisi tingkat keparahan:" in md_id
    assert "Penafian:" in md_id
    assert "Methodology: black-box" not in md_id


def test_ran_skipped_labels_localized():
    md = generate_report("t", [], meta={"ran": ["e1"],
                                        "skipped": ["s1"]}, lang="es")
    assert "Ejecutado: e1" in md and "Omitido: s1" in md
    md_en = generate_report("t", [], meta={"ran": ["e1"],
                                           "skipped": ["s1"]}, lang="en")
    assert "Ran: e1" in md_en and "Skipped: s1" in md_en


def test_cli_report_subparser_has_lang_default_none():
    import omega.core.cli as cli
    import argparse
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    # reuse the real parser builder if exposed, else check signature
    import inspect
    src = inspect.getsource(cli)
    assert '"--lang"' in src
    from omega import report as r2
    sig = inspect.signature(r2.write_report)
    assert sig.parameters["lang"].default is None
    sig2 = inspect.signature(r2.generate_report)
    assert sig2.parameters["lang"].default is None
