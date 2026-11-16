"""omega/reporting/dojo.py — DefectDojo-compatible OMEGA findings export.

Converts OMEGA findings (dicts shaped {id, title, severity, verification,
cwe, cvss, evidence, manual_check, location, source}) into:

* DefectDojo "Generic Findings Import" CSV — columns:
  Title,Severity,Description,Mitigation,Impact,References,CVE,Active,
  Verified,Date
* DefectDojo engagement JSON — {test_type: 'OMEGA Scan', findings: [...]}
  using the canonical Dojo field names (title, severity, description,
  mitigation, impact, references, cve, active, verified, cwe, date).

Mappings:
  severity: CRITICAL/HIGH/MEDIUM/LOW/INFO -> Critical/High/Medium/Low/Info
  verification: 'confirmed' -> Verified=true; anything else
                (incl. 'candidate') -> Verified=false
  cwe: 'CWE-79' or 79 -> numeric 79 (Dojo numeric CWE field)

Entry point ``export_dojo(findings, fmt='csv'|'json', path=None)`` writes
the file and returns its path — or an {'error': ...} dict. NEVER raises.
"""

from __future__ import annotations

import csv
import datetime
import json
import os

__all__ = [
    "SEVERITY_MAP",
    "map_severity",
    "map_verified",
    "map_cwe",
    "to_csv_rows",
    "to_dojo_json",
    "export_dojo",
]

SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
    # already-Dojo-style inputs pass through unchanged
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Info": "Info",
}

CSV_COLUMNS = ["Title", "Severity", "Description", "Mitigation", "Impact",
               "References", "CVE", "Active", "Verified", "Date"]

_CVE_RE = None  # compiled lazily


def map_severity(sev):
    """OMEGA severity -> Dojo severity (unknown values -> 'Info')."""
    return SEVERITY_MAP.get(str(sev or "").strip().upper(),
                            SEVERITY_MAP.get(str(sev or "").strip(),
                                             "Info"))


def map_verified(verification):
    """Dojo Verified flag: only 'confirmed' is verified."""
    return str(verification or "").strip().lower() == "confirmed"


def map_cwe(value):
    """'CWE-79' / 79 / '79' -> numeric int, or None when unmappable."""
    try:
        if isinstance(value, int):
            return value
        s = str(value or "").strip()
        if s.lower().startswith("cwe-"):
            s = s[4:]
        return int(s) if s.isdigit() else None
    except (ValueError, TypeError):
        return None


def _first_cve(text):
    """First CVE-... token in free text, or None."""
    import re
    m = re.search(r"CVE-\d{4}-\d{4,}", str(text or ""))
    return m.group(0) if m else None


def _refs(find):
    """Reference links: evidence.url / evidence.urls / location hint."""
    ev = find.get("evidence") or {}
    refs = []
    if isinstance(ev, dict):
        if ev.get("url"):
            refs.append(str(ev["url"]))
        for u in ev.get("urls") or []:
            refs.append(str(u))
    return "; ".join(r for r in refs if r)


def _desc(find):
    """Description text: verification_note / evidence.why / evidence."""
    ev = find.get("evidence")
    if isinstance(ev, dict):
        ev = ev.get("why") or json.dumps(ev, default=str)
    parts = [str(find.get("verification_note") or ""),
             str(ev or ""), str(find.get("source") or "")]
    return "\n".join(p for p in parts if p)


def _row(find, date):
    """One CSV row (list of strings) for a finding dict."""
    title = str(find.get("title") or "Untitled finding")
    sev = map_severity(find.get("severity"))
    desc = _desc(find)
    mitigation = str(find.get("manual_check") or "")
    impact = str(find.get("verification_note") or desc or "")
    refs = _refs(find)
    cve = str(find.get("cve") or find.get("id") or "")
    if not cve.startswith("CVE-"):
        cve = _first_cve(title + " " + desc + " " + impact) or ""
    verified = map_verified(find.get("verification"))
    return [title, sev, desc, mitigation, impact, refs, cve,
            "true", "true" if verified else "false", date]


def to_csv_rows(findings, date=None):
    """CSV rows for findings: header row + one row per finding."""
    date = date or datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y-%m-%d")
    rows = [list(CSV_COLUMNS)]
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        rows.append(_row(f, date))
    return rows


def to_dojo_json(findings, date=None, test_type="OMEGA Scan"):
    """DefectDojo engagement JSON dict for findings."""
    date = date or datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y-%m-%d")
    dojo_findings = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        title = str(f.get("title") or "Untitled finding")
        desc = _desc(f)
        cve = str(f.get("cve") or "")
        if not cve.startswith("CVE-"):
            cve = _first_cve(title + " " + desc) or ""
        dojo_findings.append({
            "title": title,
            "severity": map_severity(f.get("severity")),
            "description": desc,
            "mitigation": str(f.get("manual_check") or ""),
            "impact": str(f.get("verification_note") or ""),
            "references": _refs(f),
            "cve": cve,
            "active": True,
            "verified": map_verified(f.get("verification")),
            "cwe": map_cwe(f.get("cwe")),
            "cvssv3": f.get("cvss") if isinstance(f.get("cvss"),
                                                  (int, float)) else None,
            "date": date,
        })
    return {"test_type": test_type, "findings": dojo_findings}


def export_dojo(findings, fmt="csv", path=None):
    """Write OMEGA findings as a DefectDojo import file; return the path.

    ``fmt`` is 'csv' (Generic Findings Import CSV) or 'json' (engagement
    JSON). ``path=None`` writes next to the caller into the current
    directory as omega-dojo-<timestamp>.<ext>. NEVER raises: on any
    problem returns {'error': '...'} instead of a path string.
    """
    try:
        fmt_l = str(fmt or "csv").lower()
        if fmt_l not in ("csv", "json"):
            return {"error": "unknown dojo format %r (use csv|json)"
                             % fmt}
        if not isinstance(findings, (list, tuple)):
            return {"error": "findings must be a list, got %s"
                             % type(findings).__name__}
        if fmt_l == "csv":
            rows = to_csv_rows(findings)
            payload = None
        else:
            payload = json.dumps(to_dojo_json(findings), indent=2,
                                 default=str)
        out = path or ("omega-dojo-%s.%s" % (
            datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y%m%dT%H%M%S"), fmt_l))
        d = os.path.dirname(out)
        if d:
            os.makedirs(d, exist_ok=True)
        if fmt_l == "csv":
            with open(out, "w", encoding="utf-8", newline="") as fh:
                csv.writer(fh).writerows(rows)
        else:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(payload)
        return out
    except Exception as exc:  # never raise
        return {"error": "dojo export failed: %s" % exc}
