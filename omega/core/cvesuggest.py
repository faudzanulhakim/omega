"""omega/core/cvesuggest — local CVE suggestion from detected stack.

Reads the tech stack detected by techprof/frameworks and looks up the
OFFLINE NVD feed (omega.scanning.cvefeed) for version-matched CVEs.
Suggestions are leads for the operator — never auto-exploited.
"""
import re

from omega.scanning.cvefeed import lookup

__all__ = ["extract_versions", "suggest_cves", "narrate"]


def extract_versions(text):
    """Pull (product, version) pairs from tech strings like
    'nginx/1.18.0', 'Jenkins 2.343', 'Apache/2.4.49'."""
    out = []
    for m in re.finditer(
            r"([A-Za-z][A-Za-z0-9._-]{1,24})[/ ]v?(\d+\.\d+(?:\.\d+)?)",
            str(text or "")):
        product = m.group(1).lower()
        if product in ("http", "https", "www", "com", "net", "org"):
            continue
        out.append((product, m.group(2)))
    seen, dedup = set(), []
    for p, v in out:
        if (p, v) not in seen:
            seen.add((p, v))
            dedup.append((p, v))
    return dedup


def suggest_cves(text, max_per_product=5):
    """Version-matched CVE leads for every detected product."""
    leads = []
    for product, version in extract_versions(text):
        try:
            res = lookup(product, version)
        except Exception:
            res = None
        entries = (res or {}).get("cves") or \
            (res or {}).get("results") or []
        for cve in entries[:max_per_product]:
            if isinstance(cve, str):
                leads.append({"product": product, "version": version,
                              "cve": cve, "summary": ""})
            elif isinstance(cve, dict):
                leads.append({
                    "product": product, "version": version,
                    "cve": cve.get("id") or cve.get("cve") or "?",
                    "summary": str(cve.get("summary") or
                                   cve.get("description") or "")[:200],
                    "severity": cve.get("severity") or ""})
    return leads


def narrate(leads):
    if not leads:
        return "cvesuggest: no version-matched CVEs in the offline feed"
    return "cvesuggest: %d lead(s): %s" % (
        len(leads), "; ".join("%s (%s %s)" % (l["cve"], l["product"],
                                              l["version"])
                              for l in leads[:5]))


def findings_from_leads(leads, target):
    """Leads -> candidate findings for the operator to review."""
    out = []
    for l in leads or []:
        out.append({
            "title": "possible known-vulnerable stack: %s %s -> %s"
                     % (l["product"], l["version"], l["cve"]),
            "severity": "HIGH",
            "verification": "candidate",
            "source": "cvesuggest",
            "evidence": l.get("summary") or "version match only — no "
                        "exploitation was attempted",
            "location": target,
            "manual_check": "confirm the running version from the "
                            "server yourself, then review %s impact"
                            % l["cve"],
        })
    return out
