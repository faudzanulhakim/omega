"""omega/scanning/cvefeed.py — offline NVD CVE feed -> compact local index.

Parses the NVD JSON feed format (CVE JSON 1.1 single-file, e.g.
``nvdcve-1.1-recent.json``, and CVE JSON 2.0 single-file, e.g.
``nvdcve-2.0-recent.json``) stored LOCALLY at a path. NEVER fetches
the network itself: the operator downloads the feed. This keeps the
scanner fully offline/hermetic.

Build/refresh a compact local index (JSON at ~/.cache/omega/cve_index.json
or OMEGA_CVE_INDEX) with entries:

    {cve_id, product, version_ranges (start/end incl/excl),
     severity, summary (first 200 chars)}

Public API (called by brain capability ``scanning.cvefeed`` and usable
from cvexref-based flows WITHOUT touching cvexref.py):

    refresh(feed_path=None)   -> dict (never raises)
    lookup(product, version)  -> list of matching CVE dicts
    status()                  -> dict (counts, staleness days)

Rules: never raises on malformed feed content (skips bad items and
reports them in ``errors``); no network access of any kind.
"""

from __future__ import annotations

import datetime
import json
import os
import re

__all__ = [
    "index_path",
    "feed_path",
    "refresh",
    "lookup",
    "status",
    "load_index",
]

# One product entry per matched CPE product token:
#   {cve_id, product, version_ranges: [{start, end, start_incl, end_incl}],
#    severity, summary}
_SUMMARY_MAX = 200
_CPE_TOKEN_RE = re.compile(r"^cpe:/[aho]:[^:]+:([^:]+)")
_CPE23_RE = re.compile(r"^cpe:2\.3:[aho]:[^:]+:([^:]+)")


def index_path():
    """Compact index location: OMEGA_CVE_INDEX or ~/.cache/omega/."""
    env = os.environ.get("OMEGA_CVE_INDEX")
    if env:
        return env
    return os.path.join(os.path.expanduser("~"), ".cache", "omega",
                        "cve_index.json")


def feed_path():
    """Default local feed path: OMEGA_CVE_FEED or None."""
    return os.environ.get("OMEGA_CVE_FEED") or None


# --------------------------------------------------------------- parsing

def _summary_of(desc):
    """First-200-chars English description (JSON 1.1 or 2.0 shapes)."""
    value = ""
    if isinstance(desc, dict):
        for d in desc.get("description_data") or desc.get("descriptions") \
                or []:
            if isinstance(d, dict) and str(d.get("lang")) == "en":
                value = str(d.get("value") or "")
                break
    elif isinstance(desc, str):
        value = desc
    return value[:_SUMMARY_MAX]


def _severity_of(cve):
    """Lowercased base severity from CVSS v3/v2 blocks, else 'unknown'."""
    # JSON 2.0: metrics.cvssMetricV31/V30/V2 list of {cvssData: {...}}
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key) or []:
            sev = ((m.get("cvssData") or {}).get("baseSeverity"))
            if sev:
                return str(sev).lower()
    for m in metrics.get("cvssMetricV2") or []:
        sev = (m.get("baseSeverity")
               or (m.get("cvssData") or {}).get("baseSeverity")
               or m.get("severity"))
        if sev:
            return str(sev).lower()
    # JSON 1.1: impact.baseMetricV3.cvssV3.baseSeverity / baseMetricV2
    impact = cve.get("impact") or {}
    v3 = impact.get("baseMetricV3") or {}
    sev = (v3.get("cvssV3") or {}).get("baseSeverity")
    if sev:
        return str(sev).lower()
    v2 = impact.get("baseMetricV2") or {}
    if v2.get("severity"):
        return str(v2["severity"]).lower()
    return "unknown"


def _product_tokens(cve):
    """Distinct lowercase CPE product tokens for a CVE record."""
    tokens = []

    def _match(criteria):
        if not isinstance(criteria, str):
            return
        m = _CPE23_RE.match(criteria) or _CPE_TOKEN_RE.match(criteria)
        if m and m.group(1):
            tokens.append(m.group(1).lower().replace("_", " ").strip())

    # JSON 1.1: cve.affects.vendor[].product[].product_name
    for vendor in (((cve.get("affects") or {}).get("vendor") or {})
                   .get("vendor_data") or []):
        for prod in ((vendor.get("product") or {}).get("product_data")
                     or []):
            name = str(prod.get("product_name") or "").strip()
            if name:
                tokens.append(name.lower())

    # JSON 2.0 (and 1.1 configurations blocks): cpeMatch criteria strings
    for cfg in cve.get("configurations") or []:
        for node in (cfg.get("nodes") or []):
            for cpe in (node.get("cpeMatch") or []):
                _match(cpe.get("criteria"))
    seen, out = set(), []
    for t in tokens:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _ranges_of(cve):
    """Version ranges [{start, end, start_incl, end_incl}] for a record.

    JSON 2.0 carries explicit versionStart*/versionEnd* keys on cpeMatch;
    JSON 1.1 has none, so a bare product version string becomes a single
    inclusive point range.
    """
    ranges = []
    for cfg in cve.get("configurations") or []:
        for node in (cfg.get("nodes") or []):
            for cpe in (node.get("cpeMatch") or []):
                if not isinstance(cpe, dict):
                    continue
                start = cpe.get("versionStartIncluding")
                start_excl = cpe.get("versionStartExcluding")
                end = cpe.get("versionEndIncluding")
                end_excl = cpe.get("versionEndExcluding")
                bare = _cpe23_version(cpe.get("criteria"))
                if start or start_excl or end or end_excl:
                    ranges.append({
                        "start": start or None,
                        "end": end or None,
                        "start_excl": start_excl or None,
                        "end_excl": end_excl or None,
                        "start_incl": bool(start),
                        "end_incl": bool(end),
                    })
                elif bare:
                    ranges.append({"start": bare, "end": bare,
                                   "start_incl": True, "end_incl": True})
    return ranges


def _cpe23_version(criteria):
    """Version token (field 5) of a cpe:2.3 criteria string, or None."""
    if not isinstance(criteria, str):
        return None
    parts = criteria.split(":")
    if len(parts) > 5 and parts[4]:
        return parts[4]
    return None


def _entries_from_json_1_1(doc, errors):
    """Flatten CVE_Items from an NVD JSON 1.1 single-file feed."""
    out = []
    for item in doc.get("CVE_Items") or []:
        try:
            cve = item.get("cve") or {}
            cid = str((cve.get("CVE_data_meta") or {}).get("ID") or "")
            if not cid.startswith("CVE-"):
                raise ValueError("missing CVE id")
            ranges = _ranges_of(cve)
            for product in _product_tokens(cve):
                out.append({
                    "cve_id": cid,
                    "product": product,
                    "version_ranges": ranges,
                    "severity": _severity_of(cve),
                    "summary": _summary_of(cve.get("description")),
                })
            if not ranges:
                # keep the record discoverable per product with open range
                for product in _product_tokens(cve):
                    for e in out:
                        if e["cve_id"] == cid and e["product"] == product \
                                and not e["version_ranges"]:
                            e["version_ranges"] = []
        except Exception as exc:  # never raise on malformed items
            errors.append("item skipped: %s" % exc)
    return out


def _entries_from_json_2_0(doc, errors):
    """Flatten vulnerabilities[] from an NVD CVE JSON 2.0 feed."""
    out = []
    for item in doc.get("vulnerabilities") or []:
        try:
            cve = item.get("cve") or item or {}
            cid = str(cve.get("id") or "")
            if not cid.startswith("CVE-"):
                raise ValueError("missing CVE id")
            ranges = _ranges_of(cve)
            for product in _product_tokens(cve):
                out.append({
                    "cve_id": cid,
                    "product": product,
                    "version_ranges": ranges,
                    "severity": _severity_of(cve),
                    "summary": _summary_of(cve.get("descriptions")
                                           or cve.get("description")),
                })
        except Exception as exc:  # never raise on malformed items
            errors.append("item skipped: %s" % exc)
    return out


# ------------------------------------------------------------ versioning

def _vtup(v):
    """Dotted-numeric sort key ('2.4.49' -> (2, 4, 49)). Non-numeric
    segments are ignored; empty -> empty tuple (sorts first)."""
    if not v:
        return ()
    return tuple(int(x) for x in re.findall(r"\d+", str(v))) or ()


def _version_in(v, rng):
    """True when version v falls in one version_range dict."""
    t = _vtup(v)
    if not t:
        return False
    lo = rng.get("start")
    lo_excl = rng.get("start_excl")
    hi = rng.get("end")
    hi_excl = rng.get("end_excl")
    if lo_excl:
        if not (_vtup(lo_excl) < t):
            return False
    elif lo and rng.get("start_incl", True):
        if not (_vtup(lo) <= t):
            return False
    if hi_excl:
        if not (t < _vtup(hi_excl)):
            return False
    elif hi and rng.get("end_incl", True):
        if not (t <= _vtup(hi)):
            return False
    if not (lo or lo_excl or hi or hi_excl):
        return False
    return True


# ----------------------------------------------------------- public API

def load_index(path=None):
    """Load the compact index, or an empty structure if absent/broken."""
    path = path or index_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        if not isinstance(doc, dict):
            return {"generated": None, "source_feed": None, "entries": []}
        if not isinstance(doc.get("entries"), list):
            doc["entries"] = []
        return doc
    except Exception:
        return {"generated": None, "source_feed": None, "entries": []}


def refresh(feed_path_arg=None, index_out=None):
    """Parse the local NVD feed and (re)build the compact index.

    Returns a summary dict and NEVER raises: unreadable/malformed feeds
    yield {"ok": False, "error": ...}. No network access — the operator
    supplies the downloaded feed file.
    """
    src = feed_path_arg or feed_path()
    if not src:
        return {"ok": False,
                "error": "no feed: pass --feed <path> or set "
                         "OMEGA_CVE_FEED"}
    try:
        with open(src, "r", encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
        if not isinstance(doc, dict):
            raise ValueError("feed root is not a JSON object")
    except Exception as exc:
        return {"ok": False, "error": "cannot read feed %r: %s"
                                      % (src, exc)}

    errors = []
    if "CVE_Items" in doc:
        entries = _entries_from_json_1_1(doc, errors)
    elif "vulnerabilities" in doc:
        entries = _entries_from_json_2_0(doc, errors)
    else:
        return {"ok": False, "error": "unrecognized NVD feed format "
                                      "(no CVE_Items / vulnerabilities)"}

    out_path = index_out or index_path()
    doc_out = {
        "generated": datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_feed": os.path.abspath(src),
        "entries": entries,
    }
    try:
        d = os.path.dirname(out_path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(doc_out, fh)
    except OSError as exc:
        return {"ok": False, "error": "cannot write index %r: %s"
                                      % (out_path, exc), "entries": len(entries)}

    cves = sorted({e["cve_id"] for e in entries})
    return {"ok": True, "entries": len(entries), "cves": len(cves),
            "products": len({e["product"] for e in entries}),
            "errors": errors, "index": out_path, "feed": src}


def lookup(product, version=None, path=None):
    """Index lookups for a product token + optional version string.

    ``product`` is matched loosely (substring, case-insensitive) against
    the indexed CPE product tokens; when ``version`` is given only CVEs
    whose version range contains it are returned. Returns a list of
    {cve_id, product, severity, summary, version_range}. Never raises.
    """
    doc = load_index(path)
    low = str(product or "").lower()
    out = []
    for e in doc.get("entries") or []:
        if low not in str(e.get("product") or "").lower():
            continue
        ranges = e.get("version_ranges") or []
        if version:
            for rng in ranges:
                if _version_in(version, rng):
                    out.append({
                        "cve_id": e.get("cve_id"),
                        "product": e.get("product"),
                        "severity": e.get("severity"),
                        "summary": e.get("summary"),
                        "version_range": rng,
                    })
        else:
            out.append({
                "cve_id": e.get("cve_id"),
                "product": e.get("product"),
                "severity": e.get("severity"),
                "summary": e.get("summary"),
                "version_range": ranges[0] if ranges else None,
            })
    return out


def status(path=None):
    """Index health: entry/CVE counts and staleness in whole days.

    Never raises; a missing or unreadable index reports
    {'present': False, ...} with empty counts.
    """
    path = path or index_path()
    doc = load_index(path)
    entries = doc.get("entries") or []
    cves = sorted({e.get("cve_id") for e in entries if e.get("cve_id")})
    stale_days = None
    generated = doc.get("generated")
    if generated:
        try:
            gen = datetime.datetime.strptime(
                str(generated), "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=datetime.timezone.utc)
            stale_days = max(0, (datetime.datetime.now(
                datetime.timezone.utc) - gen).days)
        except ValueError:
            stale_days = None
    return {
        "present": bool(entries) and doc.get("generated") is not None,
        "entries": len(entries),
        "cves": len(cves),
        "products": len({e.get("product") for e in entries
                         if e.get("product")}),
        "staleness_days": stale_days,
        "generated": generated,
        "source_feed": doc.get("source_feed"),
        "index_path": path,
    }
