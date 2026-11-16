"""omega/scanning/libcve.py — client library fingerprint -> CVE lookup
(fusion suite name: ``libcve``).

Fetches JS assets referenced in the homepage plus path_info pages
(bounded at 10 pages / 10 assets) and regex-fingerprints known client
libraries (jquery, angular 1.x, react, lodash, moment, bootstrap, vue)
from version strings, sourcemap comments and page data. Each
(product, version) pair is matched against the local offline CVE index
via omega.scanning.cvefeed.lookup; a finding's severity comes from the
CVE record and verification is ``signature`` (the offline index is the
ground truth). When no index is present/stale, a single info note
records the versions found without CVE correlation. Never raises;
GET-only; bounded.
"""

from __future__ import annotations

import re
import urllib.parse

from omega.scanning.deepchecks import default_fetch

__all__ = [
    "Finding",
    "LIB_SIGNATURES",
    "SCRIPT_SRC_RE",
    "run_libcve",
]

MAX_PAGES = 10
MAX_ASSETS = 10
MAX_FINDINGS = 8

# (product, url/body version regex) — angular pinned to 1.x only.
LIB_SIGNATURES = (
    ("jquery", re.compile(
        r"jquery[.\-/_ ]v?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("angular", re.compile(
        r"angular[.\-/_ ]v?(1\.\d+(?:\.\d+)?)", re.I)),
    ("react", re.compile(
        r"react[\-./_ ]dom?[\-./_ ]v?(\d+\.\d+\.\d+)"
        r"|react[.\-/_ ]v?(\d+\.\d+\.\d+)", re.I)),
    ("lodash", re.compile(
        r"lodash[.\-/_ ]v?(\d+\.\d+\.\d+)", re.I)),
    ("moment", re.compile(
        r"moment[.\-/_ ]v?(\d+\.\d+\.\d+)", re.I)),
    ("bootstrap", re.compile(
        r"bootstrap[.\-/_ ]v?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("vue", re.compile(
        r"vue[.\-/_ ]v?(\d+\.\d+(?:\.\d+)?)", re.I)),
)
SCRIPT_SRC_RE = re.compile(
    r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
SOURCEMAP_RE = re.compile(r"sourceMappingURL=[^\s]+", re.I)

SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")


class Finding(dict):
    """ENGINE-convention finding dict (signature verification)."""

    def __init__(self, title, severity, verification, verification_note,
                 manual_check, location, evidence, source,
                 confidence="medium"):
        super().__init__(
            title=title,
            severity=severity,
            confidence=confidence,
            verification=verification,
            verification_note=verification_note,
            manual_check=manual_check,
            location=location,
            evidence=str(evidence)[:300],
            source=source,
        )


def _text(body):
    if isinstance(body, bytes):
        return body.decode("latin-1")
    return str(body or "")


def _req(fetch, url):
    try:
        st, _h, raw = fetch("GET", url)
        return st, _text(raw)
    except Exception:
        return None


def _page_urls(base_url, path_info):
    pages = ["/"]
    info = path_info if isinstance(path_info, dict) else {}
    for p in info.get("paths") or []:
        p = str(p)
        if p and p not in pages:
            pages.append(p)
    return pages[:MAX_PAGES]


def _asset_urls(base_url, page_bodies):
    base = base_url.rstrip("/")
    urls = []
    for body in page_bodies:
        for src in SCRIPT_SRC_RE.findall(body):
            if src.startswith("//"):
                src = "http:" + src
            if src.startswith(("http://", "https://")):
                if not src.startswith(base):
                    continue  # third-party assets are not fetched
            else:
                src = base + (src if src.startswith("/") else "/" + src)
            src = src.split("?")[0]
            if src not in urls:
                urls.append(src)
    return urls[:MAX_ASSETS]


def _fingerprint(text):
    """-> {(product, version)} found in a page/asset body (+ URL)."""
    hits = {}
    for product, rx in LIB_SIGNATURES:
        m = rx.search(text)
        if not m:
            continue
        version = next((g for g in m.groups() if g), None)
        if version:
            hits[(product, version)] = True
    return hits


def _lookup(product, version):
    """Offline CVE lookup; returns (cves, index_present)."""
    try:
        from omega.scanning import cvefeed
        cves = cvefeed.lookup(product, version) or []
        try:
            present = bool(cvefeed.status().get("present"))
        except Exception:
            present = bool(cves)
        return cves, present
    except Exception:
        return [], False


def run_libcve(base_url, fetch=default_fetch, path_info=None, gate=False):
    """Fingerprint client libraries and correlate with the offline CVE
    index. Returns a list of Finding dicts; never raises."""
    out = []
    base = base_url if "://" in base_url else "http://" + base_url
    try:
        page_bodies, page_urls = [], []
        for page in _page_urls(base, path_info):
            if len(page_bodies) >= MAX_PAGES:
                break
            res = _req(fetch, base.rstrip("/") + page)
            if res and res[0] == 200:
                page_bodies.append(res[1])
                page_urls.append(base.rstrip("/") + page)

        asset_bodies = []
        for asset in _asset_urls(base, page_bodies):
            if len(asset_bodies) >= MAX_ASSETS:
                break
            res = _req(fetch, asset)
            if res and res[0] == 200:
                asset_bodies.append(res[1])

        hits = {}
        for body in page_bodies + asset_bodies:
            hits.update(_fingerprint(body))
        for asset in _asset_urls(base, page_bodies):
            hits.update(_fingerprint(asset))
        if not hits:
            return out

        index_present = None
        missing_note_done = False
        for (product, version) in sorted(hits):
            if len(out) >= MAX_FINDINGS:
                break
            cves, present = _lookup(product, version)
            if index_present is None:
                index_present = present
            if cves:
                for cve in cves[:MAX_FINDINGS - len(out)]:
                    sev = str(cve.get("severity") or "unknown").lower()
                    if sev not in SEVERITY_ORDER:
                        sev = "medium"
                    out.append(Finding(
                        title="Vulnerable client library: %s %s (%s)"
                              % (product, version, cve.get("cve_id")),
                        severity=sev, verification="signature",
                        verification_note=(
                            "%s %s fingerprinted in served JS matches "
                            "offline CVE index entry %s (severity %s): "
                            "%s The local CVE index is the offline "
                            "ground truth; confirm the exact bundle "
                            "actually exposes the affected code path."
                            % (product, version, cve.get("cve_id"), sev,
                               (cve.get("summary") or ""))[:300]),
                        manual_check="curl -sS -I <asset url>",
                        location=base, evidence="%s %s" % (product,
                                                           version),
                        source="omega-libcve", confidence="medium"))
            elif not present and not missing_note_done:
                missing_note_done = True
                out.append(Finding(
                    title="Client library versions found but local CVE "
                          "index missing/stale",
                    severity="info", verification="candidate",
                    verification_note=(
                        "Fingerprinted %s but no local CVE index is "
                        "present (build one with omega.scanning.cvefeed."
                        "refresh against an NVD feed). Versions are "
                        "recorded without CVE correlation."
                        % ", ".join("%s %s" % kv
                                    for kv in sorted(hits))[:200]),
                    manual_check="OMEGA_CVE_INDEX=<path>",
                    location=base,
                    evidence=", ".join("%s %s" % kv
                                       for kv in sorted(hits))[:300],
                    source="omega-libcve", confidence="low"))
    except Exception:
        pass
    return out

