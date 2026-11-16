"""omega/scanning/secondorder.py — second-order (stored) injection
probe (fusion suite name: ``secondorder``).

Pick 1-2 input endpoints (profile/settings/comment-ish paths from
``path_info``), submit a benign marker value (``omegasecond<rand>``)
through the form/param, then fetch OTHER pages (homepage, profile
view, list pages from path_info) looking for the marker echoed in a
DIFFERENT page — the stored-XSS/injection shape.

A HIGH candidate is reported ONLY when:
- a POST endpoint accepted the write (2xx status), and
- the marker appears in a DIFFERENT page's body (verified through
  ``claimcheck.validate_claim`` so the echo reproduces fetch-side).

Evidence includes both the write and the read location. Benign: the
marker is inert alphanumeric text. Never raises; budget-capped.
"""

from __future__ import annotations

import re
import secrets

from omega.scanning.claimcheck import validate_claim
from omega.scanning.deepchecks import Finding, default_fetch

__all__ = [
    "REQUEST_BUDGET",
    "WRITE_PATH_RE",
    "MARKER_PREFIX",
    "make_marker",
    "pick_write_paths",
    "run_secondorder",
]

REQUEST_BUDGET = 24

WRITE_PATH_RE = re.compile(
    r"profile|settings|comment|account|user|post|note|edit|update", re.I)

MARKER_PREFIX = "omegasecond"


def make_marker():
    """Unique benign marker: omegasecond<hex>."""
    return MARKER_PREFIX + secrets.token_hex(4)


def _text(body):
    if isinstance(body, bytes):
        return body.decode("latin-1", "replace")
    return str(body or "")


def _join(base, path):
    path = path if path.startswith("/") else "/" + path
    return base.rstrip("/") + path


def _form_fields(html):
    """Input names from the first <form> on the page (best effort)."""
    try:
        m = re.search(r"<form\b[^>]*>(.*?)</form>", html or "",
                      re.I | re.S)
        chunk = m.group(1) if m else (html or "")
        names = []
        for im in re.finditer(r"<input\b[^>]*>", chunk, re.I):
            nm = re.search(r'name\s*=\s*("([^"]*)"|\'([^\']*)\')',
                           im.group(0))
            name = (nm.group(2) or nm.group(3)) if nm else ""
            if name and name.lower() not in ("csrf", "csrf_token", "_token"):
                names.append(name)
        return names[:6]
    except Exception:
        return []


def pick_write_paths(path_info=None):
    """1-2 write-candidate paths from path_info (comment/profile-ish),
    plus defaults when nothing matches."""
    info = path_info or {}
    paths = [p for p in (info.get("paths") or [])
             if isinstance(p, str) and p.startswith("/")]
    writes = [p for p in paths if WRITE_PATH_RE.search(p)]
    if not writes:
        writes = []
    for default in ("/settings", "/profile"):
        if default not in writes:
            writes.append(default)
    return writes[:2]


def _read_paths(path_info, writes):
    """Pages to scan for the echoed marker: homepage + non-write
    path_info paths, capped."""
    info = path_info or {}
    reads = ["/"]
    for p in (info.get("paths") or []):
        if isinstance(p, str) and p.startswith("/") \
                and p not in writes and p not in reads:
            reads.append(p)
    return reads[:6]


def _validated(findings, base_url, fetch):
    """Keep only findings whose evidence reproduces via the claim
    gate. Never raises."""
    kept = []
    for f in findings:
        try:
            res = validate_claim(dict(f), fetch=fetch, base_url=base_url)
        except Exception:
            continue
        if res.get("validation") == "verified":
            f["verification_note"] = (
                str(f.get("verification_note") or "")
                + " [claim gate: verified]")
            kept.append(f)
    return kept


def run_secondorder(base_url, fetch=default_fetch, path_info=None,
                    gate=False):
    """Second-order (stored) injection suite. Returns a list of Finding
    dicts; never raises; budget-capped; claim-gate validated."""
    findings = []
    base = (base_url or "").rstrip("/")
    if not base:
        return findings
    budget = REQUEST_BUDGET
    writes = pick_write_paths(path_info)
    reads = _read_paths(path_info, writes)

    for wpath in writes:
        if budget <= 0:
            break
        wurl = _join(base, wpath)
        try:
            st0, _h0, b0 = fetch("GET", wurl)
        except Exception:
            continue
        budget -= 1
        if not (200 <= (st0 or 0) < 300):
            continue
        fields = _form_fields(_text(b0))
        if not fields:
            continue
        marker = make_marker()
        body = "&".join(
            "%s=%s" % (f, marker if i == 0 else "probe")
            for i, f in enumerate(fields))
        try:
            st1, _h1, b1 = fetch("POST", wurl, body=body)
        except Exception:
            continue
        budget -= 1
        # Only if the POST endpoint accepted the write
        if not (200 <= (st1 or 0) < 300):
            continue

        # fetch OTHER pages looking for the marker echoed elsewhere
        for rpath in reads:
            if budget <= 0:
                break
            rurl = _join(base, rpath)
            if rurl == wurl:
                continue
            try:
                st2, _h2, b2 = fetch("GET", rurl)
            except Exception:
                continue
            budget -= 1
            if not (200 <= (st2 or 0) < 300):
                continue
            if marker not in _text(b2):
                continue
            findings.append(Finding(
                title="Second-order marker echoed on a different page "
                      "(%s -> %s)" % (wpath, rpath),
                severity="high", verification="candidate",
                verification_note=(
                    "A benign marker value submitted to the write "
                    "endpoint %s (POST status %d) is echoed in the "
                    "body of a DIFFERENT page %s — the stored-"
                    "injection shape. The marker is inert "
                    "alphanumeric text ('%s'); HIGH candidate, "
                    "confirm rendering context manually."
                    % (wurl, st1, rurl, marker)),
                manual_check=(
                    "Re-submit the marker at %s and review where it "
                    "renders at %s (attribute/HTML context)." % (wurl,
                                                                 rurl)),
                location=rurl,
                evidence=marker,
                source="omega-secondorder/stored_echo"))
            break  # one echo per write endpoint is enough

    return _validated(findings, base, fetch)
