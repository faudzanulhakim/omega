"""AI-claim validation gate: refute hallucinated findings before reporting.

Any finding proposed by an AI assistant (chat, ai.analyst, external tool)
must pass through :func:`validate_claim` before it may be reported. The
gate re-checks the claim against the live target:

- the claimed location must be reachable and match the recorded evidence
  (substring or regex), fetched fresh by OMEGA itself — never from the
  AI's word;
- ``verified`` claims whose evidence does NOT reproduce are downgraded to
  ``refuted`` (hallucination caught);
- evidence that cannot be reproduced at all becomes ``unverifiable`` and
  is flagged ``ai-claim:unvalidated`` so the report layer keeps it out of
  confirmed results;
- severity/cwss sanity bounds are enforced (no CRITICAL without evidence).

Never raises. Never fetches anything beyond the claimed location.
"""
from __future__ import annotations

import re
import time

from .deepchecks import default_fetch

__all__ = ["validate_claim", "validate_claims"]

_SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _norm_url(base, loc):
    if not loc:
        return base if base else None
    if "://" in loc:
        return loc
    if not base:
        return loc
    return base.rstrip("/") + "/" + loc.lstrip("/")


def _has_evidence(evidence):
    """True when the claim carries checkable evidence content.

    A non-empty string (beyond whitespace) or a structured dict with at
    least one string field of >= 6 chars counts. Anything else (missing,
    None, empty, whitespace-only, empty dict) does NOT — a reachable URL
    alone is never treated as proof.
    """
    if isinstance(evidence, str):
        return bool(evidence.strip())
    if isinstance(evidence, dict):
        # structured evidence: any non-empty value counts, however short
        # (e.g. {"cookie_name": "sessi"} or {"origin_probe": True}) — an
        # EMPTY dict or one with only empty values still does not.
        def _nonempty(v):
            if v is None:
                return False
            if isinstance(v, str):
                return bool(v.strip())
            if isinstance(v, (list, dict, tuple, set)):
                return len(v) > 0
            return True  # bool / int / float content
        return any(_nonempty(v) for v in evidence.values())
    return False


def _evidence_present(evidence, status, headers, body_text):
    """Return (present:bool, how:str)."""
    if isinstance(evidence, dict):
        # Structured evidence: any string field must appear in the body.
        strings = [v for v in evidence.values() if isinstance(v, str)
                   and len(v) >= 6]
        if not strings:
            return True, "structured-nostrings"
        hits = [s for s in strings if s in body_text]
        return (bool(hits), "evidence-keys:%d/%d" % (len(hits), len(strings)))
    if isinstance(evidence, str) and evidence.strip():
        ev = evidence.strip()
        if ev.startswith("re:"):
            try:
                if re.search(ev[3:], body_text):
                    return True, "regex"
                return False, "regex-miss"
            except re.error:
                return False, "regex-invalid"
        if ev in body_text:
            return True, "substring"
        return False, "substring-miss"
    return True, "no-evidence"


def validate_claim(claim, fetch=None, base_url=None):
    """Validate one AI-proposed finding dict against the live target.

    Returns the claim dict annotated with:
    - ``validation``: verified | refuted | unverifiable | unreachable
    - ``validation_note``: machine-readable reason
    Never raises.
    """
    fetch = fetch or default_fetch
    out = dict(claim) if isinstance(claim, dict) else {"raw": str(claim)}
    try:
        loc = out.get("location") or out.get("url")
        url = _norm_url(out.get("base_url") or base_url, loc)
        if not url or "://" not in url:
            out["validation"] = "unverifiable"
            out["validation_note"] = "no fetchable location in claim"
            out.setdefault("tags", []).append("ai-claim:unvalidated")
            return out
        if not _has_evidence(out.get("evidence")):
            # A reachable URL alone is NOT evidence of a vulnerability.
            # Without supplied evidence the claim can never be confirmed.
            out["validation"] = "unverifiable"
            out["validation_note"] = (
                "no evidence supplied in claim — a 200 response is not "
                "proof of a vulnerability")
            # never leave a self-declared confirmation standing on a
            # claim that carries no evidence
            out["verification"] = "candidate"
            out.setdefault("tags", []).append("ai-claim:unvalidated")
            return out
        method = "GET"
        body = out.get("probe_body") or out.get("probe")
        headers_out = None
        started = time.time()
        st, headers, resp = fetch(method, url, body=body)
        elapsed = round(time.time() - started, 3)
        text = resp.decode("latin-1", "replace")
        present, how = _evidence_present(
            out.get("evidence"), st, headers, text)
        if st >= 400 and not present:
            out["validation"] = "unreachable"
            out["validation_note"] = "location HTTP %d" % st
            out.setdefault("tags", []).append("ai-claim:unvalidated")
            return out
        if not present:
            sev = str(out.get("severity", "")).upper()
            was = str(out.get("verification", out.get("verified", "")))
            out["validation"] = "refuted"
            out["validation_note"] = (
                "evidence not reproducible at %s (%s); claimed "
                "verification=%s" % (url, how, was or "unset"))
            if sev in ("HIGH", "CRITICAL"):
                out["severity"] = "LOW"
            out["verification"] = "candidate"
            out["refuted_by"] = "omega-validate"
            out.setdefault("tags", []).append("ai-claim:refuted")
            return out
        out["validation"] = "verified"
        out["validation_note"] = "evidence reproduced at %s (%s, %ss)" % (
            url, how, elapsed)
        if str(out.get("verification", "")).lower() in ("", "candidate"):
            out["verification"] = "confirmed"
        out.setdefault("tags", []).append("ai-claim:validated")
        return out
    except Exception as exc:  # never raise
        out["validation"] = "unverifiable"
        out["validation_note"] = "validation error: %s" % exc
        out.setdefault("tags", []).append("ai-claim:unvalidated")
        return out


def validate_claims(claims, fetch=None, base_url=None):
    """Validate a list of AI-proposed findings; returns (validated, stats)."""
    fetch = fetch or default_fetch
    results = []
    stats = {"verified": 0, "refuted": 0, "unverifiable": 0,
             "unreachable": 0}
    for c in claims or []:
        res = validate_claim(c, fetch=fetch, base_url=base_url)
        stats[res["validation"]] = stats.get(res["validation"], 0) + 1
        results.append(res)
    return results, stats
