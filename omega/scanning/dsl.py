"""omega/dsl.py — user-writable check DSL (YAML mini-templates).

Lets the user add custom checks WITHOUT code: a YAML file defines
checks with a small schema (id / title / severity + a requests list of
method / path / headers, each with an expect block) and verdict rules.

Verdict semantics (all-conditions):
  * confirmed  — ALL expects of ALL requests matched AND the
                 diff_vs_baseline condition (when any request sets
                 diff_vs_baseline: true) is satisfied.
  * candidate  — ANY expect matched, but not all conditions.
  * nothing    — no expect matched.
Validation errors (bad YAML, missing id, unknown method, bad expect
key, ...) cause the check to be SKIPPED with a reason, never a crash.

Findings use the ENGINE convention via omega.deepchecks.Finding,
source=omega-dsl/<id>. Only GET/HEAD/OPTIONS/POST-safe methods are
sent; requests are rate-capped by ``budget`` (max requests).
"""

from __future__ import annotations

import re
import yaml

__all__ = [
    "ALLOWED_METHODS",
    "Finding",
    "default_yaml_path",
    "load_checks",
    "run_dsl_checks",
]

from omega.deepchecks import Finding
from omega.probes import allowlist_ok

ALLOWED_METHODS = ("GET", "HEAD", "OPTIONS")
MAX_EXPECT_KEYS = ("status", "body_contains", "body_regex",
                   "header_contains", "diff_vs_baseline")

DEFAULT_SEVERITIES = ("info", "low", "medium", "high")


def default_yaml_path():
    import os
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "dsl_default.yaml")


# ------------------------------------------------------------------ loading


def _validate_check(raw, index):
    """Return (check, None) or (None, reason)."""
    if not isinstance(raw, dict):
        return None, "check #%d is not a mapping" % index
    cid = raw.get("id")
    if not cid or not re.match(r"^[a-z0-9_-]{2,40}$", str(cid)):
        return None, "check #%d has an invalid or missing 'id'" % index
    title = raw.get("title") or str(cid)
    severity = str(raw.get("severity", "info")).lower()
    if severity not in DEFAULT_SEVERITIES:
        return None, "check %s: unknown severity %r" % (cid, severity)
    reqs = raw.get("requests")
    if not isinstance(reqs, list) or not reqs:
        return None, "check %s: 'requests' must be a non-empty list" % cid
    clean_reqs = []
    for i, r in enumerate(reqs):
        if not isinstance(r, dict):
            return None, "check %s: request #%d is not a mapping" % (cid, i)
        method = str(r.get("method", "GET")).upper()
        if method not in ALLOWED_METHODS:
            return None, ("check %s: request #%d method %r not allowed "
                          "(%s)" % (cid, i, method, "/".join(ALLOWED_METHODS)))
        path = r.get("path", "/")
        if not isinstance(path, str) or not path.startswith("/"):
            return None, "check %s: request #%d path must start with /" % (
                cid, i)
        headers = r.get("headers") or {}
        if not isinstance(headers, dict):
            return None, "check %s: request #%d headers must be a mapping" % (
                cid, i)
        expect = r.get("expect") or {}
        if not isinstance(expect, dict):
            return None, "check %s: request #%d expect must be a mapping" % (
                cid, i)
        for k in expect:
            if k not in MAX_EXPECT_KEYS:
                return None, ("check %s: request #%d unknown expect key "
                              "%r (allowed: %s)"
                              % (cid, i, k, ", ".join(MAX_EXPECT_KEYS)))
        clean_reqs.append({"method": method, "path": path,
                           "headers": {str(h): str(v)
                                       for h, v in headers.items()},
                           "expect": expect})
    verdict = raw.get("verdict") or {}
    if not isinstance(verdict, dict):
        return None, "check %s: 'verdict' must be a mapping" % cid
    return {"id": str(cid), "title": str(title), "severity": severity,
            "requests": clean_reqs, "verdict": verdict}, None


def load_checks(path):
    """Load + validate a YAML checks file.

    Returns (checks, skipped) where skipped maps check-id-or-index to
    a human reason. Never raises for content problems; bad YAML yields
    an empty list plus a skip entry.
    """
    skipped = {}
    checks = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        return [], {"__all__": "cannot load %s: %s" % (path, exc)}
    if data is None:
        return [], {"__all__": "empty checks file: %s" % path}
    if isinstance(data, dict):
        data = data.get("checks")
    if not isinstance(data, list):
        return [], {"__all__": "expected a list of checks in %s" % path}
    for i, raw in enumerate(data):
        check, err = _validate_check(raw, i)
        if err:
            key = (raw or {}).get("id", "check#%d" % i) \
                if isinstance(raw, dict) else "check#%d" % i
            skipped[str(key)] = "validation error: %s" % err
            continue
        ids = [c["id"] for c in checks]
        if check["id"] in ids:
            skipped[check["id"]] = "validation error: duplicate id"
            continue
        checks.append(check)
    return checks, skipped


# ----------------------------------------------------------------- running


def _match_expect(expect, status, headers, body):
    """True when every condition in one expect block matched."""
    for sub in (expect.get("body_contains") or []):
        if isinstance(sub, str) and sub not in body:
            return False
    for pat in (expect.get("body_regex") or []):
        try:
            if not re.search(pat, body, re.DOTALL):
                return False
        except re.error:
            return False
    for hname, sub in (expect.get("header_contains") or {}).items():
        hv = headers.get(hname) or headers.get(hname.lower()) or ""
        if sub not in str(hv):
            return False
    if "status" in expect and int(expect["status"]) != int(status):
        return False
    return True


def run_dsl_checks(target, yaml_path, fetch=None, budget=None, log=None,
                   allowlist=None):
    """Run all valid DSL checks from ``yaml_path`` against ``target``.

    Returns {findings, ran, skipped}. rate cap: ``budget`` = max
    requests; scope-gated by ``allowlist`` (None = allowed).
    """
    import urllib.parse

    from omega.deepchecks import default_fetch
    result = {"findings": [], "ran": [], "skipped": {}}
    checks, skipped = load_checks(yaml_path)
    result["skipped"].update(skipped)
    if not checks:
        if log:
            log("dsl: no valid checks loaded from %s" % yaml_path)
        return result
    base_url = target if "://" in target else "https://" + target
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = ("target %r not in allowlist" % target)
        if log:
            log("dsl skipped: target not in allowlist: %r" % target)
        return result
    fetch = fetch or default_fetch
    cap = budget if budget is not None else 32

    for check in checks:
        cid = check["id"]
        reqs = check["requests"]
        sent = 0
        matched = 0
        total_expects = 0
        baseline_body = None
        evidence_reqs = []
        exhausted = False
        try:
            # baseline: same first path without custom headers
            first = reqs[0]
            stb, _hb, baseline_body = fetch(
                "GET", base_url.rstrip("/") + first["path"])
            for r in reqs:
                if sent >= cap:
                    result["skipped"][cid] = "budget exhausted"
                    exhausted = True
                    break
                url = base_url.rstrip("/") + r["path"]
                st, headers, body = fetch(r["method"], url,
                                          headers=r["headers"])
                sent += 1
                hdrs = {str(k).lower(): str(v)
                        for k, v in (headers or {}).items()}
                expects = r.get("expect") or {}
                total_expects += len(expects)
                ok = _match_expect(expects, st, hdrs,
                                   body.decode("latin-1", "replace"))
                if ok:
                    # count every matched condition (diff_vs_baseline is
                    # scored separately below)
                    matched += len([k for k in expects
                                    if k != "diff_vs_baseline"])
                    evidence_reqs.append({"path": r["path"],
                                          "status": st})
                if (r.get("expect") or {}).get("diff_vs_baseline"):
                    # NB: diff_vs_baseline is already counted once via
                    # len(expects) above — never double-count it.
                    differs = (baseline_body is not None
                               and baseline_body != body)
                    if differs:
                        matched += 1
                    else:
                        evidence_reqs.append(
                            {"path": r["path"],
                             "note": "diff_vs_baseline NOT satisfied"})
            if exhausted:
                continue  # budget note already recorded for this check
            if total_expects == 0:
                result["skipped"][cid] = ("validation error: no expect "
                                          "conditions defined")
                continue
            if matched == total_expects:
                verification = "confirmed"
                note = ("ALL %d DSL conditions matched (confirmed per "
                        "verdict rules)." % total_expects)
            elif matched > 0:
                verification = "candidate"
                note = ("%d of %d DSL conditions matched (candidate per "
                        "verdict rules: ANY match)." % (matched,
                                                        total_expects))
            else:
                continue  # nothing matched: no finding
            result["findings"].append(Finding(
                title=check["title"],
                severity=check["severity"],
                confidence="medium" if verification == "confirmed"
                else "low",
                verification=verification,
                verification_note="omega-dsl custom check '%s': %s" % (
                    cid, note),
                manual_check='curl -si "%s%s"' % (
                    base_url.rstrip("/"), reqs[0]["path"]),
                location=base_url.rstrip("/") + reqs[0]["path"],
                evidence={"check_id": cid, "matched": matched,
                          "total_expects": total_expects,
                          "requests_sent": sent, "details": evidence_reqs},
                source="omega-dsl/" + cid))
            result["ran"].append(cid)
        except Exception as exc:  # never raise
            result["skipped"][cid] = "error: %s" % exc
            if log:
                log("dsl check %s failed: %s" % (cid, exc))
    return result
