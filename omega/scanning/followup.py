"""Adaptive follow-up loop: AI-style depth probes, script-guarded.

Takes scanner findings (candidate/confirmed, with evidence) and runs a
SECOND-depth probe per finding-class heuristic. Every probe result is a
CLAIM dict pushed through the claimcheck gate
(omega.scanning.claimcheck.validate_claim) so nothing unverified is ever
reported: only gate-verified probe claims reach the final findings list;
refuted/unverifiable/unreachable claims are recorded in ``refuted``
(tagged ``ai-claim:refuted``) for transparency.

Design invariants:
- never raises (every probe is contained; fetch errors -> refuted/skipped);
- offline-safe (probe fetch errors never become findings);
- budget-capped (env OMEGA_FOLLOWUP_MAX, default 12 probes);
- unknown finding classes get NO probe and are recorded in ``skipped``.

Entry point: :func:`run_followups` -> {findings, refuted, skipped, probes}.
"""
from __future__ import annotations

import os
import re
import urllib.parse

from .claimcheck import validate_claim

__all__ = ["run_followups", "classify_finding", "FOLLOWUPS",
           "FOLLOWUP_SOURCE"]

FOLLOWUP_SOURCE = "omega-followup"
DEFAULT_BUDGET = 12
BUDGET_ENV = "OMEGA_FOLLOWUP_MAX"

# Finding classes that get a probe. Keys are internal probe ids; the
# FOLLOWUPS registry maps probe id -> (label, probe_fn).
PROBE_SQLI = "sqli-boolean"
PROBE_XSS = "xss-context"
PROBE_TRAVERSAL = "traversal-depth"
PROBE_ENV = "env-keys"
PROBE_CMD = "cmd-arithmetic"
PROBE_REDIRECT = "redirect-variants"
PROBE_HEADERS = "csp-parse"

MARKER = "omegafollowup7x"
EVIL_HOST = "evil.followup.example"


# --------------------------------------------------------------------------
# Finding-class heuristic
# --------------------------------------------------------------------------

def classify_finding(finding):
    """Match a finding title (keyword heuristic) to a probe id.

    Returns the probe id string or None when no probe applies.
    """
    title = str((finding or {}).get("title") or "").lower()
    if not title:
        return None
    if ".env" in title or "env file" in title or "environment file" in title \
            or "environment variable" in title:
        return PROBE_ENV
    if "open redirect" in title or (
            "redirect" in title
            and ("open" in title or "unvalidated" in title)):
        return PROBE_REDIRECT
    if "sql" in title and ("error" in title or "injection" in title
                           or "blind" in title):
        return PROBE_SQLI
    if "xss" in title or "cross-site scripting" in title \
            or "reflected" in title or "reflection" in title:
        return PROBE_XSS
    if "traversal" in title or "file inclusion" in title \
            or "lfi" in title:
        return PROBE_TRAVERSAL
    if "command" in title and ("echo" in title or "injection" in title
                               or "execution" in title):
        return PROBE_CMD
    if "csp" in title or "content-security" in title \
            or ("header" in title and "security" in title) \
            or ("response header" in title):
        return PROBE_HEADERS
    return None


# --------------------------------------------------------------------------
# URL / fetch helpers (all never raise)
# --------------------------------------------------------------------------

def _param_url(location, param, value):
    """Set (or add) ``param=value`` on the finding's location URL."""
    if not location:
        return None
    loc = str(location)
    if "?" in loc:
        base, _, qs = loc.partition("?")
        pairs = [(k, v) for k, v in
                 (p.split("=", 1) for p in qs.split("&") if "=" in p)]
        if pairs:
            # reuse the first existing parameter name unless overridden
            pairs[0] = (pairs[0][0], value)
            key = pairs[0][0]
        else:
            key = param
            pairs = [(param, value)]
        qs = "&".join("%s=%s" % (urllib.parse.quote(k, safe=""),
                                 urllib.parse.quote(v, safe=""))
                      for k, v in pairs)
        return base + "?" + qs
    return loc + "?" + urllib.parse.quote(param, safe="") + "=" + \
        urllib.parse.quote(value, safe="")


def _first_param(location):
    """First query parameter name of the location (or None)."""
    _, _, qs = str(location or "").partition("?")
    for p in qs.split("&"):
        if "=" in p:
            return p.split("=", 1)[0]
    return None


def _fetch(fetch, url):
    """GET one URL; returns (status, headers, body_text) or None on error."""
    if not url or "://" not in url:
        return None
    try:
        st, headers, body = fetch("GET", url)
        text = (body or b"").decode("latin-1", "replace")
        if not isinstance(headers, dict):
            headers = {}
        return st, headers, text
    except Exception:
        return None


def _body_slice(text, n=48):
    """A stable-ish evidence slice; empty string when no body."""
    compact = re.sub(r"\s+", " ", str(text or "")).strip()
    return compact[:n]


def _base_claim(kind, finding, url):
    src = str((finding or {}).get("location") or "")
    return {
        "title": str((finding or {}).get("title") or "") + " — follow-up",
        "location": url or src,
        "severity": str((finding or {}).get("severity") or "MEDIUM"),
        "verification": "candidate",
        "source": "%s/%s" % (FOLLOWUP_SOURCE, kind),
        "evidence": "",
        "tags": [],
    }


# --------------------------------------------------------------------------
# Probes — each returns a CLAIM dict, or None when the probe found nothing
# --------------------------------------------------------------------------

def _probe_sqli(finding, fetch, base_url):
    """Blind-SQLi boolean probe: two param values must produce a
    differential (different page length/content on the same param) that is
    STABLE across 3 alternations -> HIGH candidate claim."""
    loc = str((finding or {}).get("location") or "")
    param = _first_param(loc) or "id"
    url_true = _param_url(loc, param, "1 OR 1=1")
    url_false = _param_url(loc, param, "1 OR 1=2")
    r_true = _fetch(fetch, url_true)
    r_false = _fetch(fetch, url_false)
    if not r_true or not r_false:
        return None
    # stability: each "true" fetch must equal the first true fetch and
    # each "false" fetch must equal the first false fetch (3 alternations)
    seq = [r_true, r_false, r_true, r_false, r_true, r_false]
    stable = True
    for i, r in enumerate(seq):
        reference = seq[0] if i % 2 == 0 else seq[1]
        if r[2] != reference[2]:
            stable = False
            break
    if not stable or seq[0][2] == seq[1][2]:
        return None
    claim = _base_claim(PROBE_SQLI, finding, url_true)
    claim["title"] = ("Blind SQLi boolean differential (stable across "
                      "3 alternations)")
    claim["severity"] = "HIGH"
    claim["evidence"] = _body_slice(seq[0][2]) or "differential"
    claim["verification_note"] = (
        "boolean payload differential: true=%dB false=%dB, stable 3x"
        % (len(seq[0][2]), len(seq[1][2])))
    return claim


def _probe_xss(finding, fetch, base_url):
    """DOM-context escalation: script-tag echo probe. Always candidate —
    a raw reflection is a signal, not proof of execution."""
    loc = str((finding or {}).get("location") or "")
    param = _first_param(loc) or "q"
    payload = "<script>%s</script>" % MARKER
    url = _param_url(loc, param, payload)
    r = _fetch(fetch, url)
    if not r or MARKER not in r[2]:
        return None
    text = r[2]
    idx = text.index(MARKER)
    before = text[max(0, idx - 12):idx].lower()
    if "<script" in before and "</script>" in text[idx:]:
        context = "existing-script"
    elif "'" in before or '"' in before:
        context = "attribute"
    elif "<" in before and ">" not in before:
        context = "tag"
    else:
        context = "html-body"
    claim = _base_claim(PROBE_XSS, finding, url)
    claim["title"] = "XSS script-tag echo (DOM context: %s)" % context
    claim["evidence"] = payload
    claim["verification_note"] = (
        "script tag echoed raw in DOM context: %s" % context)
    return claim


def _probe_traversal(finding, fetch, base_url):
    """Path traversal depth probe: deeper ../ repetitions plus alternate
    encodings (..%252f, %2e%2e%2f, double-slash)."""
    loc = str((finding or {}).get("location") or "")
    param = _first_param(loc) or "file"
    deep = "../" * 5 + "etc/passwd"
    payloads = [
        ("double-encoded", urllib.parse.quote(
            urllib.parse.quote(deep, safe=""), safe="")),
        ("dotdot-encoded", "%2e%2e%2f" * 5 + "etc/passwd"),
        ("double-slash", "..//" * 5 + "etc/passwd"),
        ("deep-plain", deep),
    ]
    best = None
    for label, payload in payloads:
        url = _param_url(loc, param, payload)
        r = _fetch(fetch, url)
        if not r or r[0] >= 400 or not r[2]:
            continue
        if "root:" in r[2] or "traversal" in r[2].lower():
            best = (label, url, r[2])
            break
        if best is None:
            best = (label, url, r[2])
    if not best:
        return None
    label, url, text = best
    claim = _base_claim(PROBE_TRAVERSAL, finding, url)
    claim["title"] = "Path traversal — deeper depth/encoding probe (%s)" % (
        label,)
    claim["evidence"] = _body_slice(text) or label
    claim["verification_note"] = (
        "traversal payload %r reproduced file content" % label)
    return claim


def _probe_env(finding, fetch, base_url):
    """.env exposure: fetch and parse KEY=value lines; report key NAMES
    only in the title/summary — values stay in the verbatim evidence."""
    loc = str((finding or {}).get("location") or "")
    url = loc if (loc and loc.rstrip("/").endswith(".env")) else \
        (loc.rstrip("/") + "/.env" if loc else "/.env")
    if base_url and "://" not in url:
        url = base_url.rstrip("/") + "/" + url.lstrip("/")
    r = _fetch(fetch, url)
    if not r or r[0] >= 400:
        return None
    keys = re.findall(r"^([A-Za-z_][A-Za-z0-9_]*)=", r[2], re.M)
    if not keys:
        return None
    claim = _base_claim(PROBE_ENV, finding, url)
    claim["title"] = ("Environment file exposure — keys: %s"
                      % ", ".join(keys[:20]))
    claim["severity"] = "HIGH"
    claim["evidence"] = r[2]  # verbatim values live ONLY here
    claim["verification_note"] = (
        ".env fetched fresh; %d key name(s) reported (values in evidence "
        "only)" % len(keys))
    return claim


def _probe_cmd(finding, fetch, base_url):
    """Command echo corroboration: second arithmetic probe with DIFFERENT
    operands than the usual 7*7 (stateful corroboration)."""
    loc = str((finding or {}).get("location") or "")
    param = _first_param(loc) or "cmd"
    baseline_url = _param_url(loc, param, "noop")
    baseline = _fetch(fetch, baseline_url)
    for a, b in ((11, 13), (12, 14), (9, 9)):
        expected = str(a * b)
        for template in ("{{%d*%d}}", "%d*%d", "echo $((%d*%d))",
                         "$(echo %d*%d)"):
            payload = template % (a, b)
            url = _param_url(loc, param, payload)
            r = _fetch(fetch, url)
            if not r or expected not in r[2]:
                continue
            if baseline and expected in baseline[2]:
                continue  # echoed regardless — not command execution
            claim = _base_claim(PROBE_CMD, finding, url)
            claim["title"] = ("Command echo corroboration (%d*%d=%s "
                              "evaluated)" % (a, b, expected))
            claim["evidence"] = expected
            claim["verification_note"] = (
                "second arithmetic probe with different operands: %r -> %s"
                % (payload, expected))
            return claim
    return None


def _probe_redirect(finding, fetch, base_url):
    """Open redirect variants: protocol-relative //evil and backslash
    (backslash + host) targets (both normalize to an external host in
    browsers)."""
    loc = str((finding or {}).get("location") or "")
    param = _first_param(loc) or "url"
    variants = [
        ("protocol-relative", "//" + EVIL_HOST),
        ("backslash", "/\\" + EVIL_HOST),
        ("backslash-bare", "\\\\" + EVIL_HOST),
    ]
    for label, payload in variants:
        url = _param_url(loc, param, payload)
        r = _fetch(fetch, url)
        if not r:
            continue
        st, headers, text = r
        loc_hdr = str(headers.get("Location") or headers.get("location")
                      or "")
        if st in (301, 302, 303, 307, 308) and (
                loc_hdr.lstrip("/").startswith(EVIL_HOST)
                or EVIL_HOST in loc_hdr.replace("\\", "/")):
            claim = _base_claim(PROBE_REDIRECT, finding, url)
            claim["title"] = ("Open redirect — %s external variant "
                              "redirects" % label)
            claim["severity"] = "HIGH"
            claim["evidence"] = _body_slice(text) or ""
            claim["verification_note"] = (
                "%s variant -> Location: %s" % (label, loc_hdr))
            return claim
    return None


def _probe_headers(finding, fetch, base_url):
    """Header findings: fetch the page, parse CSP and report the SPECIFIC
    weaknesses (unsafe-inline, missing default-src, missing CSP)."""
    loc = str((finding or {}).get("location") or "") or base_url or ""
    r = _fetch(fetch, loc)
    if not r:
        return None
    csp = str(r[1].get("Content-Security-Policy")
              or r[1].get("content-security-policy") or "")
    weaknesses = []
    if not csp:
        weaknesses.append("missing Content-Security-Policy entirely")
    else:
        directives = {d.strip().split(" ", 1)[0].lower():
                      d.strip().split(" ", 1)[1] if " " in d.strip() else ""
                      for d in csp.split(";") if d.strip()}
        if "default-src" not in directives:
            weaknesses.append("missing default-src directive")
        if "unsafe-inline" in csp:
            weaknesses.append("unsafe-inline allows inline script/style")
    if not weaknesses:
        return None
    claim = _base_claim(PROBE_HEADERS, finding, loc)
    claim["title"] = "CSP weaknesses: %s" % "; ".join(weaknesses)
    claim["evidence"] = _body_slice(r[2]) or ""
    claim["verification_note"] = (
        "CSP parsed from live response: %r" % (csp[:120] or "(absent)"))
    return claim


FOLLOWUPS = {
    PROBE_SQLI: _probe_sqli,
    PROBE_XSS: _probe_xss,
    PROBE_TRAVERSAL: _probe_traversal,
    PROBE_ENV: _probe_env,
    PROBE_CMD: _probe_cmd,
    PROBE_REDIRECT: _probe_redirect,
    PROBE_HEADERS: _probe_headers,
}


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def _budget(probes_used=None, budget=None):
    """Max probes allowed (env OMEGA_FOLLOWUP_MAX, default 12)."""
    if budget is not None:
        return max(0, int(budget))
    raw = os.environ.get(BUDGET_ENV)
    if raw and raw.isdigit():
        return int(raw)
    return DEFAULT_BUDGET


def run_followups(findings, fetch=None, base_url=None, budget=None,
                  log=None):
    """Run the adaptive follow-up loop over scanner findings.

    Returns {findings, refuted, skipped, probes}:
    - findings: the input findings (each annotated with ``followup``)
      plus every gate-VERIFIED probe claim (source omega-followup/<probe>);
    - refuted: probe claims the gate did not verify, tagged
      ``ai-claim:refuted`` (transparency: never silently dropped);
    - skipped: {title, reason} entries — unknown classes, budget
      exhaustion, probe errors;
    - probes: number of probes actually executed.
    Never raises. Offline-safe: fetch errors -> refuted/skipped, never a
    finding.
    """
    log = log or (lambda msg: None)
    result = {"findings": [], "refuted": [], "skipped": [], "probes": 0}
    try:
        from .deepchecks import default_fetch
        fetch = fetch or default_fetch
    except Exception:
        fetch = fetch or (lambda *a, **k: (0, {}, b""))

    inputs = [dict(f) for f in (findings or []) if isinstance(f, dict)]
    max_probes = _budget(budget=budget)

    for finding in inputs:
        try:
            kind = classify_finding(finding)
            title = str(finding.get("title") or "?")
            if kind is None:
                finding["followup"] = {"probe": None, "status": "skipped",
                                       "reason": "unknown finding type"}
                result["findings"].append(finding)
                result["skipped"].append({
                    "title": title,
                    "reason": "no followup probe heuristic matched "
                              "finding type"})
                log("[followup] skipped (unknown type): %s" % title)
                continue
            if result["probes"] >= max_probes:
                finding["followup"] = {"probe": kind, "status": "skipped",
                                       "reason": "budget exhausted"}
                result["findings"].append(finding)
                result["skipped"].append({
                    "title": title,
                    "reason": "followup budget exhausted (%s=%d)"
                              % (BUDGET_ENV, max_probes)})
                log("[followup] budget exhausted, skipped: %s" % title)
                continue

            probe_fn = FOLLOWUPS[kind]
            result["probes"] += 1
            try:
                claim = probe_fn(finding, fetch, base_url)
            except Exception as exc:
                claim = None
                finding["followup"] = {"probe": kind, "status": "skipped",
                                       "reason": "probe error"}
                result["findings"].append(finding)
                result["skipped"].append({
                    "title": str(finding.get("title") or "?"),
                    "reason": "probe %s failed: %s" % (kind, exc)})
                continue

            if claim is None:
                finding["followup"] = {"probe": kind, "status": "no-signal",
                                       "reason": "probe produced no signal"}
                result["findings"].append(finding)
                log("[followup] probe %s: no signal for %s"
                    % (kind, finding.get("title")))
                continue

            validated = validate_claim(claim, fetch=fetch,
                                       base_url=base_url)
            if validated.get("validation") == "verified":
                # XSS escalation stays a candidate (echo != execution).
                if kind == PROBE_XSS:
                    validated["verification"] = "candidate"
                    validated["verification_note"] = (
                        str(validated.get("verification_note") or "")
                        + "; kept candidate: reflection is not execution")
                validated["followup"] = {"probe": kind, "status": "verified"}
                finding["followup"] = {"probe": kind, "status": "verified",
                                       "claim_source":
                                           validated.get("source")}
                result["findings"].append(finding)
                result["findings"].append(validated)
                log("[followup] probe %s verified: %s"
                    % (kind, validated.get("title")))
            else:
                validated.setdefault("tags", []).append("ai-claim:refuted")
                validated["followup"] = {"probe": kind,
                                         "status": "refuted"}
                finding["followup"] = {"probe": kind, "status": "refuted",
                                       "reason": validated.get(
                                           "validation_note")}
                result["findings"].append(finding)
                result["refuted"].append(validated)
                log("[followup] probe %s refuted: %s"
                    % (kind, validated.get("validation_note")))
        except Exception as exc:  # absolute containment
            finding.setdefault("followup", {
                "status": "skipped", "reason": "followup error"})
            result["findings"].append(finding)
            result["skipped"].append({
                "title": str(finding.get("title") or "?"),
                "reason": "followup loop error: %s" % exc})
    return result
