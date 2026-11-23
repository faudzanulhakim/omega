"""omega/adapters/perltools.py — Perl static-analysis adapter.

Runs omega/adapters/analyze.pl (pure-Perl regex analyzer) over HTTP
response bodies fetched for a target. Skipped gracefully when ``perl``
is missing (per the fusion degradation contract).

Protocol: JSON lines of {url, body} on the Perl script's stdin; JSON
lines of {url, endpoints[], headers_hits[], suspicious[]} on stdout.

run_perl_suite(target, fetch=None, budget=None, log=None,
               which_fn=shutil.which)
  -> {"findings", "surface", "ran", "skipped"} — never raises.
     findings use source="omega-perl/analyze" and follow the ENGINE
     finding-dict convention (verification is always "signature").

The injectable ``fetch`` follows the omega.probes contract:
    fetch(method, url, headers=None) -> (status, headers, body_bytes)
Bodies may also be returned as plain str/bytes for test stubs.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

ADAPTER_DIR = os.path.dirname(os.path.abspath(__file__))
ANALYZE_PL = os.path.join(ADAPTER_DIR, "analyze.pl")

DEFAULT_TIMEOUT_S = 60
MAX_JS_FILES = 5            # extra JS bodies fetched per run
PERL_SUITE_NAME = "perl"

_JS_SRC_RE = re.compile(
    r"""(?:src|href)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']""", re.I)


def _norm_base_url(target):
    """Normalize a target into a scheme-qualified base URL."""
    t = str(target or "").strip()
    if "://" not in t:
        t = "https://" + t
    return t.rstrip("/")


def _default_fetch(method, url, headers=None):
    """Stdlib fetch with the probes contract (never raises here)."""
    import urllib.request
    import urllib.error
    req = urllib.request.Request(url, method=method,
                                 headers=headers or {"User-Agent": "omega-perl/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, dict(resp.headers.items()), resp.read(1024 * 1024)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, dict(exc.headers.items() if exc.headers else {}), \
                (exc.read(1024 * 1024) if hasattr(exc, "read") else b"")
        except Exception:
            return exc.code, {}, b""
    except Exception as exc:
        return 0, {}, str(exc).encode("utf-8", "replace")


def _body_from_fetch_result(res):
    """Extract body text from any supported fetch return shape."""
    body = b""
    if res is None:
        return ""
    if isinstance(res, (tuple, list)):
        if len(res) >= 3:
            body = res[2]
        elif len(res) == 1:
            body = res[0]
    elif isinstance(res, dict):
        body = res.get("body", "")
    elif isinstance(res, (str, bytes)):
        body = res
    if isinstance(body, str):
        return body
    try:
        return bytes(body).decode("utf-8", "replace")
    except Exception:
        return ""


def _fetch_body(fetch, url):
    """fetch(url) -> body text (never raises)."""
    try:
        res = fetch("GET", url)
        return _body_from_fetch_result(res)
    except TypeError:
        # stub with a simpler signature: fetch(url)
        try:
            return _body_from_fetch_result(fetch(url))
        except Exception:
            return ""
    except Exception:
        return ""


def _finding(title, severity, evidence, location=""):
    return {
        "title": title,
        "severity": severity,
        "confidence": "candidate",
        "verification": "signature",
        "verification_note": (
            "signature from perl adapter 'analyze.pl'; requires manual "
            "verification before acting on it"),
        "manual_check": True,
        "location": location,
        "param": "",
        "evidence": str(evidence or "")[:400],
        "source": "omega-perl/analyze",
    }


def analyze_bodies(records, which_fn=shutil.which):
    """Run the Perl analyzer over [{url, body}, ...] -> result dicts.

    Never raises; a missing perl or a failed subprocess yields [].
    """
    perl = None
    try:
        perl = which_fn("perl")
    except Exception:
        perl = None
    if not perl or not os.path.exists(ANALYZE_PL):
        return []
    lines = "".join(
        json.dumps({"url": r.get("url", ""), "body": r.get("body", "")}) + "\n"
        for r in records)
    try:
        proc = subprocess.run(
            [perl, ANALYZE_PL], input=lines, capture_output=True,
            text=True, timeout=DEFAULT_TIMEOUT_S)
    except Exception:
        return []
    out = []
    for ln in proc.stdout.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out


def run_perl_suite(target, fetch=None, budget=None, log=None,
                   which_fn=shutil.which):
    """Fusion perl suite: fetch homepage + JS, analyze with Perl.

    Returns {"findings", "surface", "ran", "skipped"} — never raises.
    skipped entries are {"suite": "perl", "reason": "..."}.
    """
    log = log or (lambda msg: None)
    result = {"findings": [], "surface": {}, "ran": [], "skipped": []}

    perl = None
    try:
        perl = which_fn("perl")
    except Exception:
        perl = None
    if not perl:
        result["skipped"].append({
            "suite": PERL_SUITE_NAME,
            "reason": "perl binary not found; perl adapter skipped"})
        log("[perl] skipped: perl binary not found")
        return result
    if not os.path.exists(ANALYZE_PL):
        result["skipped"].append({
            "suite": PERL_SUITE_NAME,
            "reason": f"analyzer script missing: {ANALYZE_PL}"})
        log("[perl] skipped: analyzer script missing")
        return result

    base = _norm_base_url(target)
    homepage = _fetch_body(fetch or _default_fetch, base + "/")
    if not homepage:
        result["skipped"].append({
            "suite": PERL_SUITE_NAME,
            "reason": "no homepage body could be fetched for analysis"})
        log("[perl] skipped: no homepage body")
        return result

    records = [{"url": base + "/", "body": homepage}]

    # pull a bounded set of referenced .js files for the same origin
    js_budget = MAX_JS_FILES if budget is None else max(
        0, min(MAX_JS_FILES, int(budget) - 1))
    for src in _JS_SRC_RE.findall(homepage)[:js_budget]:
        js_url = src if src.startswith("http") else base + "/" + src.lstrip("/")
        body = _fetch_body(fetch or _default_fetch, js_url)
        if body:
            records.append({"url": js_url, "body": body})

    analyses = analyze_bodies(records, which_fn=which_fn)
    if not analyses:
        result["skipped"].append({
            "suite": PERL_SUITE_NAME,
            "reason": "perl analyzer produced no output"})
        log("[perl] skipped: analyzer produced no output")
        return result

    surface_urls = []
    for rec, an in zip(records, analyses):
        if an.get("error"):
            log(f"[perl] analyzer error for {rec['url']}: {an['error']}")
            continue
        endpoints = an.get("endpoints") or []
        surface_urls.extend(endpoints)
        loc = rec["url"]
        if endpoints:
            result["findings"].append(_finding(
                f"Perl analysis: {len(endpoints)} endpoint(s) extracted "
                f"from {os.path.basename(loc) or loc}",
                "INFO",
                "; ".join(endpoints[:10]),
                location=loc))
        for hit in (an.get("headers_hits") or []):
            sev = "LOW" if hit in ("set-cookie", "authorization",
                                   "api-key", "basic-auth") else "INFO"
            result["findings"].append(_finding(
                f"Perl analysis: sensitive header pattern '{hit}'",
                sev, f"pattern '{hit}' matched in body of {loc}",
                location=loc))
        suspicious = an.get("suspicious") or []
        if suspicious:
            masked = "; ".join(
                (t[:8] + "…" + f"<len {len(t)}>") for t in suspicious[:5])
            result["findings"].append(_finding(
                f"Perl analysis: {len(suspicious)} high-entropy token(s) "
                f"(possible secrets)",
                "LOW", masked, location=loc))

    if surface_urls:
        result["surface"]["urls"] = surface_urls[:100]

    result["ran"].append(PERL_SUITE_NAME)
    log(f"[perl] analyzed {len(records)} body/bodies; "
        f"{len(result['findings'])} finding(s)")
    return result
