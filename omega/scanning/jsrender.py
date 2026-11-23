"""omega/jsrender.py — browser-rendered differential scan (Playwright).

Renders a target page in headless Chromium and compares what the browser
sees against the raw static HTML the server returned. JavaScript-only
artifacts (secrets, tokens, internal hostnames, console errors, XHR/fetch
API calls, DOM injection sinks) are surfaced as *candidate* findings —
never confirmed, because "appears only after JS execution" is evidence,
not proof of a vulnerability.

Checks:

  rendered_vs_static_diff — secrets/tokens/internal hostnames present in
      the rendered DOM but absent from the static HTML -> candidate
      (HIGH for API-key/JWT-shaped strings, LOW for internal hosts /
      private IPs); a large non-secret differential is INFO inventory.
  console_error_capture — console/page errors collected during render;
      key-like strings in error text -> candidate HIGH; stack traces or
      internal URLs -> candidate LOW.
  api_call_discovery — JSON/XHR responses observed during render are
      recorded as an INFO inventory; JSON bodies containing
      password/token/secret keys -> candidate.
  dom_injection_sinks — ``javascript:`` hrefs carrying eval-like
      payloads in the rendered HTML -> candidate LOW.

Playwright usage is fully contained: if the playwright package or the
Chromium executable is unavailable, run_jsrender returns the skipped
shape and never raises. The browser is launched headless with
--no-sandbox, navigates to the target ONLY (plus up to 2 discovered
same-host links, hard cap 3 renders per run), all non-target requests
are aborted via route interception, navigation timeout is 10s, and the
browser is always closed in ``finally``.

run_jsrender(target, fetch=None, budget=3, log=None) -> dict with
findings / skipped / requests_sent / ran and never raises.
"""

from __future__ import annotations

import ipaddress
import os
import re
import urllib.parse

__all__ = [
    "playwright_available",
    "run_jsrender",
]

RENDER_TIMEOUT_MS = 10000
SETTLE_MS = 400
MAX_URLS = 3
EVIDENCE_CAP = 300

_SRC = "omega-jsrender"

# Secret-shaped strings looked for in the *rendered-only* differential.
_KEY_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("API key literal", re.compile(r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9._-]{16,}['\"]")),
    ("bearer token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}")),
    ("secret literal", re.compile(r"(?i)(secret|token|password)['\"]?\s*[:=]\s*['\"][A-Za-z0-9._+/-]{16,}['\"]")),
]
_HOST_PATTERNS = [
    ("internal hostname", re.compile(r"\b[A-Za-z0-9._-]+\.(?:internal|local|corp|intranet)\b")),
    ("private IPv4", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b")),
]
_STACK_HINT = re.compile(r"(?i)(traceback|\bat\s+https?://|\n\s+at\s+|at line \d+|\.js:\d+:\d+)")
_KEYISH_ERROR = re.compile(r"(?i)(api[_-]?key|token|secret|password)[^a-z]")
_SINK_PATTERN = re.compile(
    r"(?i)javascript:[^\"']{0,200}?(eval\s*\(|new\s+Function\s*\(|document\.write\s*\(|atob\s*\(|setTimeout\s*\(\s*['\"])"
)
_CRED_JSON_KEY = re.compile(r"(?i)[\{,]\s*[\"'](password|token|secret|api[_-]?key)[\"']\s*:")


def _ev(text):
    """Evidence string capped at the convention limit."""
    text = (text or "").strip().replace("\n", " | ")
    if len(text) > EVIDENCE_CAP:
        text = text[: EVIDENCE_CAP - 3] + "..."
    return text


def _finding(title, severity, note, manual_check, location, evidence, confidence="medium"):
    return {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "verification": "candidate",
        "verification_note": note,
        "manual_check": manual_check,
        "location": location,
        "evidence": _ev(evidence),
        "source": _SRC,
    }


def _is_private_ip(text):
    try:
        return ipaddress.ip_address(text.strip()).is_private
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Pure classification helpers (unit-tested against canned render results).
# ---------------------------------------------------------------------------

_SECRETISH = re.compile(r"(?i)(secret|token|api[_-]?key|password)|[A-Za-z0-9._-]{24,}")


def diff_findings(static_html, rendered_html, rendered_title=None):
    """Secrets/tokens/internal hosts present only after JS execution."""
    static = static_html or ""
    rendered = rendered_html or ""
    findings = []
    title = (rendered_title or "").strip()
    static_title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", static, re.IGNORECASE | re.DOTALL)
    if m:
        static_title = m.group(1).strip()
    if title and title != static_title and _SECRETISH.search(title):
        findings.append(_finding(
            "Secret-looking value appears only in rendered document.title",
            "high",
            "document.title was set to a secret-looking string by JS "
            "execution; the value is absent from the static HTML. Manual "
            "verification required.",
            "Open the page in a browser, read document.title, and trace "
            "the JS that sets it; confirm whether the value is a real "
            "secret.",
            "rendered document.title after JS execution",
            title,
        ))
    if not rendered or rendered == static:
        return findings
    for name, pattern in _KEY_PATTERNS:
        matches = sorted(set(pattern.findall(rendered)))
        if not matches:
            continue
        if pattern.search(static):
            continue  # present in static too: not a JS-execution differential
        findings.append(_finding(
            "Secret-like string appears only in rendered DOM (%s)" % name,
            "high",
            "String absent from static HTML but present after JS execution; "
            "manual verification required.",
            "Inspect the rendered DOM and the JS bundle that produced the "
            "string; confirm whether the value is a real credential and "
            "revoke/rotate if so.",
            "rendered DOM after JS execution",
            "; ".join(matches[:5]),
            confidence="medium",
        ))
        if len(findings) >= 3:
            break
    if not findings:
        for name, pattern in _HOST_PATTERNS:
            matches = sorted(set(pattern.findall(rendered)))
            if not matches:
                continue
            if pattern.search(static):
                continue
            findings.append(_finding(
                "Internal %s appears only in rendered DOM" % name,
                "low",
                "Internal indicator absent from static HTML but introduced "
                "by JS execution; possible internal-surface disclosure.",
                "Check whether the JS bundle references internal "
                "infrastructure and whether the names resolve externally.",
                "rendered DOM after JS execution",
                "; ".join(matches[:5]),
            ))
            break
    diff_len = len(rendered) - len(static)
    if not findings and diff_len > 2000:
        findings.append(_finding(
            "Large static-vs-rendered DOM differential",
            "info",
            "JS execution changed the DOM substantially (informational "
            "inventory, no secret patterns matched).",
            "Compare rendered vs static DOM in a browser devtools diff.",
            "rendered DOM after JS execution",
            "rendered %d chars vs static %d chars (delta %d)"
            % (len(rendered), len(static), diff_len),
        ))
    return findings


def console_findings(errors):
    """Classify console/page errors collected during the render."""
    findings = []
    seen = set()
    for err in errors or []:
        text = str(err)
        if text in seen:
            continue
        seen.add(text)
        if _KEYISH_ERROR.search(text):
            findings.append(_finding(
                "Console error contains key-like string",
                "high",
                "Error text mentions api key/token/secret/password; may "
                "leak credential material. Manual verification required.",
                "Reproduce the error in a browser console and inspect the "
                "full message and stack for real credential values.",
                "browser console during render",
                text,
            ))
        elif _STACK_HINT.search(text) or _HOST_PATTERNS[0][1].search(text):
            findings.append(_finding(
                "Console error leaks stack trace or internal URL",
                "low",
                "Error output includes a stack trace or internal "
                "hostname/URL — possible information disclosure.",
                "Reproduce in a browser console and review the leaked "
                "paths/hosts.",
                "browser console during render",
                text,
            ))
        else:
            findings.append(_finding(
                "Console error during render",
                "info",
                "Informational: page logged a console error during render.",
                "Reproduce in a browser console.",
                "browser console during render",
                text,
            ))
    return findings[:10]


def api_findings(responses):
    """Inventory of JSON/XHR endpoints + credential-shaped JSON bodies."""
    findings = []
    endpoints = []
    flagged = []
    for resp in responses or []:
        url = resp.get("url", "")
        ctype = (resp.get("content_type") or "").lower()
        if not url:
            continue
        if "json" in ctype or "javascript" in ctype or resp.get("is_xhr"):
            endpoints.append(url)
            body = resp.get("body") or ""
            if body and _CRED_JSON_KEY.search(body):
                flagged.append(url)
    if endpoints:
        uniq = list(dict.fromkeys(endpoints))
        findings.append(_finding(
            "JSON/XHR API endpoints observed during render",
            "info",
            "Inventory of API endpoints the page contacted at render time.",
            "Review the listed endpoints manually (browser devtools "
            "network tab).",
            "network responses during render",
            "; ".join(uniq[:15]),
        ))
    for url in flagged[:5]:
        findings.append(_finding(
            "API response body contains credential-shaped JSON keys",
            "medium",
            "Response JSON includes password/token/secret/api-key keys; "
            "manual verification required to confirm real credentials.",
            "Fetch the endpoint manually and inspect the JSON keys and "
            "values; confirm whether real credentials are returned.",
            url,
            "endpoint %s returned credential-shaped JSON keys" % url,
        ))
    return findings


def sink_findings(rendered_html):
    """DOM injection sinks in the rendered HTML (javascript: hrefs)."""
    findings = []
    for match in _SINK_PATTERN.finditer(rendered_html or ""):
        findings.append(_finding(
            "javascript: URL with eval-like payload in rendered DOM",
            "low",
            "Rendered HTML contains a javascript: href whose payload "
            "looks like dynamic code evaluation (sink pattern); candidate "
            "DOM injection sink, not a proof of execution.",
            "Inspect the element and its JS context; check whether any "
            "attacker-controllable value reaches the payload.",
            "rendered DOM after JS execution",
            match.group(0),
        ))
        if len(findings) >= 5:
            break
    return findings


def analyze_render(static_html, rendered_html, console_errors, page_errors, responses, rendered_title=None):
    """Combined classification for one rendered page (pure, testable)."""
    findings = []
    findings.extend(diff_findings(static_html, rendered_html, rendered_title))
    findings.extend(console_findings((console_errors or []) + (page_errors or [])))
    findings.extend(api_findings(responses))
    findings.extend(sink_findings(rendered_html))
    return findings


# ---------------------------------------------------------------------------
# Playwright-backed rendering (contained).
# ---------------------------------------------------------------------------

def playwright_available():
    """True when playwright is importable AND a chromium binary exists."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        with sync_playwright() as p:
            path = p.chromium.executable_path
        return bool(path) and os.path.exists(path)
    except Exception:
        return False


def _target_host(url):
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except ValueError:
        return ""


def _same_host(url, base_host):
    return _target_host(url) == base_host and url.startswith(("http://", "https://"))


def _static_fetch(url, fetch=None):
    """GET the raw (pre-JS) HTML. fetch contract: (method,url,headers)->(status,hdr,bytes)."""
    headers = {"User-Agent": "omega-jsrender/1.0"}
    try:
        if fetch is not None:
            status, _hdrs, body = fetch("GET", url, headers)
            return body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
        import urllib.request
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception:
        return ""


def _render_page(url, log=None):
    """Render one URL in headless Chromium.

    Returns a result dict or None when the render fails. All non-target
    requests are aborted via route interception; browser is closed in
    ``finally``.
    """
    from playwright.sync_api import sync_playwright

    base_host = _target_host(url)
    result = {
        "url": url,
        "static_html": "",
        "rendered_html": "",
        "title": "",
        "console_errors": [],
        "page_errors": [],
        "responses": [],
        "links": [],
    }
    browser = None
    pw = None
    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
        context = browser.new_context()
        page = context.new_page()

        def _route(route):
            if _same_host(route.request.url, base_host):
                route.continue_()
            else:
                route.abort()

        context.route("**/*", _route)
        page.on("console", lambda msg: result["console_errors"].append(msg.text)
                if msg.type in ("error", "warning") else None)
        page.on("pageerror", lambda exc: result["page_errors"].append(str(exc)))

        def _on_response(resp):
            entry = {"url": resp.url, "content_type": resp.headers.get("content-type", "")}
            try:
                req = resp.request
                entry["is_xhr"] = req.resource_type in ("xhr", "fetch")
            except Exception:
                entry["is_xhr"] = False
            if "json" in entry["content_type"] or entry["is_xhr"]:
                try:
                    entry["body"] = resp.text()
                except Exception:
                    entry["body"] = ""
            result["responses"].append(entry)

        page.on("response", _on_response)
        page.goto(url, wait_until="load", timeout=RENDER_TIMEOUT_MS)
        page.wait_for_timeout(SETTLE_MS)
        result["rendered_html"] = page.content()
        result["title"] = page.title()
        try:
            hrefs = page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)")
            result["links"] = [h for h in hrefs if _same_host(h, base_host)]
        except Exception:
            result["links"] = []
        return result
    except Exception as exc:
        if log:
            log("render failed for %s: %s" % (url, exc))
        return None
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        if pw is not None:
            try:
                pw.stop()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Entry point — never raises.
# ---------------------------------------------------------------------------

def run_jsrender(target, fetch=None, budget=3, log=None):
    """Browser-rendered differential scan. Never raises."""
    result = {"findings": [], "skipped": {}, "requests_sent": 0, "ran": []}
    try:
        if not target:
            result["skipped"]["jsrender"] = "no target"
            return result
        budget = max(1, min(int(budget or 3), MAX_URLS))
        if not playwright_available():
            result["skipped"]["jsrender"] = "playwright/chromium unavailable"
            return result
        result["ran"].append("jsrender")
        if log:
            log("jsrender: rendering %s (budget %d)" % (target, budget))

        urls_queued = [target]
        rendered_count = 0
        while urls_queued and rendered_count < budget:
            url = urls_queued.pop(0)
            if url not in (target,) and url in getattr(run_jsrender, "_seen", set()):
                continue
            rendered = _render_page(url, log=log)
            if rendered is None:
                continue
            rendered_count += 1
            result["requests_sent"] += 1
            if log:
                log("jsrender: rendered %s" % url)
            static_html = rendered["static_html"] or _static_fetch(url, fetch=fetch)
            result["findings"].extend(analyze_render(
                static_html,
                rendered["rendered_html"],
                rendered["console_errors"],
                rendered["page_errors"],
                rendered["responses"],
                rendered_title=rendered["title"],
            ))
            # Discover up to (budget - rendered) additional same-host links.
            for link in rendered["links"]:
                if rendered_count + len(urls_queued) >= budget:
                    break
                if link != url and link not in urls_queued and link != target:
                    urls_queued.append(link)
        if rendered_count == 0:
            result["skipped"]["jsrender"] = "all renders failed"
    except Exception as exc:  # containment: run_* never raises
        result["skipped"]["jsrender"] = "error: %s" % exc
    return result
