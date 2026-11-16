"""omega/browser.py — headless-browser scanning layer (Playwright).

One honest, contained browser pass over a web target:

  browser_available()  -> True when playwright is importable AND the
                          chromium executable exists on disk
  scan_dom(base_url)   -> {findings, surface, ran, skipped}
  run_browser_suite()  -> same shape, never raises, allowlist-gated

What scan_dom collects (single headless chromium visit, plus a bounded
same-origin crawl):

  a) DOM-XSS sink instrumentation — an init script hooks the
     innerHTML/outerHTML setters, document.write/writeln and
     location.assign/replace and records every sink evaluation with its
     argument and the location at evaluation time. Evidence uses
     same-page hash injection with a fixed marker token
     (``OMEGADOMXSS`` + a per-scan nonce): a sink that executes with
     location-derived content reflected is a *candidate*; the finding is
     *confirmed* only when the marker string injected via
     location.hash reaches the sink during evaluation (a documented
     differential: the marker only ever enters the page through the
     location, so its appearance inside a sink value proves the
     location -> sink flow).
  b) SPA route discovery — history.pushState/replaceState calls plus a
     same-origin <a href> crawl (surface.urls).
  c) console / JS errors — INFO findings, capped at 10.
  d) postMessage audit — a window 'message' listener whose source never
     mentions an origin check is a candidate MEDIUM.
  e) localStorage/sessionStorage — keys matching
     token/password/secret/api-key with non-empty values are candidates.
  f) fetch/XHR endpoint recording — wrapped in the init script
     (surface.api_endpoints).

Honesty contract: every finding is candidate unless its documented
differential fully holds; only the marker-through-location sink hit is
confirmed. Findings use source ``omega-browser/<kind>``. The module
never raises out of run_browser_suite; a missing browser degrades to
``skipped``.
"""

from __future__ import annotations

import uuid

__all__ = [
    "MARKER_PREFIX",
    "browser_available",
    "scan_dom",
    "run_browser_suite",
]

MARKER_PREFIX = "OMEGADOMXSS"
CONSOLE_ERROR_CAP = 10
URL_CAP = 100
API_CAP = 100
CRAWL_SETTLE_MS = 400

_SRC = "omega-browser"


# --------------------------------------------------------------------------
# Availability
# --------------------------------------------------------------------------

def _chromium_executable():
    """Path of the chromium binary playwright will use, or None."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return None
    try:
        with sync_playwright() as p:
            return p.chromium.executable_path
    except Exception:
        return None


def _get_sync_playwright():
    """Import seam (tests stub this to inject a fake playwright)."""
    from playwright.sync_api import sync_playwright
    return sync_playwright


def browser_available():
    """True when playwright is importable AND chromium exists on disk."""
    try:
        exe = _chromium_executable()
    except Exception:
        return False
    import os
    return bool(exe) and os.path.isfile(exe)


# --------------------------------------------------------------------------
# Injected JS (constants so stubbed tests can dispatch on them)
# --------------------------------------------------------------------------

INIT_JS = r"""
(() => {
  if (window.__omega) { return; }
  window.__omega = { sinks: [], routes: [], api: [], msgs: 0, msg_loose: 0 };
  const href = () => { try { return window.location.href; } catch (e) { return ""; } };
  const rec = (kind, value) => {
    try {
      window.__omega.sinks.push({ kind: kind, value: String(value).slice(0, 2000), href: href() });
    } catch (e) {}
  };
  for (const prop of ["innerHTML", "outerHTML"]) {
    const d = Object.getOwnPropertyDescriptor(Element.prototype, prop);
    if (d && d.set) {
      Object.defineProperty(Element.prototype, prop, {
        configurable: true, enumerable: d.enumerable, get: d.get,
        set: function (v) { rec(prop, v); return d.set.call(this, v); }
      });
    }
  }
  for (const m of ["write", "writeln"]) {
    const o = document[m].bind(document);
    document[m] = function (s) { rec("document." + m, s); return o.apply(document, arguments); };
  }
  for (const m of ["assign", "replace"]) {
    try {
      const o = window.location[m].bind(window.location);
      window.location[m] = function (u) { rec("location." + m, u); return o(u); };
    } catch (e) {}
  }
  for (const m of ["pushState", "replaceState"]) {
    const o = history[m].bind(history);
    history[m] = function (s, t, u) {
      try { if (u !== undefined && u !== null) window.__omega.routes.push(String(u)); } catch (e) {}
      return o(s, t, u);
    };
  }
  const of_ = window.fetch;
  if (of_) {
    window.fetch = function (input) {
      try {
        window.__omega.api.push(String(typeof input === "string" ? input : (input && input.url) || ""));
      } catch (e) {}
      return of_.apply(this, arguments);
    };
  }
  const xo = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m, u) {
    try { window.__omega.api.push(String(u)); } catch (e) {}
    return xo.apply(this, arguments);
  };
  const oal = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, fn) {
    if (type === "message" && (this === window || this === self)) {
      window.__omega.msgs++;
      try { if (!String(fn).includes("origin")) window.__omega.msg_loose++; } catch (e) {}
    }
    return oal.apply(this, arguments);
  };
})()
"""

COLLECT_JS = r"""
(() => {
  const o = window.__omega || { sinks: [], routes: [], api: [], msgs: 0, msg_loose: 0 };
  const origin = window.location.origin;
  const urls = [];
  document.querySelectorAll("a[href]").forEach(a => {
    try {
      const u = new URL(a.href, window.location.href);
      if (u.origin === origin) urls.push(u.href.split("#")[0]);
    } catch (e) {}
  });
  const sensitive = [];
  const re = /token|password|secret|api[-_]?key/i;
  for (const pair of [["localStorage", window.localStorage],
                      ["sessionStorage", window.sessionStorage]]) {
    try {
      const store = pair[1];
      for (let i = 0; i < store.length; i++) {
        const k = store.key(i);
        const v = store.getItem(k);
        if (k && v && re.test(k)) {
          sensitive.push({ store: pair[0], key: String(k).slice(0, 80),
                           value: String(v).slice(0, 120) });
        }
      }
    } catch (e) {}
  }
  return { urls: urls, storage: sensitive, routes: o.routes || [],
           api: o.api || [], msgs: o.msgs || 0, msg_loose: o.msg_loose || 0 };
})()
"""

SINKS_JS = "(() => (window.__omega ? window.__omega.sinks : []))()"

MANUAL_XSS_PLAYWRIGHT = (
    "python -c \"from playwright.sync_api import sync_playwright; "
    "p = sync_playwright().start(); b = p.chromium.launch(); pg = b.new_page(); "
    "pg.goto('<URL>'); pg.evaluate('h => location.hash = h', "
    "'#OMEGADOMXSS<nonce>'); pg.wait_for_timeout(500); "
    "print(pg.content()); b.close(); p.stop()\"  # inspect rendered DOM for the marker"
)


# --------------------------------------------------------------------------
# Finding helpers (pure; unit-testable without a browser)
# --------------------------------------------------------------------------

def _base(source_kind, title, severity, location, evidence,
          verification, manual_check, note=""):
    f = {
        "title": title,
        "severity": severity,
        "confidence": "high" if verification == "confirmed" else "medium",
        "verification": verification,
        "verification_note": note or f"{_SRC}/{source_kind} observation",
        "manual_check": manual_check,
        "location": location,
        "evidence": evidence,
        "source": f"{_SRC}/{source_kind}",
    }
    return f


def _location_pieces(href):
    """(hash_content, [query values]) of a URL, both possibly empty."""
    h, q = "", []
    rest = str(href or "")
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        h = frag
    if "?" in rest:
        qs = rest.split("?", 1)[1]
        for part in qs.split("&"):
            if "=" in part:
                q.append(part.split("=", 1)[1])
            elif part:
                q.append(part)
    return h, q


def _location_reflected(value, href):
    """True when `value` contains content derived from the location's
    hash or query string (attacker-influenced reflection heuristic)."""
    h, q = _location_pieces(href)
    if h and len(h) >= 3 and h in value:
        return True
    return any(v and len(v) >= 3 and v in value for v in q)


def sink_findings(sinks, marker):
    """Classify recorded sink evaluations against the marker token.

    confirmed: the marker (injected ONLY via location.hash) appears in
    a sink value during evaluation. candidate: a sink executed with
    location hash/query content reflected but the marker did not reach
    it. Deduplicates per (kind, first-80-chars of value).
    """
    findings, seen = [], set()
    for s in sinks or []:
        if not isinstance(s, dict):
            continue
        value = str(s.get("value") or "")
        kind = str(s.get("kind") or "unknown-sink")
        href = str(s.get("href") or "")
        if marker and marker in value:
            key = ("c", kind, value[:80])
            if key in seen:
                continue
            seen.add(key)
            findings.append(_base(
                "dom_xss", f"DOM XSS: location-derived value reaches {kind} sink",
                "high", href,
                f"sink {kind!r} evaluated with value containing marker "
                f"{marker!r} injected via location.hash (flow "
                f"location -> {kind} -> sink proven during evaluation)",
                "confirmed", MANUAL_XSS_PLAYWRIGHT,
                note="marker token entered the page only through "
                     "location.hash and reached the sink during evaluation"))
        elif _location_reflected(value, href):
            key = ("k", kind, value[:80])
            if key in seen:
                continue
            seen.add(key)
            findings.append(_base(
                "dom_xss", f"DOM sink {kind} executes with location-derived content",
                "medium", href,
                f"sink {kind!r} evaluated with value reflecting location "
                f"hash/query content {value[:120]!r}; marker differential "
                "not reached (candidate)",
                "candidate", MANUAL_XSS_PLAYWRIGHT))
    return findings


def storage_findings(entries):
    """Sensitive web-storage keys with values -> candidate findings."""
    findings = []
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        store = str(e.get("store") or "storage")
        key = str(e.get("key") or "")
        val = str(e.get("value") or "")
        findings.append(_base(
            "storage", f"Sensitive-looking value in {store}: {key!r}",
            "medium", None,
            f"{store}[{key!r}] holds a non-empty value "
            f"({val[:40]}{'...' if len(val) > 40 else ''}); "
            "key matches token/password/secret/api-key pattern (candidate)",
            "candidate",
            "curl -s <URL> and review the application's storage usage; "
            "confirm whether the value is a live credential and whether "
            "the page origin is shared with less-trusted content"))
    return findings


def postmessage_findings(msgs, msg_loose):
    """Loose-origin postMessage listeners -> one candidate MEDIUM."""
    if not msgs or not msg_loose:
        return []
    return [_base(
        "postmessage",
        "window 'message' handler without a visible origin check",
        "medium", None,
        f"{msg_loose} of {msgs} window message listener(s) never "
        "reference an origin check in their source; messages from any "
        "origin may be trusted (candidate)",
        "candidate",
        "In devtools: window.addEventListener('message', e => "
        "console.log(e.origin)); post from another origin and verify "
        "the handler processes it without validating e.origin")]


def console_findings(errors):
    """JS console errors as INFO findings, capped."""
    findings = []
    for err in (errors or [])[:CONSOLE_ERROR_CAP]:
        findings.append(_base(
            "console", "JavaScript console error during browser scan",
            "info", None, str(err)[:300],
            "candidate",
            "Reproduce in a browser devtools console on the target page "
            "and review whether the error leaks stack/path details"))
    return findings


# --------------------------------------------------------------------------
# scan_dom
# --------------------------------------------------------------------------

def scan_dom(base_url, timeout_s=30, fetch_limit=25, log=None):
    """One headless-chromium pass over `base_url`.

    Returns {findings, surface, ran, skipped}; when the browser is
    missing, {findings: [], surface: {}, ran: [], skipped: {browser:
    reason}}.
    """
    log = log or (lambda msg: None)
    if not browser_available():
        return {"findings": [], "surface": {}, "ran": [],
                "skipped": {"browser": "playwright chromium not available "
                                      "(install playwright + chromium)"}}

    import time
    nonce = uuid.uuid4().hex[:8]
    marker = MARKER_PREFIX + nonce
    deadline = time.monotonic() + max(1, int(timeout_s))
    findings = []
    surface = {"urls": [], "api_endpoints": []}
    sinks, data, console_errors = [], {}, []

    from playwright.sync_api import sync_playwright  # noqa: F401
    sync_playwright = _get_sync_playwright()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            ctx = browser.new_context()
            page = ctx.new_page()
            page.on("pageerror", lambda exc: console_errors.append(str(exc)))
            page.on("console", lambda m: console_errors.append(m.text)
                    if m.type == "error" else None)
            page.add_init_script(INIT_JS)

            visited, queue = set(), [str(base_url).split("#", 1)[0]]
            while queue and len(visited) < max(1, int(fetch_limit)) \
                    and time.monotonic() < deadline:
                url = queue.pop(0).split("#", 1)[0]
                if url in visited:
                    continue
                visited.add(url)
                log(f"[browser] visiting {url}")
                try:
                    page.goto(url, wait_until="domcontentloaded",
                              timeout=max(1000, int(
                                  (deadline - time.monotonic()) * 1000)))
                    page.wait_for_timeout(CRAWL_SETTLE_MS)
                except Exception as exc:
                    log(f"[browser] goto {url} failed: {exc}")
                    continue
                batch = page.evaluate(COLLECT_JS) or {}
                for u in batch.get("urls") or []:
                    if u not in visited and u not in queue \
                            and len(queue) < int(fetch_limit) * 2:
                        queue.append(u)
                for k in ("urls", "api"):
                    vals = batch.get(k) or []
                    key = "urls" if k == "urls" else "api_endpoints"
                    for v in vals:
                        if v and v not in surface[key]:
                            surface[key].append(v)
                surface.setdefault("routes", [])
                for r in batch.get("routes") or []:
                    if r and r not in surface["routes"]:
                        surface["routes"].append(r)
                data = batch

            # documented differential: the marker enters the page ONLY
            # via location.hash, then we give sinks a moment to fire
            try:
                page.evaluate("h => { window.location.hash = h; }", marker)
                page.wait_for_timeout(CRAWL_SETTLE_MS)
            except Exception as exc:
                log(f"[browser] marker injection failed: {exc}")
            try:
                sinks = page.evaluate(SINKS_JS) or []
            except Exception as exc:
                log(f"[browser] sink collection failed: {exc}")

            try:
                page.close()
                ctx.close()
            finally:
                browser.close()
        except Exception as exc:
            log(f"[browser] scan failed: {exc}")
            try:
                browser.close()
            except Exception:
                pass
            return {"findings": [], "surface": {}, "ran": [],
                    "skipped": {"browser": f"scan failed: "
                                           f"{type(exc).__name__}: {exc}"}}

    findings.extend(sink_findings(sinks, marker))
    findings.extend(storage_findings((data or {}).get("storage")))
    findings.extend(postmessage_findings((data or {}).get("msgs") or 0,
                                         (data or {}).get("msg_loose") or 0))
    findings.extend(console_findings(console_errors))

    surface["urls"] = surface["urls"][:URL_CAP]
    surface["api_endpoints"] = surface["api_endpoints"][:API_CAP]
    log(f"[browser] scan complete: {len(findings)} finding(s), "
        f"{len(surface['urls'])} url(s), "
        f"{len(surface['api_endpoints'])} api endpoint(s)")
    return {"findings": findings, "surface": surface,
            "ran": ["browser"], "skipped": {}}


# --------------------------------------------------------------------------
# run_browser_suite — the fusion/brain entry point (never raises)
# --------------------------------------------------------------------------

def run_browser_suite(target, budget=None, log=None, allowlist=None,
                      timeout_s=30, fetch_limit=25):
    """Allowlist-gated browser scan; degrades to a contained skip."""
    log = log or (lambda msg: None)
    try:
        from omega.probes import allowlist_ok
    except ImportError:
        def allowlist_ok(_t, _a=None):
            return True
    if allowlist is not None and not allowlist_ok(target, allowlist):
        log(f"[browser] target {target!r} not in allowlist — skipped")
        return {"findings": [], "surface": {}, "ran": [],
                "skipped": {"browser": "target not in allowlist"}}
    if budget is not None and int(budget) <= 0:
        return {"findings": [], "surface": {}, "ran": [],
                "skipped": {"browser": "budget exhausted"}}
    if not browser_available():
        return {"findings": [], "surface": {}, "ran": [],
                "skipped": {"browser": "playwright chromium not available "
                                      "(install playwright + chromium)"}}
    try:
        return scan_dom(target, timeout_s=timeout_s, fetch_limit=fetch_limit,
                        log=log)
    except Exception as exc:  # absolute containment
        log(f"[browser] suite failed: {exc}")
        return {"findings": [], "surface": {}, "ran": [],
                "skipped": {"browser": f"scan failed: "
                                       f"{type(exc).__name__}: {exc}"}}
