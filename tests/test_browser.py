"""Tests for omega/browser.py — headless-browser scanning layer.

Hermetic:
  * All logic tests (sink classification, storage/postMessage/console
    helpers, brain capability wiring, fusion SUITES entry) run against
    stubbed sync_playwright fakes / pure data — no browser needed.
  * Exactly two tests exercise a real chromium via a local
    ThreadingHTTPServer (marker-differential path + clean-page FP
    guard) and are SKIPPED when the browser is not available.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))))

from omega import browser as br  # noqa: E402
from omega.brain import (  # noqa: E402
    Capability,
    CapabilityRegistry,
    BrainState,
    default_registry,
)
from omega.fusion import SUITES, _suite_browser, fuse  # noqa: E402


# ------------------------------------------------------------- availability

def test_browser_available_bool():
    result = br.browser_available()
    assert isinstance(result, bool)


def test_browser_available_false_without_playwright(monkeypatch):
    def boom():
        raise ImportError("no playwright")
    monkeypatch.setattr(br, "_chromium_executable", boom)
    assert br.browser_available() is False


def test_browser_available_false_missing_binary(monkeypatch, tmp_path):
    monkeypatch.setattr(br, "_chromium_executable",
                        lambda: str(tmp_path / "nope" / "chrome"))
    assert br.browser_available() is False


# ------------------------------------------------------- pure helper logic

def test_sink_findings_confirmed_marker_reaches_sink():
    marker = "OMEGADOMXSSdeadbeef"
    sinks = [{"kind": "innerHTML", "value": f"<b>{marker}</b>",
              "href": "http://x/#" + marker}]
    fs = br.sink_findings(sinks, marker)
    assert len(fs) == 1
    f = fs[0]
    assert f["verification"] == "confirmed"
    assert f["severity"] == "high"
    assert f["source"] == "omega-browser/dom_xss"
    assert marker in f["evidence"]
    assert f["manual_check"]


def test_sink_findings_candidate_location_reflection_only():
    sinks = [{"kind": "document.write",
              "value": "welcome user gustavo",
              "href": "http://x/page?name=gustavo"}]
    fs = br.sink_findings(sinks, "OMEGADOMXSSother")
    assert len(fs) == 1
    f = fs[0]
    assert f["verification"] == "candidate"
    assert f["severity"] == "medium"
    assert "candidate" in f["evidence"].lower()


def test_sink_findings_no_finding_without_location_content():
    assert br.sink_findings(
        [{"kind": "innerHTML", "value": "static text",
          "href": "http://x/page"}], "OMEGADOMXSSn") == []
    assert br.sink_findings([], "OMEGADOMXSSn") == []
    assert br.sink_findings([None, "junk", 42], "OMEGADOMXSSn") == []


def test_sink_findings_deduplicates():
    marker = "OMEGADOMXSSaa"
    sinks = [{"kind": "innerHTML", "value": marker, "href": "http://x"},
             {"kind": "innerHTML", "value": marker, "href": "http://x"}]
    assert len(br.sink_findings(sinks, marker)) == 1


def test_storage_findings():
    fs = br.storage_findings([
        {"store": "localStorage", "key": "auth_token", "value": "abc.def"},
        {"store": "sessionStorage", "key": "session_password", "value": "x" * 100},
    ])
    assert len(fs) == 2
    assert all(f["source"] == "omega-browser/storage" for f in fs)
    assert all(f["verification"] == "candidate" for f in fs)
    assert "localStorage" in fs[0]["evidence"]
    assert len(fs[1]["evidence"]) < 300


def test_postmessage_findings_loose_origin():
    assert br.postmessage_findings(0, 0) == []
    assert br.postmessage_findings(2, 0) == []
    fs = br.postmessage_findings(3, 2)
    assert len(fs) == 1
    assert fs[0]["source"] == "omega-browser/postmessage"
    assert fs[0]["severity"] == "medium"
    assert fs[0]["verification"] == "candidate"
    assert "2 of 3" in fs[0]["evidence"]


def test_console_findings_capped_at_10():
    errs = [f"error {i}" for i in range(25)]
    fs = br.console_findings(errs)
    assert len(fs) == 10
    assert all(f["source"] == "omega-browser/console" for f in fs)
    assert all(f["severity"] == "info" for f in fs)
    assert br.console_findings([]) == []


# --------------------------------------------- scan_dom with a fake browser

class FakePage:
    """Minimal page double: dispatches on omega.browser's JS constants."""

    def __init__(self, script):
        self.script = script
        self.init_scripts = []
        self.hash_set = None
        self._listeners = {}

    def add_init_script(self, js):
        self.init_scripts.append(js)

    def on(self, ev, fn):
        self._listeners.setdefault(ev, []).append(fn)

    def goto(self, url, **kw):
        self.url = url

    def wait_for_timeout(self, ms):
        pass

    def evaluate(self, js, *args):
        if "location.hash" in js and args:
            # marker injection; the fixture page's sink then "fires"
            self.hash_set = args[0]
            if self.script.get("sink_kinds"):
                for kind in self.script["sink_kinds"]:
                    self.script["sinks"].append(
                        {"kind": kind,
                         "value": self.script["sink_value"](self.hash_set),
                         "href": (self.url or "") + "#" + self.hash_set})
            return None
        if js == br.SINKS_JS:
            return self.script.get("sinks", [])
        if js == br.COLLECT_JS:
            return self.script.get("collect", {})
        return None

    def close(self):
        pass


class FakeContext:
    def __init__(self, script):
        self.script = script

    def new_page(self):
        return FakePage(self.script)

    def close(self):
        pass


class FakeBrowser:
    def __init__(self, script):
        self.script = script

    def new_context(self):
        return FakeContext(self.script)

    def close(self):
        pass


class FakePW:
    def __init__(self, script):
        self.script = script

    def __call__(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    @property
    def chromium(self):
        launcher = lambda **kw: FakeBrowser(self.script)
        launcher.executable_path = "/usr/bin/fake-chrome"
        return type("C", (), {"launch": staticmethod(launcher),
                              "executable_path": "/usr/bin/fake-chrome"})()


def _with_fake_browser(monkeypatch, script):
    monkeypatch.setattr(br, "_get_sync_playwright",
                        lambda: FakePW(script))
    monkeypatch.setattr(br, "browser_available", lambda: True)


def test_scan_dom_confirmed_via_fake(monkeypatch):
    marker_re = None
    script = {
        "sink_kinds": ["innerHTML"],
        "sinks": [],
        # sink value echoes the injected hash -> marker reaches the sink
        "sink_value": lambda h: "<b>" + h + "</b>",
        "collect": {"urls": ["http://x/2"], "api": ["/api/v1/me"],
                    "routes": ["/spa/route"], "storage": [], "msgs": 0,
                    "msg_loose": 0},
    }
    _with_fake_browser(monkeypatch, script)
    out = br.scan_dom("http://x/", timeout_s=10, fetch_limit=5)
    assert out["ran"] == ["browser"] and out["skipped"] == {}
    dom = [f for f in out["findings"] if f["source"] == "omega-browser/dom_xss"]
    assert len(dom) == 1 and dom[0]["verification"] == "confirmed"
    assert out["surface"]["urls"] == ["http://x/2"]
    assert out["surface"]["api_endpoints"] == ["/api/v1/me"]
    assert out["surface"]["routes"] == ["/spa/route"]
    # marker actually went through location.hash only
    assert script["sinks"][0]["value"].count("OMEGADOMXSS") == 1


def test_scan_dom_clean_page_fp_guard(monkeypatch):
    script = {
        "sinks": [],
        "collect": {"urls": [], "api": [], "routes": [], "storage": [],
                    "msgs": 0, "msg_loose": 0},
    }
    _with_fake_browser(monkeypatch, script)
    out = br.scan_dom("http://clean/", timeout_s=10, fetch_limit=5)
    assert out["findings"] == []
    assert out["ran"] == ["browser"]


def test_scan_dom_skips_without_browser(monkeypatch):
    monkeypatch.setattr(br, "browser_available", lambda: False)
    out = br.scan_dom("http://x/")
    assert out["ran"] == []
    assert "browser" in out["skipped"]


def test_scan_dom_fake_console_and_storage(monkeypatch):
    script = {
        "sinks": [{"kind": "innerHTML", "value": "OMEGADOMXSSzz token",
                   "href": "http://x/#OMEGADOMXSSzz"}],
        "collect": {"urls": [], "api": [], "routes": [],
                    "storage": [{"store": "localStorage",
                                 "key": "api_key", "value": "s3cr3t"}],
                    "msgs": 1, "msg_loose": 1},
    }
    _with_fake_browser(monkeypatch, script)

    class _P(FakePage):
        def on(self, ev, fn):
            if ev == "pageerror":
                fn("ReferenceError: x is not defined")

    orig = FakeContext.new_page

    def new_page(self):
        p = orig(self)
        p.__class__ = _P
        return p
    monkeypatch.setattr(FakeContext, "new_page", new_page)
    out = br.scan_dom("http://x/", timeout_s=10)
    kinds = sorted(f["source"] for f in out["findings"])
    assert "omega-browser/dom_xss" in kinds
    assert "omega-browser/console" in kinds
    assert "omega-browser/storage" in kinds
    assert "omega-browser/postmessage" in kinds
    # the fake sink saw the hash content but not the exact marker token:
    # honest classification is candidate, never confirmed
    dom = [f for f in out["findings"]
           if f["source"] == "omega-browser/dom_xss"]
    assert len(dom) == 1 and dom[0]["verification"] == "candidate"
    assert not [f for f in out["findings"]
                if f["verification"] == "confirmed"]


# -------------------------------------------------------- run_browser_suite

def test_run_browser_suite_allowlist_gate(monkeypatch):
    monkeypatch.setattr(br, "browser_available", lambda: True)
    out = br.run_browser_suite("http://evil.example/", allowlist=["good.test"])
    assert out["ran"] == []
    assert "allowlist" in out["skipped"]["browser"]


def test_run_browser_suite_never_raises(monkeypatch):
    monkeypatch.setattr(br, "browser_available", lambda: True)

    def boom(*a, **kw):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(br, "scan_dom", boom)
    out = br.run_browser_suite("http://x/", allowlist=None)
    assert out["ran"] == []
    assert "scan failed" in out["skipped"]["browser"]


def test_run_browser_suite_budget(monkeypatch):
    called = {}

    def fake_scan(target, **kw):
        called["t"] = target
        return {"findings": [], "surface": {}, "ran": ["browser"],
                "skipped": {}}
    monkeypatch.setattr(br, "browser_available", lambda: True)
    monkeypatch.setattr(br, "scan_dom", fake_scan)
    assert br.run_browser_suite("http://x/", budget=0)["skipped"]
    out = br.run_browser_suite("http://x/", budget=5, allowlist=["x"])
    assert out["ran"] == ["browser"] and called["t"] == "http://x/"


# --------------------------------------------------------- brain capability

def test_brain_browser_scan_capability_metadata():
    reg = default_registry()
    cap = reg.get("browser.scan")
    assert cap is not None
    assert cap.cost == 5
    assert cap.risk == "active"
    assert cap.kind == "probe"
    assert cap.requires == ("has_web",)
    count, problems = reg.audit()
    assert problems == []


def test_brain_browser_scan_duplicate_guard():
    reg = default_registry()
    with pytest.raises(ValueError):
        reg.register(Capability("browser.scan", "probe",
                                lambda s, b=None: {}, cost=5))


def test_brain_browser_scan_eligibility():
    reg = default_registry()
    cap = reg.get("browser.scan")
    assert not cap.eligible({"has_web": False})
    assert not cap.eligible({"has_web": True}, budget_remaining=4)
    assert cap.eligible({"has_web": True}, budget_remaining=5)


def test_brain_browser_scan_contained():
    reg = default_registry()
    cap = reg.get("browser.scan")
    state = BrainState("http://x/")
    # no exception even though omega.browser.run_browser_suite is real;
    # the allowlist gate / contained suite keeps it a note
    result = cap.fn(state, None)
    assert isinstance(result, dict)
    assert "findings" in result and "note" in result


# ------------------------------------------------------------ fusion wiring

def test_fusion_suites_has_browser_entry():
    names = [(n, lang) for n, lang, _ in SUITES]
    assert ("python-browser", "python") in names


def test_fusion_browser_suite_contained_skip(monkeypatch):
    monkeypatch.setattr(br, "browser_available", lambda: False)
    with pytest.raises(RuntimeError) as ei:
        _suite_browser("http://x/", {"budget": 5, "log": lambda m: None,
                                     "allowlist": None})
    assert "skipped" in str(ei.value)


def test_fuse_with_only_browser_suite(monkeypatch):
    # fuse() must contain the browser-suite skip: replace SUITES so only
    # the browser suite runs, then check the skipped entry.
    import omega.fusion as fus
    monkeypatch.setattr(br, "browser_available", lambda: False)
    orig = fus.SUITES
    monkeypatch.setattr(fus, "SUITES",
                        (("python-browser", "python", _suite_browser),))
    try:
        out = fuse("http://127.0.0.1:1/", budget=5)
    finally:
        monkeypatch.setattr(fus, "SUITES", orig)
    # no browser suite ran; jq hygiene (on zero findings) may still add
    # its own ran entry
    assert "python-browser" not in out["ran"]
    assert any(s["suite"] == "python-browser" for s in out["skipped"])


# ------------------------------------------------- real browser (optional)

VULN_PAGE = """<!doctype html><html><body>
<div id="s"></div>
<script>
  function render() {
    document.getElementById('s').innerHTML = "Hi " + location.hash.slice(1);
  }
  window.addEventListener('hashchange', render);
  render();
</script>
</body></html>"""

CLEAN_PAGE = """<!doctype html><html><body>
<h1>Nothing to see here</h1>
<a href="/page2">next</a>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        page = VULN_PAGE if self.path.startswith("/vuln") else CLEAN_PAGE
        body = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def local_site():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.mark.skipif(not br.browser_available(),
                    reason="playwright chromium not available")
def test_real_browser_marker_differential(local_site):
    out = br.scan_dom(local_site + "/vuln", timeout_s=45, fetch_limit=3,
                      log=lambda m: None)
    assert out["ran"] == ["browser"] and not out["skipped"]
    dom = [f for f in out["findings"]
           if f["source"] == "omega-browser/dom_xss"]
    assert dom, "expected a DOM-XSS finding on the sink fixture page"
    assert any(f["verification"] == "confirmed" for f in dom), \
        "marker injected via location.hash must reach the innerHTML sink"
    assert all("OMEGADOMXSS" in f["evidence"] or f["verification"] == "candidate"
               for f in dom)


@pytest.mark.skipif(not br.browser_available(),
                    reason="playwright chromium not available")
def test_real_browser_clean_page_fp_guard(local_site):
    out = br.scan_dom(local_site + "/clean", timeout_s=45, fetch_limit=3,
                      log=lambda m: None)
    assert out["ran"] == ["browser"] and not out["skipped"]
    assert out["findings"] == [], \
        f"clean page must produce no findings: {json.dumps(out['findings'])}"
