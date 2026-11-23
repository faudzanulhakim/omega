"""Hermetic tests for omega.jsrender (no real browser except one guarded test)."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import omega.jsrender as jsr


# ---------------------------------------------------------------------------
# Missing-playwright path
# ---------------------------------------------------------------------------

def test_missing_playwright_returns_skipped_shape(monkeypatch):
    monkeypatch.setattr(jsr, "playwright_available", lambda: False)
    res = jsr.run_jsrender("http://127.0.0.1:1/x")
    assert res["findings"] == []
    assert res["requests_sent"] == 0
    assert res["ran"] == []
    assert res["skipped"]["jsrender"] == "playwright/chromium unavailable"


def test_no_target_skips():
    res = jsr.run_jsrender("")
    assert res["skipped"] and res["findings"] == []


# ---------------------------------------------------------------------------
# rendered_vs_static_diff classification
# ---------------------------------------------------------------------------

def test_diff_fires_on_js_only_secret():
    static = "<html><body>hello</body></html>"
    rendered = static + "<div>key: AKIAABCDEFGHIJKLMNOP</div>"
    findings = jsr.diff_findings(static, rendered)
    assert any(f["severity"] == "high" and f["verification"] == "candidate"
               and "AKIA" in f["evidence"] for f in findings)


def test_diff_ignores_secret_present_in_static():
    static = "<html>AKIAABCDEFGHIJKLMNOP</html>"
    rendered = "<html>AKIAABCDEFGHIJKLMNOP<br>more</html>"
    assert not [f for f in jsr.diff_findings(static, rendered)
                if f["severity"] == "high"]


def test_diff_internal_hostname_is_low_candidate():
    static = "<p>ok</p>"
    rendered = "<p>ok</p><span>db.prod.internal:5432</span>"
    findings = jsr.diff_findings(static, rendered)
    assert any(f["severity"] == "low" and "internal" in f["title"].lower()
               for f in findings)


def test_diff_no_change_no_findings():
    assert jsr.diff_findings("<p>x</p>", "<p>x</p>") == []


def test_diff_big_change_without_secrets_is_info():
    static = "<p>x</p>"
    rendered = "<p>x</p>" + "y" * 4000
    findings = jsr.diff_findings(static, rendered)
    assert len(findings) == 1 and findings[0]["severity"] == "info"


# ---------------------------------------------------------------------------
# console_error_capture
# ---------------------------------------------------------------------------

def test_console_keylike_error_is_high_candidate():
    findings = jsr.console_findings(
        ["TypeError: api_key 'sk_live_abcdef1234567890' invalid"])
    assert any(f["severity"] == "high" and f["verification"] == "candidate"
               for f in findings)


def test_console_stack_trace_is_low_candidate():
    findings = jsr.console_findings(["Uncaught\n    at foo (app.js:12:5)"])
    assert any(f["severity"] == "low" and "stack" in f["title"].lower()
               for f in findings)


def test_console_plain_error_is_info():
    findings = jsr.console_findings(["boom"])
    assert findings and findings[0]["severity"] == "info"


def test_page_errors_included():
    findings = jsr.analyze_render("<p></p>", "<p></p>", [], ["ReferenceError: token 'x' undefined"], [])
    assert any(f["severity"] == "high" for f in findings)


# ---------------------------------------------------------------------------
# api_call_discovery
# ---------------------------------------------------------------------------

def test_api_inventory_info_and_cred_json_candidate():
    responses = [
        {"url": "http://h/api/v1/users", "content_type": "application/json",
         "is_xhr": True, "body": '{"data": []}'},
        {"url": "http://h/api/v1/session", "content_type": "application/json",
         "is_xhr": True, "body": '{"user": "a", "password": "hunter2hunter2"}'},
    ]
    findings = jsr.api_findings(responses)
    assert any(f["severity"] == "info" and "endpoints" in f["title"].lower()
               for f in findings)
    assert any(f["severity"] == "medium" and f["verification"] == "candidate"
               and "session" in f["location"] for f in findings)


def test_api_no_responses_no_findings():
    assert jsr.api_findings([]) == []


# ---------------------------------------------------------------------------
# dom_injection_sinks
# ---------------------------------------------------------------------------

def test_sink_javascript_eval_href_is_low_candidate():
    html = '<a href="javascript:eval(atob(this.dataset.p))">x</a>'
    findings = jsr.sink_findings(html)
    assert len(findings) == 1
    assert findings[0]["severity"] == "low"
    assert findings[0]["verification"] == "candidate"


def test_sink_none_clean_html():
    assert jsr.sink_findings('<a href="/safe">x</a>') == []


# ---------------------------------------------------------------------------
# FP guard: page with no JS and no secrets -> zero findings
# ---------------------------------------------------------------------------

def test_fp_guard_plain_static_page_zero_findings():
    html = "<html><body><h1>About us</h1><p>Contact sales@example.com</p></body></html>"
    findings = jsr.analyze_render(html, html, [], [], [])
    assert findings == []


# ---------------------------------------------------------------------------
# run_jsrender orchestration with canned renders (no browser)
# ---------------------------------------------------------------------------

class _FakePage:
    def __init__(self, url, rendered, links=()):
        self.url = url
        self.rendered = rendered
        self.links = list(links)


def _install_fake_renders(monkeypatch, pages):
    calls = []

    def fake_render(url, log=None):
        calls.append(url)
        page = pages.get(url)
        if page is None:
            return None
        return {
            "url": url,
            "static_html": "<html>static</html>",
            "rendered_html": page.rendered,
            "title": "t",
            "console_errors": [],
            "page_errors": [],
            "responses": [],
            "links": page.links,
        }

    monkeypatch.setattr(jsr, "playwright_available", lambda: True)
    monkeypatch.setattr(jsr, "_render_page", fake_render)
    return calls


def test_budget_caps_renders_to_3(monkeypatch):
    pages = {
        "http://h/": _FakePage("http://h/", "<p>1</p>",
                               ["http://h/a", "http://h/b", "http://h/c"]),
        "http://h/a": _FakePage("http://h/a", "<p>2</p>", ["http://h/b"]),
        "http://h/b": _FakePage("http://h/b", "<p>3</p>"),
    }
    calls = _install_fake_renders(monkeypatch, pages)
    res = jsr.run_jsrender("http://h/", budget=3)
    assert len(calls) == 3
    assert res["requests_sent"] == 3
    assert res["ran"] == ["jsrender"]


def test_budget_one_only_target(monkeypatch):
    pages = {"http://h/": _FakePage("http://h/", "<p>1</p>", ["http://h/a"])}
    calls = _install_fake_renders(monkeypatch, pages)
    res = jsr.run_jsrender("http://h/", budget=1)
    assert calls == ["http://h/"]
    assert res["requests_sent"] == 1


def test_all_renders_fail_records_skipped(monkeypatch):
    monkeypatch.setattr(jsr, "playwright_available", lambda: True)
    monkeypatch.setattr(jsr, "_render_page", lambda url, log=None: None)
    res = jsr.run_jsrender("http://h/", budget=2)
    assert res["requests_sent"] == 0
    assert "jsrender" in res["skipped"]


def test_render_exception_contained(monkeypatch):
    monkeypatch.setattr(jsr, "playwright_available", lambda: True)

    def boom(url, log=None):
        raise RuntimeError("no browser")

    monkeypatch.setattr(jsr, "_render_page", boom)
    res = jsr.run_jsrender("http://h/")
    assert "jsrender" in res["skipped"]
    assert res["findings"] == []


# ---------------------------------------------------------------------------
# One real-render test (skipped automatically without playwright+chromium)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not jsr.playwright_available(),
                    reason="playwright/chromium unavailable")
def test_real_render_differential_fires_on_js_title_secret():
    pytest.importorskip("playwright")
    payload = {"rendered": None}
    marker = "OMEGARENDERSECRET" + "9f2c1ab7d4e8"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = (
                "<html><head><title>static title</title></head><body>"
                "<p>plain static page, nothing hidden here</p>"
                "<script>document.title = '%s';</script>"
                "</body></html>" % marker
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = "http://127.0.0.1:%d/" % server.server_address[1]
        res = jsr.run_jsrender(url, budget=1)
        payload["rendered"] = res
    finally:
        server.shutdown()
    res = payload["rendered"]
    assert res["skipped"] == {}
    assert res["requests_sent"] == 1
    assert res["ran"] == ["jsrender"]
    # The JS-only secret marker must produce a static-vs-rendered candidate.
    diffs = [f for f in res["findings"]
             if f["verification"] == "candidate"
             and ("rendered" in f["title"].lower() or "rendered" in f["location"])]
    assert diffs, "expected static-vs-rendered differential finding"
    assert any(marker in f["evidence"] for f in diffs)
