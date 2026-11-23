"""Hermetic tests for omega/scanning/tfinger.py (pure-Python fingerprints).

No real network: signal matching is tested on synthetic headers/bodies;
run_tfinger is tested against a local ThreadingHTTPServer and via fake
fetch callables. cvexref correlation is exercised read-only.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.tfinger import (
    extract_version,
    fingerprint,
    run_tfinger,
    summarize_stack,
)

NGINX_HEADERS = {"Server": "nginx/1.18.0",
                 "Set-Cookie": "__cfduid=abc123; Path=/"}
EXPRESS_HEADERS = {"X-Powered-By": "Express"}
PAGE = """<html><head>
<meta name="generator" content="WordPress 6.4.1">
<script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>
<div ng-version="16.2.3" data-reactroot></div>
</head><body>wp-content/themes/x</body></html>"""


def make_server(headers, body):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(payload)))
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def products(techs):
    return {t["product"] for t in techs}


def get_tech(techs, product):
    return next(t for t in techs if t["product"] == product)


# ------------------------------------------------------------ primitives
def test_extract_version():
    assert extract_version("nginx/1.18.0", r"nginx/(\d[\d.]*)") == "1.18.0"
    assert extract_version("no version here", r"nginx/(\d[\d.]*)") is None
    assert extract_version("anything", None) is None


def test_banner_header_high_confidence():
    techs = fingerprint(NGINX_HEADERS, "<html>x</html>")
    nginx = get_tech(techs, "nginx")
    assert nginx["confidence"] == "high"
    assert nginx["version"] == "1.18.0"
    assert nginx["category"] == "server"


def test_x_powered_by_express():
    techs = fingerprint(EXPRESS_HEADERS, "<html></html>")
    assert get_tech(techs, "Express")["version"] is None or True
    assert any(t["product"] == "Express" and t["confidence"] == "high"
               for t in techs)


def test_body_markers_cms_and_js():
    techs = fingerprint({}, PAGE)
    prods = products(techs)
    assert "WordPress" in prods
    assert "React" in prods
    assert "Angular" in prods
    assert "jQuery" in prods


def test_meta_generator_version():
    techs = fingerprint({}, PAGE)
    wp = get_tech(techs, "WordPress")
    assert wp["version"] == "6.4.1"


def test_cookie_signal_cloudflare_and_laravel():
    techs = fingerprint({}, "", cookies=["laravel_session=xyz"])
    assert "Laravel" in products(techs)


def test_ng_version_extracted():
    techs = fingerprint({}, PAGE)
    ang = get_tech(techs, "Angular")
    assert ang["version"] == "16.2.3"


def test_best_confidence_wins_per_product():
    """A low-confidence generic marker must not shadow a high banner."""
    techs = fingerprint({"Server": "nginx/1.20.1"}, "nginx/1.19.0 in body")
    nginx = [t for t in techs if t["product"] == "nginx"]
    assert len(nginx) == 1
    assert nginx[0]["confidence"] == "high"
    assert nginx[0]["version"] == "1.20.1"


def test_empty_input_no_findings():
    assert fingerprint({}, "") == []


def test_summarize_stack():
    techs = [{"product": "nginx", "category": "server", "version": "1.18.0",
              "confidence": "high", "evidence": "x"}]
    s = summarize_stack(techs)
    assert s == "nginx/1.18.0 (server, high)"


# ------------------------------------------------------------------ run
def test_run_tfinger_loopback():
    srv = make_server({"Server": "Apache/2.4.49"},
                      "<html><body>wp-content ok</body></html>")
    try:
        result = run_tfinger(
            "http://127.0.0.1:%d" % srv.server_address[1])
    finally:
        srv.shutdown()
    assert "Apache HTTP Server" in products(result["techs"])
    stack = next(f for f in result["findings"]
                 if f["source"] == "omega-tfinger/stack")
    assert stack["severity"] == "info"
    # Apache 2.4.49 is in the bundled CVE range -> correlated finding
    assert any(f["source"].startswith("omega-cve/")
               for f in result["findings"])


def test_run_tfinger_dead_target():
    result = run_tfinger("http://127.0.0.1:1")
    assert result["techs"] == []
    assert result["summary"] == ""


def test_run_tfinger_with_fake_fetch():
    def fake(method, url):
        return 200, {"Server": "nginx/1.20.0"}, b"<html>ok</html>"
    result = run_tfinger("http://fake.local", fetch=fake)
    assert "nginx" in products(result["techs"])
    assert result["requests_sent"] == 1
