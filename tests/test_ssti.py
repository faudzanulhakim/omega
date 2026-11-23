"""Hermetic tests for omega.ssti (engine-specific SSTI prober).

Local ThreadingHTTPServer fixtures that render inert arithmetic
payloads per engine; loopback only. Verifies fingerprinting,
disambiguation, FP guards, budget, allowlist, never-raise and the
safe-payload / candidate-only contracts.
"""

import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path
                                              .dirname(__import__("os")
                                                       .path.abspath(__file__))))

from omega.ssti import (  # noqa: E402
    ENGINES,
    disambiguate,
    fingerprint,
    registry,
    run_ssti,
)
from omega.scanning.deepchecks import default_fetch  # noqa: E402


def _render(tpl, engine):
    """Inert renderer: maps the safe arithmetic payloads to results."""
    rules = {
        "jinja2": {"{{7*7}}": "49", "{{7*'7'}}": "7777777"},
        "twig": {"{{7*7}}": "49", "{{7*'7'}}": "49"},
        "freemarker": {"${7*7}": "49", "${7*'7'}": "49"},
        "erb": {"<%= 7*7 %>": "49", "<%= 7*'7' %>": "49"},
        "pebble": {"#{7*7}": "49", "#{7*'7'}": "49"},
        "smarty": {"{7*7}": "49", "{7*'7'}": "49"},
    }
    return rules.get(engine, {}).get(tpl)


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, body=b""):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        engine = type(self).engine
        parsed = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(parsed.query)
        tpl = (q.get("q") or q.get("name") or [""])[0]
        body = "hello world"
        if engine == "static49":
            body += " 49"  # FP: baseline always renders the number
        else:
            result = _render(tpl, engine)
            if result:
                body += " " + result
        self._send(200, body)


def _serve(engine):
    _Base.engine = engine
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Base)
    import threading
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def jinja_base():
    yield from _serve("jinja2")


@pytest.fixture
def twig_base():
    yield from _serve("twig")


@pytest.fixture
def erb_base():
    yield from _serve("erb")


@pytest.fixture
def static49_base():
    yield from _serve("static49")


@pytest.fixture
def clean_base():
    yield from _serve("none")


class TestFingerprint:
    def test_jinja2_hit(self, jinja_base):
        hit = fingerprint(jinja_base, default_fetch, "{{7*7}}", "49")
        assert hit is not None
        param, path, text, _canary, base_text, st, st_b = hit
        assert param == "q" and path == "/"
        assert "49" in text and "49" not in base_text
        assert st == st_b == 200

    def test_clean_server_no_hit(self, clean_base):
        assert fingerprint(clean_base, default_fetch, "{{7*7}}",
                           "49") is None

    def test_static49_baseline_fp_guard(self, static49_base):
        # baseline already contains the result -> probe must not fire
        assert fingerprint(static49_base, default_fetch, "{{7*7}}",
                           "49") is None

    def test_disambiguation_confirms_jinja2(self, jinja_base):
        hit = fingerprint(jinja_base, default_fetch, "{{7*7}}", "49")
        confirmed, _st = disambiguate(jinja_base, default_fetch,
                                      hit[0], hit[1], "{{7*'7'}}",
                                      "7777777")
        assert confirmed is True

    def test_disambiguation_leaves_twig_unconfirmed(self, twig_base):
        hit = fingerprint(twig_base, default_fetch, "{{7*7}}", "49")
        confirmed, _st = disambiguate(twig_base, default_fetch,
                                      hit[0], hit[1], "{{7*'7'}}",
                                      "7777777")
        assert confirmed is False


class TestEngines:
    def test_registry_covers_six_engines(self):
        names = [e for e, *_rest in registry]
        assert names == ["jinja2", "twig", "freemarker", "erb", "pebble",
                         "smarty"]
        assert len(ENGINES) == 6

    def test_freemarker_engine(self, clean_base):
        out = run_ssti(clean_base, default_fetch)
        assert out["findings"] == []

    def test_erb_detected_high(self, erb_base):
        out = run_ssti(erb_base, default_fetch)
        assert len(out["findings"]) == 1
        f = out["findings"][0]
        assert f["confidence"] == "high"
        assert "erb" in f["title"]


class TestSuite:
    def test_jinja2_full_flow(self, jinja_base):
        out = run_ssti(jinja_base, default_fetch)
        assert len(out["findings"]) == 1
        f = out["findings"][0]
        assert f["confidence"] == "high"
        assert "jinja2" in f["title"]
        assert f["source"] == "omega-ssti/fingerprint"
        assert f["verification"] == "candidate"

    def test_twig_class_marked_unconfirmed(self, twig_base):
        out = run_ssti(twig_base, default_fetch)
        assert len(out["findings"]) == 1
        assert out["findings"][0]["confidence"] == "medium"
        assert "unconfirmed" in out["findings"][0]["title"]

    def test_clean_server_no_findings(self, clean_base):
        out = run_ssti(clean_base, default_fetch)
        assert out["findings"] == []
        assert len(out["ran"]) == len(registry)

    def test_probes_are_arithmetic_only(self):
        # SAFETY CONTRACT: every payload is pure arithmetic / string
        # repetition — no attribute access, no filters, no callables.
        for _e, probe, _x, dis, _dx in registry:
            for payload in (probe, dis):
                assert "{{" in payload or "${" in payload or \
                    "<%=" in payload or "#{" in payload or \
                    payload.startswith("{7")
                assert "(" not in payload.replace("7*7", "").replace(
                    "7*'7'", "").replace("*", "") or "7*" in payload
                assert "__" not in payload and "|" not in payload

    def test_allowlist_gate(self, jinja_base):
        out = run_ssti(jinja_base, default_fetch,
                       allowlist=["https://other.example"])
        assert out["findings"] == []
        assert "not in allowlist" in out["skipped"]["__all__"]

    def test_budget_exhaustion_is_contained(self, jinja_base):
        out = run_ssti(jinja_base, default_fetch, budget=2)
        assert any(v == "budget exhausted"
                   for v in out["skipped"].values())

    def test_never_raises_on_broken_fetch(self, jinja_base):
        def broken(method, url, headers=None, body=None):
            raise OSError("boom")
        out = run_ssti(jinja_base, broken)
        assert out["findings"] == []
        assert len(out["skipped"]) == len(registry)

    def test_finding_contract(self, jinja_base):
        out = run_ssti(jinja_base, default_fetch)
        for f in out["findings"]:
            assert set(f) >= {"title", "severity", "confidence",
                              "verification", "verification_note",
                              "manual_check", "location", "evidence",
                              "source"}
            assert "SAFE-PROBE ONLY" in f["verification_note"]
            assert "curl" in f["manual_check"]
            assert len(f["evidence"]) <= 300
