"""Hermetic tests for the AI-claim validation gate (omega validate)."""
import json
import os
import sys
import tempfile
import threading
import http.server

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from omega.scanning.claimcheck import (  # noqa: E402
    validate_claim, validate_claims, _evidence_present)


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/vuln":
            body = b"leaked-secret-value 123"
            self.send_response(200)
        elif self.path == "/refl":
            body = b"user said: anything-echoed"
            self.send_response(200)
        elif self.path == "/gone":
            self.send_response(404)
            body = b"not found"
        else:
            body = b"hello"
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


def _server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, "http://127.0.0.1:%d" % srv.server_port


srv, BASE = _server()


def teardown_module(module):
    srv.shutdown()


def test_verified_substring_evidence():
    claim = {"title": "secret exposure", "severity": "high",
             "location": BASE + "/vuln", "evidence": "leaked-secret-value"}
    out = validate_claim(claim)
    assert out["validation"] == "verified"
    assert out["verification"] == "confirmed"
    assert "ai-claim:validated" in out["tags"]


def test_refuted_hallucination():
    claim = {"title": "invented sqli", "severity": "critical",
             "verification": "confirmed", "location": BASE + "/hello",
             "evidence": "this-string-never-exists"}
    out = validate_claim(claim)
    assert out["validation"] == "refuted"
    assert out["severity"] == "LOW"  # critical downgraded
    assert out["refuted_by"] == "omega-validate"


def test_regex_evidence():
    claim = {"title": "pattern", "location": BASE + "/vuln",
             "evidence": "re:leaked-secret-\\w+"}
    assert validate_claim(claim)["validation"] == "verified"


def test_regex_invalid_is_refuted():
    claim = {"title": "bad regex", "location": BASE + "/vuln",
             "evidence": "re:["}
    out = validate_claim(claim)
    assert out["validation"] == "refuted"
    assert "regex-invalid" in out["validation_note"]


def test_structured_evidence():
    claim = {"title": "structured", "location": BASE + "/vuln",
             "evidence": {"marker": "leaked-secret-value", "n": 1}}
    out = validate_claim(claim)
    assert out["validation"] == "verified"
    assert out["validation_note"].startswith("evidence reproduced")


def test_unverifiable_no_location():
    out = validate_claim({"title": "no loc", "evidence": "x"})
    assert out["validation"] == "unverifiable"


def test_unreachable_404():
    claim = {"title": "gone", "location": BASE + "/gone",
             "evidence": "never-exists-xyz"}
    assert validate_claim(claim)["validation"] == "unreachable"


def test_unreachable_but_evidence_present_is_not_unreachable():
    claim = {"title": "gone", "location": BASE + "/gone",
             "evidence": "not found"}
    out = validate_claim(claim)
    assert out["validation"] == "verified"


def test_relative_location_with_base():
    claim = {"title": "rel", "location": "/vuln",
             "evidence": "leaked-secret-value"}
    out = validate_claim(claim, base_url=BASE)
    assert out["validation"] == "verified"


def test_stats_counts():
    claims = [{"title": "a", "location": BASE + "/vuln",
               "evidence": "leaked-secret-value"},
              {"title": "b", "location": BASE + "/hello",
               "evidence": "hallucinated-evidence"}]
    results, stats = validate_claims(claims)
    assert stats["verified"] == 1 and stats["refuted"] == 1


def test_never_raises_on_junk():
    for junk in (None, 42, {"location": 1}, {"evidence": {"x": ["y"]}}):
        out = validate_claim(junk)
        assert out.get("validation") in ("unverifiable", "unreachable",
                                         "verified", "refuted")


def test_evidence_present_helper():
    assert _evidence_present("abc", 200, {}, "xx abc yy")[0] is True
    assert _evidence_present({"a": "long-string-ok"}, 200, {}, "")[1] == \
        "evidence-keys:0/1"
    assert _evidence_present("", 200, {}, "")[0] is True


def test_cli_validate_end_to_end():
    from omega.core.cli import main
    claims = [{"title": "real", "severity": "high",
               "location": "/vuln", "evidence": "leaked-secret-value"},
              {"title": "fake", "severity": "critical",
               "verification": "confirmed", "location": "/hello",
               "evidence": "made-up-evidence-string"}]
    with tempfile.NamedTemporaryFile("w", suffix=".json",
                                     delete=False) as fh:
        json.dump(claims, fh)
        path = fh.name
    try:
        rc = main(["validate", path, "--base", BASE])
        assert rc == 2  # refuted present -> nonzero gate
        rc = main(["validate", path, "--base", BASE, "--json",
                   "--drop-refuted"])
        assert rc == 0
    finally:
        os.unlink(path)
