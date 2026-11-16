"""Hermetic tests for omega.deser (safe-signature deserialization
probes).

Local ThreadingHTTPServer fixtures that emit per-language error
fingerprints; loopback only. Verifies fingerprint classification,
baseline FP guard, magic-reflection low-confidence path, the
no-gadget-chain payload contract, budget/allowlist gates, never-raise,
and the candidate-only finding contract.
"""

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path
                                              .dirname(__import__("os")
                                                       .path.abspath(__file__))))

from omega.deser import (  # noqa: E402
    LANG_FINGERPRINTS,
    PAYLOADS,
    _payload_for,
    classify_response,
    registry,
    run_deser,
)
from omega.scanning.deepchecks import default_fetch  # noqa: E402


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
        # static baseline: no fingerprints on plain GETs
        self._send(200, "welcome")

    def do_POST(self):
        engine = type(self).engine
        ln = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(ln)
        if engine == "clean":
            self._send(200, "ok")
            return
        if engine == "static_fp":
            self._send(500, "java.io.StreamCorruptedException always")
            return
        if engine == "magic_echo":
            self._send(200, b"echo:" + data[:4].hex())
            return
        b64 = data.decode("latin-1", "replace")
        if engine == "java" and data.startswith(b"\xac\xed\x00\x05"):
            self._send(500, "java.io.StreamCorruptedException: invalid "
                            "stream header")
            return
        if engine == "java" and b64.startswith("qACEd") is False and \
                data[:1] == b"q":
            # base64-wrapped payload posted by the java_b64 probe
            self._send(500, "ClassNotFoundException: omega")
            return
        if engine == "php" and b'O:8:"OmegaStub"' in data:
            self._send(500, "unserialize(): Error at offset 0")
            return
        if engine == "python" and data.startswith(b"\x80\x04\x95"):
            self._send(500, "_pickle.UnpicklingError: unpickling failed")
            return
        self._send(200, "ok")


def _serve(engine):
    _Base.engine = engine
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Base)
    import threading
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def java_base():
    yield from _serve("java")


@pytest.fixture
def php_base():
    yield from _serve("php")


@pytest.fixture
def python_base():
    yield from _serve("python")


@pytest.fixture
def magic_base():
    yield from _serve("magic_echo")


@pytest.fixture
def staticfp_base():
    yield from _serve("static_fp")


@pytest.fixture
def clean_base():
    yield from _serve("clean")


class TestClassify:
    def test_java_fingerprints(self):
        hits = classify_response("java.io.StreamCorruptedException: x")
        assert ("java", "java.io.StreamCorruptedException") in hits

    def test_php_fingerprints(self):
        assert ("php", "unserialize()") in \
            classify_response("unserialize(): Error at offset 4")
        assert ("php", "wddx") in classify_response("wddx error")

    def test_python_fingerprints(self):
        assert ("python", "_pickle.UnpicklingError") in \
            classify_response("_pickle.UnpicklingError: invalid")
        assert ("python", "python/pickle") in \
            classify_response("python/pickle: bad stream")

    def test_no_fp_in_plain_text(self):
        assert classify_response("all systems normal") == []

    def test_fingerprint_tables_match_payloads(self):
        langs = {name.split("_")[0] for name, _lang in registry}
        assert {"java", "php", "python"} <= langs
        for lang in ("java", "php", "python"):
            assert LANG_FINGERPRINTS[lang]


class TestPayloadSafety:
    def test_java_payload_is_inert_marker(self):
        data = _payload_for("java")
        assert data.startswith(b"\xac\xed\x00\x05")
        assert b"omega-marker" in data
        # no class reference / no gadget content
        assert b"Runtime" not in data and b"Object" not in data

    def test_php_payload_is_stub_object(self):
        assert b'OmegaStub' in _payload_for("php")

    def test_python_payload_has_no_global_opcode(self):
        data = _payload_for("python")
        assert data.startswith(b"\x80\x04\x95")
        assert b"c" + b"\n" not in data  # no GLOBAL opcode
        assert b"cos" not in data and b"system" not in data

    def test_no_gadget_strings_anywhere(self):
        blob = b"".join(p or b"" for _n, p, _f, _note in PAYLOADS) + \
            str(LANG_FINGERPRINTS).encode()
        for gadget in (b"java.lang.Runtime", b"/bin/sh",
                       b"TemplatesImpl", b"eval(", b"popen"):
            assert gadget not in blob

    def test_base64_payload_is_aced_magic(self):
        import base64
        assert base64.b64decode(_payload_for("java_b64")).startswith(
            b"\xac\xed\x00\x05")


class TestProbes:
    def test_java_endpoint_flagged(self, java_base):
        out = run_deser(java_base, default_fetch)
        assert out["findings"]
        f = out["findings"][0]
        assert f["confidence"] == "high"
        assert "java" in f["source"] or "java" in f["title"]
        assert f["verification"] == "candidate"

    def test_php_endpoint_flagged(self, php_base):
        out = run_deser(php_base, default_fetch)
        assert out["findings"]
        assert any("unserialize()" in f["evidence"]
                   for f in out["findings"])

    def test_python_endpoint_flagged(self, python_base):
        out = run_deser(python_base, default_fetch)
        assert out["findings"]
        assert any("pickle" in f["evidence"].lower()
                   for f in out["findings"])

    def test_magic_echo_only_is_low_confidence(self, magic_base):
        out = run_deser(magic_base, default_fetch)
        for f in out["findings"]:
            assert f["confidence"] == "low"

    def test_static_fingerprint_baseline_guard(self, staticfp_base):
        # the error text is present on the GET baseline too -> the
        # differential guard must suppress the finding
        out = run_deser(staticfp_base, default_fetch)
        assert out["findings"] == []

    def test_clean_server_silent(self, clean_base):
        out = run_deser(clean_base, default_fetch)
        assert out["findings"] == []
        assert len(out["ran"]) == len(registry)


class TestSuite:
    def test_registry_names(self):
        assert [n for n, _l in registry] == ["java", "java_b64", "php",
                                             "python"]

    def test_finding_contract(self, java_base):
        out = run_deser(java_base, default_fetch)
        for f in out["findings"]:
            assert set(f) >= {"title", "severity", "confidence",
                              "verification", "verification_note",
                              "manual_check", "location", "evidence",
                              "source"}
            assert f["verification"] == "candidate"
            assert f["source"].startswith("omega-deser/")
            assert "no gadget" in f["verification_note"].lower() or \
                "INERT MARKER" in f["verification_note"]
            assert len(f["evidence"]) <= 300

    def test_allowlist_gate(self, clean_base):
        out = run_deser(clean_base, default_fetch,
                        allowlist=["https://other.example"])
        assert out["findings"] == []
        assert "not in allowlist" in out["skipped"]["__all__"]

    def test_budget_exhaustion_is_contained(self, clean_base):
        out = run_deser(clean_base, default_fetch, budget=2)
        assert any(v == "budget exhausted"
                   for v in out["skipped"].values())

    def test_never_raises_on_broken_fetch(self, clean_base):
        def broken(method, url, headers=None, body=None):
            raise OSError("refused")
        out = run_deser(clean_base, broken)
        assert out["findings"] == []
        assert len(out["skipped"]) == len(registry)
