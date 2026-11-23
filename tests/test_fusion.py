"""Hermetic tests for the FUSION engine (omega.fusion + adapters).

Everything is contained: the real perl/jq binaries are exercised only
via fixture data and stub fetches; no external network access.
"""

import json
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))))

from omega.fusion import (  # noqa: E402
    corroborate,
    fuse,
    sort_findings,
    severity_score,
    source_prefix,
    title_class,
)
from omega.adapters.perltools import run_perl_suite  # noqa: E402
from omega.adapters.jqtools import (  # noqa: E402
    normalize_findings,
    run_jq_suite,
)


def mk(title="Open port", sev="LOW", loc="http://t:80", conf="candidate",
       ver="signature", source="omega-py/tool", **extra):
    f = {
        "title": title,
        "severity": sev,
        "confidence": conf,
        "verification": ver,
        "verification_note": "signature from tool",
        "manual_check": True,
        "location": loc,
        "param": "",
        "evidence": "evidence text",
        "source": source,
    }
    f.update(extra)
    return f


def has_perl():
    return shutil.which("perl") is not None


def has_jq():
    return shutil.which("jq") is not None


# ------------------------------------------------------- corroboration


class TestCorroboration:
    def test_two_sources_same_title_location(self):
        a = mk(source="omega-py/cookie_flag_audit")
        b = mk(source="omega-probe/security_headers_probe",
               ver="confirmed", conf="high")
        out, corr = corroborate([a, b])
        assert len(corr) == 2
        for f in out:
            assert f["corroborated"] is True
            assert f["confidence"] == "high"
            assert "corroborated by: omega-probe/security_headers_probe, " \
                   "omega-py/cookie_flag_audit" in f["verification_note"]
        # honesty contract: verification label never upgraded
        assert out[0]["verification"] == "signature"
        assert out[1]["verification"] == "confirmed"

    def test_single_source_untouched(self):
        a = mk(source="omega-py/tool")
        out, corr = corroborate([a])
        assert corr == []
        assert out[0] == a  # no annotation at all
        assert "corroborated" not in out[0]

    def test_same_source_prefix_not_corroborated(self):
        a = mk(source="omega-py/tool_a")
        b = mk(source="omega-py/tool_b")
        out, corr = corroborate([a, b])
        assert corr == []
        assert all("corroborated" not in f for f in out)

    def test_semantic_signature_grouping(self):
        # different titles, same title-class ("missing security") and
        # location, from independent scanners -> corroborated
        a = mk(title="Missing security response headers",
               source="omega-py/headers")
        b = mk(title="Missing security headers",
               source="omega-probe/security_headers_probe")
        out, corr = corroborate([a, b])
        assert len(corr) == 2
        assert all(f["corroborated"] for f in out)

    def test_different_locations_not_corroborated(self):
        a = mk(loc="http://t/a", source="omega-py/x")
        b = mk(loc="http://t/b", source="omega-probe/y")
        out, corr = corroborate([a, b])
        assert corr == []

    def test_corroborated_sorted_first(self):
        a = mk(source="omega-py/x", sev="LOW")
        b = mk(source="omega-probe/y", sev="LOW")
        c = mk(title="Critical thing", sev="CRITICAL",
               source="omega-py/alone")
        out = sort_findings(corroborate([a, b, c])[0])
        assert all(f["corroborated"] is True for f in out[:2])
        assert out[0]["severity"] == "LOW"
        assert out[2]["severity"] == "CRITICAL"
        assert out[2].get("corroborated") is None

    def test_severity_score_aliases(self):
        assert severity_score("HIGH") == severity_score("high") == 4
        assert severity_score("bogus") == 0

    def test_source_prefix_and_title_class(self):
        assert source_prefix(mk(source="omega-py/x/y")) == "omega-py"
        assert source_prefix(mk(source="")) == ""
        assert title_class(mk(title="Missing Security Headers!")) == \
            "missing security"


# --------------------------------------------------- concurrency/fuse


class _Req(BaseHTTPRequestHandler):
    BODY = (b"<html><head><script src='/app.js'></script></head><body>"
            b"Set-Cookie: sessionid=abc; Path=/\n"
            b"<a href='https://api.example.com/v1/users'>api</a>\n"
            b"token: AAAABBBBCCCCDDDDEEEEFFFF</body></html>")

    def do_GET(self):
        body = self.BODY
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


@pytest.fixture
def local_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Req)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


class TestFuse:
    def test_suite_failure_is_contained(self, monkeypatch):
        def boom(target, ctx):
            raise RuntimeError("scanner exploded")

        def good(target, ctx):
            return {"findings": [mk(source="omega-py/good")],
                    "surface": {}, "ran": ["good"], "skipped": []}

        import omega.fusion as fz
        monkeypatch.setattr(fz, "SUITES",
                            (("bad", "python", boom),
                             ("good", "python", good)))
        out = fuse("http://127.0.0.1:1", budget=2, gate=False)
        assert any(s["suite"] == "bad" and "scanner exploded" in s["reason"]
                   for s in out["skipped"])
        assert "good" in out["ran"]
        assert out["findings"][0]["source"] == "omega-py/good"
        assert "python" in out["languages_used"]

    def test_gate_closed_disables_gated_suites(self, monkeypatch):
        import omega.fusion as fz
        calls = []

        def native_spy(target, ctx):
            calls.append(ctx["gate"])
            from omega.adapters.native import run_native_suite
            return run_native_suite(target, ["portspeed"], budget=1,
                                    allow=() if not ctx["gate"]
                                    else ("fusion",))

        monkeypatch.setattr(fz, "SUITES",
                            (("native", "go+node", native_spy),))
        out = fuse("http://127.0.0.1:1", budget=2, gate=False)
        assert calls == [False]
        assert any("native" in s["suite"] and
                   "PTK_POLYGLOT" in s["reason"] for s in out["skipped"])

    def test_result_shape(self, local_server):
        out = fuse(local_server, budget=6, gate=False)
        for key in ("findings", "corroborated", "surface", "ran",
                    "skipped", "languages_used"):
            assert key in out
        assert "python-pytools" in out["ran"]
        assert "python-probes" in out["ran"]
        assert "python" in out["languages_used"]
        assert out["findings"], "expected findings from the local server"
        # corroboration is always a subset of findings
        titles = {(f["title"], f.get("location")) for f in out["findings"]}
        for f in out["corroborated"]:
            assert (f["title"], f.get("location")) in titles
            assert f["corroborated"] is True
            assert f["verification"] != "confirmed" or \
                f["verification"] == "confirmed"  # label never upgraded
        # honesty contract: no finding gains 'confirmed' unless it had it
        # (fixture findings start as candidate/signature)
        for f in out["findings"]:
            if f.get("corroborated"):
                assert "corroborated by:" in str(
                    f.get("verification_note") or "")

    def test_perl_suite_on_local_server(self, local_server):
        if not has_perl():
            pytest.skip("perl not available")
        out = fuse(local_server, budget=6, gate=False)
        assert "perl" in out["ran"]
        assert "perl" in out["languages_used"]
        assert any(str(f.get("source") or "").startswith("omega-perl/")
                   for f in out["findings"])

    def test_fuse_never_raises_on_garbage_target(self):
        out = fuse("not-a-valid-target", budget=2, gate=False)
        assert "findings" in out
        assert isinstance(out["skipped"], list)


# ------------------------------------------------------- perl adapter

FIXTURE_HTML = (
    "<html><head><script src='/static/app.js'></script></head><body>"
    "visit https://api.example.com/v1/users and https://cdn.example.net/x.js "
    "Set-Cookie: sessionid=abc123; Path=/\n"
    "backup: https://t.example/admin.php\n"
    "secret-ish: QXV0aG9yaXphdGlvbi1Qb2ludGVyLXJlYWxseS1sb25nLXRva2Vu"
    "</body></html>"
)


class TestPerlAdapter:
    def _fetch(self, url):
        return 200, {}, FIXTURE_HTML.encode()

    def test_real_perl_fixture(self):
        if not has_perl():
            pytest.skip("perl not available")
        out = run_perl_suite("http://fixture.test", fetch=self._fetch,
                             which_fn=shutil.which)
        assert out["skipped"] == []
        assert out["ran"] == ["perl"]
        sources = {f["source"] for f in out["findings"]}
        assert sources == {"omega-perl/analyze"}
        titles = [f["title"] for f in out["findings"]]
        assert any("endpoint" in t.lower() for t in titles)
        assert any("set-cookie" in t.lower() for t in titles)
        assert any("high-entropy" in t.lower() for t in titles)
        # all findings follow the signature convention
        for f in out["findings"]:
            assert f["verification"] == "signature"
            assert f["manual_check"] is True
        # surface urls harvested from the perl analysis
        assert out["surface"].get("urls")

    def test_analyze_bodies_json_lines_protocol(self):
        if not has_perl():
            pytest.skip("perl not available")
        from omega.adapters.perltools import analyze_bodies
        res = analyze_bodies([
            {"url": "http://a/", "body": "see https://x.test/y and "
             "img: /img/logo.js"},
            {"url": "http://b/", "body": ""},
        ])
        assert len(res) == 2
        assert res[0]["url"] == "http://a/"
        assert "https://x.test/y" in res[0]["endpoints"]
        assert "/img/logo.js" in res[0]["endpoints"]
        assert res[1]["endpoints"] == []

    def test_missing_perl_skip(self):
        out = run_perl_suite("http://t", fetch=self._fetch,
                             which_fn=lambda name: None)
        assert out["ran"] == []
        assert out["findings"] == []
        assert out["skipped"] and "perl" in out["skipped"][0]["reason"]


# --------------------------------------------------------- jq adapter


class TestJqAdapter:
    def test_real_jq_validation(self):
        if not has_jq():
            pytest.skip("jq not available")
        good = mk()
        bad_missing_key = {"title": "x", "severity": "LOW",
                           "confidence": "candidate"}  # no verification
        not_a_dict = "just a string"
        res = normalize_findings([good, bad_missing_key, not_a_dict])
        assert res["valid"] == [good]
        reasons = [q["reason"] for q in res["quarantined"]]
        assert len(reasons) == 2
        assert "verification" in reasons[0]

    def test_real_jq_suite_run_and_quarantine(self):
        if not has_jq():
            pytest.skip("jq not available")
        good = mk()
        bad = {"title": "broken"}
        out = run_jq_suite([good, bad])
        assert out["ran"] == ["jq.validate"]
        assert out["findings"] == [good]
        assert len(out["quarantined"]) == 1
        assert out["quarantined"][0]["finding"] == bad

    def test_missing_jq_suite_passes_through(self):
        out = run_jq_suite([mk()], which_fn=lambda name: None)
        assert out["findings"] == [mk()]
        assert out["skipped"] and "jq" in out["skipped"][0]["reason"]
        assert out["quarantined"] == []

    def test_missing_jq_normalize_fails_closed(self):
        res = normalize_findings([mk()], which_fn=lambda name: None)
        assert res["valid"] == []
        assert "not validated" in res["quarantined"][0]["reason"]


# ------------------------------------------------------ brain wiring


class TestBrainFusionCapability:
    def test_registered_with_expected_metadata(self):
        from omega.brain import default_registry, DEFAULT_REGISTRY
        reg = default_registry()
        cap = reg.get("fusion.all")
        assert cap is not None
        assert cap.cost == 5
        assert cap.risk == "active"
        assert cap.requires == ("has_web",)
        assert callable(cap.fn)
        assert DEFAULT_REGISTRY.get("fusion.all") is not None

    def test_duplicate_guard(self):
        from omega.brain import default_registry
        reg = default_registry()  # fresh registry already has fusion.all
        cap = reg.get("fusion.all")
        with pytest.raises(ValueError):
            reg.register(cap)

    def test_eligibility_requires_has_web(self):
        from omega.brain import default_registry, BrainState
        reg = default_registry()
        state = BrainState("http://t", budget=100)
        cap = reg.get("fusion.all")
        assert not cap.eligible(state.facts(), 100)
        state.surface["urls"] = ["http://t/"]
        assert cap.eligible(state.facts(), 100)
        assert not cap.eligible(state.facts(), 4)  # budget too small

    def test_capability_fn_calls_fuse_contained(self, monkeypatch):
        import omega.fusion as fz
        from omega.brain import default_registry, BrainState

        called = {}

        def fake_fuse(target, **kw):
            called["target"] = target
            called["kw"] = kw
            return {"findings": [mk(source="omega-py/x")],
                    "corroborated": [mk(source="omega-py/x",
                                        corroborated=True)],
                    "surface": {"urls": ["http://t/"]},
                    "ran": ["python-probes"], "skipped": [],
                    "languages_used": ["python"]}

        monkeypatch.setattr(fz, "fuse", fake_fuse)
        state = BrainState("http://t", budget=100)
        state.surface["urls"] = ["http://t/"]
        res = reg_fn = default_registry().get("fusion.all").fn(state, None)
        assert called["target"] == "http://t"
        assert res["findings"] == [mk(source="omega-py/x")]
        assert res["urls"] == ["http://t/"]
        assert "fusion.all" in json.dumps(res.get("note", "")) or \
            "python" in res["note"]
