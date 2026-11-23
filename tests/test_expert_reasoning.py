"""tests/test_expert_reasoning.py — batch expert-reasoning.

Covers: hypothesis engine, attackkb, oracle, logic templates,
permutation runner (gate), lessonsv2, cvesuggest, wafprofiler,
brain caps + CLI flags wiring.
"""
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest  # noqa: E402


# ------------------------------------------------------------- lab
class Lab(BaseHTTPRequestHandler):
    """Small app: / errors on ?q='; /api/user/<id> echoes id;
    /omegatest reflects the parameter."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        if "q='" in self.path or "q=%27" in self.path:
            body = b"<html>MySQL syntax error near '''</html>"
            self.send_response(500)
        elif self.path.startswith("/api/user/"):
            body = ("user %d" % int(self.path.rsplit("/", 1)[
                1] or 0)).encode()
            self.send_response(200)
        elif "omegatest=" in self.path:
            body = ("echo %s" % self.path.split("omegatest=")[
                1].split("&")[0]).encode()
            self.send_response(200)
        else:
            body = b"<html>home nginx/1.18.0</html>"
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def lab_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Lab)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    yield url
    srv.shutdown()


def fetch(method, url, headers=None, body=None):
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, method=method, data=body)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        r = opener.open(req, timeout=5)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


# ------------------------------------------------------ hypothesis
def test_hypothesis_build_and_verify(lab_url):
    from omega.core.hypothesis import run_hypothesis_loop

    doc = run_hypothesis_loop(
        ["500 on q=' — MySQL syntax error"], fetch, lab_url)
    assert doc["raised"] >= 1
    kinds = {h["kind"] for h in doc["hypotheses"]}
    assert "sqli" in kinds
    assert doc["counts"]["verified"] >= 1


def test_hypothesis_refuted_clean(lab_url):
    from omega.core.hypothesis import run_hypothesis_loop

    doc = run_hypothesis_loop(
        ["login form found"], fetch, lab_url)
    assert all(h["status"] in ("refuted", "uncertain")
               for h in doc["hypotheses"])


# -------------------------------------------------------- attackkb
def test_attackkb_suggests():
    from omega.core.attackkb import suggest

    out = suggest(["login form detected", "search?q= param"])
    techs = {s["technique"] for s in out}
    assert "injection ladder" in techs
    assert "username enumeration differential" in techs
    # sorted by priority desc
    prios = [s["priority"] for s in out]
    assert prios == sorted(prios, reverse=True)


def test_attackkb_empty():
    from omega.core.attackkb import suggest

    assert suggest(["nothing relevant"]) == []


# ---------------------------------------------------------- oracle
def test_oracle_classifies_status_shift():
    from omega.core.oracle import classify_delta

    base = (200, {}, b"<html>home nginx/1.18.0</html>")
    probe = (500, {}, b"MySQL syntax error")
    doc = classify_delta(base, probe)
    assert doc["verdict"] in ("status-shift", "error-shape-change")
    assert doc["confidence"] >= 0.5
    assert any("status 200 -> 500" in s for s in doc["signals"])


def test_oracle_error_shape_change():
    from omega.core.oracle import classify_delta

    base = (200, {}, b"ok fine")
    probe = (200, {}, b"ok fine ... exception in module")
    doc = classify_delta(base, probe)
    assert doc["verdict"] == "error-shape-change"


def test_oracle_probe_and_classify(lab_url):
    from omega.core.oracle import probe_and_classify

    doc = probe_and_classify(fetch, lab_url,
                             probe_path="/?q=%27")
    assert doc["verdict"] in ("status-shift", "error-shape-change",
                              "content-shift")


# ----------------------------------------------------------- logic
def test_logic_dry_run(lab_url):
    from omega.core.logic import run_logic_templates

    doc = run_logic_templates(lab_url,
                              surface_text="cart checkout price",
                              fetch=None)
    assert doc["dry_run"] is True
    names = {t["name"] for t in doc["templates"]}
    assert "price-tamper" in names
    for t in doc["templates"]:
        for s in t["steps"]:
            assert s["sent"] is False


def test_logic_live_and_findings(lab_url):
    from omega.core.logic import findings_from_result, \
        run_logic_templates

    doc = run_logic_templates(lab_url,
                              surface_text="api user profile",
                              fetch=fetch)
    findings = findings_from_result(doc)
    # /api/user/2 echoes any id -> accepted -> candidate finding
    assert findings, "idor template should flag accepted swap"
    f = findings[0]
    assert f["verification"] == "candidate"
    assert f["manual_check"]


# ------------------------------------------------------ permutate
def test_permutate_gate_closed():
    from omega.offense.permutate import run_permutation

    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        doc = run_permutation("http://example.test/", "q", fetch=fetch)
        assert doc["skipped"] is True
        assert "PTK_OFFENSE" in doc["reason"]
    finally:
        if old is not None:
            os.environ["PTK_OFFENSE"] = old


def test_permutate_matrix_budget():
    from omega.offense.permutate import build_matrix

    m = build_matrix("q", max_requests=10)
    assert len(m) <= 10
    encs = {p["encoding"] for p in m}
    assert "double-url" in encs


# ------------------------------------------------------ lessonsv2
def test_lessonsv2_record_consult_propagate(tmp_path, monkeypatch):
    monkeypatch.setenv("OMEGA_LESSONS_HOME",
                       str(tmp_path / "lessons.json"))
    from omega.core.lessonsv2 import consult_endpoint, \
        endpoint_summary, propagate_hint, record_endpoint

    record_endpoint("h1", "/api/login", "worked",
                    hint="double-encode passed")
    record_endpoint("h1", "/api/login", "blocked",
                    hint="plain single-quote blocked")
    doc = consult_endpoint("h1", "/api/login")
    assert doc["from"] == "/api/login"
    assert len(doc["worked"]) == 1 and len(doc["blocked"]) == 1

    # sibling propagation: /api/logout inherits /api/login knowledge
    assert propagate_hint("h1", "/api/login", "/api/logout") is True
    sib = consult_endpoint("h1", "/api/logout")
    assert sib["worked"], "propagated hint must land on the sibling"
    assert any("propagated-from" in w for w in sib["worked"])

    # no secrets in storage — hints only
    raw = open(str(tmp_path / "lessons.json")).read()
    assert "double-encode passed" in raw

    assert endpoint_summary("h1")["/api/login"]["worked"] == 1


# ----------------------------------------------------- cvesuggest
def test_cvesuggest_extract_and_mock(monkeypatch):
    import omega.core.cvesuggest as cs

    pairs = cs.extract_versions("nginx/1.18.0 Jenkins 2.343 "
                                "https://x.com")
    assert ("nginx", "1.18.0") in pairs
    assert ("jenkins", "2.343") in pairs
    assert all(p[0] not in ("http", "https") for p in pairs)

    monkeypatch.setattr(cs, "lookup",
                        lambda p, v: {"cves": [{"id": "CVE-2021-1",
                                                "summary": "bad"}]})
    leads = cs.suggest_cves("nginx/1.18.0")
    assert leads[0]["cve"] == "CVE-2021-1"
    findings = cs.findings_from_leads(leads, "http://t")
    assert findings[0]["verification"] == "candidate"


# ---------------------------------------------------- wafprofiler
def test_wafprofiler_lab(lab_url, monkeypatch):
    monkeypatch.setenv("OMEGA_LESSONS_HOME",
                       "/nonexistent-profiler-test/lessons.json")
    from omega.core.wafprofiler import findings_from_doc, profile

    doc = profile(lab_url + "/")
    assert doc["verdict"] == "no-evidence-of-waf"  # lab blocks nothing
    assert len(doc["probes"]) == 5
    assert findings_from_doc(doc) == []


# ------------------------------------------------- brain caps/CLI
def test_brain_caps_registered():
    from omega.core.brain import DEFAULT_REGISTRY as reg

    for cid in ("core.hypothesis", "core.attackkb", "core.oracle",
                "core.logic", "offense.permutate", "core.lessonsv2",
                "core.cvesuggest", "core.wafprofiler",
                "core.planner"):
        assert reg.get(cid), "missing cap %s" % cid


def test_cli_flags_present():
    from omega.core import cli as cli_mod
    import inspect

    src = inspect.getsource(cli_mod.main)
    for flag in ("--hypothesize", "--logic", "--kb", "--waf-profile",
                 "--cvesuggest"):
        assert flag in src, flag


def test_state_fetch_resilience(lab_url):
    """Caps never raise on fetch errors."""
    from omega.core.brain import DEFAULT_REGISTRY

    class S:
        target = lab_url
        findings = [{"title": "sql error", "severity": "HIGH"}]
        surface = {"techs": ["nginx/1.18.0"], "notes": []}
        history = []

        def fetch(self, *a, **k):
            raise ConnectionError("down")

        log = staticmethod(lambda *a, **k: None)

    s = S()
    for cid in ("core.hypothesis", "core.attackkb", "core.oracle",
                "core.logic", "offense.permutate", "core.lessonsv2",
                "core.cvesuggest"):
        cap = DEFAULT_REGISTRY.get(cid)
        out = cap.fn(s)
        assert "note" in out
