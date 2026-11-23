"""Tests for the AI-autonomy batch: engagement loop, self-critique,
auth deep-scan, chain-graph proposals, executive summary, report
'fix first' wiring, multi-target aggregation.
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


class _FakeState:
    def __init__(self, target="http://t.local", findings=None,
                 history=None):
        self.target = target
        self.findings = findings or []
        self.history = history or []
        self.notes = []


# ------------------------------------------------- engagement loop

def test_engagement_runs_and_stops_on_saturated_planner():
    from omega.core.engagement import run_engagement
    # a stage map with only planner-consuming stages: headers adds a
    # finding, so the planner escalates; after budget the planner has
    # nothing reachable -> unavailable stop
    def headers(state):
        state.findings.append({
            "title": "security headers missing: csp",
            "severity": "LOW", "source": "engagement/headers",
            "location": state.target, "evidence": "absent: csp",
            "verification": "candidate",
            "manual_check": "curl -sI"})
        return {"findings": state.findings[:1], "requests": 1}

    doc = run_engagement("http://t.local", max_stages=4,
                         stage_fns={"campaign.headers": headers})
    assert doc["stages"], "at least one stage must run"
    assert doc["stop_reason"] in (
        "planner-saturated (no escalation warranted)",
        "planner requested unavailable stage: "
        "polyglot.tlsprobe", "planner requested unavailable stage: "
        "polyglot.subhunt")
    assert doc["findings"]


def test_engagement_budget_stop():
    from omega.core.engagement import run_engagement
    doc = run_engagement(
        "http://t.local", max_stages=8, request_budget=0,
        stage_fns={"campaign.headers": lambda s: {"requests": 1}})
    # budget 0 -> first planner call still allowed, then budget cut;
    # either way no runaway
    assert doc["requests_used"] <= 1
    assert doc["stop_reason"] in (
        "request budget exhausted",
        "planner-saturated (no escalation warranted)",
        "planner requested unavailable stage: polyglot.tlsprobe",
        "planner requested unavailable stage: polyglot.subhunt",
        "stage-budget")


def test_engagement_stage_error_never_raises():
    from omega.core.engagement import run_engagement
    doc = run_engagement(
        "http://t.local", max_stages=2,
        stage_fns={"campaign.headers":
                   lambda s: (_ for _ in ()).throw(RuntimeError("x"))})
    assert doc["stages"][0]["status"] == "error"


def test_engagement_multi_aggregate_ranking():
    from omega.core.engagement import run_multi
    doc = run_multi(["http://a.local", "http://b.local"],
                    max_stages=1, stage_fns={"campaign.headers":
                                             lambda s: {"requests": 0}})
    agg = doc["aggregate"]
    assert agg["targets"] == 2
    risks = [r["risk"] for r in agg["ranking"]]
    assert risks == sorted(risks, reverse=True)


# -------------------------------------------------- self-critique

def test_critique_flags_vague_evidence():
    from omega.core.critique import critique
    doc = critique([{"title": "X", "severity": "LOW",
                     "evidence": "maybe"}])
    assert doc["fp_smells"]
    assert doc["followups"][0]["action"] == "re-verify"
    assert doc["followups"][0]["auto_approved"] is False


def test_critique_flags_high_severity_without_replay():
    from omega.core.critique import critique
    doc = critique([{"title": "SQLi", "severity": "HIGH",
                     "evidence": "long enough evidence string here",
                     "verification": "candidate"}])
    assert any("candidate without a replay check" in s["why"]
               for s in doc["fp_smells"])


def test_critique_verdict_scale():
    from omega.core.critique import critique
    findings = [{"title": "t%d" % i, "severity": "LOW",
                 "evidence": "maybe"} for i in range(5)]
    doc = critique(findings)
    assert "LOW CONFIDENCE" in doc["verdict"]


def test_critique_planner_followups_with_auto_approval():
    from omega.core.critique import critique
    from omega.core.planner import score_surface
    plan = score_surface(_FakeState(
        findings=[{"severity": "HIGH",
                   "source": "go-portsweep/443"}]))
    doc = critique([], planner_plan=plan)
    runs = [f for f in doc["followups"] if f["action"] == "run-stage"]
    assert runs
    auto = [f for f in runs if f["auto_approved"]]
    manual = [f for f in runs if not f["auto_approved"]]
    # low-priority stages are auto-approved, high-priority are not
    assert all(f["priority"] <= 5 for f in auto)
    assert all(f["priority"] > 5 for f in manual)


def test_narrate_critique_render():
    from omega.core.critique import critique, narrate_critique
    doc = critique([{"title": "X", "severity": "LOW",
                     "evidence": "maybe"}], target="http://t.local")
    text = narrate_critique(doc)
    assert "# Self-critique — http://t.local" in text
    assert "Verdict:" in text


# -------------------------------------------------- auth deep-scan

@pytest.fixture()
def auth_lab():
    """Lab with a login form; session cookie NOT rotated on login;
    logout returns 200 but the old cookie still works."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/":
                if self.headers.get("Cookie") == "sessid=FIXED":
                    body = b"<html>admin dashboard</html>"
                else:
                    body = (b"<html><form action='/login' "
                            b"method='POST'>"
                            b"<input name='user'><input name='pass' "
                            b"type='password'></form></html>")
                self.send_response(200)
                # pre-login session cookie that the login does NOT
                # rotate (session-fixation sim)
                self.send_header("Set-Cookie", "sessid=FIXED; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/logout":
                body = b"bye"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                body = b"not found"
                self.send_response(404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def do_POST(self):
            ln = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(ln)
            body = b"ok"
            # FIXED session id: pre-issued cookie is reused (fixation)
            self.send_response(302)
            self.send_header("Set-Cookie", "sessid=FIXED; Path=/")
            self.send_header("Location", "/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def test_authscan_detects_fixation_and_logout_failure(auth_lab):
    from omega.core.authscan import run_auth_deep_scan

    def fetch(method, url, headers=None, body=None):
        import urllib.request

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None

        opener = urllib.request.build_opener(_NoRedirect)
        req = urllib.request.Request(
            url, method=method,
            data=body.encode() if isinstance(body, str) else body)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        if body:
            req.add_header("Content-Length", str(len(body)))
        try:
            r = opener.open(req, timeout=5)
            return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    out = run_auth_deep_scan(auth_lab, fetch=fetch,
                             creds="admin:admin123")
    titles = [f["title"] for f in out.get("findings") or []]
    assert out["logged_in"] is True
    assert any("fixation" in t for t in titles), titles
    assert any("survives logout" in t for t in titles)


def test_authscan_no_creds_note():
    from omega.core.authscan import run_auth_deep_scan
    out = run_auth_deep_scan("http://t.local", creds=None)
    assert out["logged_in"] is False and out["note"]


# --------------------------------------------- chain graph proposals

def test_chain_propose_sqli_to_credentials():
    from omega.core.autochain import chain_propose
    findings = [
        {"title": "SQL injection in /search", "evidence": "time-based",
         "location": "/search"},
        {"title": "DB_URL credential in backup dump",
         "evidence": "postgres://...", "location": "/dump.sql"},
    ]
    props = chain_propose(findings)
    assert props
    assert all(p["requires_operator_approval"] is True for p in props)
    assert any("SQLi" in p["chain"] or "SQLi" in p["chain"]
               for p in props)
    # links carry evidence refs for auditability
    assert all(p["links"] and all(l["finding"] for l in p["links"])
               for p in props)


def test_chain_propose_no_findings_empty():
    from omega.core.autochain import chain_propose
    assert chain_propose([]) == []


def test_chain_propose_cap():
    from omega.core.autochain import chain_propose
    findings = [{"title": "SSRF in fetcher %d" % i,
                 "evidence": "e", "location": "/x%d" % i}
                for i in range(20)]
    props = chain_propose(findings, max_proposals=5)
    assert len(props) <= 5


# ------------------------------------------------ executive summary

def test_executive_summary_headline_and_do_first():
    from omega.core.summary import executive_summary
    doc = executive_summary([
        {"title": "SQL injection in /search", "severity": "CRITICAL",
         "evidence": "x"},
        {"title": "security headers missing: csp", "severity": "LOW",
         "evidence": "x"},
    ], target="http://t.local")
    assert "1 critical" in doc["headline"]
    assert doc["counts"]["CRITICAL"] == 1
    assert doc["do_first"] and "SQL injection" in doc["do_first"][0]


def test_executive_summary_impact_mapping():
    from omega.core.summary import executive_summary
    doc = executive_summary([{"title": "session fixation on /login",
                              "severity": "HIGH"}])
    assert "take over the account" in doc["by_severity"]["HIGH"][0]


def test_narrate_executive_render():
    from omega.core.summary import executive_summary, narrate_executive
    doc = executive_summary([{"title": "open port 3389",
                              "severity": "MEDIUM"}])
    text = narrate_executive(doc)
    assert "## Executive summary" in text
    assert "MEDIUM" in text and "Fix first" in text


# ------------------------------------------- report 'fix first' wiring

def test_report_markdown_contains_fix_first():
    from omega.reporting.report import generate_report
    md = generate_report(
        "http://t.local",
        [{"id": "F-1", "title": "SQL injection in /search",
          "severity": "CRITICAL", "evidence": "time-based",
          "location": "/search", "verification": "candidate",
          "manual_check": "curl", "description": "d", "impact": "i",
          "recommendation": "r"}],
        fmt="markdown")
    assert "**Fix first:**" in md
    assert "take over" in md or "database" in md


# ------------------------------------------------- CLI flag contract

def test_cli_flags_registered():
    import inspect
    from omega.core import cli
    src = inspect.getsource(cli.main)
    for flag in ("--authscan", "--critique", "--chain-proposals"):
        assert flag in src
