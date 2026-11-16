"""Hermetic tests for the adaptive follow-up loop (omega.scanning.followup).

Loopback server mirrors the lab/vuln_app.py endpoint style: traversal
echo, XSS echo, boolean-diff endpoint, .env file, redirect target,
command echo, CSP-bearing page.
"""
import copy
import json
import os
import sys
import threading
import http.server
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from omega.scanning.followup import (  # noqa: E402
    run_followups, classify_finding)


class _Handler(http.server.BaseHTTPRequestHandler):
    # first arithmetic request succeeds, later ones stop echoing (refuted)
    flaky_state = {"used": False}

    def do_GET(self):
        parsed = urllib.parse.parse_qs(
            urllib.parse.urlparse(self.path).query, keep_blank_values=True)
        val = (parsed.get("val") or parsed.get("id") or parsed.get("q") or
               parsed.get("file") or parsed.get("next") or
               parsed.get("c") or parsed.get("cmd") or
               parsed.get("url") or [""])[0]

        if self.path.startswith("/bool"):
            if "1=2" in val:
                body = b"PAGE: no results"
            else:
                body = (b"PAGE: results listed here with many records "
                        b"and a long deterministic body")
            self.send_response(200)
        elif self.path.startswith("/flat"):
            body = b"PAGE: identical body regardless of input"
            self.send_response(200)
        elif self.path.startswith("/xss"):
            body = ("echo: %s" % val).encode("latin-1", "replace")
            self.send_response(200)
        elif self.path.startswith("/trav"):
            # decode once more for double-encoded payloads
            once = urllib.parse.unquote(val)
            twice = urllib.parse.unquote(once)
            target = once if ".." in once else twice
            if "etc/passwd" in target:
                body = b"root:x:0:0:lab-secret-traversal-content"
                self.send_response(200)
            else:
                body = b"error: file not found"
                self.send_response(200)
        elif self.path.startswith("/.env") or self.path == "/.env":
            body = b"DB_PASSWORD=supersecret1\nAPI_KEY=ak-live-1234\n"
            self.send_response(200)
        elif self.path.startswith("/redir"):
            body = ("Redirecting to %s" % val).encode("latin-1", "replace")
            self.send_response(302)
            self.send_header("Location", val)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        elif self.path.startswith("/cmd"):
            import re as _re
            m = _re.search(r"(\d+)\*(\d+)", val)
            if m and not self.path.startswith("/cmd-flaky"):
                body = ("output: %d done" % (int(m.group(1))
                                             * int(m.group(2)))).encode()
                self.send_response(200)
            elif m and self.path.startswith("/cmd-flaky"):
                if self.flaky_state["used"]:
                    body = b"no output"
                else:
                    self.flaky_state["used"] = True
                    body = ("output: %d done"
                            % (int(m.group(1)) * int(m.group(2)))).encode()
                self.send_response(200)
            else:
                body = b"no output"
                self.send_response(200)
        elif self.path.startswith("/csp-weak"):
            body = b"csp weak page body content"
            self.send_response(200)
            self.send_header(
                "Content-Security-Policy",
                "script-src 'unsafe-inline'; img-src *")
        elif self.path.startswith("/gone"):
            body = b"not found"
            self.send_response(404)
        else:
            body = b"plain page without security headers"
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


def _f(title, location, severity="MEDIUM", **kw):
    d = {"title": title, "severity": severity, "location": location,
         "evidence": kw.pop("evidence", "plain page"),
         "verification": "candidate", "source": "omega-test",
         "confidence": "medium"}
    d.update(kw)
    return d


def _verified_sources(res):
    return [f.get("source") for f in res["findings"]
            if str(f.get("source") or "").startswith("omega-followup/")]


def test_classify_finding_heuristics():
    assert classify_finding(_f("Possible SQL error-based injection",
                               BASE)) == "sqli-boolean"
    assert classify_finding(_f("Reflected XSS in query parameter",
                               BASE)) == "xss-context"
    assert classify_finding(_f("Path traversal via file parameter",
                               BASE)) == "traversal-depth"
    assert classify_finding(_f("Exposed .env file", BASE)) == "env-keys"
    assert classify_finding(_f("OS command echo detected",
                               BASE)) == "cmd-arithmetic"
    assert classify_finding(_f("Open redirect in next parameter",
                               BASE)) == "redirect-variants"
    assert classify_finding(_f("Missing security response headers",
                               BASE)) == "csp-parse"
    assert classify_finding(_f("Weird unknown issue", BASE)) is None


def test_sqli_boolean_probe_verified():
    res = run_followups([_f("Possible SQL error-based injection",
                            BASE + "/bool")], base_url=BASE)
    assert res["probes"] == 1
    srcs = _verified_sources(res)
    assert "omega-followup/sqli-boolean" in srcs
    claim = [f for f in res["findings"]
             if f.get("source") == "omega-followup/sqli-boolean"][0]
    assert claim["validation"] == "verified"
    assert claim["severity"] == "HIGH"


def test_sqli_no_differential_no_signal():
    res = run_followups([_f("Possible SQL error-based injection",
                            BASE + "/flat")], base_url=BASE)
    assert res["probes"] == 1
    assert _verified_sources(res) == []
    assert res["refuted"] == []
    f = res["findings"][0]
    assert f["followup"]["status"] == "no-signal"


def test_xss_probe_verified_but_candidate():
    res = run_followups([_f("Reflected XSS in query parameter",
                            BASE + "/xss")], base_url=BASE)
    claim = [f for f in res["findings"]
             if f.get("source") == "omega-followup/xss-context"]
    assert claim, res["findings"]
    claim = claim[0]
    assert claim["validation"] == "verified"
    assert claim["verification"] == "candidate"  # echo is not execution
    assert "DOM context" in claim["title"]


def test_traversal_probe_verified():
    res = run_followups([_f("Path traversal via file parameter",
                            BASE + "/trav")], base_url=BASE)
    srcs = _verified_sources(res)
    assert "omega-followup/traversal-depth" in srcs
    claim = [f for f in res["findings"]
             if f.get("source") == "omega-followup/traversal-depth"][0]
    assert "encoding" in claim["title"] or "depth" in claim["title"]
    assert claim["validation"] == "verified"


def test_env_probe_reports_key_names_only():
    res = run_followups([_f("Exposed .env file", BASE + "/.env",
                            severity="HIGH")], base_url=BASE)
    claim = [f for f in res["findings"]
             if f.get("source") == "omega-followup/env-keys"]
    assert claim, res
    claim = claim[0]
    assert claim["validation"] == "verified"
    assert "DB_PASSWORD" in claim["title"]
    assert "API_KEY" in claim["title"]
    # values only in the verbatim evidence, never in the reported title
    assert "supersecret1" not in claim["title"]
    assert "supersecret1" in claim["evidence"]


def test_cmd_arithmetic_probe_verified():
    res = run_followups([_f("OS command echo detected",
                            BASE + "/cmd")], base_url=BASE)
    srcs = _verified_sources(res)
    assert "omega-followup/cmd-arithmetic" in srcs
    claim = [f for f in res["findings"]
             if f.get("source") == "omega-followup/cmd-arithmetic"][0]
    # different operands than the classic 7*7
    assert "11*13" in claim["title"] or "12*14" in claim["title"] \
        or "9*9" in claim["title"]
    assert claim["validation"] == "verified"


def test_redirect_variants_probe_verified():
    res = run_followups([_f("Open redirect in next parameter",
                            BASE + "/redir")], base_url=BASE)
    srcs = _verified_sources(res)
    assert "omega-followup/redirect-variants" in srcs
    claim = [f for f in res["findings"]
             if f.get("source") == "omega-followup/redirect-variants"][0]
    assert "evil.followup.example" in claim["location"]
    assert claim["validation"] == "verified"


def test_csp_missing_headers_probe():
    res = run_followups([_f("Missing security response headers",
                            BASE + "/")], base_url=BASE)
    claim = [f for f in res["findings"]
             if f.get("source") == "omega-followup/csp-parse"]
    assert claim, res
    claim = claim[0]
    assert claim["validation"] == "verified"
    assert "missing Content-Security-Policy" in claim["title"]


def test_csp_unsafe_inline_weakness_reported():
    res = run_followups([_f("Missing security response headers",
                            BASE + "/csp-weak")], base_url=BASE)
    claim = [f for f in res["findings"]
             if f.get("source") == "omega-followup/csp-parse"]
    assert claim, res
    assert "unsafe-inline" in claim[0]["title"]


def test_unknown_type_skipped_with_reason():
    res = run_followups([_f("Something entirely unclassified",
                            BASE + "/")], base_url=BASE)
    assert res["probes"] == 0
    assert res["skipped"] and "no followup probe heuristic" in \
        res["skipped"][0]["reason"]
    assert res["findings"][0]["followup"]["status"] == "skipped"


def test_budget_caps_probes():
    findings = [
        _f("Possible SQL error-based injection", BASE + "/bool"),
        _f("Reflected XSS in query parameter", BASE + "/xss"),
        _f("Exposed .env file", BASE + "/.env"),
        _f("Open redirect in next parameter", BASE + "/redir"),
    ]
    res = run_followups(findings, base_url=BASE, budget=2)
    assert res["probes"] == 2
    skipped_reasons = [s["reason"] for s in res["skipped"]]
    assert sum("budget exhausted" in r for r in skipped_reasons) == 2


def test_budget_env_variable():
    os.environ["OMEGA_FOLLOWUP_MAX"] = "1"
    try:
        findings = [
            _f("Possible SQL error-based injection", BASE + "/bool"),
            _f("Reflected XSS in query parameter", BASE + "/xss"),
        ]
        res = run_followups(findings, base_url=BASE)
        assert res["probes"] == 1
        assert len(res["skipped"]) == 1
    finally:
        os.environ.pop("OMEGA_FOLLOWUP_MAX", None)


def test_refuted_probe_recorded_transparently():
    res = run_followups([_f("OS command echo detected",
                            BASE + "/cmd-flaky")], base_url=BASE)
    assert len(res["refuted"]) == 1
    ref = res["refuted"][0]
    assert "ai-claim:refuted" in ref["tags"]
    assert ref["validation"] == "refuted"
    assert ref["source"] == "omega-followup/cmd-arithmetic"
    # the refuted claim never reached findings
    assert "omega-followup/" not in "".join(
        str(s) for s in _verified_sources(res))


def test_offline_fetch_errors_never_raise():
    def _broken(method, url, **kw):
        raise OSError("network down")

    findings = [
        _f("Possible SQL error-based injection", BASE + "/bool"),
        _f("Reflected XSS in query parameter", BASE + "/xss"),
        _f("Open redirect in next parameter", BASE + "/redir"),
    ]
    res = run_followups(findings, fetch=_broken, base_url=BASE)
    assert res["probes"] == 3
    assert _verified_sources(res) == []
    assert res["refuted"] == []  # probes produced no claim -> skipped
    assert all(f.get("followup") for f in res["findings"])


def test_no_findings_is_safe():
    res = run_followups([], base_url=BASE)
    assert res == {"findings": [], "refuted": [], "skipped": [],
                   "probes": 0}


def test_fuse_followup_merge_smoke():
    import omega.scanning.fusion as fusion
    stub_findings = [
        _f("Possible SQL error-based injection", BASE + "/bool"),
        _f("OS command echo detected", BASE + "/cmd"),
        _f("Something entirely unclassified", BASE + "/"),
    ]
    original = fusion.SUITES
    fusion.SUITES = (("stub-suite", "python",
                      lambda target, ctx: {"findings": copy.deepcopy(
                          stub_findings)}),)
    try:
        out = fusion.fuse(BASE, budget=5, followup=True)
    finally:
        fusion.SUITES = original
    assert out["followup"]["probes"] >= 2
    srcs = _verified_sources(out)
    assert "omega-followup/sqli-boolean" in srcs
    assert "omega-followup/cmd-arithmetic" in srcs
    assert out["followup"]["skipped"], "unknown type must be skipped"
    # fuse(followup=False) default keeps the shape identical
    fusion.SUITES = (("stub-suite", "python",
                      lambda target, ctx: {"findings": []}),)
    try:
        plain = fusion.fuse(BASE, budget=5)
    finally:
        fusion.SUITES = original
    assert "followup" not in plain


def test_cli_followup_subcommand_end_to_end(tmp_path, capsys):
    from omega.core import cli
    findings = [
        _f("Possible SQL error-based injection", BASE + "/bool"),
        _f("Reflected XSS in query parameter", BASE + "/xss"),
        _f("Weird unknown issue", BASE + "/"),
    ]
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(findings), encoding="utf-8")
    code = cli.main(["followup", str(path), "--base", BASE, "--json"])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["probes"] == 2
    srcs = _verified_sources(out)
    assert "omega-followup/xss-context" in srcs
    assert len(out["skipped"]) == 1

    # human-readable mode + budget flag
    code = cli.main(["followup", str(path), "--base", BASE,
                     "--budget", "1"])
    assert code == 0
    text = capsys.readouterr().out
    assert "probes: 1" in text
    assert "budget exhausted" in text


def test_cli_followup_missing_file(tmp_path, capsys):
    from omega.core import cli
    code = cli.main(["followup", str(tmp_path / "nope.json")])
    assert code == 1
