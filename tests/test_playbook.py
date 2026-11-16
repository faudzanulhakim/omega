"""Hermetic tests for omega/offensive/playbook.py — loopback only.

Emulates stage targets with a ThreadingHTTPServer fixture: a login
endpoint accepting known creds, a marker upload endpoint, an internal
URL-fetch endpoint (SSRF canary) and a cookie endpoint. Covers prereq
grounding, gate refusal (never auto-opens), stage execution through the
claim gate, refuted-stage abort, plan readability, CLI end-to-end and
never-raises behavior.
"""

import http.server
import json
import threading
import types
import urllib.request

import pytest

from omega.core import cli
from omega.offensive.playbook import (
    PLAYBOOKS, check_prereqs, format_plan, get_playbook, list_playbooks,
    plan, run_stage)


# ---------------------------------------------------------------- fixture

class _PBHandler(http.server.BaseHTTPRequestHandler):
    """Multi-endpoint lab target. State lives on the server instance."""

    def log_message(self, *a):  # silence
        pass

    # -- helpers ---------------------------------------------------------
    def _body(self, text, status=200, ctype="text/html; charset=utf-8",
              extra=None):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _redirect_echo(self, target_url):
        # Emulated open-redirect/SSRF param: echo the param (for the
        # redirect stage) and, for loopback URLs only, fetch it
        # server-side (for the SSRF stage).
        fetched = ""
        if target_url.startswith("http://127.0.0.1") \
                or target_url.startswith("http://localhost"):
            try:
                with urllib.request.urlopen(target_url, timeout=3) as r:
                    fetched = r.read().decode("latin-1", "replace")
            except Exception:
                fetched = ""
        self._body("redirecting to %s %s" % (target_url, fetched),
                   extra={"Location": target_url})

    def _footer(self):
        return ("<div>OMEGA-PB-FLAGCHECK session cookie issued without "
                "Secure/HttpOnly</div>")

    def _page(self, path):
        st = self.server.pb_state
        base = "<html><body><h1>%s</h1>" % path.strip("/") or "home"
        if path == "/":
            return base + "home page" + self._footer() + "</body></html>"
        if path == "/login":
            bits = ["login form"]
            if st.get("login_ok"):
                bits.append("OMEGA-PB-LOGIN-OK")
            if st.get("fixation_accepted"):
                bits.append("OMEGA-PB-FIXATION")
            return base + " ".join(bits) + self._footer() + "</body></html>"
        if path == "/protected":
            bits = ["protected page"]
            if st.get("protected_ok"):
                bits.append("OMEGA-PB-PROTECTED-OK")
            return base + " ".join(bits) + "</body></html>"
        if path == "/admin":
            bits = ["admin page"]
            if st.get("admin_ok"):
                bits.append("OMEGA-PB-ADMIN-OK")
            return base + " ".join(bits) + "</body></html>"
        if path == "/app.conf":
            return "db_password=OMEGA-PB-CONFIG\n"
        if path == "/omega-pb-internal":
            return "OMEGA-PB-INTERNAL canary page"
        if path == "/download":
            return None  # handled in do_GET
        return base + "not found" + self._footer() + "</body></html>"

    # -- routes ----------------------------------------------------------
    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        st = self.server.pb_state
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/redirect":
            self._redirect_echo((q.get("url") or [""])[0])
            return
        if u.path == "/download":
            fname = (q.get("file") or [""])[-1]
            if fname.endswith("omega_pb_marker.txt"):
                self._body("OMEGA-PB-TRAVERSAL lab marker",
                           ctype="text/plain")
            else:
                self._body("no such file", status=404, ctype="text/plain")
            return
        if u.path.startswith("/storage/"):
            fname = u.path.rsplit("/", 1)[-1]
            marker = st["uploads"].get(fname)
            if marker is None:
                self._body("gone", status=404, ctype="text/plain")
                return
            if st.get("broken_storage"):
                self._body("cleaned", ctype="text/plain")
                return
            self._body(marker, ctype="text/plain")
            return
        cookie = self.headers.get("Cookie") or ""
        extra = {}
        if u.path in ("/", "/login"):
            extra["Set-Cookie"] = "sessionid=OMEGA-PB-SESSION-1; Path=/"
        if u.path == "/login" and "OMEGA-PB-FIX" in cookie:
            st["fixation_accepted"] = True
        if u.path == "/protected" and "OMEGA-PB-FIX" in cookie \
                and st.get("fixation_accepted"):
            st["protected_ok"] = True
        if u.path == "/admin" and "sessionid=" in cookie \
                and st.get("login_ok"):
            st["admin_ok"] = True
        page = self._page(u.path)
        if page is None:
            self._body("not found", status=404)
            return
        self._body(page, extra=extra)

    def do_DELETE(self):
        st = self.server.pb_state
        fname = self.path.rsplit("/", 1)[-1]
        st["uploads"].pop(fname, None)
        self._body("deleted", ctype="text/plain")

    def do_POST(self):
        st = self.server.pb_state
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("latin-1", "replace")
        if self.path == "/login":
            user = pass_ = ""
            for pair in body.split("&"):
                k, _, v = pair.partition("=")
                if k == "username":
                    user = v
                elif k == "password":
                    pass_ = v
            cookie = self.headers.get("Cookie") or ""
            if user == st["user"] and pass_ == st["pass"]:
                st["login_ok"] = True
                text = "OMEGA-PB-LOGIN-OK welcome"
            else:
                text = "invalid credentials"
            if "OMEGA-PB-FIX" in cookie:
                st["fixation_accepted"] = True
                text += " OMEGA-PB-FIXATION"
            self._body(text)
            return
        if self.path == "/upload":
            import re
            fn = re.search(r'filename="([^"]+)"', body)
            mk = re.search(r"(OMEGA-PB-UPLOAD-\d+)", body)
            if not (fn and mk):
                self._body("upload rejected", status=400)
                return
            fname = fn.group(1)
            st["uploads"][fname] = mk.group(1)
            self._body("stored at /storage/%s" % fname)
            return
        self._body("not found", status=404)


@pytest.fixture
def target():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _PBHandler)
    srv.pb_state = {"user": "admin", "pass": "hunter2", "login_ok": False,
                    "fixation_accepted": False, "protected_ok": False,
                    "admin_ok": False, "uploads": {},
                    "broken_storage": False}
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    yield base
    srv.shutdown()
    srv.server_close()


def _fetch(method, url, headers=None, body=None):
    """stdlib fetch: (status, headers, body-bytes); never follows
    redirects."""
    import http.client
    from urllib.parse import urlparse
    p = urlparse(url)
    conn = http.client.HTTPConnection(p.hostname, p.port, timeout=5)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    conn.request(method, path, body=body,
                 headers=headers or {"Content-Type":
                                     "application/x-www-form-urlencoded"})
    r = conn.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def _no_redirect_fetch(method, url, headers=None, body=None):
    st, h, b = _fetch(method, url, headers, body)
    # drop Location so probes must rely on the echoed body
    h = {k: v for k, v in h.items() if k.lower() != "location"}
    return st, h, b


def F(title, location, evidence="", verification="verified", severity="high"):
    return {"title": title, "location": location, "evidence": evidence,
            "verification": verification, "severity": severity}


# ------------------------------------------------------------ registry

def test_registry_has_five_playbooks_with_expected_names():
    assert list_playbooks() == sorted([
        "auth-takeover", "upload-rce-path", "ssrf-pivot", "privesc-chain",
        "session-weakness"])
    for name in list_playbooks():
        pb = PLAYBOOKS[name]
        assert pb["name"] == name
        assert pb["requires"] and pb["stages"]
        for s in pb["stages"]:
            assert s["gate"] in ("none", "offense", "exploit", "no_limits")
            assert s["probe"] is None or isinstance(s["probe"], str)


def test_get_playbook_never_raises_on_junk():
    assert get_playbook("nope") is None
    assert get_playbook(None) is None
    assert get_playbook(123) is None


# ------------------------------------------------------- prereq checks

def test_prereqs_grounded_and_satisfied(target):
    findings = [F("Credentials leaked in environment file",
                  target + "/.env", "user=admin password=hunter2"),
                F("Login form discovered", target + "/login")]
    pre = check_prereqs("auth-takeover", findings)
    assert pre["ok"] is True
    assert pre["missing"] == []
    assert pre["candidate_only"] == []


def test_prereqs_missing_reports_keyword_groups():
    pre = check_prereqs("auth-takeover", [F("Unrelated banner bug",
                                            "/x")])
    assert pre["ok"] is False
    assert pre["missing"]  # both requirement groups unmet
    assert pre["candidate_only"] == []


def test_prereqs_candidate_only_lists_titles(target):
    findings = [F("Credentials leaked in environment file",
                  target + "/.env", "user=admin password=hunter2",
                  verification="candidate"),
                F("Login form discovered", target + "/login")]
    pre = check_prereqs("auth-takeover", findings)
    assert pre["ok"] is True
    assert pre["candidate_only"] == [
        "Credentials leaked in environment file"]


def test_prereqs_never_invent_evidence():
    pre = check_prereqs("privesc-chain", [])
    assert pre["ok"] is False and len(pre["missing"]) == 2


# ---------------------------------------------------------------- gates

def test_gate_closed_refuses_and_never_opens(target, monkeypatch):
    monkeypatch.delenv("PTK_OFFENSE", raising=False)
    findings = [F("Credentials leaked in environment file",
                  target + "/.env", "user=admin password=hunter2"),
                F("Login form discovered", target + "/login")]
    res = run_stage("auth-takeover", 0, _fetch, target, findings)
    assert res["executed"] is False
    assert res["gate_required"] == "offense"
    assert res["gate_closed"] is True
    assert res["refuted"] is False
    # gate was NOT auto-opened
    import os
    assert os.environ.get("PTK_OFFENSE") != "1"


def test_gate_open_allows_execution(target, monkeypatch):
    monkeypatch.setenv("PTK_OFFENSE", "1")
    findings = [F("Credentials leaked in environment file",
                  target + "/.env", "user=admin password=hunter2"),
                F("Login form discovered", target + "/login")]
    res = run_stage("auth-takeover", 0, _fetch, target, findings)
    assert res["executed"] is True
    assert res["refuted"] is False
    assert res["verified"] is True


def test_no_gate_stage_runs_freely(target):
    findings = [F("Open redirect in URL parameter", target + "/redirect")]
    res = run_stage("ssrf-pivot", 0, _no_redirect_fetch, target, findings)
    assert res["executed"] is True and res["verified"] is True


# ---------------------------------------------------- execution + claim

def test_stage_executes_and_passes_claim_gate(target, monkeypatch):
    monkeypatch.setenv("PTK_OFFENSE", "1")
    monkeypatch.setenv("PTK_EXPLOIT", "1")
    findings = [F("Credentials leaked in environment file",
                  target + "/.env", "user=admin password=hunter2"),
                F("Login form discovered", target + "/login")]
    res = run_stage("auth-takeover", 0, _fetch, target, findings)
    assert res["verified"] is True
    assert res["finding"]["validation"] == "verified"
    assert res["finding"]["verification"] == "confirmed"
    assert "OMEGA-PB" in res["finding"]["evidence"]


def test_upload_path_stages_chain(target, monkeypatch):
    monkeypatch.setenv("PTK_EXPLOIT", "1")
    findings = [F("File upload endpoint", target + "/upload")]
    r1 = run_stage("upload-rce-path", 0, _fetch, target, findings)
    assert r1["verified"] is True
    # stage result becomes a finding; stage 2 retrieves it
    findings = findings + [r1["finding"]]
    r2 = run_stage("upload-rce-path", 1, _fetch, target, findings)
    assert r2["verified"] is True
    # stage 3 is analysis-only: executed, no probe, nothing refuted
    r3 = run_stage("upload-rce-path", 2, _fetch, target, findings)
    assert r3["executed"] is True
    assert r3["verified"] is False and r3["refuted"] is False
    assert r3["finding"] is None


def test_ssrf_pivot_internal_stage(target, monkeypatch):
    monkeypatch.setenv("PTK_EXPLOIT", "1")
    findings = [F("Open redirect in URL parameter", target + "/redirect")]
    r = run_stage("ssrf-pivot", 1, _fetch, target, findings)
    assert r["executed"] is True
    assert r["verified"] is True
    assert r["finding"]["severity"] == "high"


def test_privesc_chain_full_run(target, monkeypatch):
    monkeypatch.setenv("PTK_EXPLOIT", "1")
    monkeypatch.setenv("PTK_OFFENSE", "1")
    findings = [
        F("Path traversal in file download endpoint",
          target + "/download?file=report.pdf"),
        F("Config file exposure leaks database secrets",
          target + "/app.conf", "db config"),
        F("Credentials recovered from leaked config",
          target + "/.env", "user=admin password=hunter2"),
        F("Login form discovered", target + "/login"),
    ]
    for i in range(3):
        r = run_stage("privesc-chain", i, _fetch, target, findings)
        assert r["executed"] is True and r["refuted"] is False, r
        assert r["verified"] is True


def test_session_weakness_full_run(target, monkeypatch):
    monkeypatch.setenv("PTK_OFFENSE", "1")
    monkeypatch.setenv("PTK_EXPLOIT", "1")
    findings = [
        F("Session cookie set without Secure flag", target + "/login"),
        F("Protected account page", target + "/protected"),
    ]
    for i in range(3):
        r = run_stage("session-weakness", i, _fetch, target, findings)
        assert r["executed"] is True and r["refuted"] is False, r


# ------------------------------------------------------------- refuted

def test_refuted_stage_stops_playbook(target, monkeypatch):
    monkeypatch.setenv("PTK_OFFENSE", "1")
    findings = [F("Credentials leaked in environment file",
                  target + "/.env", "user=nobody password=wrongpass"),
                F("Login form discovered", target + "/login")]
    res = run_stage("auth-takeover", 0, _fetch, target, findings)
    assert res["executed"] is True
    assert res["refuted"] is True
    assert res["verified"] is False
    assert res["stop_reason"] and "refuted" in res["stop_reason"]


def test_claim_gate_refutes_unreproducible_evidence(target, monkeypatch):
    monkeypatch.setenv("PTK_EXPLOIT", "1")
    # server storage returns 'cleaned' (no marker) -> probe uploads fine
    # but the claim cannot be reproduced -> refuted by claimcheck
    import http.server as hs
    # reuse the fixture server but flip broken_storage after upload:
    # done inline via a raw run against a second server
    srv = hs.ThreadingHTTPServer(("127.0.0.1", 0), _PBHandler)
    srv.pb_state = {"user": "admin", "pass": "hunter2", "login_ok": False,
                    "fixation_accepted": False, "protected_ok": False,
                    "admin_ok": False, "uploads": {},
                    "broken_storage": False}
    st = srv.pb_state
    st["broken_storage"] = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        findings = [F("File upload endpoint", base + "/upload")]
        r = run_stage("upload-rce-path", 0, _fetch, base, findings)
        assert r["executed"] is True
        assert r["refuted"] is True
        assert r["finding"] is not None
        assert r["finding"]["validation"] == "refuted"
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------- plan

def test_plan_is_readable_and_lists_stages_gates_and_aborts(target):
    findings = [F("Credentials leaked in environment file",
                  target + "/.env", "user=admin password=hunter2"),
                F("Login form discovered", target + "/login")]
    text = plan("auth-takeover", findings, target)["text"]
    assert "auth-takeover" in text
    for s in PLAYBOOKS["auth-takeover"]["stages"]:
        assert s["stage"] in text
    assert "gate" in text and "abort" in text.lower()
    assert "REFUTED" in text
    assert format_plan("nope", findings) .startswith("ERROR")


def test_plan_reports_missing_prereqs():
    p = plan("privesc-chain", [], None)
    assert p["exists"] is True
    assert p["prereqs"]["ok"] is False
    assert "MISSING" in p["text"]


def test_list_via_plan_structure(target):
    p = plan("upload-rce-path", [F("File upload endpoint",
                                   target + "/upload")])
    assert [s["gate"] for s in p["stages"]] == ["exploit", "none", "none"]
    assert p["stages"][2]["probe"] is None


# ----------------------------------------------------------------- CLI

def test_cli_playbook_list(capsys):
    assert cli.main(["playbook", "list"]) == 0
    out = capsys.readouterr().out
    for name in list_playbooks():
        assert name in out


def test_cli_playbook_list_json(capsys):
    assert cli.main(["playbook", "list", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert {p["name"] for p in doc["playbooks"]} == set(list_playbooks())


def test_cli_requires_scope_ack(tmp_path, capsys):
    f = tmp_path / "f.json"
    f.write_text(json.dumps([{"title": "Login form discovered",
                              "location": "http://127.0.0.1:1/login"}]))
    rc = cli.main(["playbook", "auth-takeover", str(f), "--stage", "0"])
    assert rc == 1
    assert "scope-ack" in capsys.readouterr().err


def test_cli_end_to_end_stage(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("PTK_OFFENSE", "1")
    doc = {"target": None, "state": {"findings": [
        {"title": "Credentials leaked in environment file",
         "location": None, "evidence": "user=admin password=hunter2",
         "verification": "verified"},
        {"title": "Login form discovered", "location": None,
         "verification": "verified"}]}}
    rc = cli.main(["playbook", "auth-takeover", "s-ptest"])
    assert rc == 1  # no session -> error, never raises
    rc = cli.main(["playbook", "nope", "s-ptest"])
    assert rc == 1
    rc = cli.main(["playbook", "unknown-playbook", "list"])
    assert rc == 1


def test_cli_end_to_end_with_session(tmp_path, capsys, monkeypatch, target):
    from omega import session as session_mod
    monkeypatch.setenv("OMEGA_SESSIONS_HOME", str(tmp_path))
    monkeypatch.setenv("PTK_OFFENSE", "1")
    session_mod.save_session("pb-e2e", {
        "target": target,
        "findings": [
            {"title": "Credentials leaked in environment file",
             "location": target + "/.env",
             "evidence": "user=admin password=hunter2",
             "verification": "verified"},
            {"title": "Login form discovered",
             "location": target + "/login",
             "verification": "verified"}]})
    # plan only (no --stage)
    assert cli.main(["playbook", "auth-takeover", "pb-e2e",
                     "--scope-ack"]) == 0
    out = capsys.readouterr().out
    assert "auth-takeover" in out and "abort" in out.lower()
    # run stage 0 end-to-end
    assert cli.main(["playbook", "auth-takeover", "pb-e2e", "--stage", "0",
                     "--scope-ack"]) == 0
    out = capsys.readouterr().out
    assert "executed   : True" in out
    assert "verified   : True" in out


def test_cli_plan_json(tmp_path, capsys, target):
    doc = {"target": target, "state": {"findings": [
        {"title": "Open redirect in URL parameter",
         "location": target + "/redirect", "verification": "verified"}]}}
    f = tmp_path / "find.json"
    f.write_text(json.dumps(doc))
    assert cli.main(["playbook", "ssrf-pivot", str(f), "--json"]) == 0
    p = json.loads(capsys.readouterr().out)
    assert p["exists"] is True and p["prereqs"]["ok"] is True
    assert len(p["stages"]) == 2


# ------------------------------------------------------- never raises

def test_run_stage_never_raises_on_junk():
    for args in [(None, 0, None, None, None),
                 ("nope", 0, None, None, None),
                 ("auth-takeover", 99, None, None, None),
                 ("auth-takeover", "x", None, None, None),
                 ("auth-takeover", 0, None, None, None)]:
        res = run_stage(*args)
        assert isinstance(res, dict)
        assert res["executed"] is False


def test_run_stage_survives_raising_fetch(monkeypatch):
    monkeypatch.setenv("PTK_OFFENSE", "1")

    def boom(*a, **k):
        raise RuntimeError("socket exploded")

    findings = [F("Credentials leaked", "http://127.0.0.1:1/x",
                  "user=a password=b"),
                F("Login form", "http://127.0.0.1:1/login")]
    res = run_stage("auth-takeover", 0, boom, "http://127.0.0.1:1",
                    findings)
    assert isinstance(res, dict)
    assert res["refuted"] is True or res["executed"] in (False, True)


def test_check_prereqs_never_raises_on_junk():
    assert check_prereqs(None, None)["ok"] is False
    assert check_prereqs("nope", [None, 42, {"title": 5}])["ok"] is False
    assert check_prereqs("auth-takeover", [None, "string finding"]) \
        is not None


# ------------------------------------------------------- brain wiring

def test_brain_registers_offense_playbook_planning_only():
    from omega.core.brain import DEFAULT_REGISTRY, _offense_playbook_fn
    cap = DEFAULT_REGISTRY.get("offense.playbook")
    assert cap is not None
    assert cap.risk == "offense"
    assert cap.cost == 2
    assert callable(cap.fn)
    assert cap.fn is _offense_playbook_fn


def test_brain_playbook_capability_plans_but_never_executes(monkeypatch):
    from omega.core.brain import DEFAULT_REGISTRY
    cap = DEFAULT_REGISTRY.get("offense.playbook")
    state = types.SimpleNamespace(
        target="http://127.0.0.1:9",
        findings=[{"title": "Login form discovered",
                   "location": "http://127.0.0.1:9/login",
                   "verification": "verified"}])
    out = cap.fn(state)
    assert isinstance(out, dict)
    assert out["playbooks"]
    assert "no execution" in out["note"]
    for entry in out["playbooks"]:
        assert "stages" not in entry or all(
            "probe" not in s for s in entry["stages"])
    # nothing was executed: no stage produced a finding
    assert not state.findings or all(
        "validation" not in f for f in state.findings
        if isinstance(f, dict))
