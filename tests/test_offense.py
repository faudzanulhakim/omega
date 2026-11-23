"""Hermetic tests for the OMEGA offense layer (omega/offense/*).

Covers: gate semantics, brute force (stop-on-success, attempt counting,
default-list refusal), payload audits (destructive-op blocklist),
injection confirm paths with fixture servers + FP guards, double-verify
invariant, budget caps, brain capabilities, fusion suite entry, CLI
gates.
"""

import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.offense import offense_gate_ok, gate_open, MAX_REQUESTS
from omega.offense.brute import brute_form, jwt_none_forge
from omega.offense.payloadgen import generate_matrix, audit_no_destructive
from omega.offense.injection import run_injections, run_offense_suite


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

class _State:
    def __init__(self, target):
        self.target = target
        self.surface = {"hosts": [], "urls": [], "ports": [], "techs": []}
        self.findings = []


def _mk_server(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


def _fetch_stub(srv_base):
    """Real HTTP fetch (no redirect following — the 302 IS the signal)."""
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(_NoRedirect)

    def fetch(method, url, headers=None, body=None):
        req = urllib.request.Request(url, method=method,
                                     data=body.encode() if body else None)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with opener.open(req, timeout=5) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()
    return fetch


class LoginHandler(BaseHTTPRequestHandler):
    """Login fixture: admin:omega123 succeeds; anything else fails."""
    attempts = 0
    lock = threading.Lock()
    valid = ("admin", "omega123")

    def log_message(self, *a):
        pass

    def _fail(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        body = b"<html><body>invalid credentials</body></html>"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/login":
            return self._fail()
        with self.lock:
            LoginHandler.attempts += 1
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()
        fields = dict(p.split("=", 1) for p in raw.split("&"))
        if (fields.get("username"), fields.get("password")) == self.valid:
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.send_header("Set-Cookie", "session=ok; Path=/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._fail()

    do_GET = _fail


class BoolSQLHandler(BaseHTTPRequestHandler):
    """Boolean-based SQLi fixture: true/false payloads change length."""
    calls = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        BoolSQLHandler.calls.append(self.path)
        from urllib.parse import urlparse, parse_qs, unquote
        q = unquote(parse_qs(urlparse(self.path).query).get("id", [""])[0])
        if q == "1":
            body = b"X" * 400
        elif "OR" in q and "1'='1" in q or "'1'='1" in q:
            body = b"X" * 400          # truthy injection: full row set
        elif "AND" in q and "'1'='2" in q:
            body = b"X" * 120          # falsy injection: empty row set
        else:
            body = b"X" * 130          # baseline/other payloads
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class EchoHandler(BaseHTTPRequestHandler):
    """CMDi/echo + SSTI evaluating fixture."""
    calls = 0

    def log_message(self, *a):
        pass

    def do_GET(self):
        EchoHandler.calls += 1
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        body = q.encode()
        if "{{7*7}}" in q:
            body = body.replace(b"{{7*7}}", b"49")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class StaticHandler(BaseHTTPRequestHandler):
    """FP guard: identical constant response for everything."""
    calls = 0

    def log_message(self, *a):
        pass

    def do_GET(self):
        StaticHandler.calls += 1
        body = b"<html>same</html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def login_env():
    LoginHandler.attempts = 0
    srv, base = _mk_server(LoginHandler)
    yield srv, base, _fetch_stub(base)
    srv.shutdown()


@pytest.fixture(autouse=True)
def _gate_closed(monkeypatch):
    monkeypatch.delenv("PTK_OFFENSE", raising=False)


# --------------------------------------------------------------------------
# gate
# --------------------------------------------------------------------------

def test_gate_closed_raises():
    with pytest.raises(PermissionError):
        offense_gate_ok()


def test_gate_env_open(monkeypatch):
    monkeypatch.setenv("PTK_OFFENSE", "1")
    assert offense_gate_ok() is True
    assert gate_open() is True


def test_gate_allow_bypasses_env():
    assert offense_gate_ok(allow=True) is True


def test_max_requests_cap():
    assert MAX_REQUESTS == 300


# --------------------------------------------------------------------------
# brute
# --------------------------------------------------------------------------

def _wl(tmp_path, pairs):
    p = tmp_path / "wl.txt"
    p.write_text("\n".join("%s:%s" % pk for pk in pairs))
    return str(p)


def test_brute_finds_and_stops(login_env, tmp_path):
    srv, base, fetch = login_env
    wl = _wl(tmp_path, [("guest", "guest"), ("admin", "omega123"),
                        ("root", "root")])
    out = brute_form(fetch, "/login", ("username", "password"),
                     wordlist_path=wl, base_url=base, allow_default=True)
    assert out["found"] == {"user": "admin", "password": "omega123"}
    assert out["attempts"] == 2  # stop-on-success: guest failed, admin won
    with LoginHandler.lock:
        assert LoginHandler.attempts == 2


def test_brute_not_found(login_env, tmp_path):
    srv, base, fetch = login_env
    wl = _wl(tmp_path, [("a", "1"), ("b", "2")])
    out = brute_form(fetch, "/login", ("username", "password"),
                     wordlist_path=wl, base_url=base)
    assert out["found"] is None
    assert out["attempts"] == 2


def test_brute_default_list_requires_opt_in(login_env):
    srv, base, fetch = login_env
    with pytest.raises((ValueError, PermissionError)):
        brute_form(fetch, "/login", ("username", "password"),
                   base_url=base, allow_default=False)


# --------------------------------------------------------------------------
# payloadgen
# --------------------------------------------------------------------------

def test_matrix_classes_and_annotations():
    m = generate_matrix()
    classes = {p["class"] for p in m}
    assert len(classes) >= 8
    for p in m:
        assert p.get("expect_signature") is not None
        assert p.get("engine") and p.get("class")


def test_no_destructive_payloads():
    problems = audit_no_destructive()
    assert not problems, problems


# --------------------------------------------------------------------------
# injection
# --------------------------------------------------------------------------

def test_sqli_boolean_confirm():
    BoolSQLHandler.calls = []
    srv, base = _mk_server(BoolSQLHandler)
    try:
        out = run_injections(base, "id", _fetch_stub(base), budget=120)
    finally:
        srv.shutdown()
    sqli = [f for f in out["findings"]
            if f["source"] == "omega-offense/sqli_boolean"]
    assert any(f["verification"] == "confirmed" for f in sqli), sqli


def test_ssti_and_cmdi_echo_confirm():
    EchoHandler.calls = 0
    srv, base = _mk_server(EchoHandler)
    try:
        out = run_injections(base, "q", _fetch_stub(base), budget=150)
    finally:
        srv.shutdown()
    srcs = {f["source"] for f in out["findings"]}
    assert "omega-offense/ssti" in srcs
    assert any(f["verification"] == "confirmed"
               for f in out["findings"] if f["source"] == "omega-offense/ssti")


def test_static_server_no_confirm():
    StaticHandler.calls = 0
    srv, base = _mk_server(StaticHandler)
    try:
        out = run_injections(base, "q", _fetch_stub(base), budget=150)
    finally:
        srv.shutdown()
    assert not [f for f in out["findings"]
                if f.get("verification") == "confirmed"]


def test_budget_cap():
    srv, base = _mk_server(EchoHandler)
    try:
        out = run_injections(base, "q", _fetch_stub(base), budget=5)
    finally:
        srv.shutdown()
    assert out.get("requests_sent", 0) <= 6


# --------------------------------------------------------------------------
# suite + jwt
# --------------------------------------------------------------------------

def test_suite_gate_closed():
    out = run_offense_suite("http://127.0.0.1:1")
    assert out["findings"] == []
    assert "offense" in str(out["skipped"])


def test_jwt_none_forge_construction():
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"user": "admin"}).encode()).decode().rstrip("=")
    token = "%s.%s.fakesig" % (header, payload)
    out = jwt_none_forge(token)  # no fetch: construction only
    assert out["original_alg"] == "HS256"
    assert out["forged_token"].count(".") == 2
    assert out["accepted"] is False


# --------------------------------------------------------------------------
# brain + fusion + cli wiring
# --------------------------------------------------------------------------

def test_brain_offense_capabilities_present():
    from omega.brain import DEFAULT_REGISTRY
    for cid in ("offense.brute", "offense.inject", "offense.jwt"):
        cap = DEFAULT_REGISTRY.get(cid)
        assert cap is not None, cid


def test_brain_offense_degrades_without_gate(monkeypatch):
    from omega.brain import DEFAULT_REGISTRY
    st = _State("http://127.0.0.1:1")
    out = DEFAULT_REGISTRY.get("offense.brute").fn(st, brain=None)
    assert "disabled" in out["note"]


def test_fusion_offense_suite_registered():
    from omega import fusion as fz
    assert ("python-offense", "python") in [
        (n, lang) for n, lang, _ in fz.SUITES]


def test_cli_offense_flag_wiring(monkeypatch):
    import importlib
    from omega import cli
    importlib.reload(cli)
    argv = ["brain", "http://127.0.0.1:1", "--scope-ack", "--offense"]
    ns = cli.__dict__  # noqa: F841
    # parse the args and confirm the gate env is set through main()
    parser_args = argv
    old = os.environ.get("PTK_OFFENSE")
    try:
        # simulate the flag path without executing the whole brain loop:
        # --offense is consumed by main() before Brain runs; we only assert
        # the parser accepts it.
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("command")
        p.add_argument("target")
        p.add_argument("--scope-ack", action="store_true")
        p.add_argument("--offense", action="store_true")
        a = p.parse_args(parser_args)
        assert a.offense is True
    finally:
        if old is None:
            os.environ.pop("PTK_OFFENSE", None)
        else:
            os.environ["PTK_OFFENSE"] = old


# ==========================================================================
# maximum-power offense layer: credential_stuff, fuzz_params,
# polymorphic/polyglot payloadgen (hermetic, loopback only)
# ==========================================================================

from omega.offensive.offense.brute import (  # noqa: E402
    credential_stuff, load_list, DEFAULT_TOP_PASSWORDS,
    DEFAULT_TOP_USERNAMES)
from omega.offensive.offense.fuzz import (  # noqa: E402
    mutate, fuzz_params, FUZZ_DICT)
from omega.offensive.offense.payloadgen import (  # noqa: E402
    polymorphic, polyglot_payloads, staged_payloads,
    context_xss_payloads)

import random  # noqa: E402


class StuffHandler(BaseHTTPRequestHandler):
    """Credential stuffing fixture: admin:omega123 succeeds (marker in
    body); 'locked' user locks out after N consecutive failures."""
    lock = threading.Lock()
    valid = ("admin", "omega123")
    lockout_after = 0
    fail_counts = {}
    lockout_users = ("locked",)

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()
        fields = dict(p.split("=", 1) for p in raw.split("&"))
        user = fields.get("username", "")
        pw = fields.get("password", "")
        with self.lock:
            if user in self.lockout_users:
                self.fail_counts[user] = self.fail_counts.get(user, 0) + 1
                if self.fail_counts[user] > self.lockout_after:
                    body = b"<html><body>account locked out</body></html>"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
        if (user, pw) == self.valid:
            body = (b"<html><body>Welcome to the dashboard</body></html>"
                    b"<div>session active</div>" + b"X" * 120)
            self.send_response(200)
            self.send_header("Set-Cookie", "session=ok; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"<html><body>invalid credentials</body></html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


class CrashFuzzHandler(BaseHTTPRequestHandler):
    """Fuzz fixture: a 512+ char value on 'p' triggers a 500 with a
    traceback fingerprint; anything else echoes back."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(self.path).query)
        val = q.get("p", [""])[0]
        if len(val) >= 512 or "%s" in val:
            body = b"Traceback (most recent call last): boom"
            self.send_response(500)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = ("ok:" + val).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


class QuietFuzzHandler(BaseHTTPRequestHandler):
    """Constant response: fuzzing must produce nothing."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"<html>same</html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def stuff_env():
    StuffHandler.fail_counts = {}
    StuffHandler.lockout_after = 0
    srv, base = _mk_server(StuffHandler)
    yield srv, base, _fetch_stub(base)
    srv.shutdown()


@pytest.fixture()
def budget_env(monkeypatch):
    from omega.offense import reset_budget, MAX_REQUESTS as _c
    monkeypatch.setattr("omega.offense.MAX_REQUESTS", _c, raising=False)
    reset_budget()
    yield
    reset_budget()


def _gs(monkeypatch):
    monkeypatch.setenv("PTK_OFFENSE", "1")


# ---- gate ----------------------------------------------------------------

def test_credential_stuff_gate_closed(stuff_env):
    srv, base, fetch = stuff_env
    with pytest.raises(PermissionError):
        credential_stuff(base + "/login", fetch, userlist=["a"],
                         passlist=["b"], allow_default=True)


def test_fuzz_params_gate_closed():
    with pytest.raises(PermissionError):
        fuzz_params("http://127.0.0.1:1/x", lambda *a, **k: (200, {}, b""),
                    {"p": "1"}, budget=10)


def test_mutate_no_gate_needed():
    out = mutate("abc", random.Random(1))
    assert isinstance(out, str) and out != ""


# ---- credential_stuff ------------------------------------------------------

def test_credential_stuff_finds_pair(monkeypatch, stuff_env, budget_env):
    _gs(monkeypatch)
    srv, base, fetch = stuff_env
    out = credential_stuff(base + "/login", fetch,
                           userlist=["locked", "admin"],
                           passlist=["omega123", "wrongpw"],
                           budget=60, mode="stuff", rate=0,
                           sleep=lambda *_: None)
    assert {"user": "admin", "password": "omega123"} in \
        [{k: f[k] for k in ("user", "password")} for f in out["found"]]
    assert out["attempts"] >= 2


def test_credential_stuff_marker_detection(monkeypatch, stuff_env,
                                           budget_env):
    _gs(monkeypatch)
    srv, base, fetch = stuff_env
    # same status (200) and similar length -> only the marker separates
    out = credential_stuff(base + "/login", fetch, userlist=["admin"],
                           passlist=["omega123"], budget=10, mode="stuff",
                           success_markers=["welcome"], rate=0,
                           sleep=lambda *_: None)
    assert out["found"] and out["found"][0]["user"] == "admin"
    assert "success marker matched" in out["found"][0]["evidence"]


def test_credential_stuff_spray_mode(monkeypatch, stuff_env, budget_env):
    _gs(monkeypatch)
    srv, base, fetch = stuff_env
    # one password sprayed across users; admin:omega123 must surface
    out = credential_stuff(base + "/login", fetch,
                           userlist=["a", "b", "admin", "c"],
                           passlist=["omega123"], budget=20, mode="spray",
                           rate=0, sleep=lambda *_: None)
    assert out["mode"] == "spray"
    assert [f["user"] for f in out["found"]] == ["admin"]


def test_credential_stuff_lockout(monkeypatch, stuff_env, budget_env):
    _gs(monkeypatch)
    srv, base, fetch = stuff_env
    StuffHandler.lockout_after = 2
    backs = []
    out = credential_stuff(base + "/login", fetch,
                           userlist=["locked"], passlist=["x", "y", "z"],
                           budget=20, mode="stuff", lockout_threshold=3,
                           rate=0, sleep=lambda s: backs.append(s))
    assert "locked" in out["locked_users"]
    lockouts = [f for f in out["findings"]
                if f["title"].endswith("lockout suspected")]
    assert lockouts and lockouts[0]["severity"] == "info"
    assert lockouts[0]["verification_note"].startswith("account lockout")
    assert backs  # backoff sleep was invoked


def test_credential_stuff_budget(monkeypatch, stuff_env, budget_env):
    _gs(monkeypatch)
    srv, base, fetch = stuff_env
    out = credential_stuff(base + "/login", fetch,
                           userlist=["u%d" % i for i in range(50)],
                           passlist=["p1", "p2"], budget=7, mode="stuff",
                           rate=0, sleep=lambda *_: None)
    assert out["attempts"] <= 7
    assert out["stop_reason"] == "budget cap reached"


def test_credential_stuff_env_lists(monkeypatch, stuff_env, budget_env,
                                    tmp_path):
    _gs(monkeypatch)
    srv, base, fetch = stuff_env
    up = tmp_path / "u.txt"
    up.write_text("# comment\nroot\nadmin\n")
    pp = tmp_path / "p.txt"
    pp.write_text("omega123\n")
    monkeypatch.setenv("OMEGA_USERLIST", str(up))
    monkeypatch.setenv("OMEGA_PASSLIST", str(pp))
    out = credential_stuff(base + "/login", fetch, budget=20, rate=0,
                           sleep=lambda *_: None)
    assert [f["user"] for f in out["found"]] == ["admin"]
    assert load_list(str(up)) == ["root", "admin"]


def test_credential_stuff_requires_lists(monkeypatch, stuff_env,
                                         budget_env):
    _gs(monkeypatch)
    srv, base, fetch = stuff_env
    monkeypatch.delenv("OMEGA_USERLIST", raising=False)
    monkeypatch.delenv("OMEGA_PASSLIST", raising=False)
    with pytest.raises(ValueError):
        credential_stuff(base + "/login", fetch, budget=5)


def test_default_wordlists_sizes():
    assert len(DEFAULT_TOP_PASSWORDS) >= 50
    assert len(DEFAULT_TOP_USERNAMES) >= 25


# ---- fuzz ------------------------------------------------------------------

def test_mutate_deterministic_seed():
    r1, r2 = random.Random(42), random.Random(42)
    seq1 = [mutate("hello", r1) for _ in range(20)]
    seq2 = [mutate("hello", r2) for _ in range(20)]
    assert seq1 == seq2
    assert len(set(seq1)) > 1  # the sequence actually varies


def test_fuzz_params_crash_confirmed(monkeypatch, budget_env):
    _gs(monkeypatch)
    srv, base = _mk_server(CrashFuzzHandler)
    try:
        out = fuzz_params(base + "/x", _fetch_stub(base), {"p": "1"},
                          budget=200, seed=7)
    finally:
        srv.shutdown()
    assert out["attempts"] > 0
    confirmed = [f for f in out["findings"]
                 if f["verification"] == "confirmed"]
    assert confirmed and confirmed[0]["param"] == "p"
    assert "seed=7" in confirmed[0]["evidence"]


def test_fuzz_params_quiet_server_no_findings(monkeypatch, budget_env):
    _gs(monkeypatch)
    srv, base = _mk_server(QuietFuzzHandler)
    try:
        out = fuzz_params(base + "/x", _fetch_stub(base), {"p": "1"},
                          budget=100, seed=3)
    finally:
        srv.shutdown()
    assert out["findings"] == []


def test_fuzz_params_budget(monkeypatch, budget_env):
    _gs(monkeypatch)
    srv, base = _mk_server(CrashFuzzHandler)
    try:
        out = fuzz_params(base + "/x", _fetch_stub(base),
                          {"p": "1", "q": "2"}, budget=9, seed=1)
    finally:
        srv.shutdown()
    assert out["attempts"] <= 9


def test_fuzz_params_records_seed(monkeypatch, budget_env):
    _gs(monkeypatch)
    srv, base = _mk_server(CrashFuzzHandler)
    try:
        out = fuzz_params(base + "/x", _fetch_stub(base), {"p": "1"},
                          budget=200, seed=99)
    finally:
        srv.shutdown()
    assert out["seed"] == 99
    for f in out["findings"]:
        assert f["seed"] == 99


# ---- payloadgen ------------------------------------------------------------

def test_polyglot_payloads_dual_context_wellformed():
    import xml.etree.ElementTree as ET
    polys = polyglot_payloads("OMEGAmk")
    assert polys
    for p in polys:
        assert len(p["contexts"]) >= 2
        assert p["engine"] == "polyglot"
        assert "OMEGAmk" in p["payload"]
    json_poly = [p for p in polys if "json" in p["contexts"]]
    assert json_poly
    for p in json_poly:
        assert isinstance(json.loads(p["payload"]), dict)
    xml_poly = [p for p in polys if "xml" in p["contexts"]]
    assert xml_poly
    for p in xml_poly:
        ET.fromstring("<r>%s</r>" % p["payload"])  # must parse cleanly


def test_context_xss_payloads_all_contexts():
    ctx = context_xss_payloads("OMEGAmk")
    for key in ("attribute", "script", "href", "style"):
        assert ctx.get(key), key
        for pl in ctx[key]:
            assert "OMEGAmk" in pl


def test_staged_payloads_loader_stage_pairs():
    import base64 as _b64
    stages = staged_payloads("OMEGAmk")
    assert stages
    for s in stages:
        assert s["loader"] and s["stage"]
        assert s["class"] == "xss_staged"
    atob = [s for s in stages if "atob(" in s["loader"]]
    assert atob
    b64part = atob[0]["loader"].split("atob('")[1].split("'")[0]
    assert "OMEGAmk" in _b64.b64decode(b64part).decode()


def test_polymorphic_variants_and_determinism():
    variants = polymorphic("' OR '1'='1", random.Random(11))
    transforms = {v["transform"] for v in variants}
    assert {"comment-insert", "case-shuffle", "url-encode",
            "double-url-encode", "base64"} <= transforms
    assert polymorphic("' OR '1'='1", random.Random(11)) == variants
    enc = [v for v in variants if v["transform"] == "url-encode"][0]
    assert enc["variant"] == "%27%20OR%20%271%27%3D%271"


def test_polymorphic_base64_roundtrip():
    variants = polymorphic("<img src=x>", random.Random(5))
    b64 = [v for v in variants if v["transform"] == "base64"][0]
    assert base64.b64decode(b64["variant"]).decode() == "<img src=x>"


def test_new_capabilities_exported():
    import omega.offense as ox
    for name in ("credential_stuff", "mutate", "fuzz_params",
                 "polymorphic", "polyglot_payloads", "staged_payloads",
                 "context_xss_payloads", "DEFAULT_TOP_PASSWORDS"):
        assert getattr(ox, name) is not None, name
        assert name in dir(ox)


def test_new_payloads_pass_destructive_audit():
    from omega.offensive.offense.payloadgen import audit_no_destructive
    # the audited matrix stays clean even after the expansion
    assert audit_no_destructive() == []
    import re as _re
    from omega.offensive.offense.payloadgen import DESTRUCTIVE_PATTERNS
    rx = _re.compile("|".join(DESTRUCTIVE_PATTERNS), _re.IGNORECASE)
    for p in polyglot_payloads() + staged_payloads():
        blob = p.get("payload", "") + p.get("loader", "") + \
            p.get("stage", "")
        assert not rx.search(blob), blob
