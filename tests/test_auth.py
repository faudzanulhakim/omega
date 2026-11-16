"""tests/test_auth.py — hermetic tests for the authenticated scanning layer.

Fixture: a ThreadingHTTPServer emulating a small site with:
  * a login form (with CSRF token) at /login (or /signin variant),
  * a session cookie issued on successful login (missing Secure/
    SameSite flags, so the flag audit fires),
  * a JWT session cookie with an alg=none structure (decode-only scan),
  * protected resources: 200 with a valid session, 401/403 anonymous,
  * a POST form without CSRF on an authenticated page,
  * numeric id objects for the authenticated IDOR differential,
  * a public resource for the authz-bypass false-positive guard,
  * an anonymous /api/public/info endpoint for the anon differential.

The server counts POSTs to /login so the no-brute-force invariant
(exactly ONE attempt) is asserted directly.
"""

import base64
import json
import os
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.auth import (AuthSession, SessionFetcher, detect_login_form,
                        login, parse_creds)
from omega.authchecks import (anon_api_diff, authz_bypass_diff,
                              csrf_token_audit, idor_authenticated,
                              jwt_session_scan, role_probe,
                              run_authchecks, session_flag_audit)

USER = "admin"
PASS = "secret123"
CSRF = "csrf-value-abc123"
SID = "sid-session-token-0001"

AUTHED_BODY = ("Account dashboard for admin: settings, billing, "
               "profile overview and notifications.")
ANON_403_BODY = ("Access to the account dashboard requires sign-in. "
                 "Please authenticate to view your account.")


def _b64url(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


JWT_NONE = "%s.%s." % (_b64url({"alg": "none", "typ": "JWT"}),
                       _b64url({"sub": "admin"}))


class SiteState:
    def __init__(self):
        self.login_posts = 0
        self.login_path = "/login"
        self.protect_account = True   # FP guard toggle
        self.api_public = True        # anon api endpoint toggle


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def _send(self, code, body, headers=None):
            data = body.encode()
            self.send_response(code)
            for k, v in (headers or []):
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authed(self):
            cookies = self.headers.get("Cookie") or ""
            return ("sid=%s" % SID) in cookies

        def do_GET(self):
            p = urllib.parse.urlparse(self.path)
            path = p.path
            q = urllib.parse.parse_qs(p.query)
            if path == "/" and q.get("id") is not None:
                if not self._authed():
                    self._send(403, "forbidden")
                else:
                    item = (q.get("id") or ["1"])[0]
                    self._send(200, "item-body-%s-%s"
                               % (item, "A" * (10 + len(item))))
                return
            if path == "/":
                self._send(200, "home page omega test site "
                                "<form method='post' action='/do'>"
                                "<input name='note'></form>")
            elif path == state.login_path:
                self._send(200, (
                    "<html><title>Sign in</title><body>"
                    "<form method='post' action='%s'>"
                    "<input type='hidden' name='csrf_token' value='%s'>"
                    "<input type='text' name='username'>"
                    "<input type='password' name='password'>"
                    "<button>Log in</button></form></body></html>"
                    % (state.login_path, CSRF)))
            elif path == "/protected":
                if self._authed():
                    self._send(200, "Welcome admin to the protected area "
                                    "with confidential content.")
                else:
                    self._send(403, "forbidden")
            elif path == "/account":
                if not state.protect_account or self._authed():
                    self._send(200, AUTHED_BODY)
                else:
                    self._send(403, ANON_403_BODY)
            elif path == "/profile":
                if self._authed():
                    self._send(200, "Profile of admin (role=user) json")
                else:
                    self._send(401, "unauthorized profile")
            elif path == "/api/me":
                if self._authed():
                    self._send(200, '{"user":"admin","role":"user"}')
                else:
                    self._send(401, '{"error":"unauthorized"}')
            elif path == "/api/public/info":
                if state.api_public:
                    self._send(200, '{"info":"public endpoint v1"}')
                else:
                    self._send(404, "not found page generic omega")
            elif path == "/api/admin/users":
                self._send(401, "unauthorized")
            elif path == "/formpage":
                if self._authed():
                    self._send(200, (
                        "<html><body><form method='post' action='/do'>"
                        "<input name='note'><button>go</button></form>"
                        "</body></html>"))
                else:
                    self._send(403, "forbidden")
            elif path == "/item":
                if not self._authed():
                    self._send(403, "forbidden")
                else:
                    q = urllib.parse.parse_qs(p.query)
                    item = (q.get("id") or ["1"])[0]
                    self._send(200, "item-body-%s-%s"
                               % (item, "A" * (10 + len(item))))
            else:
                self._send(404, "not found page generic omega")

        def do_POST(self):
            p = urllib.parse.urlparse(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode()
            if p.path == state.login_path:
                state.login_posts += 1
                form = urllib.parse.parse_qs(body)
                user = (form.get("username") or [""])[0]
                password = (form.get("password") or [""])[0]
                token = (form.get("csrf_token") or [""])[0]
                if user == USER and password == PASS and token == CSRF:
                    self._send(302, "", [
                        ("Location", "/protected"),
                        ("Set-Cookie", "sid=%s; Path=/; HttpOnly" % SID),
                        ("Set-Cookie", "jwt=%s; Path=/" % JWT_NONE),
                    ])
                else:
                    self._send(200, "Sign in page: invalid credentials "
                                    "form username password")
                return
            self._send(404, "not found page generic omega")

    return Handler


@pytest.fixture()
def site():
    state = SiteState()
    server = ThreadingHTTPServer(("127.0.0.1", 0),
                                 make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.base_url = "http://127.0.0.1:%d" % server.server_address[1]
    state.server = server
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


def _logged_in_fetcher(state):
    sess = AuthSession(state.base_url, creds={"user": USER,
                                              "password": PASS})
    assert sess.login() is not None
    assert sess.login_result["ok"]
    return sess.fetcher()


# ------------------------------------------------------------- creds

def test_parse_creds_simple_and_json():
    assert parse_creds("alice:wonder") == {"user": "alice",
                                           "password": "wonder"}
    parsed = parse_creds(json.dumps({
        "user": "bob", "pass": "pw", "login_path": "/signin"}))
    assert parsed["user"] == "bob" and parsed["password"] == "pw"
    assert parsed["login_path"] == "/signin"
    assert parse_creds("") is None
    assert parse_creds("nopassword") is None


def test_parse_creds_kwargs_precedence_and_extra_field():
    parsed = parse_creds(json.dumps({"user": "a", "password": "b"}),
                         user="z", password="y")
    assert parsed == {"user": "z", "password": "y"}
    parsed = parse_creds(json.dumps({
        "user": "a", "password": "b", "login_path": "/x",
        "extra_field": {"remember": "1"}}))
    assert parsed["extra_field"] == {"remember": "1"}


def test_creds_from_env(monkeypatch):
    from omega.auth import creds_from_env
    monkeypatch.setenv("OMEGA_CREDS", "carol:x9")
    assert creds_from_env()["user"] == "carol"
    monkeypatch.delenv("OMEGA_CREDS")
    assert creds_from_env() is None


def test_authsession_env_and_kwargs(site, monkeypatch):
    monkeypatch.delenv("OMEGA_CREDS", raising=False)
    monkeypatch.setenv("OMEGA_CREDS", "%s:%s" % (USER, PASS))
    sess = AuthSession(site.base_url)
    assert sess.has_creds
    assert sess.login()["ok"]
    assert sess.fetcher().authenticated
    sess2 = AuthSession(site.base_url, creds=None, env={})
    assert not sess2.has_creds
    assert sess2.login() is None


# --------------------------------------------------- form detection

def test_detect_login_form(site):
    form = detect_login_form(None, site.base_url,
                             path_info={"paths": ["/login"]})
    # uses default fetch when fetch=None is not callable — pass explicitly
    from omega.deepchecks import default_fetch
    form = detect_login_form(default_fetch, site.base_url)
    assert form is not None
    assert form["login_path"] == "/login"
    assert form["fields"]["user_field"] == "username"
    assert form["fields"]["pass_field"] == "password"
    assert form["fields"]["csrf_field"] == "csrf_token"
    assert form["csrf_value"] == CSRF


def test_detect_login_form_multiple_paths(site):
    from omega.deepchecks import default_fetch
    state = site
    state.login_path = "/signin"
    form = detect_login_form(default_fetch, state.base_url)
    assert form is not None
    assert form["login_path"] == "/signin"
    state.login_path = "/login"


def test_detect_login_form_none_when_absent(site):
    from omega.deepchecks import default_fetch
    state = site
    state.login_path = "/definitely-not-login"
    assert detect_login_form(default_fetch, state.base_url) is None


# ------------------------------------------------------- login flow

def test_login_e2e_and_session_fetcher_propagation(site):
    from omega.deepchecks import default_fetch
    result = login(default_fetch, site.base_url,
                   {"user": USER, "password": PASS})
    assert result["ok"] is True
    assert "sid" in result["cookies"]
    assert result["redirected_to"] == "/protected"
    sfetch = SessionFetcher(fetch=default_fetch,
                            cookies=result["cookies"])
    st, _h, body = sfetch("GET", site.base_url + "/protected")
    assert st == 200 and b"admin" in body
    # the same URL without the session is denied
    plain_st, _h2, _b2 = default_fetch("GET",
                                       site.base_url + "/protected")
    assert plain_st == 403


def test_login_failure_single_attempt_no_brute_force(site):
    from omega.deepchecks import default_fetch
    result = login(default_fetch, site.base_url,
                   {"user": USER, "password": "wrong"})
    assert result["ok"] is False
    assert site.login_posts == 1  # exactly one POST — never retried


def test_no_brute_force_across_run(site):
    from omega.deepchecks import default_fetch
    login(default_fetch, site.base_url, {"user": USER, "password": PASS})
    login(default_fetch, site.base_url,
          {"user": USER, "password": "also-wrong"})
    assert site.login_posts == 2  # one per call, never a retry loop


def test_session_expired_flag(site):
    from omega.deepchecks import default_fetch
    sfetch = SessionFetcher(fetch=default_fetch,
                            cookies={"sid": "bogus"})
    st, _h, _b = sfetch("GET", site.base_url + "/protected")
    assert st == 403
    assert sfetch.session_expired is True


# ------------------------------------------------- authenticated checks

def test_authz_bypass_diff_candidate(site):
    sfetch = _logged_in_fetcher(site)
    findings = authz_bypass_diff(site.base_url, sfetch,
                                 path_info={"paths": ["/account"]})
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "high"
    assert f["verification"] == "candidate"
    assert f["source"] == "omega-auth/authz_bypass_diff"
    assert f["evidence"]["status_anonymous"] in (401, 403)


def test_authz_bypass_diff_fp_guard(site):
    sfetch = _logged_in_fetcher(site)
    site.protect_account = False  # resource is 200 anonymously too
    findings = authz_bypass_diff(site.base_url, sfetch,
                                 path_info={"paths": ["/account"]})
    assert findings == []


def test_role_probe_info(site):
    sfetch = _logged_in_fetcher(site)
    findings = role_probe(site.base_url, sfetch,
                          path_info={"paths": ["/api/me"]})
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "info"
    assert f["source"] == "omega-auth/role_probe"


def test_session_flag_audit(site):
    from omega.deepchecks import default_fetch
    result = login(default_fetch, site.base_url,
                   {"user": USER, "password": PASS})
    sfetch = SessionFetcher(fetch=default_fetch,
                            cookies=result["cookies"])
    findings = session_flag_audit(site.base_url, sfetch,
                                  login_headers=result["headers"])
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "medium"
    assert f["source"] == "omega-auth/session_flag_audit"
    missing = f["evidence"]["cookies"]["sid"]
    assert "Secure" in missing and "SameSite" in missing


def test_jwt_session_scan_alg_none(site):
    sfetch = _logged_in_fetcher(site)
    findings = jwt_session_scan(site.base_url, sfetch)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "high"
    assert f["verification"] == "candidate"
    assert f["evidence"]["alg"] == "none"
    assert f["source"] == "omega-auth/jwt_session_scan"
    # the token value itself never lands in evidence
    assert JWT_NONE not in json.dumps(f)


def test_csrf_token_audit(site):
    sfetch = _logged_in_fetcher(site)
    findings = csrf_token_audit(site.base_url, sfetch,
                                path_info={"paths": ["/formpage"]})
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "medium"
    assert f["verification"] == "candidate"
    assert f["source"] == "omega-auth/csrf_token_audit"


def test_idor_authenticated(site):
    sfetch = _logged_in_fetcher(site)
    findings = idor_authenticated(site.base_url, sfetch,
                                  path_info={"params": ["id"]})
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "medium"
    assert f["verification"] == "candidate"
    assert f["source"] == "omega-auth/idor_authenticated"
    assert f["evidence"]["bodies_differ"] is True


def test_anon_api_diff(site):
    from omega.deepchecks import default_fetch
    findings = anon_api_diff(site.base_url, default_fetch,
                             path_info={"paths": ["/api/public/info",
                                                  "/api/me"]})
    assert len(findings) == 1
    assert findings[0]["evidence"]["path"] == "/api/public/info"
    assert findings[0]["source"].startswith("omega-auth/authz_bypass_diff")


def test_checks_skip_plain_fetch(site):
    from omega.deepchecks import default_fetch
    assert authz_bypass_diff(site.base_url, default_fetch) == []
    assert role_probe(site.base_url, default_fetch) == []
    assert session_flag_audit(site.base_url, default_fetch) == []
    assert jwt_session_scan(site.base_url, default_fetch) == []
    assert csrf_token_audit(site.base_url, default_fetch) == []
    assert idor_authenticated(site.base_url, default_fetch) == []


# --------------------------------------------------- run_authchecks

def test_run_authchecks_no_creds(site, monkeypatch):
    monkeypatch.delenv("OMEGA_CREDS", raising=False)
    out = run_authchecks(site.base_url, creds=None)
    assert out["ran"] == []
    assert out["findings"] == []
    assert out["skipped"]["__all__"] == \
        "no credentials provided (OMEGA_CREDS)"


def test_run_authchecks_plain_fetch_skipped(site):
    from omega.deepchecks import default_fetch
    out = run_authchecks(site.base_url, creds="a:b", fetch=default_fetch)
    assert out["ran"] == []
    assert all(v == "no auth session" for v in out["skipped"].values())
    assert len(out["skipped"]) == 6


def test_run_authchecks_full_run(site, monkeypatch):
    monkeypatch.delenv("OMEGA_CREDS", raising=False)
    out = run_authchecks(site.base_url,
                         creds="%s:%s" % (USER, PASS))
    assert set(out["ran"]) == {
        "authz_bypass_diff", "role_probe", "session_flag_audit",
        "jwt_session_scan", "csrf_token_audit", "idor_authenticated"}
    assert out["auth_state"]["logged_in"] is True
    assert out["auth_state"]["session_expired"] is False
    sources = {f["source"] for f in out["findings"]}
    assert sources == {
        "omega-auth/authz_bypass_diff", "omega-auth/role_probe",
        "omega-auth/session_flag_audit", "omega-auth/jwt_session_scan",
        "omega-auth/csrf_token_audit", "omega-auth/idor_authenticated"}
    assert site.login_posts == 1  # single login attempt


def test_run_authchecks_login_failure_contained(site):
    out = run_authchecks(site.base_url, creds="%s:nope" % USER)
    assert out["ran"] == []
    assert "login failed" in out["skipped"]["__all__"]


def test_run_authchecks_env_creds_and_allowlist(site, monkeypatch):
    monkeypatch.setenv("OMEGA_CREDS", json.dumps(
        {"user": USER, "password": PASS, "login_path": "/login"}))
    out = run_authchecks(site.base_url, creds=None,
                         allowlist=["127.0.0.1"])
    assert "authz_bypass_diff" in out["ran"]
    out2 = run_authchecks(site.base_url, creds=None,
                          allowlist=["other.example"])
    assert out2["skipped"]["__all__"].startswith("target")


def test_run_authchecks_never_raises(site):
    out = run_authchecks(site.base_url, creds="%s:%s" % (USER, PASS),
                         path_info={"paths": ["/account", "/formpage"]},
                         budget=3)
    assert isinstance(out, dict)
    assert len(out["ran"]) <= 3


# ------------------------------------------------------- brain wiring

def test_brain_capabilities_registered():
    from omega.brain import DEFAULT_REGISTRY
    scan = DEFAULT_REGISTRY.get("auth.session_scan")
    diff = DEFAULT_REGISTRY.get("auth.unauth_diff")
    assert scan is not None and diff is not None
    assert scan.cost == 4 and scan.risk == "active"
    assert diff.cost == 2 and diff.risk == "active"
    assert scan.requires == ("has_web",)
    assert diff.requires == ("has_web",)


def test_brain_duplicate_guard():
    from omega.brain import DEFAULT_REGISTRY, Capability
    import pytest as _pytest
    with _pytest.raises(ValueError):
        DEFAULT_REGISTRY.register(Capability(
            "auth.session_scan", "enum", lambda s, b=None: {},
            cost=4, risk="active"))


def test_brain_eligibility_and_metadata():
    from omega.brain import DEFAULT_REGISTRY
    facts_no_web = {"has_web": False}
    facts_web = {"has_web": True}
    for cap_id in ("auth.session_scan", "auth.unauth_diff"):
        cap = DEFAULT_REGISTRY.get(cap_id)
        assert not cap.eligible(facts_no_web)
        assert cap.eligible(facts_web, budget_remaining=cap.cost)
        assert not cap.eligible(facts_web, budget_remaining=cap.cost - 1)
    # sorted eligibility places the cheaper unauth diff first
    elig = DEFAULT_REGISTRY.eligible(facts_web, budget_remaining=10)
    ids = [c.id for c in elig if c.id.startswith("auth.")]
    assert ids == ["auth.unauth_diff", "auth.session_scan"]


def test_brain_session_scan_degrades_without_creds(site, monkeypatch):
    from omega.brain import DEFAULT_REGISTRY, BrainState
    monkeypatch.delenv("OMEGA_CREDS", raising=False)
    state = BrainState(site.base_url)
    state.surface["urls"] = [site.base_url]
    result = DEFAULT_REGISTRY.get("auth.session_scan").fn(state)
    assert "no credentials provided (OMEGA_CREDS)" in result["note"]
    assert result.get("findings") is None or result.get("findings") == []


def test_brain_session_scan_with_creds(site, monkeypatch):
    from omega.brain import DEFAULT_REGISTRY, BrainState
    monkeypatch.setenv("OMEGA_CREDS", "%s:%s" % (USER, PASS))
    state = BrainState(site.base_url)
    state.surface["urls"] = [site.base_url]
    result = DEFAULT_REGISTRY.get("auth.session_scan").fn(state)
    assert result["auth_state"]["logged_in"] is True
    assert result["findings"]
    assert site.login_posts == 1


def test_brain_unauth_diff_runs_anonymously(site, monkeypatch):
    from omega.brain import DEFAULT_REGISTRY, BrainState
    monkeypatch.delenv("OMEGA_CREDS", raising=False)
    state = BrainState(site.base_url)
    state.surface["urls"] = [site.base_url + "/api/public/info"]
    result = DEFAULT_REGISTRY.get("auth.unauth_diff").fn(state)
    assert "findings" in result
    # only the anonymous differential ran — no login happened
    assert site.login_posts == 0
