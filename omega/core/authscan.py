"""omega/core/authscan — authenticated deep-scan session engine.

Wraps omega.core.auth (AuthSession/SessionFetcher) into a full
authenticated-scan lifecycle:

    detect login form -> login (single attempt, OMEGA_CREDS) ->
    session fixation check -> logout invalidation check ->
    authenticated fetcher handed back to the caller for the suites

All findings are candidate + manual_check. Credentials are taken from
the environment (OMEGA_CREDS) or the creds argument, never stored
anywhere. Single login attempt by design — no brute force.
"""
import os

from omega.core.auth import AuthSession, detect_login_form

LOGOUT_PATHS = ("/logout", "/logout.php", "/user/logout",
                "/api/auth/logout", "/auth/logout", "/signout")


def _finding(title, severity, source, evidence, location, manual_check):
    return {"title": title, "severity": severity, "source": source,
            "evidence": evidence, "location": location,
            "manual_check": manual_check,
            "verification": "candidate",
            "verification_note": "candidate from the auth deep-scan "
                                 "engine; verify manually"}


def _default_fetch(method, url, body=None):
    from omega.scanning.deepchecks import default_fetch
    return default_fetch(method, url, body=body)


def _cookie_snapshot(login_result):
    """Cookie mapping from a login-result-like dict (never logged)."""
    return dict((login_result or {}).get("cookies") or {})


def run_auth_deep_scan(target, fetch=None, creds=None, log=None):
    """Full authenticated lifecycle against ONE target.

    Returns {ok, logged_in, findings, session_fetcher, pre_cookies,
    post_cookies, note}. ``session_fetcher`` can drive the other
    suites authenticated. Never raises.
    """
    fetch = fetch or _default_fetch
    creds = creds or os.environ.get("OMEGA_CREDS")
    out = {"target": target, "ok": False, "logged_in": False,
           "findings": [], "session_fetcher": None, "note": None}
    if not creds:
        out["note"] = "no credentials: set OMEGA_CREDS (user:pass)"
        return out
    if not isinstance(creds, str) or ":" not in creds:
        out["note"] = "creds must be user:pass (or OMEGA_CREDS env)"
        return out

    # --- pre-login fingerprint: is a session cookie issued already? ---
    pre_cookies = {}
    try:
        from omega.core.auth import _extract_cookies, parse_forms, \
            _classify_fields
        st0, headers, body = fetch("GET", target, body=None)
        pre_cookies = _extract_cookies(headers) if isinstance(
            headers, dict) else {}
        info = detect_login_form(fetch, target)
        if not info:
            # fall back to the root page's own forms before giving up
            text = (body or b"").decode("latin-1", "replace")
            for form in parse_forms(text):
                fields = _classify_fields(form)
                if fields.get("pass_field"):
                    info = {"login_path": "/",
                            "fields": fields,
                            "action": form.get("action") or "/",
                            "csrf_value": None, "markers": []}
                    break
    except Exception as exc:
        out["note"] = "login form detection failed: %s" % exc
        return out
    if not info or not info.get("login_path"):
        out["note"] = "no recognizable login form on the target"
        return out

    # --- login (single attempt) ---
    sess = AuthSession(target, creds=creds, fetch=fetch)
    result = sess.login()
    if not result or not result.get("ok"):
        out["note"] = "login failed: credentials rejected or form " \
                      "flow unexpected (single attempt only — no " \
                      "brute force by design)"
        return out
    out["logged_in"] = True
    out["ok"] = True
    post_cookies = _cookie_snapshot(result)
    out["pre_cookies"] = sorted(pre_cookies)
    out["post_cookies"] = sorted(post_cookies)
    out["session_fetcher"] = sess.fetcher()

    # --- session fixation: the session cookie must be NEW post-login ---
    sess_names = {k for k in post_cookies
                  if any(s in k.lower() for s in
                         ("sess", "sid", "token", "auth"))}
    if sess_names and all(k in pre_cookies and
                          pre_cookies[k] == post_cookies[k]
                          for k in sess_names):
        out["findings"].append(_finding(
            "session ID not rotated on login (session fixation)",
            "HIGH", "authscan/fixation",
            "session cookie(s) %s identical before and after "
            "authentication" % sorted(sess_names), target,
            "log in in a browser and compare the session cookie value "
            "before/after authentication"))

    # --- logout invalidation check ---
    logged_out = False
    logout_path = None
    for lp in LOGOUT_PATHS:
        try:
            st, headers, body = fetch("GET", target.rstrip("/") + lp,
                                      body=None)
        except Exception:
            continue
        if st and st < 400:
            logged_out = True
            logout_path = lp
            break
    if logged_out and post_cookies:
        # replay the captured session on the target root
        try:
            from omega.core.auth import SessionFetcher
            sfetch = SessionFetcher(fetch=fetch, cookies=post_cookies)
            st2, h2, b2 = sfetch("GET", target, body=None)
            if st2 and st2 < 400:
                out["findings"].append(_finding(
                    "session survives logout (invalidation failure)",
                    "HIGH", "authscan/logout",
                    "after %s the previous session token still "
                    "returns HTTP %s on the target root"
                    % (logout_path, st2), target + str(logout_path),
                    "log in, capture the cookie, hit logout, replay "
                    "the cookie on a protected page"))
        except Exception as exc:
            out["note"] = "logout replay check error: %s" % exc
    if log:
        log("authscan %s logged_in=%s findings=%d"
            % (target, out["logged_in"], len(out["findings"])))
    return out
