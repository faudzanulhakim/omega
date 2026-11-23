"""omega/authchecks.py — AUTHENTICATED checks (session required).

Six checks that run only through an authenticated ``SessionFetcher``:
when a plain (unauthenticated) fetch is supplied, every check is
skipped with the reason ``no auth session`` — nothing anonymous leaks
into the authenticated findings.

Checks (source=omega-auth/<name>):
  authz_bypass_diff   — same resource with cookies vs without:
                        200-with-cookie + 401/403-without + same body
                        length band -> candidate HIGH. Anonymous mode
                        (no session) does a contained /api/* differential
                        for the brain's auth.unauth_diff capability.
  role_probe          — /api/me /profile differential authed vs anon — INFO.
  session_flag_audit  — Set-Cookie flags on the authenticated response.
  jwt_session_scan    — JWT extracted from cookies/headers; decode-only
                        structure + local weak-secret verify (candidate
                        / confirmed offline).
  csrf_token_audit    — POST forms on authenticated pages missing a CSRF
                        field -> candidate MEDIUM.
  idor_authenticated  — numeric param +1 differential WITH a valid
                        session: 200 + different body vs 403 — candidate.

run_authchecks never raises; returns {findings, ran, skipped, auth_state}.
Credentials are NEVER logged or echoed into evidence.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import urllib.parse

from omega.auth import (SessionFetcher, _cookie_flags, parse_creds,
                        creds_from_env)
from omega.deepchecks import default_fetch
from omega.probes import Finding, allowlist_ok

__all__ = [
    "anon_api_diff",
    "authz_bypass_diff",
    "csrf_token_audit",
    "idor_authenticated",
    "jwt_session_scan",
    "registry",
    "role_probe",
    "run_authchecks",
    "session_flag_audit",
]

SOURCE_PREFIX = "omega-auth/"

# Weak HMAC secrets — verify-only, offline, never brute-force against
# the target (reuses the deepchecks jwt decode-only logic shape).
JWT_COMMON_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "changeme", "admin",
    "key", "test", "qwerty", "letmein", "welcome", "iloveyou",
    "default", "supersecret", "mysecret", "token", "abc123", "hello",
    "example", "secretkey",
]

# Profile/api paths belong to role_probe; authz_bypass_diff targets
# app-style protected pages only (avoids double-reporting /api/me).
PROTECTED_PATHS = ["/admin", "/account", "/dashboard", "/settings",
                   "/console", "/protected"]
ROLE_PATHS = ["/api/me", "/profile", "/api/user", "/user"]
CSRF_HINTS = ("csrf", "_token", "token", "authenticity")
NUMERIC_PARAMS = ["id", "user_id", "uid", "account", "order_id", "item_id"]


def _skip(name, result, reason):
    result["skipped"][name] = reason
    return []


def _same_length_band(a, b):
    """Same body length band: within 25% of each other (both > 0)."""
    if a <= 0 or b <= 0:
        return False
    lo, hi = sorted((a, b))
    return (hi - lo) <= 0.25 * hi


def _api_paths(path_info):
    paths = []
    if isinstance(path_info, dict):
        for p in (path_info.get("paths") or []):
            ps = str(p)
            if ps.startswith("/") and ("/api/" in ps or ps.startswith("/api")
                                       or "admin" in ps.lower()):
                paths.append(ps)
    if not paths:
        paths = ["/api/me", "/api/profile", "/api/admin/users"]
    return paths[:8]


# ---------------------------------------------------------------- checks

def authz_bypass_diff(base_url, fetch, path_info=None):
    """Same protected resource with session cookies vs without.

    candidate HIGH only when: with-cookie = 200, without-cookie =
    401/403, and both bodies fall in the same length band (the anon
    denial is a thin wrapper around the same content). A resource that
    returns 200 anonymously yields NO finding (false-positive guard).
    Requires a SessionFetcher; a plain fetch is skipped upstream.
    """
    if not isinstance(fetch, SessionFetcher):
        return []  # plain fetch: skipped upstream with 'no auth session'
    base = base_url.rstrip("/")
    paths = []
    if isinstance(path_info, dict):
        for p in (path_info.get("paths") or []):
            ps = str(p)
            if ps.startswith("/") and "logout" not in ps.lower():
                paths.append(ps)
    for p in PROTECTED_PATHS:
        if p not in paths:
            paths.append(p)
    for path in paths[:8]:
        url = base + path
        try:
            st_auth, _h_auth, b_auth = fetch("GET", url)
        except Exception:
            continue
        if st_auth != 200:
            continue
        # same underlying transport, deliberately WITHOUT session cookies
        anon = SessionFetcher(fetch=fetch._fetch)
        st_anon, _h_anon, b_anon = anon("GET", url)
        if st_anon not in (401, 403):
            # FP guard: resource is public or behaves differently — no claim
            continue
        if _same_length_band(len(b_auth), len(b_anon)):
            return [Finding(
                title="Authorization bypass differential on %s" % path,
                severity="high",
                verification="candidate",
                verification_note=(
                    "With a valid session the resource returns HTTP 200 "
                    "while the identical anonymous request is refused "
                    "(401/403) with a body in the same length band as "
                    "the authenticated content — consistent with an "
                    "object/resource served to authenticated users and "
                    "a denial page for others. Candidate: manual "
                    "verification required to confirm the anon denial "
                    "is authorization (not e.g. a different route)."),
                manual_check=('curl -sS -i "%s"  # with vs without the '
                              'authenticated cookie' % url),
                location=url,
                evidence={"path": path,
                          "status_with_session": st_auth,
                          "status_anonymous": st_anon,
                          "body_len_with_session": len(b_auth),
                          "body_len_anonymous": len(b_anon)},
                source=SOURCE_PREFIX + "authz_bypass_diff")]
    return []


def anon_api_diff(base_url, fetch, path_info=None):
    """Anonymous /api/* differential used by brain's auth.unauth_diff.

    An /api/* path answering 200 anonymously with a body that differs
    from the site-wide 404 page yields a candidate (an unauthenticated
    API endpoint exists where neighbors are denied).
    """
    base = base_url.rstrip("/")
    probe404 = base + "/omega-no-such-path-%d" % (
        hash(str(base_url)) % 100000)
    try:
        _s404, _h404, b404 = fetch("GET", probe404)
    except Exception:
        b404 = b""
    for path in _api_paths(path_info):
        url = base + path
        try:
            st, _h, body = fetch("GET", url)
        except Exception:
            continue
        if st != 200:
            continue
        if len(body) and body != b404:
            return [Finding(
                title="Anonymous-accessible API endpoint: %s" % path,
                severity="low",
                verification="candidate",
                verification_note=(
                    "The /api/* style path answers HTTP 200 without any "
                    "session cookie, with content that differs from the "
                    "site-wide 404 page. Informational discovery of an "
                    "unauthenticated API surface; review its exposure "
                    "manually."),
                manual_check='curl -sS -i "%s"' % url,
                location=url,
                evidence={"path": path, "status": st,
                          "body_len": len(body)},
                source=SOURCE_PREFIX + "authz_bypass_diff/anon_api_diff")]
    return []


def role_probe(base_url, fetch, path_info=None):
    """Authed vs anonymous differential on profile-ish endpoints — INFO.

    Requires a SessionFetcher; plain fetch -> skipped 'no auth session'.
    """
    if not isinstance(fetch, SessionFetcher):
        return []
    base = base_url.rstrip("/")
    for path in ROLE_PATHS:
        url = base + path
        try:
            st_auth, _h, b_auth = fetch("GET", url)
            anon = SessionFetcher(fetch=fetch._fetch)
            st_anon, _h2, b_anon = anon("GET", url)
        except Exception:
            continue
        if st_auth == 200 and st_anon in (401, 403) \
                and b_auth != b_anon:
            return [Finding(
                title="Role-differentiated response observed at %s" % path,
                severity="info",
                verification="confirmed",
                verification_note=(
                    "Authenticated and anonymous requests to the same "
                    "profile endpoint return different content (authed: "
                    "HTTP %d; anon: HTTP %d) — informational "
                    "authorization boundary evidence, not a "
                    "vulnerability claim." % (st_auth, st_anon)),
                manual_check='curl -sS -i "%s"' % url,
                location=url,
                evidence={"path": path, "status_authed": st_auth,
                          "status_anon": st_anon,
                          "bodies_differ": True},
                source=SOURCE_PREFIX + "role_probe")]
    return []


def session_flag_audit(base_url, fetch, path_info=None, login_headers=None):
    """Set-Cookie flag audit on the authenticated session (reuses the
    probes security-headers logic shape: report the exact missing list).

    Requires a SessionFetcher (its harvest carries the session cookie
    name); flags come from the login response headers when available.
    """
    if not isinstance(fetch, SessionFetcher):
        return []
    flags = _cookie_flags(login_headers or {})
    if not flags:
        return []
    session_names = [n for n in flags if n.lower() in
                     ("sessionid", "sid", "session", "phpsessionid",
                      "jsessionid", "aspsessionid*", "auth", "token",
                      "jwt", "jwt_token", "access_token")]
    audited = session_names or list(flags)
    problems = {}
    for name in audited:
        f = flags[name]
        missing = [attr for attr, ok in
                   (("Secure", f["secure"]), ("HttpOnly", f["httponly"]),
                    ("SameSite", f["samesite"])) if not ok]
        if missing:
            problems[name] = missing
    if problems:
        return [Finding(
            title="Session cookie missing security attributes",
            severity="medium",
            verification="confirmed",
            verification_note=(
                "The authenticated response Set-Cookie for %s is missing: "
                "%s. Attribute disclosure only — cookie values are "
                "deliberately not recorded." % (
                    ", ".join(sorted(problems)),
                    "; ".join("%s: %s" % (n, "/".join(m))
                              for n, m in sorted(problems.items())))),
            manual_check=("curl -sS -i %s/login | grep -i set-cookie"
                          % base_url.rstrip("/")),
            location=base_url,
            evidence={"cookies": {n: m for n, m in problems.items()}},
            source=SOURCE_PREFIX + "session_flag_audit")]
    return []


def _b64url_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _extract_jwt(fetch, path_info=None):
    """Extract a JWT from session cookies / response headers / path_info.

    Decode-only: the token VALUE never enters evidence (only its
    header claims shape).
    """
    token = None
    for name, val in (fetch.cookies or {}).items():
        if name.lower() in ("jwt", "token", "auth", "access_token",
                            "jwt_token", "id_token"):
            token = val
            break
    if isinstance(path_info, dict) and path_info.get("jwt"):
        token = path_info["jwt"]
    if token is None and os.environ.get("OMEGA_JWT"):
        token = os.environ["OMEGA_JWT"]
    if not token:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("latin-1"))
    except Exception:
        return None
    return {"token": token, "header": header}


def jwt_session_scan(base_url, fetch, path_info=None):
    """Decode-only JWT structure scan + LOCAL weak-secret verify.

    alg=none structure -> candidate HIGH (no crafted token is ever
    sent). A locally-recomputed common-secret HMAC match -> confirmed.
    Requires a SessionFetcher; plain fetch -> skipped 'no auth session'.
    """
    if not isinstance(fetch, SessionFetcher):
        return []
    found = _extract_jwt(fetch, path_info)
    if not found:
        return []
    token = found["token"]
    parts = token.split(".")
    header = found["header"]
    alg = str(header.get("alg", ""))
    findings = []
    if alg.lower() == "none" or not parts[2]:
        findings.append(Finding(
            title="Session JWT uses alg=none structure",
            severity="high",
            verification="candidate",
            verification_note=(
                "The session token header declares alg=none (or carries "
                "an empty signature). Server acceptance of unsigned "
                "tokens was NOT tested — no crafted token was sent to "
                "the target. Decode-only offline analysis; manual "
                "verification required."),
            manual_check="Inspect the token offline (decode-only)",
            location=base_url,
            evidence={"alg": alg},
            source=SOURCE_PREFIX + "jwt_session_scan",
            confidence="high"))
    signing_input = (parts[0] + "." + parts[1]).encode("latin-1")
    try:
        sig = _b64url_decode(parts[2])
    except Exception:
        sig = b""
    for secret in JWT_COMMON_SECRETS:
        if hmac.new(secret.encode(), signing_input,
                    hashlib.sha256).digest() == sig:
            findings.append(Finding(
                title="Session JWT signature verifies with a common "
                      "weak secret",
                severity="high",
                verification="confirmed",
                verification_note=(
                    "The token's HMAC-SHA256 signature was locally "
                    "recomputed with a common weak secret and matched "
                    "exactly — token forgery is possible. Verification "
                    "was entirely offline; the secret value is withheld "
                    "from this note deliberately."),
                manual_check="Offline verify: recompute HMAC-SHA256 "
                             "over header.payload with the matched "
                             "common secret and compare.",
                location=base_url,
                evidence={"alg": alg,
                          "secret_list_size": len(JWT_COMMON_SECRETS)},
                source=SOURCE_PREFIX + "jwt_session_scan",
                confidence="high"))
            break
    return findings


def csrf_token_audit(base_url, fetch, path_info=None):
    """POST forms on authenticated pages missing a CSRF field ->
    candidate MEDIUM. Requires a SessionFetcher."""
    if not isinstance(fetch, SessionFetcher):
        return []
    from omega.auth import parse_forms  # stdlib html.parser, local import
    base = base_url.rstrip("/")
    paths = ["/"]
    if isinstance(path_info, dict):
        for p in (path_info.get("paths") or []):
            ps = str(p)
            if ps.startswith("/") and ps not in paths:
                paths.append(ps)
    checked = 0
    for path in paths[:6]:
        url = base + path
        try:
            st, _h, body = fetch("GET", url)
        except Exception:
            continue
        if st != 200:
            continue
        text = body.decode("latin-1", "replace")
        for form in parse_forms(text):
            if (form.get("method") or "get") != "post":
                continue
            checked += 1
            names = [i.get("name") or "" for i in form.get("inputs") or []]
            has_csrf = any(n and any(h in n.lower() for h in CSRF_HINTS)
                           for n in names)
            if not has_csrf:
                action = form.get("action") or path
                if not action.startswith("/"):
                    action = "/" + action
                return [Finding(
                    title="POST form without CSRF token on authenticated "
                          "page %s" % path,
                    severity="medium",
                    verification="candidate",
                    verification_note=(
                        "An authenticated page contains a POST form with "
                        "no recognizable CSRF field (checked input names "
                        "for csrf/_token/token/authenticity patterns). "
                        "Cross-site request forgery exploitability was "
                        "NOT tested — no state-changing request was sent "
                        "by this check. Candidate only."),
                    manual_check=('View the form source at "%s" and '
                                  'confirm absence of a CSRF hidden '
                                  'field' % url),
                    location=url,
                    evidence={"page": path, "form_action": action,
                              "input_names_count": len(names)},
                    source=SOURCE_PREFIX + "csrf_token_audit")]
    return []


def idor_authenticated(base_url, fetch, path_info=None):
    """Numeric param +1 differential WITH a valid session.

    candidate when: authed ?param=1 -> 200, authed ?param=2 -> 200 with
    a DIFFERENT body (another user's object) while the same request
    anonymously is 401/403 — the object-level gap is only reachable
    authenticated, so this is candidate evidence. Requires a
    SessionFetcher.
    """
    if not isinstance(fetch, SessionFetcher):
        return []
    params = []
    if isinstance(path_info, dict):
        params += [str(p) for p in (path_info.get("params") or [])]
    params += NUMERIC_PARAMS
    base = base_url.rstrip("/")
    seen = set()
    for param in params:
        if param in seen:
            continue
        seen.add(param)
        url1 = "%s/?%s=1" % (base, urllib.parse.quote(param))
        url2 = "%s/?%s=2" % (base, urllib.parse.quote(param))
        try:
            st1, _h, b1 = fetch("GET", url1)
            if st1 != 200:
                continue
            st2, _h2, b2 = fetch("GET", url2)
            anon = SessionFetcher(fetch=fetch._fetch)
            st_anon, _h3, _b3 = anon("GET", url2)
        except Exception:
            continue
        if st2 == 200 and b2 != b1 and st_anon in (401, 403):
            return [Finding(
                title="IDOR candidate (authenticated): sequential "
                      "objects served for param '%s'" % param,
                severity="medium",
                verification="candidate",
                verification_note=(
                    "With a valid session, %s=1 and %s=2 both return "
                    "HTTP 200 with different bodies (distinct objects), "
                    "while the anonymous request for %s=2 is refused "
                    "(HTTP %d). Consistent with object-level "
                    "authorization relying only on authentication — "
                    "candidate; the 200 for the second object may still "
                    "be legitimately owned by the test account."
                    % (param, param, param, st_anon)),
                manual_check=('curl -sS "%s" (authed vs anon) and verify '
                              'object ownership' % url2),
                location=url2,
                evidence={"param": param, "status_1": st1,
                          "status_2": st2, "status_anon_2": st_anon,
                          "bodies_differ": True},
                source=SOURCE_PREFIX + "idor_authenticated")]
    return []


# -------------------------------------------------------------- registry

# name -> check callable; each receives (base_url, fetch, path_info)
registry = [
    ("authz_bypass_diff", authz_bypass_diff),
    ("role_probe", role_probe),
    ("session_flag_audit", session_flag_audit),
    ("jwt_session_scan", jwt_session_scan),
    ("csrf_token_audit", csrf_token_audit),
    ("idor_authenticated", idor_authenticated),
]

_CHECK_NAMES = [n for n, _ in registry]


# ---------------------------------------------------------- run_authchecks

def run_authchecks(target, creds=None, fetch=None, path_info=None,
                   budget=None, log=None, allowlist=None, env=None):
    """Run the authenticated checks against ``target``.

    ``creds`` may be an OMEGA_CREDS-style string/dict or None (reads
    OMEGA_CREDS from ``env``). Never raises. Returns
    {findings, ran, skipped, auth_state}.
    """
    result = {"findings": [], "ran": [], "skipped": {},
              "auth_state": {"logged_in": False, "session_expired": False,
                             "has_creds": False}}
    base_url = target if "://" in target else "https://" + target

    parsed = parse_creds(creds)
    if parsed is None:
        parsed = creds_from_env(env or os.environ) if creds is None \
            else None
    if parsed is None:
        result["skipped"]["__all__"] = \
            "no credentials provided (OMEGA_CREDS)"
        if log:
            log("authchecks skipped: no credentials provided (OMEGA_CREDS)")
        return result
    result["auth_state"]["has_creds"] = True

    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = \
            "target %r not in allowlist" % target
        if log:
            log("authchecks skipped: target not in allowlist: %r" % target)
        return result

    _login_headers = None
    if not isinstance(fetch, SessionFetcher):
        if fetch is not None:
            # A plain (unauthenticated) fetch was supplied: checks are
            # skipped — plain fetches must not masquerade as authed scans.
            for name in _CHECK_NAMES:
                result["skipped"][name] = "no auth session"
            result["auth_state"]["note"] = "no auth session"
            if log:
                log("authchecks skipped: no auth session (plain fetch)")
            return result
        # No fetch supplied: perform the login ourselves (ONE attempt —
        # never retries passwords, no brute force).
        from omega.auth import login as do_login
        underlying = default_fetch
        try:
            login_result = do_login(underlying, base_url, parsed)
        except Exception as exc:
            result["skipped"]["__all__"] = "login error: %s" % exc
            if log:
                log("authchecks login failed: %s" % exc)
            return result
        if not login_result.get("ok"):
            result["skipped"]["__all__"] = \
                "login failed (single attempt; no retry performed)"
            result["auth_state"]["note"] = "login failed"
            if log:
                log("authchecks login failed (single attempt)")
            return result
        result["auth_state"]["login_redirect"] = \
            login_result.get("redirected_to")
        _login_headers = login_result.get("headers")
        fetch = SessionFetcher(fetch=underlying,
                               cookies=login_result.get("cookies") or {})

    # Session health: the fetcher must actually be logged in.
    if not fetch.authenticated:
        for name in _CHECK_NAMES:
            result["skipped"][name] = \
                "session fetcher carries no cookies (not logged in)"
        result["auth_state"]["note"] = "session fetcher has no cookies"
        return result
    result["auth_state"]["logged_in"] = True

    for name, check in registry:
        if budget is not None and len(result["ran"]) >= budget:
            result["skipped"][name] = "budget exhausted"
            continue
        try:
            found = check(base_url, fetch, path_info=path_info,
                          **({"login_headers": _login_headers}
                             if name == "session_flag_audit" else {})) or []
        except Exception as exc:  # never raise
            result["skipped"][name] = "error: %s" % exc
            if log:
                log("authcheck %s failed: %s" % (name, exc))
            continue
        result["ran"].append(name)
        result["findings"].extend(found)
        if log:
            log("authcheck %s: %d finding(s)" % (name, len(found)))

    result["auth_state"]["session_expired"] = bool(fetch.session_expired)
    if fetch.session_expired:
        result["auth_state"]["note"] = \
            "session expired mid-run (401/403 onset observed)"
    return result
