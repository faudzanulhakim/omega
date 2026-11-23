"""omega/auth.py — authenticated scanning layer.

Provides:
  * ``parse_creds``          — OMEGA_CREDS parsing ('user:pass' or JSON)
  * ``AuthSession``          — credential holder + login driver
  * ``detect_login_form``    — locate a login form on common paths
  * ``login``                — ONE credential, ONE POST attempt (never
                               retries passwords; no brute force)
  * ``SessionFetcher``       — fetch wrapper carrying auth cookies +
                               CSRF header propagation, drop-in
                               compatible with the probes/deepchecks
                               injectable ``fetch(method, url, headers,
                               body) -> (status, headers, body)``
                               contract, with 401/403-onset
                               ``session_expired`` detection.

Safety invariants:
  * Credentials are NEVER logged or echoed into findings/evidence.
  * Exactly one login attempt per run per credential set — the login
    function performs a single POST and never loops on failure.
  * The SessionFetcher is strictly additive: it wraps an existing fetch
    callable and adds only Cookie/CSRF headers.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from html.parser import HTMLParser

__all__ = [
    "AuthSession",
    "FETCH_TIMEOUT",
    "SessionFetcher",
    "detect_login_form",
    "login",
    "parse_creds",
]

try:  # deepchecks fetch supports body=; probes fetch does not
    from omega.deepchecks import default_fetch as _default_fetch
except ImportError:  # pragma: no cover
    from omega.probes import default_fetch as _default_fetch

FETCH_TIMEOUT = 5.0

COMMON_LOGIN_PATHS = ["/login", "/signin", "/wp-login.php", "/admin",
                      "/user/login"]

LOGIN_PAGE_MARKERS = ["sign in", "log in", "login", "password",
                      "sign-in", "username"]

USER_FIELD_HINTS = ("user", "email", "login", "username", "account")
CSRF_FIELD_HINTS = ("csrf", "_token", "token", "authenticity")


# ----------------------------------------------------------------- creds

def parse_creds(spec=None, **kwargs):
    """Parse credentials from ``spec`` (env-style string) or kwargs.

    ``spec`` may be:
      * ``'user:pass'``                    — simple form
      * JSON ``'{"user":..,"pass":..}'``   — extended form, optionally
        with ``login_path`` and ``extra_field`` (dict of extra form
        fields, e.g. {"remember": "1"}).

    Explicit kwargs (user=, password=, ...) take precedence. Returns a
    dict {user, password, login_path?, extra_field?} or None when no
    credentials are available. The password is never logged anywhere.
    """
    creds = {}
    if isinstance(spec, dict):
        creds.update(spec)
    elif isinstance(spec, str) and spec.strip():
        text = spec.strip()
        if text.startswith("{"):
            try:
                data = json.loads(text)
            except ValueError:
                return None
            if not isinstance(data, dict):
                return None
            creds.update(data)
        elif ":" in text:
            user, _, password = text.partition(":")
            creds["user"] = user
            creds["password"] = password
        else:
            return None
    if kwargs.get("user"):
        creds["user"] = kwargs["user"]
    if kwargs.get("password"):
        creds["password"] = kwargs["password"]
    if kwargs.get("login_path"):
        creds["login_path"] = kwargs["login_path"]
    if kwargs.get("extra_field"):
        creds["extra_field"] = kwargs["extra_field"]
    if not creds.get("password"):
        creds["password"] = creds.get("pass") or creds.get("pwd")
    if not creds.get("user") or not creds.get("password"):
        return None
    out = {"user": str(creds["user"]), "password": str(creds["password"])}
    if creds.get("login_path"):
        out["login_path"] = str(creds["login_path"])
    if isinstance(creds.get("extra_field"), dict):
        out["extra_field"] = dict(creds["extra_field"])
    return out


def creds_from_env(env=None):
    """Read OMEGA_CREDS from ``env`` (default os.environ); None when
    absent/empty/unparseable."""
    env = os.environ if env is None else env
    raw = env.get("OMEGA_CREDS")
    if not raw:
        return None
    return parse_creds(raw)


# --------------------------------------------------------- form parsing

class _FormParser(HTMLParser):
    """Collect <form> elements with their input fields (stdlib only)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag.lower() == "form":
            self._cur = {"action": a.get("action") or "",
                         "method": (a.get("method") or "get").lower(),
                         "inputs": []}
        elif tag.lower() == "input" and self._cur is not None:
            self._cur["inputs"].append({
                "name": a.get("name") or "",
                "type": (a.get("type") or "text").lower(),
                "value": a.get("value") or "",
            })

    def handle_endtag(self, tag):
        if tag.lower() == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def parse_forms(html_text):
    """Parse all <form> structures from an HTML fragment."""
    p = _FormParser()
    try:
        p.feed(html_text)
        p.close()
    except Exception:
        return []
    return p.forms


def _classify_fields(form):
    """Map a parsed form to {user_field, pass_field, csrf_field}."""
    user_field = pass_field = csrf_field = None
    for inp in form.get("inputs") or []:
        name = (inp.get("name") or "").lower()
        itype = inp.get("type") or ""
        if itype == "password" and not pass_field:
            pass_field = inp.get("name")
        elif itype in ("text", "email") and not user_field and (
                any(h in name for h in USER_FIELD_HINTS) or name):
            if any(h in name for h in USER_FIELD_HINTS) or not user_field:
                user_field = inp.get("name")
        if name and any(h in name for h in CSRF_FIELD_HINTS) and \
                itype in ("hidden", "text", "") and not csrf_field:
            csrf_field = inp.get("name")
    return {"user_field": user_field, "pass_field": pass_field,
            "csrf_field": csrf_field}


def _form_csrf_value(form):
    for inp in form.get("inputs") or []:
        if inp.get("name") and inp.get("name").lower() in (
                (form.get("csrf_field") or "").lower(),) and inp.get("value"):
            return inp["value"]
    return None


def detect_login_form(fetch, base_url, path_info=None):
    """Locate a login form by fetching common login paths.

    Returns ``{login_path, fields:{user_field,pass_field,csrf_field},
    action, csrf_value, markers}`` or None when no login form is found.
    ``path_info['paths']`` entries containing login-ish words are tried
    first (no blind guessing beyond the common list).
    """
    paths = []
    if isinstance(path_info, dict):
        for p in (path_info.get("paths") or []):
            pl = str(p).lower()
            if any(h in pl for h in ("login", "signin", "sign-in",
                                     "auth", "session")):
                paths.append(str(p) if str(p).startswith("/")
                             else "/" + str(p))
    for p in COMMON_LOGIN_PATHS:
        if p not in paths:
            paths.append(p)
    base = base_url.rstrip("/")
    for path in paths:
        try:
            st, _h, body = fetch("GET", base + path)
        except Exception:
            continue
        if st != 200:
            continue
        text = body.decode("latin-1", "replace")
        for form in parse_forms(text):
            fields = _classify_fields(form)
            if not fields["pass_field"]:
                continue
            markers = [m for m in LOGIN_PAGE_MARKERS
                       if m in text.lower()][:4]
            csrf_value = None
            for inp in form.get("inputs") or []:
                if inp.get("name") == fields["csrf_field"] \
                        and inp.get("value"):
                    csrf_value = inp["value"]
                    break
            return {
                "login_path": path,
                "fields": fields,
                "action": form.get("action") or path,
                "csrf_value": csrf_value,
                "markers": markers,
            }
    return None


# ----------------------------------------------------------------- login

def _extract_cookies(headers):
    """Pull cookie name=value pairs out of Set-Cookie response headers."""
    cookies = {}
    for key, val in (headers or {}).items():
        if key.lower() != "set-cookie":
            continue
        for part in val.split(","):
            part = part.strip()
            if not part or "=" not in part:
                continue
            first = part.split(";")[0].strip()
            name, _, value = first.partition("=")
            if name:
                cookies[name.strip()] = value.strip()
    return cookies


def _cookie_flags(headers):
    """Set-Cookie attribute audit info: {name: {secure, httponly,
    samesite}} — attributes only, never cookie values."""
    out = {}
    for key, val in (headers or {}).items():
        if key.lower() != "set-cookie":
            continue
        for part in val.split(","):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name = part.split(";")[0].partition("=")[0].strip()
            low = part.lower()
            out[name] = {
                "secure": "secure" in low,
                "httponly": "httponly" in low,
                "samesite": ("samesite=strict" in low
                             or "samesite=lax" in low
                             or "samesite=none" in low),
            }
    return out


def login(fetch, base_url, creds):
    """Perform the login: exactly ONE POST with the supplied credential.

    Returns {ok, cookies, headers, redirected_to, status, flags}. Never
    retries passwords, never brute-forces: one credential, one attempt
    per run. Credentials never appear in the returned evidence.
    """
    base = base_url.rstrip("/")
    detected = detect_login_form(fetch, base,
                                 path_info=creds.get("_path_info"))
    login_path = creds.get("login_path") or \
        (detected or {}).get("login_path") or "/login"
    fields = (detected or {}).get("fields") or {}
    user_field = fields.get("user_field") or "username"
    pass_field = fields.get("pass_field") or "password"
    csrf_field = fields.get("csrf_field")

    form_data = {user_field: creds["user"], pass_field: creds["password"]}
    csrf_value = (detected or {}).get("csrf_value")
    if csrf_field and csrf_value:
        form_data[csrf_field] = csrf_value
    extra = creds.get("extra_field")
    if isinstance(extra, dict):
        form_data.update({str(k): str(v) for k, v in extra.items()})

    action = (detected or {}).get("action") or login_path
    if not action.startswith("/"):
        action = "/" + action
    url = base + action
    body = urllib.parse.urlencode(form_data)
    try:
        st, headers, _resp = fetch("POST", url,
                                   headers={"Content-Type":
                                            "application/x-www-form-urlencoded"},
                                   body=body)
    except TypeError:
        st, headers, _resp = fetch(
            "POST", url,
            headers={"Content-Type":
                     "application/x-www-form-urlencoded"})
    cookies = _extract_cookies(headers)
    redirected_to = headers.get("Location") or headers.get("location")
    # Success heuristic: the server set a session cookie, or redirected
    # away from the login form. A failed login re-renders the form with
    # no cookie. This is NOT a password oracle — we never re-attempt.
    ok = bool(cookies) or (st in (301, 302, 303) and redirected_to
                           and redirected_to.split("?")[0] != login_path)
    return {
        "ok": ok,
        "cookies": cookies,
        "headers": headers,
        "redirected_to": redirected_to,
        "status": st,
        "flags": _cookie_flags(headers),
        "login_path": login_path,
    }


# -------------------------------------------------------- SessionFetcher

class SessionFetcher:
    """Drop-in fetch wrapper carrying authentication state.

    Wraps an underlying fetch callable (probes/deepchecks contract) and
    adds Cookie + CSRF headers to every request, harvests new
    Set-Cookie values, and flags ``session_expired`` when a 401/403
    onset is observed (the session stopped working mid-run).
    """

    def __init__(self, fetch=None, cookies=None, headers=None):
        self._fetch = fetch or _default_fetch
        self.cookies = dict(cookies or {})
        self.extra_headers = dict(headers or {})
        self.session_expired = False

    @property
    def authenticated(self):
        return bool(self.cookies)

    def _merged_headers(self, headers):
        merged = dict(self.extra_headers)
        merged.update(headers or {})
        if self.cookies:
            existing = merged.get("Cookie") or merged.get("cookie")
            ours = "; ".join("%s=%s" % (k, v)
                             for k, v in sorted(self.cookies.items()))
            merged["Cookie"] = (ours + "; " + existing) if existing \
                else ours
        return merged

    def __call__(self, method, url, headers=None, body=None):
        h = self._merged_headers(headers)
        try:
            st, rh, resp = self._fetch(method, url, headers=h, body=body)
        except TypeError:
            st, rh, resp = self._fetch(method, url, headers=h)
        if st in (401, 403):
            self.session_expired = True
        new_cookies = _extract_cookies(rh)
        if new_cookies:
            self.cookies.update(new_cookies)
        return st, rh, resp


# ------------------------------------------------------------ AuthSession

class AuthSession:
    """Authenticated session: creds (env or kwargs) + login + fetcher.

    Usage::

        sess = AuthSession(base_url, creds=parse_creds(...), fetch=...)
        sess.login()               # ONE attempt, never retries
        sfetch = sess.fetcher()    # SessionFetcher or None
    """

    def __init__(self, base_url=None, creds=None, fetch=None, env=None):
        self.base_url = base_url
        self._fetch = fetch
        if creds is None:
            creds = creds_from_env(env)
        self.creds = parse_creds(creds) if creds else None
        if self.creds is None and creds:
            # explicit dict/spec that failed validation
            self.creds = None
        self.login_result = None
        self.detected_form = None

    @property
    def has_creds(self):
        return bool(self.creds)

    def detect(self, base_url=None, path_info=None):
        self.base_url = base_url or self.base_url
        if self.base_url is None:
            return None
        fetch = self._fetch or _default_fetch
        self.detected_form = detect_login_form(fetch, self.base_url,
                                               path_info=path_info)
        return self.detected_form

    def login(self, base_url=None):
        """One login attempt. Returns the login result dict (ok flag,
        cookies, headers, redirected_to) or None without creds."""
        self.base_url = base_url or self.base_url
        if not self.creds or self.base_url is None:
            return None
        fetch = self._fetch or _default_fetch
        payload = dict(self.creds)
        payload["_path_info"] = {}
        if self.detected_form:
            payload["login_path"] = payload.get("login_path") \
                or self.detected_form.get("login_path")
        self.login_result = login(fetch, self.base_url, payload)
        return self.login_result

    def fetcher(self):
        """SessionFetcher for this session, or None when not logged in."""
        if not self.login_result or not self.login_result.get("ok"):
            return None
        return SessionFetcher(fetch=self._fetch,
                              cookies=self.login_result.get("cookies") or {})
