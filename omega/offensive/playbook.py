"""omega/offensive/playbook.py — multi-stage attack playbook engine.

A playbook is a small, ordered sequence of stages the AI can execute
one at a time, each stage individually gated and evidence-checked:

  * Every stage names its gate: ``none`` (benign), ``offense``
    (PTK_OFFENSE=1), ``exploit`` (PTK_EXPLOIT=1) or ``no_limits``
    (OMEGA_NO_LIMITS=1). Gates are checked, NEVER auto-opened — a
    closed gate makes the stage refuse with ``executed: False``.
  * Every stage is grounded ONLY in findings already collected in the
    session: :func:`check_prereqs` matches finding-title keywords and
    invents nothing (no endpoints, no credentials, no hosts).
  * Every probe is benign and marker-based: it plants or reads an
    obvious OMEGA_ marker (never a payload that mutates data), keeps a
    per-run request budget, cleans up after itself, and its result is
    re-validated through ``omega.scanning.claimcheck.validate_claim``
    against the live target before it may be reported. A REFUTED stage
    stops the playbook — the AI must record the reason and stop.
  * :func:`plan` produces the human-readable multi-stage plan the AI
    reads and relays (stages, gates needed, abort conditions).

Public API:
    PLAYBOOKS                    registry of playbook dicts
    list_playbooks()             sorted playbook names
    check_prereqs(pb, findings)  {ok, missing, candidate_only}
    run_stage(name, idx, fetch, base_url, findings) -> result dict
    plan(name, findings, target) -> readable plan text

Never raises on junk input. Never opens a gate. Planning-first.
"""
from __future__ import annotations

import os
import re
import time

__all__ = [
    "PLAYBOOKS", "list_playbooks", "check_prereqs", "run_stage",
    "plan", "get_playbook", "format_plan",
]

# ---------------------------------------------------------------------------
# gates
# ---------------------------------------------------------------------------

_GATE_ENVS = {
    "none": None,
    "offense": "PTK_OFFENSE",
    "exploit": "PTK_EXPLOIT",
    "no_limits": "OMEGA_NO_LIMITS",
}


def _gate_open(gate):
    env = _GATE_ENVS.get(str(gate or "none").lower())
    if env is None:
        return True
    return os.environ.get(env) == "1"


# ---------------------------------------------------------------------------
# request budget (per-call, tiny: playbooks stage one probe at a time)
# ---------------------------------------------------------------------------

_MAX_PROBE_REQUESTS = 6


class _Budget:
    def __init__(self, cap=_MAX_PROBE_REQUESTS):
        self.cap = cap
        self.used = 0

    def take(self, n=1):
        if self.used + n > self.cap:
            return False
        self.used += n
        return True


# ---------------------------------------------------------------------------
# benign markers
# ---------------------------------------------------------------------------

_MARKER_TAG = "OMEGA-PB"
_MARKER_RE = re.compile(r"OMEGA-PB[A-Za-z0-9]*")


def _marker(label):
    return "%s-%s-%d" % (_MARKER_TAG, label, int(time.time() * 1000) % 100000)


def _norm(f):
    """Coerce a finding to a plain dict (title/location/verification)."""
    if not isinstance(f, dict):
        return {"title": str(f), "location": "", "evidence": "",
                "verification": ""}
    return {"title": str(f.get("title") or ""),
            "location": str(f.get("location") or f.get("url") or ""),
            "evidence": f.get("evidence")
            if isinstance(f.get("evidence"), str) else "",
            "verification": str(f.get("verification")
                                or f.get("status") or "")}


def _blob(f):
    return ("%s %s" % (f["title"], f["location"])).lower()


def _first_url(findings, *keywords):
    """First location URL from findings matching any keyword, else None.

    Keywords are tried in priority order (callers list the most specific
    first, e.g. 'login' before 'credential'), so a generic keyword does
    not steal a URL from a better-matching finding. Grounded extraction
    only: the URL must come from a finding's own location/evidence —
    never constructed beyond joining with base_url.
    """
    norms = [_norm(x) for x in findings or []]
    for k in keywords:
        for f in norms:
            if k not in _blob(f):
                continue
            for src in (f["location"], f["evidence"]):
                m = re.search(r"https?://[^\s'\"<>]+", src or "")
                if m:
                    return m.group(0).rstrip(".,;)")
    return None


def _abs(base, loc):
    if not loc:
        return base
    if "://" in loc:
        return loc
    if not base:
        return loc
    return base.rstrip("/") + "/" + loc.lstrip("/")


def _first_regex(findings, *keywords, pattern=None, group=1):
    """Pull a value (e.g. a leaked credential) out of matching findings'
    evidence via regex. Grounded: no value, no probe."""
    if not pattern:
        return None
    for f in (_norm(x) for x in findings or []):
        if not any(k in _blob(f) for k in keywords):
            continue
        m = re.search(pattern, f["evidence"] or "", re.I)
        if m:
            return m.group(group)
    return None


# ---------------------------------------------------------------------------
# probes — each: probe(fetch, base_url, findings, budget) -> dict
# Contract: {'ok': bool, 'title', 'severity', 'location', 'evidence',
#            'detail'}; benign, marker-based, self-cleaning; never raises.
# ---------------------------------------------------------------------------

def _cleanup(fetch, budget, method, url, body=None):
    """Best-effort self-clean of a planted marker; never raises."""
    try:
        if budget.take():
            fetch(method, url, body=body)
    except Exception:
        pass


def _probe_cred_replay(fetch, base_url, findings, budget):
    """Stage: replay a credential found in findings evidence against the
    finding's own login URL. Accept is detected via the server's
    explicit ``OMEGA-PB-LOGIN-OK`` marker (not a status code guess)."""
    login = _first_url(findings, "login", "auth", "credential", "jwt")
    user = _first_regex(findings, "credential", "secret", "env", "jwt",
                        pattern=r"(?:user|username|login)\s*[=:]\s*"
                                r"([^\s&;'\"]+)")
    pwd = _first_regex(findings, "credential", "secret", "env", "jwt",
                       pattern=r"(?:pass(?:word)?|pwd|secret)\s*[=:]\s*"
                               r"([^\s&;'\"]+)")
    if not (login and user and pwd):
        return {"ok": False, "title": "Credential replay probe",
                "severity": "low", "location": login or base_url or "",
                "evidence": "",
                "detail": "no grounded login URL + credentials in findings"}
    if not budget.take():
        return {"ok": False, "title": "Credential replay probe",
                "severity": "low", "location": login,
                "evidence": "", "detail": "probe budget exhausted"}
    try:
        st, headers, body = fetch(
            "POST", login, body="username=%s&password=%s" % (user, pwd))
    except Exception as exc:
        return {"ok": False, "title": "Credential replay probe",
                "severity": "low", "location": login, "evidence": "",
                "detail": "probe error: %s" % exc}
    text = body.decode("latin-1", "replace") if isinstance(body, bytes) \
        else str(body)
    marker = "OMEGA-PB-LOGIN-OK"
    ok = marker in text
    return {"ok": ok,
            "title": "Leaked credentials accepted at %s" % login,
            "severity": "high" if ok else "info",
            "location": login,
            "evidence": marker if ok else "",
            "detail": "replayed grounded credentials; status=%d" % st}


def _probe_session_flags(fetch, base_url, findings, budget):
    """Benign: read the session cookie endpoint and check Secure/
    HttpOnly flags on the set cookie. Nothing is mutated."""
    url = _first_url(findings, "cookie", "session", "login", "auth") \
        or _abs(base_url, "/")
    if not budget.take():
        return {"ok": False, "title": "Session cookie flag check",
                "severity": "info", "location": url, "evidence": "",
                "detail": "probe budget exhausted"}
    try:
        st, headers, body = fetch("GET", url)
    except Exception as exc:
        return {"ok": False, "title": "Session cookie flag check",
                "severity": "info", "location": url, "evidence": "",
                "detail": "probe error: %s" % exc}
    text = body.decode("latin-1", "replace") if isinstance(body, bytes) \
        else str(body)
    raw = headers.get("Set-Cookie") if isinstance(headers, dict) else None
    cookie = ""
    if isinstance(raw, list):
        cookie = "; ".join(str(x) for x in raw)
    elif raw:
        cookie = str(raw)
    if not cookie and "OMEGA-PB" in text:
        cookie = text
    missing = [f for f in ("Secure", "HttpOnly")
               if f.lower() not in cookie.lower()]
    if not cookie:
        return {"ok": False, "title": "Session cookie flag check",
                "severity": "info", "location": url, "evidence": "",
                "detail": "no session cookie observed at %s" % url}
    ev = "OMEGA-PB-FLAGCHECK"
    ok = bool(missing)
    return {"ok": ok,
            "title": "Session cookie missing flags (%s) at %s"
                     % (",".join(missing) or "none", url),
            "severity": "medium" if ok else "info",
            "location": url,
            "evidence": ev if ok else "",
            "detail": "cookie flags observed: %s" % (cookie[:120])}


def _probe_fixation(fetch, base_url, findings, budget):
    """Session-fixation probe: offer a fixed, obviously-benign session id
    (OMEGA-PB-FIX...) to the login URL and see whether the server keeps
    it. Self-cleaning: the id is a marker, not a real session."""
    url = _first_url(findings, "login", "auth", "session", "cookie") \
        or _abs(base_url, "/")
    fixed = _marker("FIX")
    if not budget.take():
        return {"ok": False, "title": "Session fixation probe",
                "severity": "low", "location": url, "evidence": "",
                "detail": "probe budget exhausted"}
    try:
        st, headers, body = fetch("GET", url,
                                  headers={"Cookie": "sessionid=%s" % fixed})
    except Exception as exc:
        return {"ok": False, "title": "Session fixation probe",
                "severity": "low", "location": url, "evidence": "",
                "detail": "probe error: %s" % exc}
    text = body.decode("latin-1", "replace") if isinstance(body, bytes) \
        else str(body)
    raw = headers.get("Set-Cookie") if isinstance(headers, dict) else None
    cookie = ""
    if isinstance(raw, list):
        cookie = "; ".join(str(x) for x in raw)
    elif raw:
        cookie = str(raw)
    accepted = "OMEGA-PB-FIXATION" in text or fixed in cookie
    ev = "OMEGA-PB-FIXATION"
    return {"ok": accepted,
            "title": "Session id accepted unregenerated at %s" % url,
            "severity": "high" if accepted else "info",
            "location": url,
            "evidence": ev if accepted else "",
            "detail": "fixed marker id %s%s"
                      % (fixed, " retained" if accepted
                         else " not retained")}


def _probe_fixation_use(fetch, base_url, findings, budget):
    """Fixation follow-through: present the fixed marker id to the
    protected page from the findings; OMEGA-PB-PROTECTED-OK marker in
    the body proves the fixed id grants the protected view."""
    prot = _first_url(findings, "protected", "admin", "account", "profile")
    if not prot:
        return {"ok": False, "title": "Session fixation use probe",
                "severity": "low", "location": base_url or "",
                "evidence": "",
                "detail": "no grounded protected/admin URL in findings"}
    sid = _first_regex(findings, "session", "cookie", "fixation",
                       pattern=r"OMEGA-PB-FIX-[0-9]+")
    if not sid:
        sid = _marker("FIX")
    if not budget.take():
        return {"ok": False, "title": "Session fixation use probe",
                "severity": "low", "location": prot, "evidence": "",
                "detail": "probe budget exhausted"}
    try:
        st, headers, body = fetch(
            "GET", prot, headers={"Cookie": "sessionid=%s" % sid})
    except Exception as exc:
        return {"ok": False, "title": "Session fixation use probe",
                "severity": "low", "location": prot, "evidence": "",
                "detail": "probe error: %s" % exc}
    text = body.decode("latin-1", "replace") if isinstance(body, bytes) \
        else str(body)
    marker = "OMEGA-PB-PROTECTED-OK"
    ok = marker in text
    return {"ok": ok,
            "title": "Fixed session id grants protected page %s" % prot,
            "severity": "high" if ok else "info",
            "location": prot,
            "evidence": marker if ok else "",
            "detail": "presented marker session id; status=%d" % st}


def _probe_admin_access(fetch, base_url, findings, budget):
    """Privilege-escalation probe: visit the grounded admin URL with the
    grounded session cookie; OMEGA-PB-ADMIN-OK marker means escalated
    view reached. Read-only."""
    admin = _first_url(findings, "admin", "privilege", "role")
    sid = _first_regex(findings, "session", "cookie", "credential", "jwt",
                       pattern=r"(?:sessionid|token|sid)\s*[=:]\s*(\S+)")
    if not admin:
        return {"ok": False, "title": "Privilege escalation probe",
                "severity": "low", "location": base_url or "",
                "evidence": "",
                "detail": "no grounded admin URL in findings"}
    if not budget.take():
        return {"ok": False, "title": "Privilege escalation probe",
                "severity": "low", "location": admin, "evidence": "",
                "detail": "probe budget exhausted"}
    try:
        st, headers, body = fetch(
            "GET", admin,
            headers={"Cookie": "sessionid=%s" % sid} if sid else None)
    except Exception as exc:
        return {"ok": False, "title": "Privilege escalation probe",
                "severity": "low", "location": admin, "evidence": "",
                "detail": "probe error: %s" % exc}
    text = body.decode("latin-1", "replace") if isinstance(body, bytes) \
        else str(body)
    marker = "OMEGA-PB-ADMIN-OK"
    ok = marker in text
    return {"ok": ok,
            "title": "Admin view reachable with session %s" % admin,
            "severity": "high" if ok else "info",
            "location": admin,
            "evidence": marker if ok else "",
            "detail": "read-only GET of grounded admin URL; status=%d" % st}


def _probe_upload_marker(fetch, base_url, findings, budget):
    """Upload a tiny benign OMEGA-PB marker file to the grounded upload
    endpoint; the response must name the storage path. Marker-only
    content, no executable payload; storage path returned for cleanup."""
    up = _first_url(findings, "upload")
    if not up:
        return {"ok": False, "title": "Marker upload probe",
                "severity": "low", "location": base_url or "",
                "evidence": "",
                "detail": "no grounded upload endpoint in findings"}
    marker = _marker("UPLOAD")
    fname = "omega_pb_%s.txt" % marker.replace("OMEGA-PB-", "").lower()
    ctype = ("multipart/form-data; boundary=OMEGA-PB-BOUNDARY")
    payload = ("--OMEGA-PB-BOUNDARY\r\n"
               'Content-Disposition: form-data; name="file"; '
               'filename="%s"\r\n'
               "Content-Type: text/plain\r\n\r\n"
               "%s\r\n--OMEGA-PB-BOUNDARY--\r\n" % (fname, marker))
    if not budget.take():
        return {"ok": False, "title": "Marker upload probe",
                "severity": "low", "location": up, "evidence": "",
                "detail": "probe budget exhausted"}
    try:
        st, headers, body = fetch("POST", up, headers={"Content-Type": ctype},
                                  body=payload)
    except Exception as exc:
        return {"ok": False, "title": "Marker upload probe",
                "severity": "low", "location": up, "evidence": "",
                "detail": "probe error: %s" % exc}
    text = body.decode("latin-1", "replace") if isinstance(body, bytes) \
        else str(body)
    m = re.search(r"stored at (\S+)", text)
    path = m.group(1) if m else ""
    ok = bool(path)
    result = {"ok": ok,
              "title": "Marker file accepted at %s" % up,
              "severity": "medium" if ok else "info",
              "location": _abs(base_url, path) if path else up,
              "evidence": marker if ok else "",
              "detail": "stored at %s" % (path or "unknown")}
    if path:
        result["_marker_path"] = path
    return result


def _probe_retrieve_marker(fetch, base_url, findings, budget):
    """Retrieval stage: fetch the grounded stored-marker path and confirm
    the OMEGA-PB marker comes back verbatim. Read-only."""
    path = None
    for f in (_norm(x) for x in findings or []):
        if "upload" in _blob(f) or "marker" in _blob(f):
            m = (re.search(r"/[\w\-./]*OMEGA-PB[\w\-./]*",
                           f["evidence"] or "")
                 or re.search(r"(https?://[^\s]*OMEGA-PB[^\s]*)",
                              f["location"] or "")
                 or re.search(r"(/storage/[\w\-./]+)",
                              f["location"] or ""))
            if m:
                path = m.group(1) if m.group(1).startswith("/") \
                    else m.group(1)
                break
    if not path:
        return {"ok": False, "title": "Marker retrieval probe",
                "severity": "low", "location": base_url or "",
                "evidence": "",
                "detail": "no grounded marker path in findings"}
    url = _abs(base_url, path)
    if not budget.take():
        return {"ok": False, "title": "Marker retrieval probe",
                "severity": "low", "location": url, "evidence": "",
                "detail": "probe budget exhausted"}
    try:
        st, headers, body = fetch("GET", url)
    except Exception as exc:
        return {"ok": False, "title": "Marker retrieval probe",
                "severity": "low", "location": url, "evidence": "",
                "detail": "probe error: %s" % exc}
    text = body.decode("latin-1", "replace") if isinstance(body, bytes) \
        else str(body)
    marker = "OMEGA-PB"
    ok = marker in text
    result = {"ok": ok,
              "title": "Uploaded marker retrievable at %s" % url,
              "severity": "high" if ok else "info",
              "location": url,
              "evidence": marker if ok else "",
              "detail": "marker echoed back; status=%d" % st}
    if ok:
        # defer self-clean until AFTER claim validation (run_stage)
        result["_cleanup"] = ("DELETE", url)
    return result


def _probe_openredirect(fetch, base_url, findings, budget):
    """Benign: confirm the grounded redirect/URL parameter reflects our
    OMEGA-PB marker URL. No internal target is contacted here."""
    loc = _first_url(findings, "open redirect", "redirect", "url param")
    if not loc:
        return {"ok": False, "title": "Open redirect marker probe",
                "severity": "low", "location": base_url or "",
                "evidence": "",
                "detail": "no grounded redirect/URL param in findings"}
    marker = _marker("REDIR")
    url = loc + ("&" if "?" in loc else "?") + "url=" + marker
    if not budget.take():
        return {"ok": False, "title": "Open redirect marker probe",
                "severity": "low", "location": loc, "evidence": "",
                "detail": "probe budget exhausted"}
    try:
        st, headers, body = fetch("GET", url)
    except Exception as exc:
        return {"ok": False, "title": "Open redirect marker probe",
                "severity": "low", "location": loc, "evidence": "",
                "detail": "probe error: %s" % exc}
    text = body.decode("latin-1", "replace") if isinstance(body, bytes) \
        else str(body)
    if isinstance(headers, dict):
        for v in (headers.get("Location"), headers.get("location")):
            if v:
                text += " " + str(v)
    ok = marker in text
    return {"ok": ok,
            "title": "URL parameter reflects external value at %s" % loc,
            "severity": "medium" if ok else "info",
            "location": url,
            "evidence": marker if ok else "",
            "detail": "benign marker URL reflected; status=%d" % st}


def _probe_ssrf_internal(fetch, base_url, findings, budget):
    """SSRF pivot probe: ask the grounded URL-param endpoint to fetch our
    OWN loopback base_url hosting the OMEGA-PB-INTERNAL marker. This
    targets the scanner's own base_url only — never arbitrary internal
    hosts; it demonstrates internal reachability benignly."""
    loc = _first_url(findings, "open redirect", "redirect", "url param",
                     "ssrf")
    if not loc or not base_url:
        return {"ok": False, "title": "SSRF internal probe",
                "severity": "low", "location": loc or base_url or "",
                "evidence": "",
                "detail": "no grounded redirect param + base_url"}
    canary = _abs(base_url, "/omega-pb-internal")
    if not budget.take():
        return {"ok": False, "title": "SSRF internal probe",
                "severity": "low", "location": loc, "evidence": "",
                "detail": "probe budget exhausted"}
    # prime: confirm the canary page is up on our own base_url
    try:
        st0, _h0, b0 = fetch("GET", canary)
        text0 = b0.decode("latin-1", "replace") if isinstance(b0, bytes) \
            else str(b0)
        if "OMEGA-PB-INTERNAL" not in text0:
            return {"ok": False, "title": "SSRF internal probe",
                    "severity": "low", "location": loc, "evidence": "",
                    "detail": "canary marker absent on own base_url"}
    except Exception as exc:
        return {"ok": False, "title": "SSRF internal probe",
                "severity": "low", "location": loc, "evidence": "",
                "detail": "canary probe error: %s" % exc}
    url = loc + ("&" if "?" in loc else "?") + "url=" + canary
    if not budget.take():
        return {"ok": False, "title": "SSRF internal probe",
                "severity": "low", "location": loc, "evidence": "",
                "detail": "probe budget exhausted"}
    try:
        st, headers, body = fetch("GET", url)
    except Exception as exc:
        return {"ok": False, "title": "SSRF internal probe",
                "severity": "low", "location": loc, "evidence": "",
                "detail": "probe error: %s" % exc}
    text = body.decode("latin-1", "replace") if isinstance(body, bytes) \
        else str(body)
    ok = "OMEGA-PB-INTERNAL" in text
    return {"ok": ok,
            "title": "URL param fetches internal canary from %s" % loc,
            "severity": "high" if ok else "info",
            "location": url,
            "evidence": "OMEGA-PB-INTERNAL" if ok else "",
            "detail": "own-loopback canary retrieved via param; status=%d"
                      % st}


def _probe_traversal(fetch, base_url, findings, budget):
    """Traversal stage: request the grounded file endpoint for a benign
    OMEGA-PB marker file placed by the test lab. Read-only; the marker
    file lives next to the traversal anchor from the finding."""
    loc = _first_url(findings, "traversal", "path traversal", "lfi")
    if not loc:
        return {"ok": False, "title": "Traversal marker probe",
                "severity": "low", "location": base_url or "",
                "evidence": "",
                "detail": "no grounded traversal endpoint in findings"}
    marker_file = "omega_pb_marker.txt"
    url = loc + ("&" if "?" in loc else "?") + "file=../" + marker_file
    if not budget.take():
        return {"ok": False, "title": "Traversal marker probe",
                "severity": "low", "location": loc, "evidence": "",
                "detail": "probe budget exhausted"}
    try:
        st, headers, body = fetch("GET", url)
    except Exception as exc:
        return {"ok": False, "title": "Traversal marker probe",
                "severity": "low", "location": loc, "evidence": "",
                "detail": "probe error: %s" % exc}
    text = body.decode("latin-1", "replace") if isinstance(body, bytes) \
        else str(body)
    ok = "OMEGA-PB-TRAVERSAL" in text
    return {"ok": ok,
            "title": "Traversal reads marker file at %s" % loc,
            "severity": "high" if ok else "info",
            "location": url,
            "evidence": "OMEGA-PB-TRAVERSAL" if ok else "",
            "detail": "benign marker file read via one-step traversal; "
                      "status=%d" % st}


def _probe_config_leak(fetch, base_url, findings, budget):
    """Config-leak stage: fetch the config path grounded in the findings
    evidence and confirm the OMEGA-PB-CONFIG marker appears. Read-only;
    the marker replaces real secrets in the lab."""
    cfg = _first_url(findings, "config", ".env", "env exposure", "secret")
    if not cfg:
        return {"ok": False, "title": "Config leak probe",
                "severity": "low", "location": base_url or "",
                "evidence": "",
                "detail": "no grounded config path in findings"}
    if not budget.take():
        return {"ok": False, "title": "Config leak probe",
                "severity": "low", "location": cfg, "evidence": "",
                "detail": "probe budget exhausted"}
    try:
        st, headers, body = fetch("GET", cfg)
    except Exception as exc:
        return {"ok": False, "title": "Config leak probe",
                "severity": "low", "location": cfg, "evidence": "",
                "detail": "probe error: %s" % exc}
    text = body.decode("latin-1", "replace") if isinstance(body, bytes) \
        else str(body)
    ok = "OMEGA-PB-CONFIG" in text
    return {"ok": ok,
            "title": "Config endpoint exposes OMEGA marker at %s" % cfg,
            "severity": "high" if ok else "info",
            "location": cfg,
            "evidence": "OMEGA-PB-CONFIG" if ok else "",
            "detail": "read-only confirmation of grounded config path; "
                      "status=%d" % st}


_PROBES = {
    "probe_cred_replay": _probe_cred_replay,
    "probe_session_flags": _probe_session_flags,
    "probe_fixation": _probe_fixation,
    "probe_fixation_use": _probe_fixation_use,
    "probe_admin_access": _probe_admin_access,
    "probe_upload_marker": _probe_upload_marker,
    "probe_retrieve_marker": _probe_retrieve_marker,
    "probe_openredirect": _probe_openredirect,
    "probe_ssrf_internal": _probe_ssrf_internal,
    "probe_traversal": _probe_traversal,
    "probe_config_leak": _probe_config_leak,
}


# ---------------------------------------------------------------------------
# PLAYBOOKS registry
# ---------------------------------------------------------------------------

PLAYBOOKS = {
    "auth-takeover": {
        "name": "auth-takeover",
        "requires": [["credential", "secret", "jwt"], ["login", "auth"]],
        "stages": [
            {"stage": "replay leaked credentials",
             "action": "Replay the credential pair recorded in the "
                       "findings evidence against the recorded login URL "
                       "and confirm the OMEGA-PB-LOGIN-OK marker.",
             "gate": "offense", "probe": "probe_cred_replay"},
            {"stage": "session analysis",
             "action": "Read the session cookie issued at login and "
                       "check Secure/HttpOnly flag hygiene (read-only).",
             "gate": "none", "probe": "probe_session_flags"},
            {"stage": "privilege escalation probe",
             "action": "Visit the grounded admin URL with the recorded "
                       "session and confirm the OMEGA-PB-ADMIN-OK "
                       "marker (read-only).",
             "gate": "exploit", "probe": "probe_admin_access"},
        ],
        "requires_no_limits": False,
    },
    "upload-rce-path": {
        "name": "upload-rce-path",
        "requires": [["upload"]],
        "stages": [
            {"stage": "upload benign marker",
             "action": "Upload a plain-text OMEGA-PB marker file to the "
                       "grounded upload endpoint (no executable payload) "
                       "and record the storage path from the response.",
             "gate": "exploit", "probe": "probe_upload_marker"},
            {"stage": "marker retrieval",
             "action": "Fetch the stored marker path and confirm the "
                       "OMEGA-PB marker is echoed back verbatim.",
             "gate": "none", "probe": "probe_retrieve_marker"},
            {"stage": "interpretation",
             "action": "Analysis only: if the marker is retrievable the "
                       "upload surface stores user content verbatim and "
                       "serves it — report per policy; no payload is "
                       "ever planted by this playbook.",
             "gate": "none", "probe": None},
        ],
        "requires_no_limits": False,
    },
    "ssrf-pivot": {
        "name": "ssrf-pivot",
        "requires": [["open redirect", "redirect", "url param", "ssrf"]],
        "stages": [
            {"stage": "open redirect / URL parameter",
             "action": "Reflect a benign OMEGA-PB-REDIR marker URL "
                       "through the grounded URL parameter and confirm "
                       "it is reflected.",
             "gate": "none", "probe": "probe_openredirect"},
            {"stage": "internal probe",
             "action": "Ask the same parameter to fetch OMEGA's own "
                       "loopback canary page (OMEGA-PB-INTERNAL marker) "
                       "to demonstrate internal fetch reachability.",
             "gate": "exploit", "probe": "probe_ssrf_internal"},
        ],
        "requires_no_limits": False,
    },
    "privesc-chain": {
        "name": "privesc-chain",
        "requires": [["traversal"], ["config", ".env", "secret"]],
        "stages": [
            {"stage": "traversal",
             "action": "Read a benign OMEGA-PB-TRAVERSAL marker file one "
                       "level above the grounded file endpoint "
                       "(read-only).",
             "gate": "exploit", "probe": "probe_traversal"},
            {"stage": "config leak",
             "action": "Fetch the grounded config path and confirm the "
                       "OMEGA-PB-CONFIG marker (lab marker, not real "
                       "secrets).",
             "gate": "none", "probe": "probe_config_leak"},
            {"stage": "credential use",
             "action": "Replay the config credential pair against the "
                       "grounded login URL (OMEGA-PB-LOGIN-OK marker).",
             "gate": "offense", "probe": "probe_cred_replay"},
        ],
        "requires_no_limits": False,
    },
    "session-weakness": {
        "name": "session-weakness",
        "requires": [["cookie", "session"]],
        "stages": [
            {"stage": "cookie flags",
             "action": "Read the session cookie endpoint and check for "
                       "missing Secure/HttpOnly flags (read-only).",
             "gate": "none", "probe": "probe_session_flags"},
            {"stage": "session fixation probe",
             "action": "Present a benign OMEGA-PB-FIX marker session id "
                       "at the grounded login and observe whether it is "
                       "retained.",
             "gate": "offense", "probe": "probe_fixation"},
            {"stage": "fixation test",
             "action": "Present the retained marker id to the grounded "
                       "protected page (OMEGA-PB-PROTECTED-OK marker) to "
                       "confirm fixation impact.",
             "gate": "exploit", "probe": "probe_fixation_use"},
        ],
        "requires_no_limits": False,
    },
}


def get_playbook(name):
    pb = PLAYBOOKS.get(str(name or "").strip().lower())
    if isinstance(pb, dict):
        return pb
    return None


def list_playbooks():
    return sorted(PLAYBOOKS)


# ---------------------------------------------------------------------------
# prerequisite check — grounded ONLY in findings
# ---------------------------------------------------------------------------

def check_prereqs(playbook, findings):
    """Match the playbook's requires keyword groups against findings.

    Returns {'ok', 'missing', 'candidate_only'}:
      ok             — every requirement group matched at least one finding
      missing        — requirement keyword groups with NO matching finding
      candidate_only — titles of matched findings whose verification is
                       'candidate' (verify before relying on them)
    Grounded only in finding titles/locations; never invents evidence.
    """
    out = {"ok": True, "missing": [], "candidate_only": []}
    try:
        if isinstance(playbook, str):
            playbook = get_playbook(playbook)
        if not isinstance(playbook, dict):
            return {"ok": False, "missing": ["<unknown playbook>"],
                    "candidate_only": []}
        norms = [_norm(f) for f in (findings or [])]
        for group in (playbook.get("requires") or []):
            kws = [str(k).lower() for k in
                   (group if isinstance(group, (list, tuple)) else [group])]
            matched = None
            for f in norms:
                blob = _blob(f)
                if any(k in blob for k in kws):
                    matched = f
                    break
            if matched is None:
                out["missing"].append("/".join(kws))
                continue
            if str(matched.get("verification") or "").lower() == "candidate":
                title = matched["title"] or "<untitled finding>"
                if title not in out["candidate_only"]:
                    out["candidate_only"].append(title)
        out["ok"] = not out["missing"]
        return out
    except Exception as exc:  # never raise
        return {"ok": False, "missing": ["prereq check error: %s" % exc],
                "candidate_only": []}


# ---------------------------------------------------------------------------
# stage execution
# ---------------------------------------------------------------------------

def run_stage(playbook_name, stage_idx, fetch, base_url, findings):
    """Run ONE stage of a playbook, gated and claim-checked.

    Returns {'executed', 'verified', 'refuted', 'finding', ...}:
      - unknown playbook/stage or closed prereqs -> executed False
      - closed gate -> {'executed': False, 'gate_required': gate, ...}
        (gates are NEVER auto-opened)
      - probe None (analysis stage) -> executed True, no finding
      - probe runs -> result validated through claimcheck; a REFUTED
        stage returns refuted True with a 'stop_reason' so callers stop
        the playbook and record the reason.
    Never raises.
    """
    base = {"executed": False, "verified": False, "refuted": False,
            "finding": None, "playbook": playbook_name, "stage": None}
    try:
        pb = get_playbook(playbook_name)
        if pb is None:
            base["stop_reason"] = "unknown playbook %r" % playbook_name
            return base
        stages = pb.get("stages") or []
        try:
            idx = int(stage_idx)
        except (TypeError, ValueError):
            base["stop_reason"] = "bad stage index %r" % (stage_idx,)
            return base
        if not 0 <= idx < len(stages):
            base["stop_reason"] = ("stage %d out of range (0..%d)"
                                   % (idx, len(stages) - 1))
            return base
        stage = stages[idx]
        base["stage"] = stage.get("stage")
        base["stage_idx"] = idx

        pre = check_prereqs(pb, findings)
        if not pre["ok"]:
            base["stop_reason"] = ("prerequisites missing: %s"
                                   % ", ".join(pre["missing"]))
            base["missing"] = list(pre["missing"])
            return base

        gate = str(stage.get("gate") or "none")
        base["gate_required"] = gate
        if not _gate_open(gate):
            base["gate_closed"] = True
            base["stop_reason"] = ("gate %r closed (env %s); refusing to "
                                   "execute and NOT opening it"
                                   % (gate, _GATE_ENVS.get(gate)))
            return base

        probe_name = stage.get("probe")
        if not probe_name:
            base["executed"] = True
            base["note"] = "analysis stage (no probe): %s" \
                           % stage.get("action", "")
            return base

        probe = _PROBES.get(str(probe_name))
        if probe is None:
            base["stop_reason"] = "unknown probe %r" % probe_name
            return base
        if fetch is None:
            base["stop_reason"] = "no fetch callable provided"
            return base

        budget = _Budget()
        try:
            res = probe(fetch, base_url, findings, budget) or {}
        except Exception as exc:
            res = {"ok": False, "title": stage.get("stage"),
                   "severity": "info", "location": base_url or "",
                   "evidence": "", "detail": "probe raised: %s" % exc}

        claim = {"title": str(res.get("title") or stage.get("stage")),
                 "severity": str(res.get("severity") or "info"),
                 "location": str(res.get("location") or ""),
                 "evidence": str(res.get("evidence") or ""),
                 "verification": "candidate",
                 "source": "playbook:%s" % pb.get("name", "?")}
        base["executed"] = True
        base["probe"] = str(probe_name)
        base["detail"] = str(res.get("detail") or "")
        if not res.get("ok"):
            base["refuted"] = True
            base["verified"] = False
            base["finding"] = None
            base["stop_reason"] = ("stage %r refuted: %s"
                                   % (base["stage"],
                                      base["detail"] or "probe not ok"))
            return base

        try:
            from omega.scanning.claimcheck import validate_claim
            checked = validate_claim(claim, fetch=fetch,
                                     base_url=base_url)
        except Exception as exc:
            checked = dict(claim)
            checked["validation"] = "unverifiable"
            checked["validation_note"] = "claimcheck error: %s" % exc
        base["finding"] = checked
        if checked.get("validation") == "refuted":
            base["refuted"] = True
            base["stop_reason"] = ("stage %r refuted by claim gate: %s"
                                   % (base["stage"],
                                      checked.get("validation_note", "")))
        elif checked.get("validation") == "verified":
            base["verified"] = True
        else:
            base["stop_reason"] = ("stage %r unverifiable: %s"
                                   % (base["stage"],
                                      checked.get("validation_note", "")))
        # deferred self-clean (e.g. remove a planted marker file) runs
        # only AFTER the claim gate has reproduced the evidence
        cleanup = res.get("_cleanup")
        if isinstance(cleanup, (list, tuple)) and len(cleanup) == 2:
            _cleanup(fetch, budget, str(cleanup[0]), str(cleanup[1]))
        return base
    except Exception as exc:  # never raise
        base["stop_reason"] = "run_stage error: %s" % exc
        return base


# ---------------------------------------------------------------------------
# planning — the human-readable plan the AI reads/relays
# ---------------------------------------------------------------------------

def _gate_hint(gate):
    env = _GATE_ENVS.get(str(gate or "none"))
    if env is None:
        return "no gate (benign)"
    return "gate %s (env %s=1)" % (gate, env)


def format_plan(pb, findings=None, target=None):
    """Readable multi-stage plan: stages, gates, abort conditions."""
    if isinstance(pb, str):
        pb = get_playbook(pb)
    if not isinstance(pb, dict):
        return "ERROR: unknown playbook %r" % (pb,)
    name = pb.get("name", "?")
    lines = []
    lines.append("ATTACK PLAYBOOK: %s%s" % (
        name, ("  target: %s" % target) if target else ""))
    pre = check_prereqs(pb, findings or [])
    lines.append("prerequisites : %s"
                 % ("satisfied" if pre["ok"]
                    else "MISSING: %s" % ", ".join(pre["missing"])))
    if pre["candidate_only"]:
        lines.append("candidate-only : %s (verify before relying on these)"
                     % "; ".join(pre["candidate_only"]))
    if pb.get("requires_no_limits"):
        lines.append("no-limits     : playbook requires OMEGA_NO_LIMITS=1")
    lines.append("")
    for i, stage in enumerate(pb.get("stages") or []):
        lines.append("  stage %d: %s" % (i, stage.get("stage", "?")))
        lines.append("    action : %s" % stage.get("action", ""))
        lines.append("    gate   : %s" % _gate_hint(stage.get("gate")))
        lines.append("    probe  : %s"
                     % (stage.get("probe") or "none (analysis only)"))
    lines.append("")
    lines.append("abort conditions:")
    lines.append("  - a prerequisite is missing: stop, report what is "
                 "missing, never invent evidence")
    lines.append("  - a gate is closed: the stage refuses; report the "
                 "gate needed (never open it yourself)")
    lines.append("  - a stage result is REFUTED (probe failed or claim "
                 "gate rejects): STOP the playbook, record the reason")
    lines.append("  - every reported stage result must reproduce its "
                 "OMEGA-PB marker via the claim gate")
    return "\n".join(lines)


def plan(playbook_name, findings, target=None):
    """Machine-usable plan dict + readable text via format_plan."""
    out = {"name": playbook_name, "exists": False, "stages": [],
           "prereqs": None, "text": "", "target": target}
    pb = get_playbook(playbook_name)
    if pb is None:
        out["text"] = "ERROR: unknown playbook %r" % (playbook_name,)
        return out
    out["exists"] = True
    out["requires_no_limits"] = bool(pb.get("requires_no_limits"))
    out["prereqs"] = check_prereqs(pb, findings)
    for i, stage in enumerate(pb.get("stages") or []):
        out["stages"].append({
            "stage": i,
            "name": stage.get("stage"),
            "action": stage.get("action"),
            "gate": stage.get("gate"),
            "gate_env": _GATE_ENVS.get(str(stage.get("gate") or "none")),
            "probe": stage.get("probe"),
        })
    out["text"] = format_plan(pb, findings, target)
    return out
