"""OMEGA blind-vuln confirmation checks backed by the local OOB server.

Four checks, all built on omega.oob.OOBCallbackServer:

  blind_ssrf_confirm — set URL params (from path_info or the common
      list) to a unique token URL. CONFIRMED (high) only when the
      EXACT planted token receives a callback; a single candidate
      (low) is emitted when no token was hit within the window.
  blind_xss_canary — where a parameter reflection is already
      established (marker differential), inject a script-src canary
      pointing at the token URL. Evidence-class only: always
      candidate, never confirmed.
  blind_rce_probe — OOB ONLY: put the token URL into headers and
      params; a hit yields a candidate HIGH finding explicitly
      labeled "callback observed, further manual verification
      required". No command execution is attempted, ever.
  webhook_ssrf — webhook-style param names (from path_info or a
      common list) set to the token URL; same confirm rule as
      blind_ssrf_confirm.

run_oobchecks(target, ...) never raises and returns
{findings, ran, skipped, hits}.
"""

from __future__ import annotations

import urllib.parse

from omega.probes import (
    COMMON_URL_PARAMS,
    Finding,
    allowlist_ok,
    default_fetch,
)

__all__ = [
    "blind_ssrf_confirm",
    "blind_xss_canary",
    "blind_rce_probe",
    "webhook_ssrf",
    "run_oobchecks",
]

FETCH_TIMEOUT_NOTE = "callback wait default 3.0s per token"

COMMON_WEBHOOK_PARAMS = [
    "webhook", "webhook_url", "callback", "callback_url", "notify",
    "notify_url", "hook", "hook_url", "ping", "ping_url", "postback",
    "postback_url", "endpoint_url",
]

DEFAULT_WAIT_S = 3.0


def _base_of(target):
    return target if "://" in target else "https://" + target


def _server_alive(server):
    return server is not None and getattr(server, "running", False)


def _request_params(path_info):
    """Param names supplied by earlier stages (path_info['params'] etc.)."""
    if not path_info:
        return []
    out = []
    for key in ("params", "url_params", "query_params"):
        val = path_info.get(key) or []
        if isinstance(val, dict):
            val = list(val)
        out.extend(str(v) for v in val)
    return out


def _get(fetch, base_url, params, extra_headers=None):
    """Issue one GET with the params set to the token URL (best effort)."""
    url = base_url + "/?" + urllib.parse.urlencode(params)
    try:
        fetch("GET", url, extra_headers or {})
    except Exception:
        pass
    return url


def blind_ssrf_confirm(target, server, path_info=None, fetch=default_fetch,
                       wait_s=DEFAULT_WAIT_S, log=None):
    """Blind SSRF: URL params -> token URL; confirmed only on exact hit."""
    findings, urls_tried = [], []
    base_url = _base_of(target)
    candidates = list(dict.fromkeys(
        _request_params(path_info) or COMMON_URL_PARAMS))
    for param in candidates:
        token = server.new_token()
        url = _get(fetch, base_url, {param: server.token_url(token)})
        urls_tried.append(url)
        hit = server.wait_for_hit(token, timeout_s=wait_s)
        if hit:
            if log:
                log("blind_ssrf_confirm: exact token hit for param %r" % param)
            return [Finding(
                title="Blind SSRF confirmed via OOB callback (param '%s')"
                      % param,
                severity="high",
                verification="confirmed",
                verification_note=(
                    "The parameter '%s' was set to a unique 32-hex-token "
                    "URL on the operator's own OOB collector; the exact "
                    "token received a callback, proving the server "
                    "fetched the attacker-controlled URL." % param),
                manual_check="curl -sS -i \"%s\"" % url,
                location=url,
                evidence={"param": param, "hit": hit,
                          "note": FETCH_TIMEOUT_NOTE},
                source="omega-oob/blind_ssrf_confirm")]
    if urls_tried:
        if log:
            log("blind_ssrf_confirm: no callback within %.1fs -> candidate"
                % wait_s)
        findings.append(Finding(
            title="Possible blind SSRF: URL parameters accepted canary URL "
                  "(no callback observed)",
            severity="low",
            verification="candidate",
            verification_note=(
                "URL-typed parameters were set to token URLs on the "
                "operator's OOB collector, but no exact-token callback "
                "arrived within the %.1fs window. Weak evidence — not "
                "confirmed." % wait_s),
            manual_check="curl -sS -i \"%s\"" % urls_tried[0],
            location=urls_tried[0],
            evidence={"tried": urls_tried},
            source="omega-oob/blind_ssrf_confirm"))
    return findings


def blind_xss_canary(target, server, path_info=None, fetch=default_fetch,
                     wait_s=DEFAULT_WAIT_S, log=None):
    """Inject a script-src OOB canary ONLY where reflection is found.

    Evidence-class: always candidate — a callback from a browser add-on
    proves JS execution but the check itself only verifies injection
    into a reflection point.
    """
    base_url = _base_of(target)
    candidates = list(dict.fromkeys(
        _request_params(path_info) or COMMON_URL_PARAMS))[:5]
    marker = "OMEGAXSSCANARY7f3a"
    for param in candidates:
        try:
            _st, _h, body = fetch(
                "GET", base_url + "/?" + urllib.parse.urlencode(
                    {param: marker}))
        except Exception:
            return []
        if marker.encode() not in (body or b""):
            continue
        # Reflection established: plant the script-src canary.
        token = server.new_token()
        canary = "<script src=\"%s\"></script>" % server.token_url(token)
        url = _get(fetch, base_url, {param: canary})
        hit = server.wait_for_hit(token, timeout_s=wait_s)
        if log:
            log("blind_xss_canary: reflection on %r; callback=%s"
                % (param, bool(hit)))
        return [Finding(
            title="XSS canary injected into reflected parameter '%s' "
                  "(OOB callback observed: %s)" % (param, bool(hit)),
            severity="low",
            verification="candidate",
            verification_note=(
                "Parameter '%s' reflects input verbatim; a script-src "
                "canary pointing at the operator's OOB collector was "
                "injected%s. Evidence-class only: JS execution requires "
                "a browser to load the canary (callback observed: %s). "
                "Not confirmed." % (param, " and the exact token was hit"
                                    if hit else ", but no callback arrived",
                                    bool(hit))),
            manual_check="curl -sS -i \"%s\"" % url,
            location=url,
            evidence={"param": param, "reflected_marker": marker,
                      "callback": bool(hit), "hit": hit},
            source="omega-oob/blind_xss_canary")]
    return []


def blind_rce_probe(target, server, path_info=None, fetch=default_fetch,
                    wait_s=DEFAULT_WAIT_S, log=None):
    """OOB-only blind-RCE probe: token URL in headers/params; NO command
    execution is attempted — a callback alone yields a candidate HIGH
    finding labeled for manual verification."""
    base_url = _base_of(target)
    headers = {
        "User-Agent": server.token_url(),
        "Referer": server.token_url(),
        "X-Callback-Url": server.token_url(),
    }
    for name, val in headers.items():
        token = val.rsplit("/", 1)[1]
        try:
            fetch("GET", base_url + "/", {name: val})
        except Exception:
            pass
        hit = server.wait_for_hit(token, timeout_s=wait_s)
        if hit:
            if log:
                log("blind_rce_probe: callback via header %r" % name)
            return [Finding(
                title="Blind RCE (OOB callback only) via header '%s' — "
                      "callback observed, further manual verification "
                      "required" % name,
                severity="high",
                verification="candidate",
                verification_note=(
                    "The OOB collector received a callback for the token "
                    "planted in header '%s'. This is OOB-only detection: "
                    "NO command execution was attempted or proven — "
                    "further manual verification is required." % name),
                manual_check=("curl -sS -i -H '%s: %s' \"%s/\""
                              % (name, val, base_url)),
                location=base_url + "/",
                evidence={"header": name, "hit": hit,
                          "note": "callback observed, further manual "
                                  "verification required"},
                source="omega-oob/blind_rce_probe")]
    for param in list(dict.fromkeys(
            _request_params(path_info) or ["cmd", "exec", "command", "host",
                                           "hostname", "url", "host_url",
                                           "hosturl", "remote_host"]))[:6]:
        token = server.new_token()
        url = _get(fetch, base_url, {param: server.token_url(token)})
        hit = server.wait_for_hit(token, timeout_s=wait_s)
        if hit:
            if log:
                log("blind_rce_probe: callback via param %r" % param)
            return [Finding(
                title="Blind RCE (OOB callback only) via parameter '%s' — "
                      "callback observed, further manual verification "
                      "required" % param,
                severity="high",
                verification="candidate",
                verification_note=(
                    "The OOB collector received a callback for the token "
                    "planted in parameter '%s'. This is OOB-only "
                    "detection: NO command execution was attempted or "
                    "proven — further manual verification is required."
                    % param),
                manual_check="curl -sS -i \"%s\"" % url,
                location=url,
                evidence={"param": param, "hit": hit,
                          "note": "callback observed, further manual "
                                  "verification required"},
                source="omega-oob/blind_rce_probe")]
    return []


def webhook_ssrf(target, server, path_info=None, fetch=default_fetch,
                 wait_s=DEFAULT_WAIT_S, log=None):
    """Webhook-style params -> token URL; same confirm rule as SSRF."""
    findings = []
    base_url = _base_of(target)
    given = _request_params(path_info)
    candidates = (given or COMMON_WEBHOOK_PARAMS)[:8]
    tried = []
    for param in candidates:
        token = server.new_token()
        url = _get(fetch, base_url, {param: server.token_url(token)})
        tried.append(url)
        hit = server.wait_for_hit(token, timeout_s=wait_s)
        if hit:
            if log:
                log("webhook_ssrf: exact token hit for param %r" % param)
            return [Finding(
                title="Webhook SSRF confirmed via OOB callback (param "
                      "'%s')" % param,
                severity="high",
                verification="confirmed",
                verification_note=(
                    "The webhook-style parameter '%s' was set to a unique "
                    "token URL on the operator's OOB collector; the exact "
                    "token received a callback, proving the server calls "
                    "out to attacker-supplied URLs." % param),
                manual_check="curl -sS -i \"%s\"" % url,
                location=url,
                evidence={"param": param, "hit": hit},
                source="omega-oob/webhook_ssrf")]
    if tried:
        if log:
            log("webhook_ssrf: no callback within %.1fs -> candidate"
                % wait_s)
        findings.append(Finding(
            title="Possible webhook SSRF: webhook parameters accepted "
                  "canary URL (no callback observed)",
            severity="low",
            verification="candidate",
            verification_note=(
                "Webhook-style parameters were set to token URLs but no "
                "exact-token callback arrived within the %.1fs window. "
                "Weak evidence — not confirmed." % wait_s),
            manual_check="curl -sS -i \"%s\"" % tried[0],
            location=tried[0],
            evidence={"tried": tried},
            source="omega-oob/webhook_ssrf"))
    return findings


CHECKS = [
    ("blind_ssrf_confirm", blind_ssrf_confirm),
    ("blind_xss_canary", blind_xss_canary),
    ("blind_rce_probe", blind_rce_probe),
    ("webhook_ssrf", webhook_ssrf),
]


def run_oobchecks(target, server=None, path_info=None, fetch=None,
                  budget=None, log=None, allowlist=None, wait_s=None):
    """Run all OOB-backed checks. Never raises.

    Returns {findings, ran, skipped, hits}. When no running server is
    supplied every check is skipped with 'OOB server not started'.
    """
    result = {"findings": [], "ran": [], "skipped": {}, "hits": []}
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = "target %r not in allowlist" % target
        return result
    if not _server_alive(server):
        for name, _fn in CHECKS:
            result["skipped"][name] = "OOB server not started"
        if log:
            log("oobchecks skipped: OOB server not started")
        return result
    fetch = fetch or default_fetch
    for name, fn in CHECKS:
        if budget is not None and len(result["ran"]) >= budget:
            result["skipped"][name] = "budget exhausted"
            continue
        try:
            kwargs = {}
            if wait_s is not None:
                kwargs["wait_s"] = wait_s
            found = fn(target, server, path_info=path_info, fetch=fetch,
                       log=log, **kwargs)
        except Exception as exc:  # never raise
            result["skipped"][name] = "error: %s" % exc
            if log:
                log("oobcheck %s failed: %s" % (name, exc))
            continue
        result["ran"].append(name)
        result["findings"].extend(found)
        if log:
            log("oobcheck %s: %d finding(s)" % (name, len(found)))
    try:
        result["hits"] = server.hits()
    except Exception:
        result["hits"] = []
    return result
