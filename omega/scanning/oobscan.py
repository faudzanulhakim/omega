"""omega/oobscan.py — blind-interaction scanner backed by the EXISTING
local OOB callback server (omega.oob.OOBCallbackServer).

Three kinds of evidence, all GET-only, read-only, budget-capped (20):

  1. OOB canaries: for every injectable-looking parameter (an optional
     ``params`` dict, else the built-in suspect list) send a GET whose
     value carries a UNIQUE token pointing at the OOB collector —
     ``http://TOKEN.oobhost/`` for URL-shaped params, plain
     ``TOKEN.oobhost`` otherwise. Poll the callback server (bounded:
     at most 3 polls, 0.5s apart) for interactions on the EXACT token.
       * hit  -> finding "out-of-band interaction" candidate
                 MEDIUM/HIGH with the token + interaction metadata;
       * miss -> NO finding. Blind results are honestly unlabeled: the
                 result carries an explicit note that the ABSENCE of a
                 callback is INCONCLUSIVE, never "secure".

  2. SSRF-shaped response differential (no OOB needed): probe params
     with ``http://127.0.0.1:PORT/`` where PORT is one of OUR OWN
     locally-running services (the OOB server itself by default, or
     ``internal_ports``). Fingerprint that internal service with one
     local GET, then if the target's response body embeds that
     fingerprint content, run a control request with a benign value;
     a matching body + a control body WITHOUT the fingerprint yields
     "internal service response reflected (SSRF evidence)" — HIGH,
     ``confirmed`` only because the documented differential holds
     (fingerprint content present on the probe, absent on the control;
     plain reflection of the URL string is NOT enough — the check
     matches fingerprint CONTENT, which a reflecting server cannot
     produce without actually fetching the internal service).

  3. The OOB server handle may be supplied via ``oob_server``; when it
     is not, one is started through the existing omega.oob API inside
     try/except — if that is unavailable the whole module is skipped
     with 'oob server unavailable'.

``run_oobscan`` never raises; failures land in ``result['skipped']``.
Every request we send is counted in ``requests_sent`` against
``budget``. Finding shape: title / severity / confidence /
verification / verification_note / manual_check (real-target curl) /
location / evidence (<=300 chars) / source=omega-oobscan/<name>.
"""

from __future__ import annotations

import time
import urllib.parse

from omega.probes import Finding, default_fetch

__all__ = [
    "OOBSCAN_SUSPECT_PARAMS",
    "URL_SHAPED_PARAMS",
    "POLL_ATTEMPTS",
    "POLL_SLEEP_S",
    "run_oobscan",
]

OOBSCAN_SUSPECT_PARAMS = [
    "url", "host", "uri", "path", "feed", "src", "webhook", "callback",
    "ping", "fetch", "load", "proxy", "img", "avatar", "doc", "xml",
    "saml",
]

# Params that semantically take a full URL -> plant 'http://TOKEN.oobhost/';
# the rest take a bare host shape -> plant 'TOKEN.oobhost'.
URL_SHAPED_PARAMS = {
    "url", "uri", "feed", "src", "webhook", "callback", "fetch",
    "load", "proxy", "img", "avatar", "doc",
}

POLL_ATTEMPTS = 3
POLL_SLEEP_S = 0.5
OOB_MARKER_HOST = "oobhost"

# HIGH when the param clearly makes the server fetch an arbitrary URL.
HIGH_SEVERITY_PARAMS = {
    "url", "uri", "src", "webhook", "callback", "fetch", "load",
    "proxy", "feed",
}

NO_CALLBACK_NOTE = (
    "Absence of an OOB callback is INCONCLUSIVE, not 'secure': the "
    "target may fetch asynchronously, only support other methods, or "
    "block the collector host. Manual follow-up required.")


def _base_of(target):
    return target if "://" in target else "https://" + target


def _candidate_params(params):
    if params:
        names = list(dict.fromkeys(params))
    else:
        names = list(OOBSCAN_SUSPECT_PARAMS)
    return names


def _canary_value(param, token):
    if param in URL_SHAPED_PARAMS:
        return "http://%s.%s/" % (token, OOB_MARKER_HOST)
    return "%s.%s" % (token, OOB_MARKER_HOST)


def _trim_hit(hit):
    """Compact, evidence-sized (<=300 chars) view of an OOB hit."""
    if not hit:
        return {}
    keep = {
        "token": hit.get("token"),
        "path": (hit.get("path") or "")[:120],
        "method": hit.get("method"),
        "remote": hit.get("remote"),
        "ts": hit.get("ts"),
    }
    return keep


def _poll_for_hit(server, token):
    """Bounded poll: at most POLL_ATTEMPTS checks, POLL_SLEEP_S apart."""
    for attempt in range(POLL_ATTEMPTS):
        try:
            hits = server.hits(token)
        except Exception:
            return None
        if hits:
            return hits[0]
        if attempt < POLL_ATTEMPTS - 1:
            time.sleep(POLL_SLEEP_S)
    return None


def _oob_pass(target_url, server, candidates, fetch, result, log):
    """Plant unique-token canaries in each candidate param, poll once."""
    for param in candidates:
        if result["requests_sent"] >= result["budget"]:
            result["skipped"]["oob:%s" % param] = "budget exhausted"
            continue
        try:
            token = server.new_token()
        except Exception as exc:
            result["skipped"]["oob:%s" % param] = "token error: %s" % exc
            continue
        value = _canary_value(param, token)
        url = target_url + "?" + urllib.parse.urlencode({param: value})
        result["tokens"].append({"param": param, "token": token,
                                 "value": value})
        try:
            fetch("GET", url, {})
        except Exception as exc:
            result["skipped"]["oob:%s" % param] = "request error: %s" % exc
            continue
        result["requests_sent"] += 1
        hit = _poll_for_hit(server, token)
        if hit:
            if log:
                log("oobscan: exact-token callback for param %r" % param)
            severity = ("high" if param in HIGH_SEVERITY_PARAMS
                        else "medium")
            result["findings"].append(Finding(
                title="Out-of-band interaction via parameter '%s'" % param,
                severity=severity,
                confidence="high",
                verification="candidate",
                verification_note=(
                    "A unique 32-hex token pointing at the operator's "
                    "local OOB collector was planted in parameter '%s'; "
                    "the EXACT token received a callback, so the target "
                    "made a request to an attacker-influenced host. "
                    "Candidate: further manual verification required "
                    "(callback destination is the operator's own "
                    "collector, not a third party)." % param),
                manual_check="curl -sS -i \"%s\"" % url,
                location=url,
                evidence=dict({"param": param, "token": token},
                              **_trim_hit(hit)),
                source="omega-oobscan/oob_interaction"))
        # No hit: deliberately NO finding (blind result, honestly
        # unlabeled). result['note'] explains why below.


def _ssrf_pass(target_url, server, candidates, fetch, result, log,
               internal_ports):
    """Response-differential SSRF check against OUR OWN local services."""
    ports = (list(internal_ports)
             if internal_ports is not None else [])
    if internal_ports is None:
        try:
            ports = [int(server.port)]
        except Exception:
            return
    if not ports:
        return
    for port in ports:
        if result["requests_sent"] + 1 >= result["budget"]:
            result["skipped"]["ssrf:port%d" % port] = "budget exhausted"
            continue
        # Fingerprint the internal service with one local GET.
        fingerprint = None
        try:
            _st, _h, body = fetch("GET", "http://127.0.0.1:%d/" % port, {})
            result["requests_sent"] += 1
            if body and len(body) >= 8:
                fingerprint = body[:64]
        except Exception as exc:
            result["skipped"]["ssrf:port%d" % port] = (
                "fingerprint failed: %s" % exc)
            continue
        if fingerprint is None:
            continue
        marker = fingerprint.decode("utf-8", "replace")
        for param in candidates:
            if result["requests_sent"] + 2 > result["budget"]:
                result["skipped"]["ssrf:%s" % param] = "budget exhausted"
                continue
            probe_value = "http://127.0.0.1:%d/" % port
            url = target_url + "?" + urllib.parse.urlencode(
                {param: probe_value})
            try:
                status, _h, body = fetch("GET", url, {})
            except Exception as exc:
                result["skipped"]["ssrf:%s" % param] = (
                    "request error: %s" % exc)
                continue
            result["requests_sent"] += 1
            text = (body or b"").decode("utf-8", "replace")
            if marker not in text:
                continue
            # Differential control: a benign value must NOT produce the
            # internal service's fingerprint content.
            controlled = True
            try:
                ctrl_url = target_url + "?" + urllib.parse.urlencode(
                    {param: "/dashboard"})
                _cs, _ch, cbody = fetch("GET", ctrl_url, {})
                result["requests_sent"] += 1
                if marker in cbody.decode("utf-8", "replace"):
                    controlled = False
            except Exception:
                controlled = False  # can't run differential -> don't confirm
            if log:
                log("oobscan: internal fingerprint for port %d reflected "
                    "via param %r" % (port, param))
            result["findings"].append(Finding(
                title="Internal service response reflected (SSRF evidence)",
                severity="high",
                confidence="high" if controlled else "low",
                verification="confirmed" if controlled else "candidate",
                verification_note=(
                    "Setting '%s' to http://127.0.0.1:%d/ made the target "
                    "return content fingerprint-matched to OUR OWN local "
                    "service on that port. Differential holds: the probe "
                    "body contains the internal fingerprint while a "
                    "control request with '/dashboard' does not — the "
                    "server fetched the internal URL server-side. "
                    "Reflection of the URL string alone would not match, "
                    "as the check compares fingerprint content."
                    % (param, port)
                    if controlled else
                    "Internal fingerprint content matched, but the "
                    "control differential FAILED or was unavailable — "
                    "candidate only."),
                manual_check="curl -sS -i \"%s\"" % url,
                location=url,
                evidence={"param": param, "internal_port": port,
                          "fingerprint_sha_like": marker[:48],
                          "status": status,
                          "differential": "control '/dashboard' lacks "
                                          "fingerprint" if controlled
                          else "control also matches"},
                source="omega-oobscan/ssrf_internal_reflection"))
            return  # one SSRF evidence finding per run


def run_oobscan(target, fetch=None, budget=20, log=None, params=None,
                oob_server=None, internal_ports=None):
    """Blind-interaction scan. Never raises.

    Returns {findings, skipped, requests_sent, ran:['oobscan'], tokens,
    budget, note}.
    """
    result = {
        "findings": [],
        "skipped": {},
        "requests_sent": 0,
        "ran": ["oobscan"],
        "tokens": [],
        "budget": int(budget),
    }
    try:
        fetch = fetch or default_fetch
        # --- obtain / validate the OOB server -------------------------
        server = oob_server
        if server is None:
            try:
                from omega.oob import OOBCallbackServer
                server = OOBCallbackServer().start()
                result["oob_server_started"] = True
            except Exception as exc:
                result["skipped"]["oobscan"] = (
                    "oob server unavailable: %s" % exc)
                if log:
                    log("oobscan skipped: oob server unavailable: %s" % exc)
                return result
        alive = False
        try:
            alive = bool(server.running)
        except Exception:
            alive = False
        if not alive:
            result["skipped"]["oobscan"] = "oob server unavailable"
            if log:
                log("oobscan skipped: supplied oob server not running")
            return result

        target_url = _base_of(target)
        candidates = _candidate_params(params)

        # --- pass 1: OOB canaries --------------------------------------
        _oob_pass(target_url, server, candidates, fetch, result, log)

        # --- pass 2: SSRF-shaped response differential ------------------
        if result["requests_sent"] < result["budget"]:
            _ssrf_pass(target_url, server, candidates, fetch, result, log,
                       internal_ports)

        result["note"] = (
            "No finding for params without a callback: absence of an OOB "
            "interaction is inconclusive, NOT evidence of security.")
    except Exception as exc:  # never raise
        result["skipped"]["__all__"] = "error: %s" % exc
        if log:
            log("oobscan failed: %s" % exc)
    result["findings"] = result["findings"][: result["budget"]]
    return result
