"""omega/redirects.py — open-redirect and redirect-chain auditor.

Two independent checks, GET-only, read-only, budget-capped:

  1. Parameter redirect audit: for every candidate parameter (the
     common URL-ish suspect names plus any param whose original value
     looks like a URL), send a GET with the value
     ``http://omega-redirect-check.example`` (a benign, non-resolving
     domain — nothing is fetched, nothing is attacked). Classify:

       (a) 3xx whose Location points at an external host
           -> open-redirect candidate (HIGH);
       (b) 200 whose body carries a meta-refresh or a
           ``window.location`` assignment to that external URL
           -> client-side open-redirect candidate (MEDIUM);
       (c) body echoes the probe URL but no redirect
           -> "reflected redirect param" (LOW);
       (d) no trace at all -> clean, NO finding.

  2. Chain audit: follow up to 5 hops of same-origin redirects
     (relative or same-host Location) from the target root. Flag a
     chain longer than 3 hops (INFO) and any hop whose Location lands
     on a DIFFERENT host (candidate MEDIUM, "redirect chain crosses
     trust boundary").

Differential confirm rule (documented): an open-redirect candidate is
upgraded to ``confirmed`` ONLY when a control request with a benign
same-origin value (``/dashboard``) does NOT redirect externally while
the external-value request DOES. Without that differential the finding
stays ``candidate``. Client-side and reflected findings are always
``candidate`` — they need a browser/manual review.

Caps: at most ``budget`` (default 40) requests are sent, all counted
in ``requests_sent``. One probe per parameter (deduped). ``run_redirects``
never raises — any failure is contained into ``result['skipped']``.

Finding shape follows the ENGINE convention (plain dict):
title / severity / confidence / verification / verification_note /
manual_check (real-target curl) / location / evidence (<=300 chars) /
source=omega-redirects/<name>.
"""

from __future__ import annotations

import re
import urllib.parse

from omega.probes import Finding, default_fetch

__all__ = [
    "PROBE_HOST",
    "REDIRECT_PARAM_SUSPECTS",
    "MAX_CHAIN_HOPS",
    "discover_redirect_params",
    "run_redirects",
]

PROBE_HOST = "omega-redirect-check.example"
PROBE_URL = "http://" + PROBE_HOST

REDIRECT_PARAM_SUSPECTS = [
    "url", "next", "redirect", "redirect_uri", "return", "returnTo",
    "goto", "target", "dest", "r", "u", "continue", "link", "out",
    "view",
]

MAX_CHAIN_HOPS = 5

_REDIRECT_CODES = (301, 302, 303, 307, 308)

_META_RE = re.compile(
    r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh[\"']?[^>]*>", re.I)
_META_URL_RE = re.compile(r"url\s*=\s*[\"']?(https?://[^\"'>\s]+)", re.I)
_WINLOC_RE = re.compile(
    r"window\.location(?:\.href)?\s*=\s*[\"']([^\"']+)[\"']", re.I)


def _base_of(target):
    return target if "://" in target else "https://" + target


def _host_of(url):
    try:
        return (urllib.parse.urlsplit(url).netloc or "").lower()
    except ValueError:
        return ""


def _is_external(url, base_host):
    """True when url points at a host other than the target's own."""
    host = _host_of(url)
    return bool(host) and host != base_host


def _resolve(base_url, location):
    return urllib.parse.urljoin(base_url, location)


def discover_redirect_params(params):
    """Param names worth probing: known suspects plus any param whose
    value starts with http or contains a ``://`` sequence."""
    found = []
    for name in REDIRECT_PARAM_SUSPECTS:
        if name in params:
            found.append(name)
    for name, value in params.items():
        if name in found:
            continue
        text = value if isinstance(value, str) else str(value)
        if text.lower().startswith("http") or "://" in text:
            found.append(name)
    return list(dict.fromkeys(found))


def _classify_response(status, headers, body, base_host):
    """-> (kind, location) where kind in {'external','client','reflect',
    'internal_redirect','clean'}."""
    text = body.decode("utf-8", "replace") if body else ""
    if status in _REDIRECT_CODES:
        location = headers.get("Location") or headers.get("location") or ""
        if location and _is_external(location, base_host):
            return "external", location
        if location:
            return "internal_redirect", location
        return "clean", ""
    for meta in _META_RE.findall(text):
        m = _META_URL_RE.search(meta)
        if m and _is_external(m.group(1), base_host):
            return "client", m.group(1)
    for m in _WINLOC_RE.finditer(text):
        if _is_external(m.group(1), base_host):
            return "client", m.group(1)
    if PROBE_URL in text or PROBE_HOST in text:
        return "reflect", ""
    return "clean", ""


def _probe_param(target_url, param, fetch, base_host):
    """One GET with the benign external probe value. Never raises."""
    url = target_url + "?" + urllib.parse.urlencode({param: PROBE_URL})
    try:
        status, headers, body = fetch("GET", url, {})
    except Exception as exc:
        return url, None, "error: %s" % exc
    kind, location = _classify_response(status, headers, body, base_host)
    return url, (status, kind, location, body), None


def _control_redirects_externally(target_url, param, fetch, base_host):
    """Differential control: a benign same-origin value must NOT send
    the user off-host. Returns True when the control value DOES cause
    an external redirect (i.e. the param redirects for ANY value and
    the external finding must stay 'candidate')."""
    url = target_url + "?" + urllib.parse.urlencode({param: "/dashboard"})
    try:
        status, headers, _body = fetch("GET", url, {})
    except Exception:
        return True  # can't run the differential -> don't confirm
    if status in _REDIRECT_CODES:
        location = headers.get("Location") or headers.get("location") or ""
        return bool(location) and _is_external(location, base_host)
    return False


def _audit_param(target_url, param, fetch, base_host, result):
    """Probe one param, classify, run the differential, append findings."""
    probe_url, obs, err = _probe_param(target_url, param, fetch, base_host)
    if obs is None:
        result["skipped"]["param:%s" % param] = err
        return
    result["requests_sent"] += 1
    result["probed"].append(param)
    status, kind, location, body = obs
    common = {
        "param": param,
        "probe_url": probe_url,
        "probe_host": PROBE_HOST,
        "status": status,
    }
    if kind == "external":
        controlled = not _control_redirects_externally(
            target_url, param, fetch, base_host)
        result["requests_sent"] += 1
        evidence = dict(common, location=location,
                        differential="control value '/dashboard' did not "
                                     "redirect externally"
                                     if controlled else
                                     "control also redirects externally")
        result["findings"].append(Finding(
            title="Open redirect via parameter '%s'" % param,
            severity="high",
            confidence="medium" if controlled else "low",
            verification="confirmed" if controlled else "candidate",
            verification_note=(
                "Setting '%s' to the benign non-resolving probe host %s "
                "made the server issue a 3xx to %s. %s"
                % (param, PROBE_HOST, location,
                   "Differential holds: a same-origin control value "
                   "('/dashboard') does not redirect externally, so the "
                   "redirect target is attacker-influenced."
                   if controlled else
                   "Differential FAILED or unavailable: the same-origin "
                   "control value also redirects externally, so the "
                   "external hop may be unconditional — candidate only.")),
            manual_check="curl -sS -i \"%s\"" % probe_url,
            location=probe_url,
            evidence=evidence,
            source="omega-redirects/open_redirect_param"))
    elif kind == "client":
        result["findings"].append(Finding(
            title="Client-side open redirect via parameter '%s'" % param,
            severity="medium",
            verification="candidate",
            verification_note=(
                "The response body embeds a client-side navigation "
                "(meta-refresh or window.location) to the probe URL %s. "
                "Requires a browser to trigger; never auto-confirmed." % (
                    location,)),
            manual_check="curl -sS \"%s\" | grep -iE 'refresh|location'"
                         % probe_url,
            location=probe_url,
            evidence=dict(common, client_target=location),
            source="omega-redirects/client_open_redirect"))
    elif kind == "reflect":
        result["findings"].append(Finding(
            title="Reflected redirect parameter '%s'" % param,
            severity="low",
            verification="candidate",
            verification_note=(
                "The probe URL %s is echoed in the response body but no "
                "redirect occurs. Reflection only — may be usable for "
                "client-side tricks; candidate, not confirmed."
                % PROBE_HOST),
            manual_check="curl -sS -i \"%s\"" % probe_url,
            location=probe_url,
            evidence=dict(common, note="reflected, no redirect"),
            source="omega-redirects/reflected_param"))
    # kind in ('clean', 'internal_redirect'): no finding.


def _audit_chain(target_url, fetch, base_host, result):
    """Follow up to 5 same-origin hops from the target root."""
    url = target_url
    hops = 0
    crossed = None
    while hops < MAX_CHAIN_HOPS:
        if result["requests_sent"] >= result["budget"]:
            result["skipped"]["chain"] = "budget exhausted"
            return
        try:
            status, headers, _body = fetch("GET", url, {})
        except Exception as exc:
            result["skipped"]["chain"] = "error at hop %d: %s" % (hops, exc)
            return
        result["requests_sent"] += 1
        if status not in _REDIRECT_CODES:
            break
        location = headers.get("Location") or headers.get("location") or ""
        if not location:
            break
        hops += 1
        nxt = _resolve(url, location)
        if _is_external(nxt, base_host):
            crossed = nxt
            break
        url = nxt
    if crossed is not None:
        result["findings"].append(Finding(
            title="Redirect chain crosses trust boundary",
            severity="medium",
            confidence="medium",
            verification="candidate",
            verification_note=(
                "Following redirects from %s, hop %d lands on a different "
                "host (%s). Candidate only — many sites legitimately "
                "redirect to auth/CDN hosts; review manually."
                % (target_url, hops, crossed)),
            manual_check="curl -sS -i \"%s\"" % target_url,
            location=target_url,
            evidence={"start": target_url, "hops": hops, "crossed_to": crossed},
            source="omega-redirects/chain_trust_boundary"))
    if hops > 3:
        result["findings"].append(Finding(
            title="Redirect chain longer than 3 hops",
            severity="info",
            confidence="low",
            verification="candidate",
            verification_note=(
                "The target issued %d consecutive same-origin redirects "
                "(limit followed: %d). Long chains enable open-redirect "
                "smuggling and leak referrer data; informational."
                % (hops, MAX_CHAIN_HOPS)),
            manual_check="curl -sS -i \"%s\"" % target_url,
            location=target_url,
            evidence={"start": target_url, "hops": hops},
            source="omega-redirects/chain_length"))


def run_redirects(target, fetch=None, budget=40, log=None, params=None):
    """Open-redirect and redirect-chain audit. Never raises.

    Returns {findings, skipped, requests_sent, ran:['redirects'],
    probed, budget}.
    """
    result = {
        "findings": [],
        "skipped": {},
        "requests_sent": 0,
        "ran": ["redirects"],
        "probed": [],
        "budget": int(budget),
    }
    try:
        fetch = fetch or default_fetch
        if params is None:
            params = {}
        target_url = _base_of(target)
        base_host = _host_of(target_url)
        candidates = discover_redirect_params(params)
        if log:
            log("redirects: probing %d candidate param(s) %r"
                % (len(candidates), candidates))
        for param in candidates:
            if result["requests_sent"] + 2 > result["budget"]:
                result["skipped"]["param:%s" % param] = "budget exhausted"
                continue
            _audit_param(target_url, param, fetch, base_host, result)
        if base_host:
            _audit_chain(target_url, fetch, base_host, result)
    except Exception as exc:  # never raise
        result["skipped"]["__all__"] = "error: %s" % exc
        if log:
            log("redirects failed: %s" % exc)
    result["findings"] = result["findings"][: result["budget"]]
    return result
