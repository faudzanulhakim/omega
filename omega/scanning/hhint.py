"""omega/scanning/hhint.py — host-header injection suite
(fusion suite name: ``hh-inject``).

Python-only, string-differential, non-destructive. Checks:

  absolute_url_override  — absolute-form request URI override
  xfh_reset_flow         — X-Forwarded-Host canary in password-reset
                           style flows (body/Location reflection)
  cache_poisoning        — host-header web-cache poisoning
                           (candidate-only, two-shot differential)
  host_port_confusion    — wrong/odd Host ports and bracketed IPv6
  forwarded_chain        — X-Forwarded-Proto/Port reflection

Every check compares against a canary baseline (a random host is
injected; the response must contain the canary ONLY when the header is
overridden). All findings are ``verification='candidate'``.
"""

from __future__ import annotations

import re
import secrets

__all__ = [
    "Finding",
    "absolute_url_override",
    "cache_poisoning",
    "host_port_confusion",
    "registry",
    "run_hhint",
    "xfh_reset_flow",
]

RESET_PATHS = ["/password-reset", "/reset-password", "/forgot-password",
               "/reset", "/login", "/"]

FORWARDED_HEADERS = ["X-Forwarded-Host", "X-Host", "X-HTTP-Host-Override"]

_WIKI_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]+:\d{1,5}$")


class Finding(dict):
    """ENGINE-convention finding dict (differential, candidate-only)."""

    def __init__(self, title, severity, verification_note, manual_check,
                 location, evidence, source, confidence="medium"):
        super().__init__(
            title=title,
            severity=severity,
            confidence=confidence,
            verification="candidate",
            verification_note=verification_note,
            manual_check=manual_check,
            location=location,
            evidence=evidence[:300],
            source=source,
        )


def _canary():
    return "omega-hh-%s.example" % secrets.token_hex(4)


def _text(body):
    if isinstance(body, bytes):
        return body.decode("latin-1")
    return str(body or "")


def _reflects(canary, status, headers, body):
    hay = _text(body) + " " + str(headers.get("Location") or
                                  headers.get("location") or "")
    return canary.lower() in hay.lower()


# ------------------------------------------------------------------ checks
def absolute_url_override(base_url, fetch):
    """Absolute-form request URI (GET http://canary/ HTTP/1.1 style,
    sent as the request target) — servers that honor it over the Host
    header generate links to the canary."""
    canary = _canary()
    base = base_url.rstrip("/")
    st0, _h0, b0 = fetch("GET", base + "/")
    # stdlib fetch cannot split connection-target from request-target,
    # so the absolute-URI override is emulated by carrying the absolute
    # URL of the canary as the PATH on the real host connection.
    st2, h2, b2 = fetch("GET", base + "/http://%s/" % canary,
                        headers={"Host": _host_of(base)})
    if st2 != 200 or not _reflects(canary, st2, h2, b2):
        return []
    if _reflects(canary, st0, _h0, b0):
        return []
    return [Finding(
        title="Absolute-URL override reflected in response",
        severity="medium",
        verification_note=(
            "A path carrying an absolute-form URI (%s) is reflected in "
            "the response while the baseline does not contain it — the "
            "application builds links from request-target input; "
            "password-reset/link poisoning is candidate only." % canary),
        manual_check='curl -sS -i "%s/http://%s/"'
                     % (base, canary),
        location=base + "/http://%s/" % canary,
        evidence="canary=%s probe_status=%s baseline_status=%s"
                 % (canary, st2, st0),
        source="omega-hhint/absolute_url_override")]


def _host_of(url):
    import urllib.parse
    return urllib.parse.urlparse(
        url if "://" in url else "http://" + url).hostname or ""


def xfh_reset_flow(base_url, fetch):
    """X-Forwarded-Host (and variants) injection across reset-style
    endpoints: any endpoint that reflects the canary host in its body
    or Location differentially is a candidate finding."""
    canary = _canary()
    base = base_url.rstrip("/")
    st0, h0, b0 = fetch("GET", base + "/")
    if _reflects(canary, st0, h0, b0):
        return []  # canary collision guard (never expected)
    findings = []
    for path in RESET_PATHS:
        url = base + path
        for header in FORWARDED_HEADERS:
            st, headers, body = fetch("GET", url, headers={header: canary})
            if not _reflects(canary, st, headers, body):
                continue
            findings.append(Finding(
                title="%s injection reflects at %s" % (header, path),
                severity="high" if "reset" in path or "login" in path
                         else "medium",
                verification_note=(
                    "Sending %s: %s to %s makes the canary appear in the "
                    "response body/Location, absent from the baseline — "
                    "the endpoint trusts forwarded host headers; "
                    "reset-link poisoning is candidate only."
                    % (header, canary, path)),
                manual_check='curl -sS -i -H "%s: %s" "%s%s"'
                             % (header, canary, base, path),
                location=url,
                evidence="header=%s canary=%s status=%s via=%s"
                         % (header, canary, st, "reflection"),
                source="omega-hhint/xfh_reset_flow"))
            break  # one finding per endpoint
    return findings


def cache_poisoning(base_url, fetch):
    """Two-shot cache-poisoning probe (candidate-only): shot 1 requests
    the same URL with X-Forwarded-Host: canary; shot 2 requests the SAME
    URL WITHOUT the header. If the canary persists in shot 2, a cache
    (or stateful layer) served the poisoned entry."""
    canary = _canary()
    base = base_url.rstrip("/")
    url = base + "/?omega-cache-probe=%s" % canary
    st1, _h1, b1 = fetch("GET", url, headers={"X-Forwarded-Host": canary})
    if not _reflects(canary, st1, _h1, b1):
        return []
    st2, h2, b2 = fetch("GET", url)
    if _reflects(canary, st2, h2, b2):
        return [Finding(
            title="Host-header web cache poisoning suspected at "
                  "/?omega-cache-probe=<canary>",
            severity="high",
            verification_note=(
                "The canary host (X-Forwarded-Host: %s) influenced the "
                "response and PERSISTED on an unheadered repeat of the "
                "same URL — a cache or stateful layer stored the "
                "host-influenced content. Candidate only; poisoning of "
                "shared caches requires manual confirmation." % canary),
            manual_check=(
                'curl -sS -H "X-Forwarded-Host: %s" "%s"; then '
                'curl -sS "%s" | grep -F %s'
                % (canary, url, url, canary)),
            location=url,
            evidence="canary=%s shot1_status=%s shot2_status=%s "
                     "persisted=True" % (canary, st1, st2),
            source="omega-hhint/cache_poisoning",
            confidence="high")]
    return [Finding(
        title="X-Forwarded-Host reflected at %s (no cache persistence)"
              % url,
        severity="low",
        verification_note=(
            "The canary host is reflected when the header is present "
            "but does NOT persist without it — header trust confirmed, "
            "cache impact not demonstrated. Candidate only."),
        manual_check='curl -sS -i -H "X-Forwarded-Host: %s" "%s"'
                     % (canary, url),
        location=url,
        evidence="canary=%s status=%s persisted=False" % (canary, st1),
        source="omega-hhint/cache_poisoning")]


def host_port_confusion(base_url, fetch):
    """Odd Host ports (mismatched port, port 0, giant port) and
    bracketed IPv6: a differential status/Location response vs baseline
    indicates the front end forwards the raw Host — port-confusion
    candidate."""
    base = base_url.rstrip("/")
    host = _host_of(base)
    st0, h0, b0 = fetch("GET", base + "/")
    findings = []
    for weird in ("%s:1" % host, "%s:65535" % host,
                  "%s:0" % host, "[::1]:80"):
        st, headers, body = fetch("GET", base + "/",
                                  headers={"Host": weird})
        if st == st0 and _text(body) == _text(b0) and \
                (headers.get("Location") or "") == \
                (h0.get("Location") or ""):
            continue
        findings.append(Finding(
            title="Odd Host header accepted: Host: %s" % weird,
            severity="low",
            verification_note=(
                "Sending Host: %s produced a response different from "
                "the baseline (status %s vs %s) — the front end does "
                "not validate/normalize the Host header; port/host "
                "confusion routing is candidate only."
                % (weird, st, st0)),
            manual_check='curl -sS -i -H "Host: %s" "%s/"' % (weird, base),
            location=base + "/",
            evidence="host=%s status=%s baseline_status=%s"
                     % (weird, st, st0),
            source="omega-hhint/host_port_confusion"))
    return findings


def forwarded_chain(base_url, fetch):
    """X-Forwarded-Proto / X-Forwarded-Port reflection: response links
    or Location flip to the injected scheme/port differentially."""
    canary_port = str(40000 + int(secrets.token_hex(1), 16))
    base = base_url.rstrip("/")
    st0, h0, b0 = fetch("GET", base + "/")
    st, headers, body = fetch("GET", base + "/", headers={
        "X-Forwarded-Proto": "http",
        "X-Forwarded-Port": canary_port,
    })
    hay = _text(body) + " " + (headers.get("Location") or "")
    base_hay = _text(b0) + " " + (h0.get("Location") or "")
    if (":%s" % canary_port) in hay and (":%s" % canary_port) not in \
            base_hay:
        return [Finding(
            title="X-Forwarded-Proto/Port reflected in generated links",
            severity="medium",
            verification_note=(
                "X-Forwarded-Port: %s appears in the response "
                "(body/Location) only when the header is set — generated "
                "links trust forwarding headers; open-redirect-style "
                "abuse is candidate only." % canary_port),
            manual_check='curl -sS -i -H "X-Forwarded-Port: %s" "%s/"'
                         % (canary_port, base),
            location=base + "/",
            evidence="canary_port=%s status=%s" % (canary_port, st),
            source="omega-hhint/forwarded_chain")]
    return []


registry = [
    ("absolute_url_override", absolute_url_override),
    ("xfh_reset_flow", xfh_reset_flow),
    ("cache_poisoning", cache_poisoning),
    ("host_port_confusion", host_port_confusion),
    ("forwarded_chain", forwarded_chain),
]


class _BudgetExhausted(Exception):
    """Internal: raised when the per-run request budget is spent."""


class _CountingFetch:
    def __init__(self, fetch, cap):
        self._fetch = fetch
        self.cap = cap
        self.sent = 0

    def __call__(self, method, url, headers=None, body=None):
        if self.sent >= self.cap:
            raise _BudgetExhausted()
        resp = self._fetch(method, url, headers=headers, body=body)
        self.sent += 1
        return resp


def run_hhint(target, fetch, budget=40, log=None, allowlist=None):
    """Run all registered host-header-injection checks. Never raises;
    per-check errors become skipped entries. Returns
    {findings, skipped, requests_sent, ran}."""
    from omega.probes import allowlist_ok

    result = {"findings": [], "skipped": {}, "requests_sent": 0, "ran": []}
    base_url = target if "://" in target else "http://" + target
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = \
            "target %r not in allowlist" % target
        if log:
            log("hhint skipped: target not in allowlist: %r" % target)
        return result
    fb = _CountingFetch(fetch, budget)
    exhausted = False
    for name, check in registry:
        if exhausted:
            result["skipped"][name] = "budget exhausted"
            continue
        try:
            found = check(base_url, fb)
        except _BudgetExhausted:
            # the check STARTED (its partial work was contained) — record
            # it as both ran and budget-exhausted-skipped.
            result["skipped"][name] = "budget exhausted"
            result["ran"].append(name)
            exhausted = True
            continue
        except Exception as exc:
            result["skipped"][name] = "error: %s" % exc
            if log:
                log("hhint check %s failed: %s" % (name, exc))
            continue
        result["ran"].append(name)
        result["findings"].extend(found)
        if log:
            log("hhint %s: %d finding(s)" % (name, len(found)))
    result["requests_sent"] = fb.sent
    return result
