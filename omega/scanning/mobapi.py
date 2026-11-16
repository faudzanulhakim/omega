"""omega/scanning/mobapi.py — mobile backend API checks
(fusion suite name: ``mobapi``).

Given the API endpoint list extracted from the APK (from the mobdeep
evidence or ``path_info``), runs four bounded, benign checks per
endpoint:

- missing rate limiting on login/register endpoints (3 rapid requests,
  same pattern as the engine rate_limit check): no 429/503 and no
  Retry-After across the burst -> MEDIUM candidate;
- TLS downgrade acceptance: the ``http://`` variant of an ``https://``
  endpoint answers 200 -> MEDIUM candidate;
- API versioning exposure: a matching /v1/... and /v2/... pair is both
  active and shows different auth results for an inert bogus bearer
  token -> INFO candidate;
- unauthenticated sensitive endpoints (apidocs logic scoped to mobile
  endpoints): 200 + parseable JSON body unauthenticated -> MEDIUM
  candidate.

GET-only, never raises, bounded (MAX_ENDPOINTS endpoints x a handful of
requests each).
"""

from __future__ import annotations

import json

from omega.scanning.deepchecks import default_fetch

__all__ = [
    "Finding",
    "MAX_ENDPOINTS",
    "SENSITIVE_MARKERS",
    "collect_endpoints",
    "run_mobapi",
]

MAX_ENDPOINTS = 12
MAX_RATE_PROBES = 3

SENSITIVE_MARKERS = (
    "user", "profile", "account", "order", "payment", "token",
    "key", "admin", "data", "message", "customer", "card",
)

AUTH_ENDPOINT_MARKERS = ("login", "register", "signup", "signin")


class Finding(dict):
    """ENGINE-convention finding dict (candidate only)."""

    def __init__(self, title, severity, verification, verification_note,
                 manual_check, location, evidence, source,
                 confidence="medium"):
        super().__init__(
            title=title,
            severity=severity,
            confidence=confidence,
            verification=verification,
            verification_note=verification_note,
            manual_check=manual_check,
            location=location,
            evidence=str(evidence)[:300],
            source=source,
        )


def _text(body):
    if isinstance(body, bytes):
        return body.decode("latin-1")
    return str(body or "")


def _get(fetch, url, headers=None):
    """Contained GET -> (status, headers, text); never raises."""
    try:
        st, h, raw = fetch("GET", url, headers=headers)
        return st, h or {}, _text(raw)
    except Exception:
        return None, {}, ""


def collect_endpoints(path_info):
    """Endpoint list from path_info['paths'] + path_info
    ['apk_endpoints'] (the mobdeep evidence channel). Deduped, bounded."""
    if not isinstance(path_info, dict):
        return []
    out = []
    for source in ("paths", "apk_endpoints", "apk"):
        for item in path_info.get(source) or []:
            if not isinstance(item, str) or not item:
                continue
            ep = item if item.startswith("/") or "://" in item \
                else "/" + item
            if ep not in out:
                out.append(ep)
    return out[:MAX_ENDPOINTS]


def _url_for(base, endpoint):
    if "://" in endpoint:
        return endpoint
    return base.rstrip("/") + endpoint


def _https_candidates(base, endpoints):
    """Endpoints whose TLS-downgrade http:// variant can be tested."""
    cands = []
    for ep in endpoints:
        if ep.startswith("https://"):
            cands.append(ep)
        elif not ep.startswith("http") and \
                base.lower().startswith("https://"):
            cands.append(_url_for(base, ep))
    return cands


def _version_pair(endpoints):
    """First matching (v1_path, v2_path) pair with the same suffix."""
    v1 = [e for e in endpoints if "/v1/" in e or e.endswith("/v1")]
    v2 = [e for e in endpoints if "/v2/" in e or e.endswith("/v2")]
    for a in v1:
        suffix = a.split("/v1", 1)[1]
        for b in v2:
            if b.split("/v2", 1)[1] == suffix:
                return a, b
    return None


def run_mobapi(base_url, fetch=default_fetch, path_info=None, gate=False):
    """Mobile backend API checks. Returns a list of Finding dicts;
    never raises. ``gate`` accepted for suite-signature symmetry."""
    out = []
    try:
        base = base_url if "://" in base_url else "http://" + base_url
        base = base.rstrip("/")
        endpoints = collect_endpoints(path_info)
        if not endpoints:
            return out

        # 1. Missing rate limiting on auth endpoints (3 rapid requests).
        for ep in endpoints:
            low = ep.lower()
            if not any(m in low for m in AUTH_ENDPOINT_MARKERS):
                continue
            url = _url_for(base, ep)
            statuses, retry_after = [], None
            for _ in range(MAX_RATE_PROBES):
                st, h, _t = _get(fetch, url)
                statuses.append(st)
                low_h = {str(k).lower(): v for k, v in h.items()}
                retry_after = retry_after or low_h.get("retry-after")
            if any(s in (429, 503) for s in statuses) or retry_after:
                continue
            # only judge reachable endpoints: all-None (fetch errors) or
            # all-4xx (e.g. auth-gated) say nothing about rate limiting.
            reachable = [s for s in statuses
                         if s is not None and s < 400]
            if not reachable:
                continue
            out.append(Finding(
                title="No rate limiting on auth endpoint %s "
                      "(%d rapid requests)" % (ep, MAX_RATE_PROBES),
                severity="medium", verification="candidate",
                verification_note=(
                    "%d rapid unauthenticated requests to %s all "
                    "completed without 429/503 or Retry-After "
                    "(statuses: %s) — no rate limiting observed at "
                    "this intensity (not proof of absence under load)."
                    % (MAX_RATE_PROBES, url, statuses)),
                manual_check=("for i in 1 2 3; do curl -sS -o /dev/null "
                              "-w '%%{http_code}\\n' %s; done" % url),
                location=url,
                evidence="statuses=%s endpoint=%s" % (statuses, ep),
                source="omega-mobapi"))

        # 2. TLS downgrade acceptance.
        for https_url in _https_candidates(base, endpoints)[:5]:
            http_url = "http://" + https_url.split("://", 1)[1]
            st, _h, _t = _get(fetch, http_url)
            if st == 200:
                out.append(Finding(
                    title="TLS downgrade accepted: http:// variant of "
                          "%s answers 200" % https_url,
                    severity="medium", verification="candidate",
                    verification_note=(
                        "The http:// variant of the HTTPS endpoint "
                        "returned HTTP 200 without redirecting to TLS "
                        "— plaintext traffic is accepted where the app "
                        "may hold tokens. Candidate only."),
                    manual_check="curl -sS -i %s" % http_url,
                    location=http_url,
                    evidence="https=%s http_status=%s" % (https_url, st),
                    source="omega-mobapi"))

        # 3. API versioning exposure (v1 + v2 both active, different
        #    auth results with an inert bogus token).
        pair = _version_pair(endpoints)
        if pair:
            v1, v2 = pair
            st1, _h1, b1 = _get(fetch, _url_for(base, v1))
            st2, _h2, b2 = _get(fetch, _url_for(base, v2))
            bogus = {"Authorization": "Bearer omegainertprobe"}
            stb1, _h3, _t1 = _get(fetch, _url_for(base, v1), headers=bogus)
            stb2, _h4, _t2 = _get(fetch, _url_for(base, v2), headers=bogus)
            if st1 == 200 and st2 == 200 and (stb1 != stb2
                                              or b1 != b2):
                out.append(Finding(
                    title="Both API versions v1 and v2 active with "
                          "different auth results",
                    severity="info", verification="candidate",
                    verification_note=(
                        "Both /v1 and /v2 variants of the same endpoint "
                        "answer 200 unauthenticated, and an inert bogus "
                        "bearer token produces different results "
                        "(v1: %s, v2: %s) — parallel versions with "
                        "divergent auth behavior broaden the attack "
                        "surface. Informational." % (stb1, stb2)),
                    manual_check="curl -sS -i %s; curl -sS -i %s"
                                 % (_url_for(base, v1), _url_for(base, v2)),
                    location=_url_for(base, v2),
                    evidence="v1=%s v2=%s token_v1=%s token_v2=%s"
                             % (st1, st2, stb1, stb2),
                    source="omega-mobapi"))

        # 4. Unauthenticated sensitive endpoints (apidocs logic scoped
        #    to mobile endpoints).
        for ep in endpoints[:MAX_ENDPOINTS]:
            low = ep.lower()
            if not any(m in low for m in SENSITIVE_MARKERS):
                continue
            url = _url_for(base, ep)
            st, _h, body = _get(fetch, url)
            if st != 200 or not body.strip():
                continue
            stripped = body.lstrip()
            if not stripped.startswith(("{", "[")):
                continue
            try:
                json.loads(body)
            except Exception:
                continue
            out.append(Finding(
                title="Unauthenticated sensitive mobile API endpoint "
                      "answers 200: %s" % ep,
                severity="medium", verification="candidate",
                verification_note=(
                    "The endpoint returned HTTP 200 with a JSON body "
                    "when fetched without any credentials. Candidate "
                    "only: confirm the data is not intentionally "
                    "public and whether it exposes sensitive objects."),
                manual_check="curl -sS %s" % url,
                location=url,
                evidence="status=%s endpoint=%s bytes=%d"
                         % (st, ep, len(body)),
                source="omega-mobapi"))
    except Exception:
        pass
    return out
