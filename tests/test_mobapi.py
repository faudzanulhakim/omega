"""Hermetic tests for omega.scanning.mobapi (mobile backend API checks).

Injectable fetch stubs only — no server, no egress. Covers the
rate-limit pattern, TLS downgrade, v1/v2 versioning exposure,
unauthenticated sensitive endpoints, endpoint collection bounds,
skip-when-no-endpoints and never-raise behavior.
"""

import pytest

from omega.scanning.mobapi import (
    MAX_ENDPOINTS,
    collect_endpoints,
    run_mobapi,
)

LEAKY_ENDPOINTS = [
    "/api/login",
    "/api/user/profile",
    "/v1/user",
    "/v2/user",
    "https://api.example.com/v2/login",
]


def _leaky_fetch(method, url, headers=None, body=None):
    """200 everywhere except: v2 rejects the inert bogus token; JSON
    bodies on the sensitive endpoint."""
    if headers and headers.get("Authorization", "").startswith(
            "Bearer omegainertprobe") and "/v2/" in url:
        return 401, {}, b'{"error":"unauthorized"}'
    if "/api/user/profile" in url:
        return 200, {}, b'{"user":"alice","email":"a@x.test"}'
    return 200, {}, b"ok"


def _clean_fetch(method, url, headers=None, body=None):
    return 401, {}, b'{"error":"unauthorized"}'


def test_collect_endpoints_dedup_and_bound():
    pi = {"paths": ["/api/login", "/api/login", "api/x"],
          "apk_endpoints": ["/v2/user"]}
    eps = collect_endpoints(pi)
    assert "/api/login" in eps and "/api/x" in eps and "/v2/user" in eps
    assert len(eps) == len(set(eps))
    assert len(eps) <= MAX_ENDPOINTS
    assert collect_endpoints(None) == []
    assert collect_endpoints({}) == []


def test_skip_when_no_endpoints():
    assert run_mobapi("http://127.0.0.1:1", _clean_fetch,
                      path_info={}) == []
    assert run_mobapi("http://127.0.0.1:1", _clean_fetch,
                      path_info=None) == []


def test_missing_rate_limiting_on_login():
    found = run_mobapi("http://127.0.0.1:1", _leaky_fetch,
                       path_info={"paths": ["/api/login"]})
    rl = [f for f in found if "rate limiting" in f["title"]]
    assert rl and rl[0]["severity"] == "medium"
    assert "statuses=[200, 200, 200]" in rl[0]["evidence"]


def test_rate_limited_endpoint_is_silent():
    calls = {"n": 0}

    def throttled(method, url, headers=None, body=None):
        calls["n"] += 1
        if calls["n"] % 3 == 0:
            return 429, {}, b"slow down"
        return 200, {}, b"ok"

    found = run_mobapi("http://127.0.0.1:1", throttled,
                       path_info={"paths": ["/api/login"]})
    assert [f for f in found if "rate limiting" in f["title"]] == []


def test_tls_downgrade_accepted():
    found = run_mobapi("http://127.0.0.1:1", _leaky_fetch,
                       path_info={"paths":
                                  ["https://api.example.com/v2/login"]})
    dg = [f for f in found if "TLS downgrade" in f["title"]]
    assert dg and dg[0]["severity"] == "medium"
    assert dg[0]["location"].startswith("http://")


def test_https_only_endpoint_downgrade_on_https_base():
    found = run_mobapi("https://api.example.com", _leaky_fetch,
                       path_info={"paths": ["/v2/login"]})
    dg = [f for f in found if "TLS downgrade" in f["title"]]
    assert dg


def test_versioning_exposure_info():
    found = run_mobapi("http://127.0.0.1:1", _leaky_fetch,
                       path_info={"paths": ["/v1/user", "/v2/user"]})
    ver = [f for f in found if "v1 and v2" in f["title"]]
    assert ver and ver[0]["severity"] == "info"
    assert "token_v1=200" in ver[0]["evidence"]
    assert "token_v2=401" in ver[0]["evidence"]


def test_unauthenticated_sensitive_endpoint():
    found = run_mobapi("http://127.0.0.1:1", _leaky_fetch,
                       path_info={"paths": ["/api/user/profile"]})
    un = [f for f in found if "Unauthenticated sensitive" in f["title"]]
    assert un and un[0]["severity"] == "medium"
    assert un[0]["source"] == "omega-mobapi"


def test_clean_backend_no_findings():
    found = run_mobapi("http://127.0.0.1:1", _clean_fetch,
                       path_info={"paths": LEAKY_ENDPOINTS})
    assert found == []


def test_never_raises_on_dead_or_exploding_fetch():
    assert run_mobapi("http://127.0.0.1:1",
                      lambda *a, **k: (_ for _ in ()).throw(
                          RuntimeError("boom")),
                      path_info={"paths": LEAKY_ENDPOINTS}) == []
    assert run_mobapi("not a url", _clean_fetch,
                      path_info={"paths": ["/api/login"]}) == []


def test_suites_registered_in_fusion():
    from omega.scanning.fusion import SUITES
    names = [s[0] for s in SUITES]
    assert "mobdeep" in names and "mobapi" in names
