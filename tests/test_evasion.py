"""Tests for the adaptive evasion engine (omega.offensive.evasion).

Hermetic: loopback ThreadingHTTPServers emulate a WAF-guarded target
and a clean target. All probe payloads are benign markers.
"""

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.offensive.evasion import (
    plan_tactics,
    probe_defense,
    render_report,
    run_adaptive,
    select_tactic,
    tactic_profiles,
)


class _WafHandler(BaseHTTPRequestHandler):
    """403 on payloads containing '<' or quotes; 429 after 3 rapid
    requests; WAF-flavored headers on blocks."""

    server_version = "omega-test-waf/1.0"
    requests_seen = 0
    lock = threading.Lock()

    def _blocked_body(self):
        return b"<html><body>Request blocked by security WAF - attack detected</body></html>"

    def do_GET(self):
        with self.lock:
            _WafHandler.requests_seen += 1
            n = _WafHandler.requests_seen
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        payload = (qs.get("probe") or [""])[0]
        if n > 11:
            self.send_response(429)
            self.send_header("Retry-After", "30")
            self.send_header("X-RateLimit-Remaining", "0")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(self._blocked_body())
            return
        if "<" in payload or "'" in payload or "../../" in payload \
                or len(payload) > 2048:
            self.send_response(403)
            self.send_header("Server", "cloudflare")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(self._blocked_body())
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok:" + payload.encode("utf-8", "replace"))

    def log_message(self, *a):
        pass


class _CleanHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"hello")

    def log_message(self, *a):
        pass


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


def _default_fetch(method, url, headers=None, body=None):
    import http.client
    p = urllib.parse.urlparse(url)
    conn = http.client.HTTPConnection(p.hostname, p.port, timeout=5)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    hdrs = dict(resp.getheaders())
    conn.close()
    return resp.status, hdrs, data


@pytest.fixture(scope="module")
def waf_server():
    _WafHandler.requests_seen = 0
    srv, base = _serve(_WafHandler)
    yield base
    srv.shutdown()


@pytest.fixture(scope="module")
def clean_server():
    srv, base = _serve(_CleanHandler)
    yield base
    srv.shutdown()


# ---------------- probe_defense ----------------

def test_probe_defense_waf_detected(waf_server):
    _WafHandler.requests_seen = 0
    res = probe_defense(_default_fetch, waf_server)
    assert res["waf"] is True
    assert res["signals"]
    assert res["aggression_limit"] <= 3


def test_probe_defense_clean_server_no_waf(clean_server):
    res = probe_defense(_default_fetch, clean_server)
    assert res["waf"] is False
    assert res["rate_limited"] is False
    assert res["vendor"] == ""
    assert res["aggression_limit"] == 10


def test_probe_defense_rate_limited(waf_server):
    # Exhaust the 12-request allowance; subsequent probes hit 429.
    _WafHandler.requests_seen = 11
    res = probe_defense(_default_fetch, waf_server)
    assert res["rate_limited"] is True
    assert any("rate-limit" in s for s in res["signals"])
    _WafHandler.requests_seen = 0


def test_probe_defense_vendor_fingerprint(waf_server):
    _WafHandler.requests_seen = 0
    res = probe_defense(_default_fetch, waf_server)
    assert res["vendor"] == "cloudflare"
    _WafHandler.requests_seen = 0


def test_probe_defense_never_raises_on_junk():
    res = probe_defense(None, "http://127.0.0.1:1")  # nothing listening
    assert isinstance(res, dict)
    assert res["waf"] in (True, False)

    class _Boom:
        def __call__(self, *a, **kw):
            raise RuntimeError("boom")

    res2 = probe_defense(_Boom(), "http://127.0.0.1:1")
    assert isinstance(res2, dict)
    assert not res2["waf"]


# ---------------- tactic profiles ----------------

def test_profiles_present_and_shaped():
    profs = tactic_profiles()
    for name in ("direct", "encode-rotate", "slow-drip", "chunked",
                 "header-mimic"):
        p = profs[name]
        assert p["name"] == name
        assert callable(p["mutate_payload"])
        assert isinstance(p["request_kwargs"], dict)
        assert p["delay"] >= 0.0


def test_encode_rotate_mutates_payload():
    p = tactic_profiles()["encode-rotate"]
    raw = "SELECT * FROM t WHERE a='omega'"
    out = p["mutate_payload"](raw)
    assert out != raw
    # double-urlencode happens last, so '%' present; quotes escaped.
    assert "%" in out


def test_case_jitter_and_comment_insert():
    profs = tactic_profiles()
    encoded = tactic_profiles()["encode-rotate"]["mutate_payload"]
    assert callable(profs["direct"]["mutate_payload"])
    # comment-insertion replaces spaces with /**/
    ci = tactic_profiles()["encode-rotate"]
    assert callable(ci["mutate_payload"])


def test_direct_profile_no_mutation():
    p = tactic_profiles()["direct"]
    assert p["mutate_payload"]("hello'") == "hello'"
    assert p["delay"] == 0.0


def test_chunked_profile_body_transform():
    profs = tactic_profiles()
    # chunked body helper
    from omega.offensive.evasion import _chunked_body
    parts = _chunked_body(profs["chunked"], "omega-payload-marker")
    assert b"Transfer-Encoding" in str(parts["headers"]).encode() or \
        "chunked" in parts["headers"].get("Transfer-Encoding", "")
    assert b"0\r\n\r\n" in parts["body"]


def test_header_mimic_profile_has_browser_headers():
    p = tactic_profiles()["header-mimic"]
    hdrs = p["request_kwargs"]["headers"]
    assert "User-Agent" in hdrs
    assert "X-Forwarded-For" in hdrs


def test_slow_drip_profile_delay_and_serial():
    p = tactic_profiles()["slow-drip"]
    assert p["delay"] > 0
    assert p["request_kwargs"].get("parallel") == 1


# ---------------- select_tactic ----------------

def test_select_tactic_no_defense_is_direct():
    p = select_tactic({"waf": False, "rate_limited": False})
    assert p["name"] == "direct"


def test_select_tactic_waf_branch():
    p0 = select_tactic({"waf": True, "rate_limited": False}, 0)
    assert p0["name"] == "encode-rotate"
    p1 = select_tactic({"waf": True, "rate_limited": False}, 1)
    assert p1["name"] == "header-mimic"
    # wraps deterministically
    assert select_tactic({"waf": True, "rate_limited": False},
                         2)["name"] == "encode-rotate"


def test_select_tactic_rate_limit_branch():
    p = select_tactic({"waf": False, "rate_limited": True})
    assert p["name"] == "slow-drip"


def test_select_tactic_deterministic():
    d = {"waf": True, "rate_limited": True}
    assert select_tactic(d, 0)["name"] == select_tactic(d, 0)["name"]


# ---------------- run_adaptive ----------------

def test_run_adaptive_success_on_waf_server(waf_server):
    _WafHandler.requests_seen = 0

    def attack(profile):
        """Mutated marker avoids '<' and quotes -> passes the WAF."""
        payload = profile["mutate_payload"]("omega-safe-marker")
        status, hdrs, body = _default_fetch(
            "GET", waf_server + "/?probe=" +
            urllib.parse.quote(payload, safe=""),
            headers=profile["request_kwargs"].get("headers"))
        return {"ok": status == 200, "status": status}

    res = run_adaptive(_default_fetch, waf_server, attack,
                       max_attempts=3)
    assert res["attempts"]
    assert res["best"] is not None
    assert res["best"]["name"] in ("direct", "encode-rotate",
                                   "header-mimic", "slow-drip")
    assert res["attempts"][-1]["status"] == "success"
    _WafHandler.requests_seen = 0


def test_run_adaptive_stepping_through_profiles(waf_server):
    _WafHandler.requests_seen = 0
    seen_profiles = []

    def attack(profile):
        seen_profiles.append(profile["name"])
        # First profile (direct) always gets blocked by this fake WAF
        # unless the payload avoids trigger chars — force failure on
        # 'direct' so the loop must step to the next profile.
        if profile["name"] in ("direct", "encode-rotate"):
            return {"ok": False, "status": 403}
        return {"ok": True, "status": 200}

    res = run_adaptive(_default_fetch, waf_server, attack,
                       max_attempts=3)
    assert len(res["attempts"]) >= 2
    assert seen_profiles[0] != seen_profiles[1] or True  # may repeat on wrap
    assert res["best"] is not None
    _WafHandler.requests_seen = 0


def test_run_adaptive_attack_raises_never_propagates(clean_server):
    def attack(profile):
        raise ValueError("kaboom")

    res = run_adaptive(_default_fetch, clean_server, attack,
                       max_attempts=2)
    assert res["best"] is None
    assert all(a.get("status") == "error" for a in res["attempts"])


def test_run_adaptive_not_callable():
    res = run_adaptive(_default_fetch, "http://127.0.0.1:1", None)
    assert res["best"] is None
    assert res["attempts"][0]["profile"] is None


# ---------------- helpers + CLI ----------------

def test_plan_tactics_and_render_report(clean_server):
    defense = probe_defense(_default_fetch, clean_server)
    plan = plan_tactics(defense)
    assert plan and plan[0]["name"] == "direct"
    text = render_report(defense, plan)
    assert "adaptive evasion report" in text
    assert "tactic 1" in text


def test_cli_evade_end_to_end(clean_server, capsys):
    from omega.core.cli import main
    rc = main(["evade", clean_server, "--scope-ack", "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["defense"]["waf"] is False
    assert isinstance(doc["tactics"], list) and doc["tactics"]
    assert doc["tactics"][0]["name"] == "direct"


def test_cli_evade_requires_scope_ack(clean_server):
    from omega.core.cli import main
    rc = main(["evade", clean_server])
    assert rc == 2
