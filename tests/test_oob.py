"""Hermetic tests for the OOB callback server and blind-vuln checks.

Everything runs against a real OOBCallbackServer on 127.0.0.1 with an
ephemeral port — no external network.
"""

import json
import os
import threading
import urllib.parse
import urllib.request

import pytest

from omega.oob import (
    DEFAULT_OOB_HOST,
    HIT_LOG_CAP,
    OOBCallbackServer,
    _token_from_path,
)
from omega.oobchecks import (
    blind_rce_probe,
    blind_ssrf_confirm,
    blind_xss_canary,
    run_oobchecks,
    webhook_ssrf,
)

TARGET = "http://target.example"


# ---------------------------------------------------------------- fixtures

@pytest.fixture()
def server():
    with OOBCallbackServer() as srv:
        yield srv


def _callback_fetch(base_url="http://target.example"):
    """Fetch stub that 'honors the param': whenever a request contains a
    token URL, the (simulated) target performs a REAL HTTP GET against
    that URL — producing a genuine callback through the OOB server.
    Returns (status, headers, body) like omega.probes.default_fetch.
    """

    def fetch(method, url, headers=None):
        # If any param value looks like our OOB base URL, have the
        # "target" really fetch it (real HTTP GET -> recorded hit).
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        oob_base = None
        for values in qs.values():
            for v in values:
                if v.startswith("http://127.0.0.1"):
                    oob_base = v
        if oob_base:
            try:
                with urllib.request.urlopen(oob_base, timeout=5) as resp:
                    resp.read()
            except Exception:
                pass
        return 200, {}, b"ok"

    return fetch


# ------------------------------------------------------------- oob server

class TestOOBCallbackServer:
    def test_default_bind_is_loopback_ephemeral(self, server):
        assert server.host == DEFAULT_OOB_HOST == "127.0.0.1"
        assert server.port != 0  # ephemeral port resolved at start
        assert server.base_url().startswith("http://127.0.0.1:")

    def test_hit_recording_via_real_http_get(self, server):
        url = server.token_url()
        with urllib.request.urlopen(url, timeout=5) as resp:
            payload = json.loads(resp.read())
        assert payload == {"ok": True}
        hits = server.hits()
        assert len(hits) == 1
        hit = hits[0]
        assert hit["method"] == "GET"
        assert hit["token"] == url.rsplit("/", 1)[1]
        assert hit["remote"] == "127.0.0.1"
        assert hit["path"].startswith("/" + hit["token"])
        assert "User-Agent" in hit["headers"]
        assert isinstance(hit["ts"], float)
        assert len(hit["body_sha256"]) == 64

    def test_hit_recording_post(self, server):
        token = server.new_token()
        req = urllib.request.Request(
            server.base_url() + token, data=b"payload",
            method="POST")
        urllib.request.urlopen(req, timeout=5).read()
        hit = server.wait_for_hit(token, timeout_s=2.0)
        assert hit["method"] == "POST"
        import hashlib
        assert hit["body_sha256"] == hashlib.sha256(b"payload").hexdigest()

    def test_unique_tokens(self, server):
        tokens = {server.new_token() for _ in range(50)}
        assert len(tokens) == 50
        assert all(len(t) == 32 for t in tokens)
        assert all(all(c in "0123456789abcdef" for c in t) for t in tokens)

    def test_token_url_uses_given_token(self, server):
        assert server.token_url("a" * 32).endswith("/" + "a" * 32)

    def test_token_from_path(self):
        assert _token_from_path("/%s?x=1" % ("b" * 32)) == "b" * 32
        assert _token_from_path("/not-a-token") is None
        assert _token_from_path("/") is None

    def test_wait_for_hit_timeout_returns_none(self, server):
        token = server.new_token()
        assert server.wait_for_hit(token, timeout_s=0.2) is None

    def test_wait_for_hit_after_late_callback(self, server):
        token = server.new_token()
        url = server.base_url() + token

        def late():
            import time
            time.sleep(0.1)
            urllib.request.urlopen(url, timeout=5).read()

        threading.Thread(target=late, daemon=True).start()
        hit = server.wait_for_hit(token, timeout_s=3.0)
        assert hit is not None and hit["token"] == token

    def test_token_isolation(self, server):
        tok_hit, tok_quiet = server.token_url(), server.token_url()
        urllib.request.urlopen(tok_hit, timeout=5).read()
        assert server.wait_for_hit(tok_quiet.rsplit("/", 1)[1],
                                   timeout_s=0.2) is None
        assert len(server.hits(tok_hit.rsplit("/", 1)[1])) == 1

    def test_hit_log_cap(self, server):
        server._record("GET", "/x", {}, b"", "127.0.0.1")
        for _ in range(HIT_LOG_CAP + 25):
            server._record("GET", "/y", {}, b"", "127.0.0.1")
        assert len(server.hits()) == HIT_LOG_CAP

    def test_stop_is_idempotent_and_reentrant(self, server):
        server.stop()
        server.stop()
        assert not server.running


# ----------------------------------------------------------------- checks

class TestBlindSSRFConfirm:
    def test_confirmed_on_exact_callback(self, server):
        fetch = _callback_fetch()
        findings = blind_ssrf_confirm(TARGET, server, fetch=fetch,
                                      wait_s=3.0)
        assert len(findings) == 1
        f = findings[0]
        assert f["verification"] == "confirmed"
        assert f["severity"] == "high"
        assert f["source"] == "omega-oob/blind_ssrf_confirm"
        # The exact planted token got a REAL hit.
        assert any(h["token"] in f["location"] for h in server.hits())

    def test_no_hit_is_candidate_not_confirmed(self, server):
        findings = blind_ssrf_confirm(TARGET, server,
                                      fetch=lambda m, u, h=None: (200, {}, b""),
                                      wait_s=0.3)
        assert len(findings) == 1
        f = findings[0]
        assert f["verification"] == "candidate"
        assert f["severity"] == "low"
        assert server.hits() == []

    def test_path_info_params_honored(self, server):
        seen = []

        def fetch(method, url, headers=None):
            seen.append(dict(urllib.parse.parse_qs(
                urllib.parse.urlparse(url).query)))
            return 200, {}, b""

        blind_ssrf_confirm(TARGET, server,
                           path_info={"params": ["feed_url"]},
                           fetch=fetch, wait_s=0.1)
        assert "feed_url" in seen[0]

    def test_token_isolation_across_params(self, server):
        """A hit on one token must not confirm another param."""
        calls = {"n": 0}

        def fetch(method, url, headers=None):
            calls["n"] += 1
            if calls["n"] == 1:  # only the first param's token callbacks
                tok = urllib.parse.unquote(
                    urllib.parse.urlparse(url).query.split("=", 1)[1])
                urllib.request.urlopen(tok, timeout=5).read()
            return 200, {}, b""

        findings = blind_ssrf_confirm(TARGET, server, fetch=fetch,
                                      wait_s=0.5)
        assert findings[0]["verification"] == "confirmed"
        assert findings[0]["evidence"]["param"] == "url"  # first param only


class TestBlindXSSCanary:
    def test_reflection_yields_candidate_with_script_canary(self, server):
        def fetch(method, url, headers=None):
            qs = urllib.parse.parse_qs(
                urllib.parse.urlparse(url).query, keep_blank_values=True)
            if any("script src=" in v for values in qs.values()
                   for v in values):
                # server-side browser emulation: really fetch the src
                tok_url = list(qs.values())[0][0]
                import re
                m = re.search(r'src="([^"]+)"', tok_url)
                urllib.request.urlopen(m.group(1), timeout=5).read()
                body = tok_url.encode()
            else:
                body = ("echo: " + list(qs.values())[0][0]).encode()
            return 200, {}, body

        findings = blind_xss_canary(TARGET, server, fetch=fetch, wait_s=3.0)
        assert len(findings) == 1
        f = findings[0]
        assert f["verification"] == "candidate"  # evidence-class only
        assert f["severity"] == "low"
        assert f["evidence"]["callback"] is True
        assert "script src=" in urllib.parse.unquote_plus(f["location"])

    def test_no_reflection_no_finding(self, server):
        findings = blind_xss_canary(TARGET, server,
                                    fetch=lambda m, u, h=None: (200, {}, b"no"),
                                    wait_s=0.1)
        assert findings == []
        assert server.hits() == []


class TestBlindRCEProbe:
    def test_callback_only_candidate_high(self, server):
        def fetch(method, url, headers=None):
            for v in (headers or {}).values():
                if v.startswith("http://127.0.0.1"):
                    urllib.request.urlopen(v, timeout=5).read()
            return 200, {}, b"ok"

        findings = blind_rce_probe(TARGET, server, fetch=fetch, wait_s=3.0)
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "high"
        assert f["verification"] == "candidate"  # never confirmed
        assert "callback observed" in f["title"]
        assert "manual verification" in f["verification_note"]
        assert f["evidence"]["note"] == ("callback observed, further "
                                         "manual verification required")

    def test_no_callback_no_finding(self, server):
        findings = blind_rce_probe(TARGET, server,
                                   fetch=lambda m, u, h=None: (200, {}, b""),
                                   wait_s=0.1)
        assert findings == []


class TestWebhookSSRF:
    def test_confirmed_on_exact_callback(self, server):
        def fetch(method, url, headers=None):
            val = urllib.parse.urlparse(url).query.split("=", 1)[1]
            urllib.request.urlopen(
                urllib.parse.unquote_plus(val), timeout=5).read()
            return 200, {}, b"ok"

        findings = webhook_ssrf(TARGET, server, fetch=fetch, wait_s=3.0)
        assert findings[0]["verification"] == "confirmed"
        assert findings[0]["severity"] == "high"
        assert "webhook" in findings[0]["title"].lower()

    def test_no_hit_is_candidate(self, server):
        findings = webhook_ssrf(TARGET, server,
                                fetch=lambda m, u, h=None: (200, {}, b""),
                                wait_s=0.1)
        assert findings[0]["verification"] == "candidate"


# ---------------------------------------------------------- run_oobchecks

class TestRunOOBChecks:
    def test_no_server_all_skipped(self):
        out = run_oobchecks(TARGET, server=None)
        assert out["ran"] == []
        assert out["findings"] == []
        assert len(out["skipped"]) == 4
        assert all(v == "OOB server not started"
                   for v in out["skipped"].values())
        assert out["hits"] == []

    def test_stopped_server_counts_as_not_started(self, server):
        server.stop()
        out = run_oobchecks(TARGET, server=server)
        assert all(v == "OOB server not started"
                   for v in out["skipped"].values())

    def test_full_run_never_raises(self, server):
        out = run_oobchecks(TARGET, server=server, fetch=_callback_fetch(),
                            wait_s=0.2)
        assert set(out) == {"findings", "ran", "skipped", "hits"}
        assert sorted(out["ran"]) == ["blind_rce_probe",
                                      "blind_ssrf_confirm",
                                      "blind_xss_canary", "webhook_ssrf"]
        assert isinstance(out["hits"], list)
        # the stub made real callbacks: at least one recorded hit
        assert out["hits"]

    def test_budget_exhaustion(self, server):
        out = run_oobchecks(TARGET, server=server, budget=2, wait_s=0.05)
        assert len(out["ran"]) == 2
        assert len(out["skipped"]) == 2
        assert all(v == "budget exhausted" for v in out["skipped"].values())

    def test_allowlist_blocks(self, server):
        out = run_oobchecks(TARGET, server=server, allowlist=["other.com"])
        assert out["skipped"]["__all__"]
        assert out["ran"] == []

    def test_never_raises_on_broken_fetch(self, server):
        def boom(*a, **k):
            raise RuntimeError("network down")

        out = run_oobchecks(TARGET, server=server, fetch=boom, wait_s=0.05)
        assert "findings" in out  # skipped/ran, no exception


# ------------------------------------------------------------------ brain

class TestBrainOOBBlindScan:
    def _state(self):
        from omega.brain import BrainState
        st = BrainState(TARGET)
        st.surface["urls"] = [TARGET]
        return st

    def test_capability_metadata(self):
        from omega.brain import default_registry
        cap = default_registry().get("oob.blind_scan")
        assert cap is not None
        assert cap.cost == 4
        assert cap.risk == "active"
        assert cap.requires == ("has_web",)

    def test_duplicate_registration_rejected(self):
        import pytest
        from omega.brain import Capability, CapabilityRegistry, \
            _oob_blind_scan_fn
        reg = CapabilityRegistry()
        reg.register(Capability("oob.blind_scan", "enum",
                                _oob_blind_scan_fn, cost=4, risk="active"))
        with pytest.raises(ValueError):
            reg.register(Capability("oob.blind_scan", "enum",
                                    _oob_blind_scan_fn, cost=4,
                                    risk="active"))

    def test_eligibility(self):
        from omega.brain import default_registry
        cap = default_registry().get("oob.blind_scan")
        assert not cap.eligible({"has_web": False})
        assert cap.eligible({"has_web": True}, budget_remaining=4)
        assert not cap.eligible({"has_web": True}, budget_remaining=3)

    def test_run_starts_and_cleans_up_server(self, monkeypatch):
        from omega import oobchecks as oob_mod
        from omega.brain import _oob_blind_scan_fn
        used = {}

        def fake_run(target, server=None, **kw):
            used["target"] = target
            used["running"] = server.running
            return {"findings": [], "ran": ["blind_ssrf_confirm"],
                    "skipped": {}, "hits": []}

        monkeypatch.setattr(oob_mod, "run_oobchecks", fake_run)
        result = _oob_blind_scan_fn(self._state())
        # server was started, used, and stopped
        assert _oob_blind_scan_fn._server is None
        assert used["running"] is True
        assert used["target"] == TARGET
        assert "oobchecks ran:" in result["note"]
        assert result["findings"] == []

    def test_importerror_contained(self, monkeypatch):
        import builtins
        from omega.brain import _oob_blind_scan_fn
        real_import = builtins.__import__

        def fake_import(name, *a, **k):
            if name.startswith("omega.oob"):
                raise ImportError("nope")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        result = _oob_blind_scan_fn(self._state())
        assert "skipped gracefully" in result["note"]

    def test_dup_guard_reuses_running_server(self, monkeypatch):
        from omega import oobchecks as oob_mod
        from omega.brain import _oob_blind_scan_fn
        from omega.oob import OOBCallbackServer
        monkeypatch.setattr(oob_mod, "run_oobchecks",
                            lambda target, server=None, **kw:
                            {"findings": [], "ran": [], "skipped": {},
                             "hits": []})
        holder = OOBCallbackServer().start()
        _oob_blind_scan_fn._server = holder
        try:
            _oob_blind_scan_fn(self._state())
            # still the same server: the capability did not stop it
            assert _oob_blind_scan_fn._server is holder
            assert holder.running
        finally:
            holder.stop()
            _oob_blind_scan_fn._server = None

    def test_cleanup_on_check_exception(self, monkeypatch):
        from omega import oobchecks
        from omega.brain import _oob_blind_scan_fn

        def boom(target, server, **kw):
            raise RuntimeError("boom")

        monkeypatch.setattr(oobchecks, "run_oobchecks", boom)
        with pytest.raises(RuntimeError):
            _oob_blind_scan_fn(self._state())
        assert _oob_blind_scan_fn._server is None  # finally stopped it
        assert OOBCallbackServer()


# -------------------------------------------------------------------- CLI

class TestCliOOBFlag:
    def _args(self, argv):
        import sys
        from omega import cli
        # parse with a throwaway parser mirroring main()'s flags
        import argparse
        p = argparse.ArgumentParser(prog="omega")
        sub = p.add_subparsers(dest="command")
        for name in ("engage", "brain"):
            sp = sub.add_parser(name)
            sp.add_argument("target")
            sp.add_argument("--mode", default="auto")
            sp.add_argument("--scope-ack", action="store_true")
            sp.add_argument("--oob", action="store_true")
        return p.parse_args(argv)

    def test_flag_starts_server_and_exports_env(self):
        from omega import cli
        args = self._args(["brain", "http://t.example", "--oob"])
        srv = cli.start_oob_server(args)
        try:
            assert srv is not None and srv.running
            base = os.environ["OMEGA_OOB_BASE_URL"]
            assert base == srv.base_url()
            assert base.startswith("http://127.0.0.1:")
            # child suites can really call back against it
            urllib.request.urlopen(srv.token_url(), timeout=5).read()
            assert len(srv.hits()) == 1
        finally:
            cli._stop_oob_server(srv)
        assert "OMEGA_OOB_BASE_URL" not in os.environ

    def test_no_flag_no_server_no_env(self):
        from omega import cli
        args = self._args(["engage", "http://t.example"])
        assert cli.start_oob_server(args) is None
        assert "OMEGA_OOB_BASE_URL" not in os.environ

    def test_main_brain_oob_smoke(self, monkeypatch, capsys):
        """Full CLI path: --oob on brain starts/stops the server and
        keeps the normal exit code path."""
        from omega import brain as brain_mod
        from omega import cli

        monkeypatch.setattr(
            brain_mod.Brain, "run",
            lambda self, target, **kw: (brain_mod.BrainState(target),
                                        "# report"))
        code = cli.main(["brain", TARGET, "--scope-ack", "--oob",
                         "--max-steps", "1"])
        assert code == 0
        assert "OMEGA_OOB_BASE_URL" not in os.environ  # stopped in finally

    def test_main_brain_without_oob(self, monkeypatch):
        from omega import brain as brain_mod
        from omega import cli
        monkeypatch.setattr(
            brain_mod.Brain, "run",
            lambda self, target, **kw: (brain_mod.BrainState(target),
                                        "# report"))
        code = cli.main(["brain", TARGET, "--scope-ack", "--max-steps", "1"])
        assert code == 0

    def test_scope_gate_exit_code_unchanged(self):
        from omega import cli
        assert cli.main(["brain", TARGET, "--oob"]) == 2  # no --scope-ack
