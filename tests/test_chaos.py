"""Hermetic tests for omega/chaos.py — behavioral mutation fuzzer.

Covers: mutator table audit (>=25 pure transforms), differential
anomaly detection against a fixture ThreadingHTTPServer (error page on
mutation -> candidate + signature finding; timing via a stub delay),
SSTI evidence path (template marker evaluated to 49 -> candidate HIGH
'SSTI-evidence'), ResponseCluster soft-404 wildcard suppression (plus
distinct-404 kept), request budget cap, allowlist gate, never-raises,
brain capability wiring ('chaos.fuzz') and the fusion SUITES entry.
"""

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega import brain as br
from omega.chaos import (
    MUTATORS,
    ResponseCluster,
    cluster_signature,
    filter_wildcard_paths,
    fuzz_params,
    is_wildcard_noise,
    run_chaos,
)


# ------------------------------------------------------------- fixtures

@pytest.fixture
def http_server():
    """Start a hermetic ThreadingHTTPServer; yields (base_url, state)."""
    state = {"hits": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            vals = [v[0] for v in q.values()]
            state["hits"].append(self.path)
            body = b"baseline ok page content"
            status = 200
            joined = " ".join(vals)
            if any(tok in joined for tok in (
                    "99999999999999999999",
                    "1.7976931348623157",
                    "2147483647")):
                status = 500
                body = (b"Fatal error: uncaught Error: Traceback "
                        b"(most recent call last) sqlstate")
            elif "7*7" in joined:
                # template marker evaluated: result 49, raw marker gone
                body = b"rendered page value=49 done"
            elif any(v == "A" * 1024 for v in vals):
                body = b"x" * 4096
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d" % srv.server_address[1], state
    srv.shutdown()
    srv.server_close()


# --------------------------------------------------------- mutator audit

_BANNED = {"system", "popen", "socket", "urlopen", "urllib.request",
           "request", "execute", "eval", "exec", "subprocess", "os"}


def test_mutators_at_least_25_and_pure():
    assert len(MUTATORS) >= 25
    seen = set()
    for name, fn in MUTATORS:
        assert name not in seen, "duplicate mutator %s" % name
        seen.add(name)
        out1 = fn("probe-v1")
        out2 = fn("probe-v1")
        assert isinstance(out1, str), name
        assert out1 == out2, "mutator %s is not deterministic" % name
        # no execution/network machinery referenced by the transform
        banned = {n for n in fn.__code__.co_names if n in _BANNED}
        assert not banned, "mutator %s references %s" % (name, banned)
    # all pure transforms: no side-effect machinery anywhere
    assert all(callable(f) for _n, f in MUTATORS)


def test_mutators_never_produce_executable_payloads():
    """Evidence-only: template/format markers are inert strings."""
    for name, fn in MUTATORS:
        out = fn("index")
        assert "{{7*7}}" not in out or name.startswith("template-"), name


# ---------------------------------------------------- anomaly detection

def test_error_page_on_mutation_yields_candidate(http_server):
    base, _state = http_server
    findings = fuzz_params(base, ["id"], budget=60)
    sig = [f for f in findings
           if f["evidence"].get("kind") == "error-signature"]
    assert sig, "expected an error-signature finding"
    f = sig[0]
    assert f["verification"] == "candidate"
    assert f["source"] == "omega-chaos/fuzz_params"


def test_length_delta_path(http_server):
    base, _state = http_server
    findings = fuzz_params(base, ["q"], budget=60)
    kinds = {f["evidence"].get("kind") for f in findings}
    assert "body-length" in kinds


def test_timing_anomaly_with_stub_clock(http_server, monkeypatch):
    base, _state = http_server
    # stub monotonic: baseline latency 0.05s, mutations 0.5s (> 3x)
    ticks = {"n": 0}

    def fake_monotonic():
        ticks["n"] += 1
        return ticks["n"] * (0.05 if ticks["n"] <= 2 else 0.5)

    import omega.chaos as chaos
    monkeypatch.setattr(chaos.time, "monotonic", fake_monotonic)
    findings = fuzz_params(base, ["id"], budget=60)
    timing = [f for f in findings
              if f["evidence"].get("kind") == "timing"]
    assert timing, "expected a timing anomaly finding"
    assert timing[0]["evidence"]["elapsed_s"] > 0.15


# --------------------------------------------------------- SSTI evidence

def test_ssti_evidence_candidate_high(http_server):
    base, _state = http_server
    findings = fuzz_params(base, ["template"], budget=60)
    ssti = [f for f in findings if "SSTI-evidence" in f["title"]]
    assert ssti, "expected the SSTI-evidence finding"
    f = ssti[0]
    assert f["severity"] == "high"
    assert f["verification"] == "candidate"  # never auto-confirmed
    assert f["evidence"].get("evaluated_result") == "49"


# ------------------------------------------------------ ResponseCluster

def test_cluster_signature_deterministic():
    assert cluster_signature(b"abc") == cluster_signature(b"abc")
    assert cluster_signature(b"abc") != cluster_signature(b"abd")


def test_wildcard_noise_suppression_and_distinct_kept():
    noise = b"<html>404 not found page default</html>"
    distinct = b"<html>real admin login page</html>"
    samples = [noise, noise, noise, noise, distinct]
    assert is_wildcard_noise(cluster_signature(noise), samples)
    assert not is_wildcard_noise(cluster_signature(distinct), samples)
    rc = ResponseCluster()
    for i in range(4):
        assert rc.add(404, noise)
    sig_d = rc.add(404, distinct)
    assert len(rc) == 5
    assert rc.is_noise(rc.dominant())
    assert not rc.is_noise(sig_d)
    assert rc.summary()[0]["count"] == 4


def test_filter_wildcard_paths_with_server(http_server):
    base, _state = http_server

    class Soft404Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            body = (b"admin panel real page"
                    if self.path == "/admin" else
                    b"generic soft-404 body")
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    import socket
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Soft404Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base2 = "http://127.0.0.1:%d" % srv.server_address[1]
        kept, suppressed = filter_wildcard_paths(
            base2, ["/admin", "/a", "/b", "/c", "/d"])
        assert kept == ["/admin"]
        assert len(suppressed) == 4
    finally:
        srv.shutdown()
        srv.server_close()


# ------------------------------------------------ budget / allowlist

def test_budget_cap_counts_requests(http_server):
    base, state = http_server
    findings = fuzz_params(base, ["id"], budget=3)
    # 1 baseline + 2 mutations = 3 total; nothing beyond
    hits_before = len(state["hits"])
    assert hits_before <= 3
    fuzz_params(base, ["id"], budget=3)
    assert len(state["hits"]) - hits_before <= 3


def test_fuzz_params_counts_with_custom_fetch():
    sent = {"n": 0}

    def fetch(_m, _url, _h=None):
        sent["n"] += 1
        return 200, {}, b"ok body"

    fuzz_params("http://stub.invalid", ["id", "q"], fetch=fetch,
                budget=5)
    assert sent["n"] <= 5


def test_run_chaos_allowlist_gate(http_server):
    base, _state = http_server
    out = run_chaos(base, allowlist=["example.invalid"])
    assert out["findings"] == []
    assert "not in allowlist" in out["skipped"]["__all__"]
    # and allowed target runs
    out2 = run_chaos(base, allowlist=["127.0.0.1"], budget=8)
    assert isinstance(out2, dict) and "findings" in out2


def test_run_chaos_never_raises():
    out = run_chaos("http://127.0.0.1:1/", allowlist=["127.0.0.1"],
                    budget=4)
    assert isinstance(out, dict)
    assert "findings" in out and "skipped" in out
    # garbage target: still no exception
    out2 = run_chaos("not a url \x01", allowlist=None, budget=4)
    assert isinstance(out2, dict)


# ------------------------------------------------------- brain / fusion

def test_brain_chaos_fuzz_capability():
    cap = br.DEFAULT_REGISTRY.get("chaos.fuzz")
    assert cap is not None
    assert cap.cost == 5
    assert cap.risk == "active"
    assert cap.requires == ("has_web",)
    assert callable(cap.fn)
    # eligibility: requires has_web
    assert not cap.eligible({"has_web": False})
    assert cap.eligible({"has_web": True})
    # duplicate registration is rejected by the registry
    with pytest.raises(ValueError):
        br.DEFAULT_REGISTRY.register(cap)


def test_brain_chaos_fuzz_fn_contained():
    from omega.brain import BrainState
    cap = br.DEFAULT_REGISTRY.get("chaos.fuzz")
    state = BrainState("http://127.0.0.1:1/")
    state.surface["urls"] = ["http://127.0.0.1:1/"]
    out = cap.fn(state)
    assert isinstance(out, dict)  # contained, never raises


def test_fusion_python_chaos_suite():
    from omega.fusion import SUITES
    names = {(n, lang) for n, lang, _r in SUITES}
    assert ("python-chaos", "python") in names
