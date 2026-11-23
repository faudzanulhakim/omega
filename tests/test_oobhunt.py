"""Hermetic tests for omega/scanning/oobhunt.py.

The target fixture "fetches" URL-shaped parameters server-side against
the local OOB collector (the vulnerable case) or never fetches (the
benign case). The fake OOB base-URL collector is a real local HTTP
server that records canary callbacks and exposes them via the
``_hits?token=`` status endpoint oobhunt polls in URL-only mode. No
internet anywhere.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen

import pytest

from omega.oob import OOBCallbackServer
from omega.oobhunt import (
    NO_CALLBACK_NOTE,
    NO_OOB_NOTE,
    OOBHUNT_SUSPECT_PARAMS,
    new_marker,
    run_oobhunt,
)


# ------------------------------------------------------------ fixtures

class _CollectorHandler(BaseHTTPRequestHandler):
    """Fake OOB collector: records canary hits, serves _hits JSON."""

    def do_GET(self):      # noqa: N802 (http.server API)
        path = self.path
        if path.startswith("/_hits"):
            q = parse_qs(urlsplit(path).query, keep_blank_values=True)
            token = (q.get("token") or [None])[0]
            hits = self.server.omega_hits
            if token:
                hits = [h for h in hits if h["token"] == token]
            payload = json.dumps(hits).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.server.omega_hits.append({
            "token": path.lstrip("/").split("?")[0].split("/")[0],
            "path": path,
            "method": "GET",
            "remote": self.client_address[0],
        })
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):   # silence
        pass


@pytest.fixture
def fake_oob_collector():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _CollectorHandler)
    srv.omega_hits = []
    t = threading.Thread(target=srv.serve_forever,
                         kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


class _TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):      # noqa: N802 (http.server API)
        q = {k: v[0] for k, v in
             parse_qs(urlsplit(self.path).query, keep_blank_values=True).items()}
        fetched = b""
        import re as _re
        from urllib.parse import unquote as _unquote
        m = _re.search(r"https?://[^\s\"'<>]+", _unquote(self.path))
        val = m.group(0) if m else ""
        if val and self.server.omega_fetches:
            try:
                with urlopen(val, timeout=2.0) as resp:
                    fetched = resp.read(4096)
            except Exception:
                fetched = b"fetch-error"
        body = b"page | " + fetched
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):   # silence
        pass


def _make_target(fetches):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    srv.omega_fetches = fetches
    t = threading.Thread(target=srv.serve_forever,
                         kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    return srv


@pytest.fixture
def vulnerable_target():
    srv = _make_target(True)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def benign_target():
    srv = _make_target(False)
    yield srv
    srv.shutdown()
    srv.server_close()


def _url(srv, path="/"):
    return "http://127.0.0.1:%d%s" % (srv.server_address[1], path)


# -------------------------------------------------------------- markers

def test_new_marker_shape_and_uniqueness():
    m1, m2 = new_marker(), new_marker()
    assert m1 != m2
    assert len(m1) == 32
    assert all(c in "0123456789abcdef" for c in m1)


def test_suspect_params_documented():
    assert "url" in OOBHUNT_SUSPECT_PARAMS
    assert "xml" in OOBHUNT_SUSPECT_PARAMS


# ---------------------------------------------------------- skip path

def test_skip_without_oob_base_url(monkeypatch, benign_target):
    monkeypatch.delenv("OMEGA_OOB_BASE_URL", raising=False)
    res = run_oobhunt(_url(benign_target), params=["url"])
    assert res["findings"] == []
    assert res["tokens"] == []
    assert res["note"] == NO_OOB_NOTE
    assert "oobhunt" in res["skipped"]
    assert NO_OOB_NOTE  # documented skip note constant


def test_skip_never_raises_on_dead_target(monkeypatch, fake_oob_collector):
    monkeypatch.setenv("OMEGA_OOB_BASE_URL", _url(fake_oob_collector))
    res = run_oobhunt("http://127.0.0.1:1/", params=["url"], timeout_s=0.2)
    # target dead -> no callback -> no finding, still no exception
    assert res["findings"] == []


# -------------------------------------------------- confirm path (URL)

def test_blind_ssrf_confirmed_via_env_base_url(monkeypatch,
                                               vulnerable_target,
                                               fake_oob_collector):
    monkeypatch.setenv("OMEGA_OOB_BASE_URL", _url(fake_oob_collector))
    res = run_oobhunt(_url(vulnerable_target), params=["url"],
                      timeout_s=3.0)
    assert res["ran"] == ["blind_ssrf_oob:url"]
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["severity"] == "high"
    assert f["verification"] == "confirmed"
    assert f["evidence"]["param"] == "url"
    marker = f["evidence"]["marker"]
    assert fake_oob_collector.omega_hits[0]["token"] == marker
    assert [t["marker"] for t in res["tokens"]] == [marker]


def test_blind_ssrf_confirmed_via_explicit_base_url(vulnerable_target,
                                                    fake_oob_collector):
    res = run_oobhunt(_url(vulnerable_target), params=["url"],
                      oob_base_url=_url(fake_oob_collector),
                      timeout_s=3.0)
    assert len(res["findings"]) == 1
    assert res["findings"][0]["verification"] == "confirmed"


def test_blind_ssrf_confirmed_via_server_handle(vulnerable_target):
    with OOBCallbackServer() as collector:
        res = run_oobhunt(_url(vulnerable_target), params=["url"],
                          oob_server=collector, timeout_s=3.0)
        assert len(res["findings"]) == 1
        f = res["findings"][0]
        assert f["verification"] == "confirmed"
        assert collector.hits(f["evidence"]["marker"])


def test_no_callback_no_finding_and_inconclusive_note(monkeypatch,
                                                      benign_target,
                                                      fake_oob_collector):
    monkeypatch.setenv("OMEGA_OOB_BASE_URL", _url(fake_oob_collector))
    res = run_oobhunt(_url(benign_target), params=["url"], timeout_s=0.3)
    assert res["findings"] == []
    assert res["tokens"]              # canaries were planted
    assert fake_oob_collector.omega_hits == []
    assert res["note"] == NO_CALLBACK_NOTE
    assert "INCONCLUSIVE" in NO_CALLBACK_NOTE


def test_markers_unique_per_param(monkeypatch, vulnerable_target,
                                  fake_oob_collector):
    monkeypatch.setenv("OMEGA_OOB_BASE_URL", _url(fake_oob_collector))
    res = run_oobhunt(_url(vulnerable_target), params=["url", "src"],
                      timeout_s=3.0)
    markers = [t["marker"] for t in res["tokens"]]
    assert len(markers) == 2 and len(set(markers)) == 2
    assert len(res["findings"]) == 2


# ------------------------------------------------------- XXE sink

def test_xxe_oob_confirmed(vulnerable_target, fake_oob_collector):
    res = run_oobhunt(_url(vulnerable_target), params=["xml"],
                      oob_base_url=_url(fake_oob_collector),
                      timeout_s=3.0)
    assert res["ran"] == ["xxe_oob:xml"]
    f = res["findings"][0]
    assert f["verification"] == "confirmed"
    assert "XXE" in f["title"] or "xxe_oob" in f["title"]
    marker = f["evidence"]["marker"]
    assert fake_oob_collector.omega_hits[0]["token"] == marker


def test_result_shape_always(monkeypatch, benign_target):
    monkeypatch.delenv("OMEGA_OOB_BASE_URL", raising=False)
    res = run_oobhunt(_url(benign_target), params=["url"])
    for key in ("findings", "ran", "skipped", "tokens", "note"):
        assert key in res
