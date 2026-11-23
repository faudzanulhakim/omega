"""Tests for batch-13 BLACKOUT: smuggle, cachepoison, wsprobe,
protopollute, sessionmatrix, mimeconfusion, blindrelay, h2probe."""
import json
import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


class R:
    def __init__(self, text, status=200, headers=None):
        self.status = status
        self.text = text
        self.headers = headers or {}


def gate_env():
    os.environ["PTK_OFFENSE"] = "1"


def ungate():
    os.environ.pop("PTK_OFFENSE", None)


# ---------------------------------------------------------------- gates
@pytest.mark.parametrize("mod,fn,args", [
    ("smuggle", "run_smuggle", ("http://127.0.0.1:1/",)),
    ("cachepoison", "run_cachepoison", ("http://x/", None)),
    ("wsprobe", "run_wsprobe", ("http://127.0.0.1:1/",)),
    ("protopollute", "run_protopollute", ("http://x/", None)),
    ("sessionmatrix", "run_sessionmatrix", ("http://x/", None)),
    ("mimeconfusion", "run_mimeconfusion", ("http://x/", None)),
    ("blindrelay", "run_blindrelay", ("http://x/", None)),
    ("h2probe", "run_h2probe", ("http://127.0.0.1:1/",)),
])
def test_all_blackout_modules_gate(mod, fn, args):
    import importlib
    m = importlib.import_module(f"omega.offensive.offense.{mod}")
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        out = getattr(m, fn)(*args)
        assert "PTK_OFFENSE" in out.get("note", "")
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


# ---------------------------------------------------------------- smuggle
def test_smuggle_detects_desync_marker():
    from omega.offensive.offense.smuggle import run_smuggle
    # craft a listener that echoes the X-Smuggle header back: the
    # desync signature the module looks for
    srv_sock = socket.socket()
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(8)
    port = srv_sock.getsockname()[1]
    stored = {"marker": None}

    def serve():
        # models front-end/back-end desync: a request carrying the
        # X-Smuggle header gets queued and its marker is echoed to the
        # NEXT connection (poisoned second response)
        import time as _t
        end = _t.time() + 15
        while _t.time() < end:
            try:
                conn, _ = srv_sock.accept()
            except Exception:
                return
            try:
                data = conn.recv(65536)
                prev = stored["marker"]
                if b"X-Smuggle:" in data:
                    stored["marker"] = \
                        data.split(b"X-Smuggle: ")[1].split(b"\r\n")[0]
                    # desync: this probe's smuggled response lands on
                    # the NEXT connection — send the previous marker
                    if prev:
                        conn.sendall(b"HTTP/1.1 200 OK\r\n"
                                     b"Content-Length: 8\r\n\r\n" + prev)
                    else:
                        conn.sendall(b"HTTP/1.1 200 OK\r\n"
                                     b"Content-Length: 2\r\n\r\nok")
                elif stored["marker"]:
                    conn.sendall(b"HTTP/1.1 200 OK\r\n"
                                 b"Content-Length: 8\r\n\r\n"
                                 + stored["marker"])
                else:
                    conn.sendall(b"HTTP/1.1 200 OK\r\n"
                                 b"Content-Length: 2\r\n\r\nok")
            except Exception:
                pass
            finally:
                conn.close()

    threading.Thread(target=serve, daemon=True).start()
    gate_env()
    try:
        out = run_smuggle(f"http://127.0.0.1:{port}/", timeout=2.0)
    finally:
        ungate()
        srv_sock.close()
    assert out["findings"], "desync marker must be flagged"
    assert out["findings"][0]["cwe"] == "CWE-444"
    assert out["findings"][0]["verification"] == "candidate"


# ---------------------------------------------------------------- poison
def test_cachepoison_marker_roundtrip():
    from omega.offensive.offense.cachepoison import run_cachepoison
    state = {"poisoned": None}

    def fetch(url, headers=None):
        if headers and any("omegcp" in str(v) for v in headers.values()):
            state["poisoned"] = [v for v in headers.values()
                                 if "omegcp" in str(v)][0].split(".")[0]
            return R("ok")
        if state["poisoned"]:
            return R(f"<html>host={state['poisoned']}</html>")
        return R("clean")

    gate_env()
    try:
        out = run_cachepoison("http://t.local/", fetch=fetch, reads=3)
    finally:
        ungate()
    assert out["findings"]
    assert "cache poisoning" in out["findings"][0]["title"].lower()


# ---------------------------------------------------------------- wsprobe
def _ws_server(accept_origins=True):
    srv_sock = socket.socket()
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(4)
    port = srv_sock.getsockname()[1]

    def serve():
        for _ in range(3):
            try:
                conn, _ = srv_sock.accept()
            except Exception:
                return
            data = conn.recv(65536).decode(errors="ignore")
            evil = "evil.example" in data
            has_cookie = "Cookie:" in data
            ok = b"101"
            if not accept_origins and evil:
                ok = b"403"
            resp = (b"HTTP/1.1 " + ok +
                    b" Switching Protocols\r\nUpgrade: websocket\r\n"
                    b"Connection: Upgrade\r\nSec-WebSocket-Accept: x\r\n"
                    b"\r\n")
            conn.sendall(resp)
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv_sock, port


def test_wsprobe_origin_bypass_and_cwsh():
    from omega.offensive.offense.wsprobe import run_wsprobe
    srv, port = _ws_server(accept_origins=True)
    gate_env()
    try:
        out = run_wsprobe(f"http://127.0.0.1:{port}/ws")
    finally:
        ungate()
        srv.close()
    titles = " | ".join(f["title"] for f in out["findings"])
    assert "arbitrary Origin" in titles
    assert "CSWSH" in titles


# ---------------------------------------------------------------- proto
def test_protopollute_gadget_effect():
    from omega.offensive.offense.protopollute import run_protopollute

    def fetch(url, method="GET", body=None):
        if "__proto__" in str(url) + str(body):
            return R("OMEGAPP", 510)
        return R("ok", 200)

    gate_env()
    try:
        out = run_protopollute("http://t.local/", fetch=fetch)
    finally:
        ungate()
    assert out["findings"][0]["cwe"] == "CWE-1321"


# ---------------------------------------------------------------- session
def test_sessionmatrix_stale_token_accepted():
    from omega.offensive.offense.sessionmatrix import run_sessionmatrix

    def fetch(url, headers=None):
        auth = (headers or {}).get("Authorization", "")
        if auth.startswith("Bearer ") and len(auth) > 10:
            return R("dashboard", 200)   # ANY bearer accepted = flaw
        return R("unauthorized", 401)

    gate_env()
    try:
        out = run_sessionmatrix(
            "http://t.local/me", fetch=fetch,
            auth_headers={"Authorization": "Bearer omegatoken123456"})
    finally:
        ungate()
    assert out["findings"]
    assert any("stale" in f["title"] for f in out["findings"])


# ---------------------------------------------------------------- mime
def test_mimeconfusion_sniffable_combo():
    from omega.offensive.offense.mimeconfusion import run_mimeconfusion

    def fetch(url, headers=None):
        return R("<html><b>user content</b>", 200,
                 headers={"Content-Type": "text/plain"})

    gate_env()
    try:
        out = run_mimeconfusion("http://t.local/note/1", fetch=fetch)
    finally:
        ungate()
    assert out["findings"]
    assert out["findings"][0]["cwe"] == "CWE-436"


# ---------------------------------------------------------------- blindrelay
def test_blindrelay_oob_confirms():
    from omega.offensive.offense.blindrelay import run_blindrelay
    hit_url = {}

    def fetch(url, method="GET", body=None):
        hit_url["u"] = url
        return R("ok")

    # find the OOB callback the module plants, then simulate the
    # target fetching it (this is what a real blind SSRF would do)
    class FetchTrap:
        pass

    gate_env()
    try:
        # monkeypatch fetch to record; then fetch again via the trap
        import omega.core.oob as oob
        out_holder = {}

        def fetch2(url, method="GET", body=None):
            hit_url["u"] = url
            return R("ok")

        # run with a wrapper that triggers a callback on the planted
        # token: we can't know the token upfront, so run blindrelay in
        # a thread that plants, then we scan hit_url for the token
        import threading
        result = {}

        def runner():
            result["out"] = run_blindrelay("http://t.local/",
                                           fetch=fetch_trap_and_hit)

        state = {"token_urls": []}

        def fetch_trap_and_hit(url, method="GET", body=None):
            state["token_urls"].append(url)
            return R("ok")

        t = threading.Thread(target=runner, daemon=True)
        t.start()
        t.join(timeout=1.0)
        # simulate target: fetch every planted token url (OOB hit)
        import http.client
        for u in state["token_urls"]:
            pass  # planted URLs handled inside fetch_relay
        # rerun full relay with the fetch that also triggers OOB:
        # simplest: call run_blindrelay with fetch that urllib-hits the
        # token urls it receives (the target mirrors them)
        def fetch_relay(url, method="GET", body=None):
            hit_url["u"] = url
            # the planted token URL is INSIDE this request; simulate
            # the server fetching it:
            import re as _re
            m = _re.search(r"http://127\.0\.0\.1:\d+/[0-9a-f]{32}", url)
            if m:
                try:
                    from urllib.parse import urlparse as _up
                    _pu = _up(m.group(0))
                    _c = http.client.HTTPConnection(_pu.hostname,
                                                    _pu.port, timeout=2)
                    _c.request("GET", _pu.path)
                    _c.getresponse().read()
                    _c.close()
                except Exception:
                    pass
            return R("ok")

        out = run_blindrelay("http://t.local/", fetch=fetch_relay,
                             wait_s=3.0)
    finally:
        ungate()
    assert out.get("confirmed") == 1, "OOB hit must CONFIRM"
    f = out["findings"][0]
    assert f["verification"] == "confirmed"
    assert "callback" in f["title"].lower()


# ---------------------------------------------------------------- h2probe
def test_h2probe_no_h2_honest():
    from omega.offensive.offense.h2probe import run_h2probe
    gate_env()
    try:
        out = run_h2probe("http://127.0.0.1:1/", streams=2)
    finally:
        ungate()
    note = out.get("note", "")
    assert ("not applicable" in note or "error" in note
            or out.get("findings") == [])


# ---------------------------------------------------------------- brain/CLI
def test_brain_caps_197():
    from omega.core.brain import DEFAULT_REGISTRY as reg
    assert len(reg.ids()) == 197
    for cid in ("offense.smuggle", "offense.cachepoison",
                "offense.wsprobe", "offense.protopollute",
                "offense.sessionmatrix", "offense.mimeconfusion",
                "offense.blindrelay", "offense.h2probe"):
        assert reg.get(cid) is not None


def test_cli_blackout_flags():
    import contextlib
    import io
    from omega.core import cli as climod
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            climod.main(["brain", "--help"])
        except SystemExit:
            pass
    txt = buf.getvalue()
    for flag in ("--smuggle", "--cache-poison", "--ws-probe",
                 "--proto-pollute", "--session-matrix",
                 "--mime-confusion", "--blind-relay", "--h2-probe"):
        assert flag in txt
