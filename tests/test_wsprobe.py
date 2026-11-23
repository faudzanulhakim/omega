"""Hermetic tests for omega.scanning.wsprobe (WebSocket discovery +
security). Loopback TCP fixtures emulate the Upgrade handshake; clean
server refuses handshakes. Benign markers only."""

import base64
import hashlib
import socket
import struct
import threading

import pytest

from omega.scanning.wsprobe import (
    candidate_paths,
    run_wsprobe,
)

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _accept_value(key):
    digest = hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


class _WsHandler:
    """Knobs: accept_handshake (bool), validate_origin (bool), echo
    (bool). Serves a handful of connections then exits."""
    accept_handshake = True
    validate_origin = False
    echo = True
    paths = ("/ws", "/socket")

    def __init__(self, conn):
        self.conn = conn

    def run(self):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = self.conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            head = data.decode("latin-1", "replace")
            lines = head.split("\r\n")
            path = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 \
                else "/"
            key = origin = None
            for ln in lines[1:]:
                low = ln.lower()
                if low.startswith("sec-websocket-key:"):
                    key = ln.split(":", 1)[1].strip()
                elif low.startswith("origin:"):
                    origin = ln.split(":", 1)[1].strip()
            if not self.accept_handshake or key is None:
                self.conn.sendall(b"HTTP/1.1 404 Not Found\r\n"
                                  b"Content-Length: 0\r\n\r\n")
                return
            if self.validate_origin and origin not in (
                    None, "http://127.0.0.1"):
                self.conn.sendall(b"HTTP/1.1 403 Forbidden\r\n"
                                  b"Content-Length: 0\r\n\r\n")
                return
            resp = ("HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Accept: %s\r\n\r\n" % _accept_value(key))
            self.conn.sendall(resp.encode("latin-1"))
            if self.echo:
                payload = self._read_frame()
                if payload:
                    frame = b"\x81" + bytes([len(payload)]) + payload
                    try:
                        self.conn.sendall(frame)
                    except OSError:
                        pass
        except Exception:
            pass
        finally:
            try:
                self.conn.close()
            except OSError:
                pass

    def _read_frame(self):
        header = self._recv_exact(2)
        if header is None:
            return None
        ln = header[1] & 0x7F
        if ln == 126:
            ext = self._recv_exact(2)
            if ext is None:
                return None
            ln = struct.unpack("!H", ext)[0]
        elif ln == 127:
            ext = self._recv_exact(8)
            if ext is None:
                return None
            ln = struct.unpack("!Q", ext)[0]
        mask = self._recv_exact(4)
        if mask is None:
            return None
        masked = self._recv_exact(ln)
        if masked is None:
            return None
        return bytes(b ^ mask[i % 4] for i, b in enumerate(masked))

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf


class _WsServer:
    def __init__(self, **attrs):
        import socketserver

        outer = self

        class Srv(socketserver.ThreadingTCPServer):
            allow_reuse_address = True

            def handle_error(self, *a):
                pass

        self.srv = Srv(("127.0.0.1", 0), self._fake)
        self.port = self.srv.server_address[1]
        self.attrs = attrs
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _fake(self, request, *a):
        pass

    def _serve(self):
        while self.running:
            try:
                conn, _addr = self.srv.socket.accept()
            except OSError:
                return
            h = _WsHandler(conn)
            for k, v in self.attrs.items():
                setattr(h, k, v)
            h.run()

    def stop(self):
        self.running = False
        try:
            self.srv.socket.close()
        except Exception:
            pass
        try:
            self.srv.server_close()
        except Exception:
            pass


@pytest.fixture
def ws_server():
    made = []

    def make(**attrs):
        srv = _WsServer(**attrs)
        made.append(srv)
        return "http://127.0.0.1:%d" % srv.port

    yield make
    for srv in made:
        srv.stop()


def test_clean_server_no_findings(ws_server):
    base = ws_server(accept_handshake=False)
    assert run_wsprobe(base) == []


def test_unauthenticated_handshake_candidate(ws_server):
    base = ws_server()
    out = run_wsprobe(base)
    assert any(f["title"].startswith("WebSocket handshake succeeds")
               for f in out)
    f = [f for f in out if "handshake succeeds" in f["title"]][0]
    assert f["severity"] == "medium"
    assert f["verification"] == "candidate"
    assert f["source"] == "omega-wsprobe/unauth_handshake"


def test_foreign_origin_high_candidate(ws_server):
    base = ws_server()
    out = run_wsprobe(base)
    hits = [f for f in out if "foreign Origin" in f["title"]]
    assert hits
    assert hits[0]["severity"] == "high"
    assert hits[0]["verification"] == "candidate"


def test_origin_validated_no_origin_finding(ws_server):
    base = ws_server(validate_origin=True)
    out = run_wsprobe(base)
    assert not [f for f in out if "foreign Origin" in f["title"]]


def test_marker_echo_info(ws_server):
    base = ws_server()
    out = run_wsprobe(base)
    echoes = [f for f in out if "echoes benign marker" in f["title"]]
    assert echoes
    assert echoes[0]["severity"] == "info"
    assert echoes[0]["verification"] == "verified"
    assert "omega-ws-probe-" in echoes[0]["evidence"]


def test_candidate_paths_from_path_info():
    pi = {"paths": ["/chat", "/api/ws", "/users", "/realtime/stream"]}
    paths = candidate_paths("http://h:1", pi)
    assert "/api/ws" in paths and "/realtime/stream" in paths
    assert "/users" not in paths
    assert "/ws" in paths and "/socket.io" in paths


def test_never_raises_on_dead_target():
    import socket as _s
    s = _s.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert run_wsprobe("http://127.0.0.1:%d" % port) == []
    assert run_wsprobe("") == []


def test_finding_shape(ws_server):
    base = ws_server()
    for f in run_wsprobe(base):
        for key in ("title", "severity", "verification", "verification_note",
                    "location", "evidence", "source"):
            assert key in f
        assert isinstance(f, dict)
