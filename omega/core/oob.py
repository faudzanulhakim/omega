"""OMEGA self-hosted out-of-band (OOB) callback server.

A small, local-only HTTP server that records blind-vuln callbacks:
the operator's probes point canary URLs at it and a hit proves the
target fetched an attacker-controlled URL (blind SSRF, blind XSS
callbacks, webhook pings, ...).

Safety properties:
  * binds a configurable interface, default 127.0.0.1 (env
    OMEGA_OOB_HOST / OMEGA_OOB_PORT, port default 0 = ephemeral);
  * every engagement uses unique, unguessable 32-hex tokens — a hit
    only counts for the exact token a probe planted;
  * no DNS logic of any kind, no rebinding support, no payload
    serving: the server only RECORDS requests (method, path, headers,
    body hash, timestamp, remote address) and answers 200;
  * nothing is sent anywhere — hits stay in an in-memory log capped at
    1000 entries for the operator's own probe.

Usage:
    with OOBCallbackServer() as srv:
        url = srv.token_url()           # http://127.0.0.1:PORT/<token>
        ...plant the canary...
        hit = srv.wait_for_hit(token, timeout_s=5.0)
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__all__ = [
    "OOBCallbackServer",
    "DEFAULT_OOB_HOST",
    "DEFAULT_OOB_PORT",
    "HIT_LOG_CAP",
]

DEFAULT_OOB_HOST = "127.0.0.1"
DEFAULT_OOB_PORT = 0          # ephemeral
HIT_LOG_CAP = 1000
TOKEN_LEN = 32                # hex chars


def _env_host():
    return os.environ.get("OMEGA_OOB_HOST") or DEFAULT_OOB_HOST


def _env_port():
    try:
        return int(os.environ.get("OMEGA_OOB_PORT", DEFAULT_OOB_PORT))
    except (TypeError, ValueError):
        return DEFAULT_OOB_PORT


def _token_from_path(path):
    """Extract a 32-hex token from the first path segment, else None."""
    seg = path.lstrip("/").split("?", 1)[0].split("/", 1)[0]
    if len(seg) == TOKEN_LEN and all(c in "0123456789abcdef" for c in seg):
        return seg
    return None


class OOBCallbackServer:
    """Local HTTP callback collector with per-engagement unique tokens."""

    def __init__(self, host=None, port=None):
        self.host = host if host is not None else _env_host()
        self.port = port if port is not None else _env_port()
        self._hits = []                 # capped log of hit dicts
        self._lock = threading.Lock()
        self._server = None
        self._thread = None
        self._started = False

    # ------------------------------------------------------------- urls

    def base_url(self):
        """The server root URL, e.g. http://127.0.0.1:54321/."""
        host = self.host
        if ":" in host:  # IPv6 literal
            host = "[%s]" % host
        return "http://%s:%d/" % (host, self.port)

    @staticmethod
    def new_token():
        """A fresh, unguessable 32-hex token (per-engagement unique)."""
        return secrets.token_hex(TOKEN_LEN // 2)

    def token_url(self, token=None):
        """A canary URL carrying a fresh (or given) 32-hex token."""
        return self.base_url() + (token or self.new_token())

    # -------------------------------------------------------- lifecycle

    def start(self):
        """Bind and serve on a background thread. Idempotent."""
        if self._started:
            return self
        handler = self._make_handler()
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self.port = self._server.server_address[1]  # resolved ephemeral port
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        self._started = True
        return self

    def stop(self):
        """Shut the server down. Safe to call twice."""
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
        self._server = None
        if self._thread is not None:
            try:
                self._thread.join(timeout=2.0)
            except Exception:
                pass
        self._thread = None
        self._started = False
        return self

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False

    # ------------------------------------------------------------- hits

    @property
    def running(self):
        return self._started

    def hits(self, token=None):
        """Recorded hits (optionally filtered by exact token)."""
        with self._lock:
            if token is None:
                return list(self._hits)
            return [h for h in self._hits if h.get("token") == token]

    def wait_for_hit(self, token, timeout_s=5.0, poll_s=0.05):
        """Poll for a hit on the EXACT token; return the hit or None."""
        deadline = time.monotonic() + max(0.0, float(timeout_s))
        while True:
            found = self.hits(token)
            if found:
                return found[0]
            if time.monotonic() >= deadline:
                return None
            time.sleep(poll_s)

    def clear(self):
        with self._lock:
            self._hits.clear()

    # ---------------------------------------------------------- handler

    def _record(self, method, path, headers, body, remote):
        headers = {str(k): str(v) for k, v in headers.items()}
        hit = {
            "token": _token_from_path(path),
            "path": path,
            "method": method,
            "headers": headers,
            "body_sha256": hashlib.sha256(body or b"").hexdigest(),
            "ts": time.time(),
            "remote": remote,
        }
        with self._lock:
            self._hits.append(hit)
            if len(self._hits) > HIT_LOG_CAP:
                del self._hits[: len(self._hits) - HIT_LOG_CAP]
        return hit

    def _make_handler(self):
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def _handle(self, method):
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except (TypeError, ValueError):
                    length = 0
                body = self.rfile.read(min(length, 65536)) if length else b""
                remote = self.client_address[0] if self.client_address else ""
                outer._record(method, self.path, dict(self.headers.items()),
                              body, remote)
                payload = json.dumps({"ok": True}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):      # noqa: N802 (http.server API)
                self._handle("GET")

            def do_POST(self):     # noqa: N802
                self._handle("POST")

            def log_message(self, fmt, *args):   # silence default logging
                pass

        return _Handler
