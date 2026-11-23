"""omega/scanning/wsprobe.py — WebSocket endpoint discovery + security
check (fusion suite name: ``wsprobe``).

Discover candidate WebSocket endpoints from ``path_info`` paths whose
name hints at ws/socket/chat/realtime plus common paths (/ws, /socket,
/socket.io), then attempt a raw HTTP Upgrade handshake over a plain
socket (stdlib only, like the smuggle raw path). Checks:

  unauth_handshake   — handshake succeeds without any auth token
                       (candidate medium)
  origin_not_validated — handshake accepted with a foreign Origin
                       header (candidate high)
  marker_echo        — the endpoint echoes a benign text-frame marker
                       back (info)

All payloads are benign markers; every socket op is timeout-contained;
the suite never raises.
"""

from __future__ import annotations

import base64
import os
import socket
import urllib.parse

from omega.scanning.deepchecks import Finding, default_fetch

__all__ = [
    "REQUEST_BUDGET",
    "WS_HINTS",
    "WS_COMMON_PATHS",
    "candidate_paths",
    "run_wsprobe",
]

REQUEST_BUDGET = 30
WS_HINTS = ("ws", "socket", "chat", "realtime")
WS_COMMON_PATHS = ("/ws", "/socket", "/socket.io")
_WS_TIMEOUT = 3.0


def _origin_of(url):
    p = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    return "%s://%s" % (p.scheme or "http",
                        p.netloc or "%s:%s" % (p.hostname, p.port or 80))


def candidate_paths(base_url, path_info=None):
    """Candidate ws endpoint paths: hinted discovered paths + common
    paths, deduped, order-stable, capped."""
    paths = []
    for p in ((path_info or {}).get("paths") or []):
        name = (p or "").split("?")[0].lower()
        if any(h in name for h in WS_HINTS) and p not in paths:
            paths.append(p)
    for p in WS_COMMON_PATHS:
        if p not in paths:
            paths.append(p)
    return paths[:10]


def _handshake(host, port, path, origin=None, extra_headers=None):
    """Raw HTTP Upgrade handshake over a plain socket. Returns
    (status:int|None, headers:dict, sock|None). Never raises."""
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    lines = [
        "GET %s HTTP/1.1" % (path or "/"),
        "Host: %s:%s" % (host, port),
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: %s" % key,
        "Sec-WebSocket-Version: 13",
    ]
    if origin:
        lines.append("Origin: %s" % origin)
    for k, v in (extra_headers or {}).items():
        lines.append("%s: %s" % (k, v))
    lines.append("\r\n")
    req = "\r\n".join(lines)
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=_WS_TIMEOUT)
        sock.sendall(req.encode("latin-1"))
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        lines_r = head.decode("latin-1", "replace").split("\r\n")
        status = None
        if lines_r and lines_r[0].startswith("HTTP/"):
            try:
                status = int(lines_r[0].split()[1])
            except (IndexError, ValueError):
                status = None
        headers = {}
        for ln in lines_r[1:]:
            if ":" in ln:
                k, _, v = ln.partition(":")
                headers[k.strip().lower()] = v.strip()
        return status, headers, sock if status == 101 else None
    except Exception:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        return None, {}, None


def _masked_frame(payload):
    """Build one masked client text frame (RFC 6455)."""
    mask = os.urandom(4)
    payload_b = payload.encode("utf-8")
    n = len(payload_b)
    if n < 126:
        hdr = bytes([0x81, 0x80 | n])
    elif n < 65536:
        hdr = bytes([0x81, 0x80 | 126]) + n.to_bytes(2, "big")
    else:
        hdr = bytes([0x81, 0x80 | 127]) + n.to_bytes(8, "big")
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload_b))
    return hdr + mask + masked


def _read_frame(sock):
    """Read one server frame payload (best-effort). Returns bytes|None."""
    try:
        h = sock.recv(2)
        if len(h) < 2:
            return None
        ln = h[1] & 0x7F
        if ln == 126:
            ext = sock.recv(2)
            ln = int.from_bytes(ext, "big")
        elif ln == 127:
            ext = sock.recv(8)
            ln = int.from_bytes(ext, "big")
        payload = b""
        while len(payload) < ln:
            chunk = sock.recv(ln - len(payload))
            if not chunk:
                break
            payload += chunk
        return payload
    except Exception:
        return None


def _echo_check(sock, marker):
    """Send one benign text frame; True if the marker comes back."""
    try:
        sock.sendall(_masked_frame(marker))
        payload = _read_frame(sock)
        return payload is not None and marker.encode() in payload
    except Exception:
        return False


def run_wsprobe(base_url, fetch=default_fetch, path_info=None, gate=False):
    """WebSocket discovery + security suite. Returns a list of Finding
    dicts; never raises. Benign markers only."""
    findings = []
    try:
        p = urllib.parse.urlparse(
            base_url if "://" in base_url else "http://" + base_url)
        host = p.hostname or ""
        port = p.port or (443 if p.scheme == "https" else 80)
        if not host:
            return findings
        marker = "omega-ws-probe-%s" % os.urandom(4).hex()
        budget = REQUEST_BUDGET
        for path in candidate_paths(base_url, path_info):
            if budget <= 0:
                break
            # check 1: unauthenticated handshake
            budget -= 1
            st, headers, sock = _handshake(host, port, path)
            if st != 101:
                continue
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            findings.append(Finding(
                title="WebSocket handshake succeeds without auth at %s"
                      % path,
                severity="medium", verification="candidate",
                verification_note=(
                    "A raw HTTP Upgrade handshake (no token, no session "
                    "cookie) completed with 101 Switching Protocols at "
                    "%s. Unauthenticated WebSocket access is a candidate "
                    "finding; confirm whether auth is enforced "
                    "application-side." % path),
                manual_check=(
                    'curl -sS -i -H "Upgrade: websocket" -H "Connection: '
                    'Upgrade" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25j'
                    'ZQ==" -H "Sec-WebSocket-Version: 13" '
                    '"ws://%s:%s%s"' % (host, port, path)),
                location="ws://%s:%s%s" % (host, port, path),
                evidence="handshake_status=101 auth=none path=%s" % path,
                source="omega-wsprobe/unauth_handshake"))
            # check 2: foreign Origin accepted
            if budget > 0:
                budget -= 1
                st2, _h2, sock2 = _handshake(
                    host, port, path, origin="https://evil.example")
                if st2 == 101:
                    findings.append(Finding(
                        title="WebSocket endpoint accepts foreign Origin "
                              "at %s" % path,
                        severity="high", verification="candidate",
                        verification_note=(
                            "The handshake completed (101) with Origin: "
                            "https://evil.example — the endpoint does not "
                            "validate the Origin header, so cross-origin "
                            "WebSocket hijack is plausible. Candidate "
                            "only; confirm token binding / session "
                            "cookies."),
                    manual_check=(
                        'curl -sS -i -H "Origin: https://evil.example" '
                        '-H "Upgrade: websocket" -H "Connection: Upgrade" '
                        '-H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" '
                        '-H "Sec-WebSocket-Version: 13" '
                        '"ws://%s:%s%s"' % (host, port, path)),
                    location="ws://%s:%s%s" % (host, port, path),
                    evidence="handshake_status=101 "
                             "origin=https://evil.example path=%s" % path,
                    source="omega-wsprobe/origin_not_validated"))
                if sock2 is not None:
                    # check 3: benign marker echo (info)
                    if budget > 0:
                        budget -= 1
                        if _echo_check(sock2, marker):
                            findings.append(Finding(
                                title="WebSocket endpoint echoes benign "
                                      "marker at %s" % path,
                                severity="info", verification="verified",
                                verification_note=(
                                    "A single benign text frame containing "
                                    "the marker %s was echoed back by the "
                                    "endpoint — informational only, "
                                    "confirms an active bidirectional "
                                    "channel." % marker),
                                manual_check=None,
                                location="ws://%s:%s%s" % (host, port, path),
                                evidence="echo=True marker=%s" % marker,
                                source="omega-wsprobe/marker_echo"))
                    try:
                        sock2.close()
                    except Exception:
                        pass
    except Exception:
        pass
    return findings
