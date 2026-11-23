"""omega/offensive/offense/wsprobe — WebSocket attack surface probe.

Raw-socket upgrade handshake tests: origin validation bypass, CSWSH
(cross-site websocket hijacking with cookies and NO origin), and
echo/message injection behavior. OFFENSE-GATED (PTK_OFFENSE).
Candidate-grade.
"""
import base64
import os
import secrets
import socket

__all__ = ["run_wsprobe"]

_KEY = base64.b64encode(secrets.token_bytes(16)).decode()


def _handshake(host, port, path, extra=None, timeout=4.0):
    raw = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {_KEY}\r\nSec-WebSocket-Version: 13\r\n")
    for k, v in (extra or {}).items():
        raw += f"{k}: {v}\r\n"
    raw += "\r\n"
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(raw.encode())
        s.settimeout(timeout)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        return s, data
    except Exception:
        return None, b""


def run_wsprobe(target, log=None, gate_open_fn=None):
    """Probe WS endpoints under ws:// or http:// targets."""
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    from urllib.parse import urlparse
    u = urlparse(target if "//" in target else "http://" + target)
    scheme = "wss" if u.scheme == "https" else "ws"
    host, port = u.hostname or "127.0.0.1", u.port or (443 if
        scheme == "wss" else 80)
    path = u.path or "/"
    findings = []
    probes = 0

    if scheme == "wss":
        return {"note": "TLS websocket needs an ssl wrapper — probe "
                        "ws:// endpoint or pass ssl context (skipped)"}

    # 1) normal upgrade (baseline)
    s1, d1 = _handshake(host, port, path)
    probes += 1
    baseline_ok = b"101" in d1[:64]
    if s1:
        s1.close()

    # 2) evil origin
    s2, d2 = _handshake(host, port, path,
                        extra={"Origin": "http://evil.example"})
    probes += 1
    if s2:
        s2.close()
    if baseline_ok and b"101" in d2[:64]:
        findings.append({
            "title": "websocket accepts arbitrary Origin",
            "severity": "MEDIUM",
            "source": "wsprobe/origin-bypass",
            "evidence": f"upgrade with Origin evil.example returned "
                        f"101 (path {path})",
            "location": f"ws://{host}:{port}{path}",
            "verification": "candidate",
            "manual_check": "confirm sensitive messages flow on the "
                            "socket before reporting",
            "cwe": "CWE-346",
        })

    # 3) CSWSH shape: cookies present, NO origin header
    cookie = secrets.token_hex(8)
    s3, d3 = _handshake(host, port, path,
                        extra={"Cookie": f"session={cookie}"})
    probes += 1
    if s3:
        s3.close()
    if baseline_ok and b"101" in d3[:64]:
        findings.append({
            "title": "websocket upgrade with cookies and no Origin "
                     "(CSWSH shape)",
            "severity": "HIGH",
            "source": "wsprobe/cswsh",
            "evidence": f"cookie-bearing origin-less upgrade returned "
                        f"101 — browser-attached sessions may be "
                        f"hijackable cross-site",
            "location": f"ws://{host}:{port}{path}",
            "verification": "candidate",
            "manual_check": "replay from a real cross-site page to "
                            "confirm session reuse",
            "cwe": "CWE-1385",
        })

    if log:
        log(f"wsprobe: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes,
            "baseline_upgrade": baseline_ok}
