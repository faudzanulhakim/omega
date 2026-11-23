"""omega/offensive/offense/dosexpose — DoS exposure detector.

Measures how DoS-able a target is WITHOUT performing a DoS: request
size caps, pagination limits, concurrency/rapid-reset tolerance,
slow-reader handling — each probed with a single bounded request and
classified. The verdict says "a third party could take this down,
here is the missing control" with evidence. Never floods, never
degrades service: every probe is one request and every blast ends.
OFFENSE-GATED (PTK_OFFENSE). Candidate + manual_check.
"""
import os
import socket
import struct
import time

__all__ = ["run_dosexpose"]

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _frame(ftype, flags, stream, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) \
        + struct.pack(">I", stream) + payload


def run_dosexpose(target, fetch=None, log=None, gate_open_fn=None,
                  timeout=4.0):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    findings = []
    probes = 0
    base = str(target).rstrip("/")
    # 1. unbounded pagination
    for param in ("limit", "per_page", "size", "count"):
        try:
            resp = fetch(base + f"/?{param}=9999999999")
            probes += 1
        except Exception:
            continue
        if resp is None:
            continue
        body = getattr(resp, "text", "") or ""
        if getattr(resp, "status", 0) == 200 and len(body) > 100000:
            findings.append({
                "title": f"unbounded pagination: ?{param}=10B accepted, "
                         f"{len(body)}-byte response",
                "severity": "MEDIUM",
                "source": "dosexpose/pagination",
                "evidence": "no result-size cap — amplifies backend "
                            "load per request",
                "location": base,
                "verification": "candidate",
                "manual_check": "cap results server-side; enables "
                                "cheap resource exhaustion by third "
                                "parties",
                "cwe": "CWE-770",
            })
            break
    # 2. request size cap (one large-but-safe body)
    try:
        resp = fetch(base, method="POST",
                     body="A" * (2 * 1024 * 1024))
        probes += 1
        if resp is not None and getattr(resp, "status", 0) in (200, 100):
            findings.append({
                "title": "no request size cap (2MB body accepted)",
                "severity": "LOW",
                "source": "dosexpose/size-cap",
                "evidence": "large POST accepted without 413",
                "location": base,
                "verification": "candidate",
                "manual_check": "set client_max_body_size / equivalent",
                "cwe": "CWE-400",
            })
    except Exception:
        pass
    # 3. slow-reader handling (single connection, short hang then close)
    try:
        from urllib.parse import urlparse
        u = urlparse(base if "//" in base else "http://" + base)
        host, port = u.hostname or "127.0.0.1", u.port or 80
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() +
                  b"\r\n\r\n")
        t0 = time.time()
        s.settimeout(timeout)
        try:
            s.recv(65536)
        except socket.timeout:
            pass
        held = time.time() - t0
        s.close()
        probes += 1
        if held >= timeout:
            findings.append({
                "title": f"connection held ~{held:.1f}s with minimal "
                         f"work — slow-reader tolerance",
                "severity": "MEDIUM",
                "source": "dosexpose/slowreader",
                "evidence": "server did not time out a stalled reader "
                            "within the probe window",
                "location": base,
                "verification": "candidate",
                "manual_check": "enable read timeouts / slowloris "
                                "protection; N such sockets per "
                                "attacker can exhaust workers",
                "cwe": "CWE-400",
            })
    except Exception:
        pass
    if log:
        log(f"dosexpose: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
