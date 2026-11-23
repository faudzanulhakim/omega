"""omega/offensive/offense/corsprobe — CORS & header misconfiguration.

Checks reflected-origin CORS with credentials, null-origin acceptance,
wildcard with credentials, and missing hardening headers. Origin
reflection alone is LOW until Access-Control-Allow-Credentials: true
is also present — the module models that distinction.
OFFENSE-GATED (PTK_OFFENSE).
"""
import os

__all__ = ["run_corsprobe"]

EVIL = "https://omegcors.example"
HEADER_SET = ("Origin", "Access-Control-Request-Method")
HARDEN = ("x-content-type-options", "x-frame-options",
          "content-security-policy", "strict-transport-security")


def _hdrs(resp):
    h = getattr(resp, "headers", {}) or {}
    return {str(k).lower(): str(v) for k, v in h.items()}


def run_corsprobe(target, fetch=None, log=None, gate_open_fn=None):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    findings = []
    probes = 0
    origins = {
        "reflected-evil": EVIL,
        "null": "null",
        "subdomain-suffix": "https://evil.omegcors.example",
    }
    for name, origin in origins.items():
        try:
            resp = fetch(str(target), headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET"})
            probes += 1
        except Exception:
            continue
        if resp is None:
            continue
        h = _hdrs(resp)
        allow = h.get("access-control-allow-origin", "")
        creds = h.get("access-control-allow-credentials", "").lower() == "true"
        if allow in (origin, "*") and (origin != "*"):
            sev = "HIGH" if creds else "LOW"
            findings.append({
                "title": f"CORS {name}: origin accepted"
                         + (" WITH credentials" if creds else " (no credentials)"),
                "severity": sev,
                "source": "corsprobe/reflect",
                "evidence": f"ACAO: {allow} | ACAC: {creds}",
                "location": str(target),
                "verification": "confirmed" if creds else "candidate",
                "manual_check": "reflected origin without credentials "
                                "has limited impact; with credentials it "
                                "is exploitable data theft",
                "cwe": "CWE-942",
            })
    # hardening header audit (informational, one finding per missing)
    try:
        resp = fetch(str(target))
        probes += 1
        if resp is not None:
            h = _hdrs(resp)
            missing = [x for x in HARDEN if x not in h]
            if missing:
                findings.append({
                    "title": "missing hardening headers: "
                             + ", ".join(missing),
                    "severity": "INFO",
                    "source": "corsprobe/headers",
                    "evidence": f"absent: {missing}",
                    "location": str(target),
                    "verification": "candidate",
                    "manual_check": "context-dependent; report as "
                                    "hygiene only",
                    "cwe": "CWE-693",
                })
    except Exception:
        pass
    if log:
        log(f"corsprobe: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
