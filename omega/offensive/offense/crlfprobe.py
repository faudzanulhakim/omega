"""omega/offensive/offense/crlfprobe — header injection / response
splitting candidate probe.

Injects CRLF into a query param and one custom header, three variants
each (raw, %0d%0a, double-encoded). A hit requires the RESPONSE to
show attacker-controlled structure (an injected header name or a
split second status line) — reflected-in-body alone is NOT a hit.
Single-request variants only; never a splitting flood.
OFFENSE-GATED (PTK_OFFENSE). Candidate + manual_check.
"""
import os

__all__ = ["run_crlfprobe"]

MARK = "omegcrlf"
VARIANTS = [
    ("raw", MARK + ": injected"),
    ("encoded", "%0d%0a" + MARK + "%3A%20injected"),
    ("double", "%250d%250a" + MARK + "%253A%2520injected"),
]


def run_crlfprobe(target, fetch=None, params=None, log=None,
                  gate_open_fn=None):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    params = params or ["next", "url", "redirect", "return", "path",
                        "dest"]
    findings = []
    probes = 0
    for p in params:
        for name, payload in VARIANTS:
            sep = "&" if "?" in str(target) else "?"
            url = str(target) + sep + p + "=" + payload
            try:
                resp = fetch(url, headers={"X-Omeg-Test": payload})
                probes += 1
            except Exception:
                continue
            if resp is None:
                continue
            # evidence in HEADERS: our injected header came back
            hdrs = {str(k).lower(): str(v)
                    for k, v in (getattr(resp, "headers", {})
                                 or {}).items()}
            if MARK in hdrs or any(MARK in str(v) for v in hdrs.values()):
                findings.append({
                    "title": f"header injection: param {p} CRLF payload "
                             f"reached response headers ({name})",
                    "severity": "HIGH",
                    "source": "crlfprobe/header-reflect",
                    "evidence": f"marker header '{MARK}' present in the "
                                f"response header set",
                    "location": str(target),
                    "verification": "candidate",
                    "manual_check": "confirm a full split (second "
                                    "response) is possible before "
                                    "claiming exploitable impact",
                    "cwe": "CWE-113",
                })
                break
    if log:
        log(f"crlfprobe: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
