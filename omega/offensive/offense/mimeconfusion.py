"""omega/offensive/offense/mimeconfusion — MIME sniffing & content
confusion probe.

User-controlled content served without X-Content-Type-Options: nosniff
can be forced into HTML/JS interpretation by the browser. This module
plants an inert marker shaped as markup, checks the serving response's
content-type security headers, and reports the sniffable combo.
OFFENSE-GATED (PTK_OFFENSE). Candidate-grade.
"""
import os
import secrets

__all__ = ["run_mimeconfusion"]


def run_mimeconfusion(target, fetch, log=None, gate_open_fn=None):
    """Check serving endpoints for sniffable content combos."""
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    if not callable(fetch):
        return {"note": "fetch adapter required"}
    mk = "omegmime" + secrets.token_hex(5)
    probes = 0
    findings = []
    # request with an HTML-forcing Accept header
    for accept in ("text/html", "*/*", "text/html,application/xhtml+xml"):
        try:
            resp = fetch(str(target), headers={"Accept": accept})
            probes += 1
        except TypeError:
            try:
                resp = fetch(str(target))
                probes += 1
            except Exception:
                continue
        except Exception:
            continue
        headers = getattr(resp, "headers", None) or {}
        lower = {str(k).lower(): str(v) for k, v in headers.items()}
        ctype = lower.get("content-type", "")
        nosniff = "nosniff" in lower.get("x-content-type-options", "")
        body = (resp if isinstance(resp, str) else
                getattr(resp, "text", "") or "")
        user_content = mk in body or "<" in body[:200]
        if ctype and ("text/plain" in ctype or "application/octet-stream"
                      in ctype or ctype == "") and user_content and \
                not nosniff:
            findings.append({
                "title": "MIME sniffing possible: user content served "
                         f"as {ctype!r} without nosniff",
                "severity": "MEDIUM",
                "source": "mimeconfusion/serving",
                "evidence": f"content-type {ctype!r}, "
                            f"X-Content-Type-Options missing, content "
                            f"contains user-influenceable markup",
                "location": str(target),
                "verification": "candidate",
                "manual_check": "open the URL directly in a browser to "
                                "confirm interpretation as HTML/JS",
                "cwe": "CWE-436",
            })
            break
    if log:
        log(f"mimeconfusion: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
