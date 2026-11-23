"""omega/offensive/offense/jsmine — client-side surface miner.

Fetches the target's JS bundles and mines what scanners never see:
API endpoints referenced in code, hardcoded key SHAPES (credential
values are NEVER stored — presence/hint only), and DOM sink
assignments (innerHTML/location.src) detected statically. Feeds
wordlistgen/scheduler. OFFENSE-GATED (PTK_OFFENSE).
"""
import os
import re

__all__ = ["run_jsmine"]

_BUNDLES = ["/", "/main.js", "/app.js", "/bundle.js", "/index.js",
            "/static/js/main.js", "/js/app.js", "/dist/bundle.js"]
_API_URL = re.compile(
    r"[\"']((?:https?:)?//[^\"']{4,80}|/[a-z0-9_\-./]{3,60})"
    r"[\"']", re.I)
_KEY_SHAPES = re.compile(
    r"(?i)\b(sk_live_|sk_test_|pk_live_|AKIA[0-9A-Z]{12,}|"
    r"ghp_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_\-]{20,}|"
    r"xox[bap]-[A-Za-z0-9\-]{10,})")
_SINKS = re.compile(
    r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|"
    r"location\.(?:href|src)\s*=|\.srcDoc\s*=|eval\s*\(")
_KEY_NAMES = re.compile(
    r"(?i)(api[_-]?key|apikey|secret|token|password)\s*[:=]\s*[\"'][^\"']{6,}"
)


def run_jsmine(target, fetch=None, max_paths=30, log=None,
               gate_open_fn=None):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    base = str(target).rstrip("/")
    endpoints, sinks, key_hints = {}, [], []
    probes = 0
    for seed in _BUNDLES:
        try:
            resp = fetch(base + seed)
            probes += 1
        except Exception:
            continue
        if resp is None:
            continue
        body = getattr(resp, "text", "") or ""
        if len(body) < 40:
            continue
        for u in _API_URL.findall(body):
            if any(u.endswith(x) for x in (".png", ".jpg", ".svg",
                                           ".css", ".woff")):
                continue
            endpoints[u] = endpoints.get(u, 0) + 1
        for m in _KEY_SHAPES.findall(body):
            hint = m[:6] + "..." + f"(len {len(m)})"
            if hint not in key_hints:
                key_hints.append(hint + " — SHAPE ONLY, value not stored")
        for m in _KEY_NAMES.findall(body):
            hint = f"credential-shaped literal '{m[0]}' in JS"
            if hint not in key_hints:
                key_hints.append(hint + " — SHAPE ONLY, value not stored")
        for m in _SINKS.findall(body):
            txt = m.strip()
            if txt and txt not in sinks:
                sinks.append(txt)
    findings = []
    if key_hints:
        findings.append({
            "title": f"credential-shaped literals found in client JS "
                     f"({len(key_hints)} shape(s))",
            "severity": "HIGH",
            "source": "jsmine/key-shape",
            "evidence": "; ".join(key_hints[:4]),
            "location": base,
            "verification": "candidate",
            "manual_check": "confirm the literal is live (not a test "
                            "fixture) and rotate it; this engine only "
                            "records the shape, never the value",
            "cwe": "CWE-798",
        })
    if sinks:
        findings.append({
            "title": f"DOM sinks reachable from client code "
                     f"({len(sinks)} assignment(s))",
            "severity": "MEDIUM",
            "source": "jsmine/dom-sink",
            "evidence": ", ".join(sinks[:6]),
            "location": base,
            "verification": "candidate",
            "manual_check": "trace whether attacker-controlled data "
                            "reaches these sinks (taint path)",
            "cwe": "CWE-79",
        })
    top = sorted(endpoints.items(), key=lambda kv: -kv[1])[:max_paths]
    if log:
        log(f"jsmine: probes={probes} endpoints={len(top)} "
            f"sinks={len(sinks)} keyshapes={len(key_hints)}")
    return {"findings": findings, "probes": probes,
            "endpoints": [u for u, _ in top], "sinks": sinks,
            "key_hints": key_hints}
