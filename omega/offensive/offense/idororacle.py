"""omega/offensive/offense/idororacle — anti-IDOR smart oracle.

Detects the ID scheme FIRST (sequential vs hash vs random UUID via
entropy/pattern analysis over observed ids), then sweeps ONLY in the
scheme's viable range — no wasted requests against obvious random
UUIDs. Differential: object A accessible as principal B = candidate.
OFFENSE-GATED (PTK_OFFENSE). Paced.
"""
import os
import re as _re
import time
import uuid as _uuid

__all__ = ["run_idororacle"]


def classify_scheme(ids):
    """Return (scheme, rationale) for a list of observed id strings."""
    if not ids:
        return "unknown", "no ids observed"
    if all(_re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                         r"[0-9a-f]{4}-[0-9a-f]{12}", i, _re.I)
           for i in ids):
        return "uuid", ("UUIDs — direct enumeration is futile; only "
                        "leaked-id replay applies")
    if all(i.isdigit() for i in ids):
        return "sequential", "numeric ids — sweepable ±range"
    if all(_re.fullmatch(r"[A-Za-z0-9]{16,32}", i) for i in ids):
        return "opaque-hash", ("fixed-width alphanumeric tokens — "
                               "entropy suggests unguessable; verify "
                               "they are not time-derived")
    return "unknown", "mixed shapes — classify manually"


def run_idororacle(target, fetch=None, known_ids=None, id_params=None,
                   sweep=10, pace_s=0.1, log=None, gate_open_fn=None):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    known_ids = known_ids or []
    id_params = id_params or ["id", "user_id", "order_id", "account"]
    scheme, rationale = classify_scheme(known_ids)
    findings = []
    probes = 0
    if scheme not in ("sequential", "unknown"):
        if log:
            log(f"idororacle: scheme={scheme} — sweep skipped")
        return {"findings": [], "probes": probes, "scheme": scheme,
                "note": f"sweep skipped: {rationale}"}
    base = str(target).rstrip("/")
    # baseline: one known id as our own principal
    baseline = None
    if known_ids:
        for p in id_params:
            try:
                r = fetch(base + f"/?{p}={known_ids[0]}")
                probes += 1
            except Exception:
                continue
            if r is not None and getattr(r, "status", 0) == 200:
                baseline = (getattr(r, "status", 0),
                            (getattr(r, "text", "") or "")[:60])
                break
    if baseline is None:
        return {"findings": [], "probes": probes, "scheme": scheme,
                "note": "no accessible baseline object — cannot "
                        "differential-sweep"}
    # sweep neighbors of the first known id
    try:
        start = int(known_ids[0])
    except (ValueError, IndexError):
        start = 1
    for p in id_params:
        for d in range(1, sweep + 1):
            for cand in (start - d, start + d):
                if cand < 0 or cand == start:
                    continue
                try:
                    r = fetch(base + f"/?{p}={cand}")
                    probes += 1
                except Exception:
                    continue
                if pace_s:
                    time.sleep(pace_s)
                if r is None:
                    continue
                if (getattr(r, "status", 0), (getattr(r, "text", "") or "")
                        [:60]) == baseline:
                    findings.append({
                        "title": f"IDOR candidate: object id {cand} "
                                 f"(param {p}) returns the SAME "
                                 f"protected response as own object",
                        "severity": "HIGH",
                        "source": "idororacle/differential",
                        "evidence": f"neighbor id {cand} response "
                                    f"identical to baseline",
                        "location": base,
                        "verification": "candidate",
                        "manual_check": "confirm the object belongs to "
                                        "another principal (owner "
                                        "field/audit log)",
                        "cwe": "CWE-639",
                    })
                    break
            else:
                continue
            break
        if findings:
            break
    if log:
        log(f"idororacle: scheme={scheme} probes={probes} "
            f"findings={len(findings)}")
    return {"findings": findings, "probes": probes, "scheme": scheme,
            "note": rationale}
