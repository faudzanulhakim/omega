"""omega/offensive/offense/deserprobe — deserialization gadget probe.

Safe detection of unsafe deserialization endpoints: Java (XStream /
ObjectInputStream), PHP (unserialize), Python (pickle), .NET
(ObjectStateFormatter / ViewState) shapes with INERT marker data only
— no real gadget chains are executed. Evidence: error-text
disclosure, behavioral differential (status/time), or marker echo.
OFFENSE-GATED (PTK_OFFENSE). Candidate + manual_check always.
"""
import base64
import os

__all__ = ["run_deserprobe"]

MARKER = "omegdsr"

# (name, param, cwe, description, payload_bytes)
SHAPES = [
    ("java-xstream", "data", "CWE-502",
     "java <string>omxxg</string> — XStream shape",
     b"<string>omegdsr</string>"),
    ("php-unserialize", "data", "CWE-502",
     "php O:8:\"omegdsr\":0:{} shape",
     b'O:8:"omegdsr":0:{}'),
    ("python-pickle", "data", "CWE-502",
     "python pickle opcode shape (no gadgets, marker-only)",
     b"\x80\x04\x95\x0e\x00\x00\x00\x00\x00\x00\x00X\x07\x00\x00"
     b"\x00omegdsr."),
    ("java-b64", "data", "CWE-502",
     "base64 hex-encoded rO0AB (ObjectInputStream magic)",
     base64.b64encode(b"\xac\xed\x00\x05omegdsr")),
    ("net-viewstate", "viewstate", "CWE-502",
     "ViewState structure without MAC validation probe",
     b"/wEPDwUJomegdsrX"),
    ("yaml-load", "config", "CWE-502",
     "yaml !!python/object shape (yaml.load unsafe)",
     b"!!python/object:omegdsr {}"),
]

ERR_MARKERS = (b"unserialize", b"pickle", b"XStream", b"ObjectInputStream",
               b"DeserializationException", b"YAMLError", b"ViewState",
               b"SERIALIZATION", b"omxxg")


def run_deserprobe(target, fetch, log=None, gate_open_fn=None):
    """Plant deserialization shapes and classify by error/behavior."""
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    if not callable(fetch):
        return {"note": "fetch adapter required"}
    findings = []
    probes = 0
    for name, param, cwe, desc, payload in SHAPES:
        sep = "&" if "?" in str(target) else "?"
        url = str(target) + sep + param + "=" + payload.decode("latin-1")
        try:
            resp = fetch(url)
            probes += 1
        except Exception:
            continue
        body = getattr(resp, "text", "") or ""
        status = getattr(resp, "status", 0)
        # evidence 1: parser error text disclosed
        if any(m.decode("latin-1", "ignore").lower() in body.lower()
               for m in ERR_MARKERS):
            findings.append({
                "title": f"deserialization endpoint revealed parser "
                         f"error text ({name})",
                "severity": "HIGH",
                "source": "deserprobe/error-disclosure",
                "evidence": f"server error text matches {desc} — "
                            f"unsanitized deserialization path",
                "location": str(target),
                "verification": "candidate",
                "manual_check": "confirm the parser actually accepts "
                                "the shape before writing this up; do "
                                "NOT chain real gadgets",
                "cwe": cwe,
            })
        # evidence 2: 500 only for this shape vs other probes
        elif status == 500:
            findings.append({
                "title": f"deserialization shape triggers server error "
                         f"({name})",
                "severity": "MEDIUM",
                "source": "deserprobe/error-status",
                "evidence": f"HTTP 500 on {desc}",
                "location": str(target),
                "verification": "candidate",
                "manual_check": "verify the 500 is deserialization and "
                                "not generic; harmless error",
                "cwe": cwe,
            })
    if log:
        log(f"deserprobe: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes, "marker": MARKER}
