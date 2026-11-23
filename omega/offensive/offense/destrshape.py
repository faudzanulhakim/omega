"""omega/offensive/offense/destrshape — destructive-shape detector.

Proves destructive injection POINTS exist without doing damage: SQL
multi-statement shapes, command shapes, and filesystem-impact shapes
are sent in INERT, GUARANTEED-HARMLESS form (e.g. SELECT 1;-- pair,
`echo`-equivalent marker command, traversal to a known-readable
system file). A hit shows the injection runs — with zero data
destruction, zero state change. OFFENSE-GATED (PTK_OFFENSE).
Candidate + manual_check; operator decides if a full PoC is warranted.
"""
import os

__all__ = ["run_destrshape"]

CASES = [
    ("sql-multi-statement", "id", "CWE-89",
     "1;SELECT 1;--", ["1"], "stacked query accepted (SELECT pair)"),
    ("sql-dml-shape", "name", "CWE-89",
     "x', 'y');--", ["500", "error"], "DML-shape reaches SQL parser"),
    ("cmd-echo", "host", "CWE-78",
     ";echo omegdsr;", ["omegdsr"], "command chaining runs"),
    ("cmd-backtick", "ip", "CWE-78",
     "`echo omegdsr`", ["omegdsr"], "command substitution runs"),
    ("traversal-system", "file", "CWE-22",
     "../../../../etc/hostname", [], "system file readable via path"),
    ("traversal-null", "path", "CWE-22",
     "%2e%2e/%2e%2e/etc/passwd", ["root:"], "encoded traversal reads "
     "passwd shape"),
]


def run_destrshape(target, fetch=None, log=None, gate_open_fn=None):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    findings = []
    probes = 0
    for name, param, cwe, payload, markers, desc in CASES:
        sep = "&" if "?" in str(target) else "?"
        url = str(target) + sep + param + "=" + payload
        try:
            resp = fetch(url)
            probes += 1
        except Exception:
            continue
        if resp is None:
            continue
        body = getattr(resp, "text", "") or ""
        status = getattr(resp, "status", 0)
        if markers and any(m.lower() in body.lower() for m in markers):
            findings.append({
                "title": f"destructive injection POINT confirmed in "
                         f"safe form ({name})",
                "severity": "CRITICAL" if "cmd" in name else "HIGH",
                "source": "destrshape/inert-proof",
                "evidence": f"{desc}; payload was inert "
                            f"({payload!r}) — no state was changed",
                "location": str(target),
                "verification": "candidate",
                "manual_check": "the shape proves injection runs; any "
                                "destructive variant must be run "
                                "manually with target-owner approval",
                "cwe": cwe,
            })
        elif name.startswith("sql-dml") and status == 500:
            findings.append({
                "title": f"SQL parser error on DML-shape ({name})",
                "severity": "MEDIUM",
                "source": "destrshape/error",
                "evidence": "HTTP 500 on inert DML shape",
                "location": str(target),
                "verification": "candidate",
                "manual_check": "error may be parser reach — verify "
                                "with stacked SELECT pair",
                "cwe": cwe,
            })
    if log:
        log(f"destrshape: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
