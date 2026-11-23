"""omega/adapters/awktools — Python runner for the awk polyglot adapter.

Drives omega/adapters/awk/urlmine.awk (POSIX-awk/mawk compatible) to
mine URL/endpoint/secret candidates (AWS keys, JWTs, API keys,
private IPs) from arbitrary text (HTML bodies, JS, config dumps).
FP-safety is handled HERE in Python: any match whose value also
appears in the constant benign baseline text is dropped before it
becomes a finding.

Everything is gated behind PTK_POLYGLOT=1 and never raises outward:
gate closed, missing awk, subprocess timeouts and malformed JSON all
become contained entries in result['skipped'].

Findings contract: title/severity/confidence('candidate')/
verification('candidate')/source/evidence(<=300)/location/manual_check
(real shell command against the real target).
"""
import json
import os
import shutil
import subprocess

from omega.adapters import native

OUTPUT_CAP = 1 * 1024 * 1024          # subprocess stdout cap (1 MB)
SUBPROC_TIMEOUT = 30                  # seconds per tool run
FINDING_EVIDENCE_CAP = native.FINDING_EVIDENCE_CAP
FINDING_CAP = 50                      # max findings per run

AWK_DIR = os.path.join(native.PACKAGE_DIR, "awk")
URLMINE_SCRIPT = os.path.join(AWK_DIR, "urlmine.awk")
GATE_KEY = "awktools"

# kind -> (severity, title, manual_check template)
KIND_SEVERITY = {
    "aws_key": ("HIGH", "AWS access key id candidate in text",
                "grep -nE 'AKIA[0-9A-Z]{16}' <source>"),
    "jwt": ("MEDIUM", "JWT token candidate in text",
            "grep -noE 'eyJ[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.]"
            "[A-Za-z0-9_-]+' <source> | head -5"),
    "api_key": ("HIGH", "API key assignment candidate in text",
                "grep -niE 'api[_-]?key' <source> | head -10"),
    "private_ip": ("LOW", "Private/loopback IP address disclosed in text",
                   "grep -noE '([0-9]{1,3}[.]){3}[0-9]{1,3}' <source> "
                   "| head -10"),
}

# Constant benign baseline: values appearing in BOTH the scanned text
# and this baseline are treated as FP and dropped (FP-safe diff).
BASELINE_TEXT = (
    "Documentation example only: docs use https://example.com/ and "
    "the placeholder key AKIAIOSFODNN7EXAMPLE and the loopback "
    "127.0.0.1 from RFC 2606/RFC 5737 sample material."
)


def _gate_open(gate_open_fn=None):
    if gate_open_fn is not None:
        try:
            return bool(gate_open_fn())
        except Exception:
            return False
    return os.environ.get("PTK_POLYGLOT") == "1"


def _result(findings=None, skipped=None, requests_sent=0, ran=None,
            surface=None):
    return {
        "findings": findings or [],
        "skipped": skipped or {},
        "requests_sent": requests_sent,
        "ran": ran or [],
        "surface": surface or {},
    }


def _finding(title, severity, source, evidence, location, manual_check,
             note=None):
    ev = str(evidence or "")
    if len(ev) > FINDING_EVIDENCE_CAP:
        ev = ev[:FINDING_EVIDENCE_CAP - 1] + "…"  # stays <= cap
    return {
        "title": title,
        "severity": severity,
        "confidence": "candidate",
        "verification": "candidate",
        "verification_note": note or (
            "regex-shape candidate from an awk adapter: string merely "
            "matches a secret/IP pattern — verify manually before acting"),
        "source": source,
        "evidence": ev,
        "location": location,
        "manual_check": manual_check,
    }


def _run_urlmine_text(text):
    """Run urlmine.awk over text; return (list of match dicts, err)."""
    if not os.path.exists(URLMINE_SCRIPT):
        return None, "urlmine.awk not found"
    try:
        proc = subprocess.run(
            ["awk", "-f", URLMINE_SCRIPT],
            input=str(text or "").encode("utf-8"),
            capture_output=True, timeout=SUBPROC_TIMEOUT)
    except FileNotFoundError:
        return None, "awk binary not found"
    except subprocess.TimeoutExpired:
        return None, f"timeout after {SUBPROC_TIMEOUT}s (process killed)"
    except Exception as e:
        return None, f"subprocess error: {e}"
    out = proc.stdout[:OUTPUT_CAP]  # hard 1 MB cap before parsing
    matches = []
    for line in out.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None, "invalid JSON from tool stdout"
        except Exception as e:
            return None, f"parse error: {e}"
        if obj.get("kind") and obj.get("value"):
            matches.append({"kind": str(obj["kind"]),
                            "value": str(obj["value"])})
    return matches, None


def run_urlmine(text, baseline=None, log=None, gate_open_fn=None,
                location=None):
    """Mine secret/endpoint candidates from text.

    baseline: extra benign text whose match values are dropped
    (FP-safe diff). Returns the engine-shaped result dict; never
    raises. 'url' matches are surface intel, never findings.
    """
    if not _gate_open(gate_open_fn):
        return _result(skipped={GATE_KEY:
                                "polyglot gate closed (PTK_POLYGLOT)"})
    if not shutil.which("awk"):
        return _result(skipped={GATE_KEY: "awk unavailable"})

    matches, err = _run_urlmine_text(text)
    if matches is None:
        return _result(skipped={GATE_KEY: f"urlmine: {err}"})

    # ---- FP-safe baseline diff (handled in Python, per contract) ----
    base_texts = [BASELINE_TEXT]
    if baseline:
        base_texts.append(str(baseline))
    baseline_values = set()
    for bt in base_texts:
        base_matches, berr = _run_urlmine_text(bt)
        if base_matches:
            baseline_values.update(m["value"] for m in base_matches)

    findings = []
    surface_urls = []
    seen_evidence = set()
    for m in matches:
        kind, value = m["kind"], m["value"]
        if kind == "url":
            if value not in surface_urls:
                surface_urls.append(value)
            continue
        if kind not in KIND_SEVERITY:
            continue
        if value in baseline_values:
            continue  # FP-safe: also present in the benign baseline
        if value in seen_evidence:
            continue  # dedupe identical values
        seen_evidence.add(value)
        severity, title, mc_tpl = KIND_SEVERITY[kind]
        if len(findings) >= FINDING_CAP:
            break
        findings.append(_finding(
            title, severity, f"awk-urlmine/{kind}", value,
            location or "pasted text",
            mc_tpl.replace("<source>", location or "src.txt")))

    if log:
        log(f"awktools: urlmine matches={len(matches)} "
            f"findings={len(findings)}")
    return _result(findings=findings, requests_sent=1, ran=["urlmine"],
                   surface={"urls": surface_urls[:200],
                            "matches": matches[:200]})


def run_awk_suite(target, fetch=None, log=None, gate_open_fn=None):
    """Convenience suite: fetch the target body and mine it.
    Without a fetch callable the suite is contained-skipped."""
    target = str(target or "")
    if not _gate_open(gate_open_fn):
        return _result(skipped={GATE_KEY:
                                "polyglot gate closed (PTK_POLYGLOT)"})
    if not target:
        return _result(skipped={GATE_KEY: "empty target"})
    if fetch is None:
        return _result(skipped={GATE_KEY: "no fetch callable available"})
    try:
        resp = fetch(target)
        body = getattr(resp, "text", None)
        if body is None:
            body = str(resp)
    except Exception as e:
        return _result(skipped={GATE_KEY: f"fetch failed: {e}"})
    return run_urlmine(body, log=log, gate_open_fn=gate_open_fn,
                       location=target)
