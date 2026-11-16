"""omega/adapters/phptools — Python runner for the PHP polyglot adapter.

Drives omega/adapters/php/seriscan.php (php-cli, stdlib only) — a
static scan of a pasted PHP snippet for dangerous call patterns:
unserialize(), eval(), and the system() family. Text in, JSON out,
no network. Graceful skip when php is absent (result['skipped']).

Everything is gated behind PTK_POLYGLOT=1 and never raises outward:
gate closed, missing php, subprocess timeouts and malformed JSON all
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

PHP_DIR = os.path.join(native.PACKAGE_DIR, "php")
SERISCAN_SCRIPT = os.path.join(PHP_DIR, "seriscan.php")
GATE_KEY = "phptools"

# kind -> (severity, title)
KIND_SEVERITY = {
    "unserialize": ("HIGH",
                    "PHP unserialize() call candidate (deserialization "
                    "risk)"),
    "eval": ("HIGH", "PHP eval() call candidate (code execution)"),
    "system": ("HIGH", "PHP system-family call candidate "
               "(system/shell_exec/passthru/exec/proc_open/popen)"),
}


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
        ev = ev[:FINDING_EVIDENCE_CAP] + "…"
    return {
        "title": title,
        "severity": severity,
        "confidence": "candidate",
        "verification": "candidate",
        "verification_note": note or (
            "static call-pattern candidate from a PHP adapter: the "
            "snippet merely contains the call — verify manually "
            "(data flow, reachability) before acting"),
        "source": source,
        "evidence": ev,
        "location": location,
        "manual_check": manual_check,
    }


def _run_seriscan(code):
    """Run seriscan.php over a snippet; return (report dict, err)."""
    if not os.path.exists(SERISCAN_SCRIPT):
        return None, "seriscan.php not found"
    try:
        proc = subprocess.run(
            ["php", SERISCAN_SCRIPT],
            input=str(code or "").encode("utf-8"),
            capture_output=True, timeout=SUBPROC_TIMEOUT)
    except FileNotFoundError:
        return None, "php binary not found"
    except subprocess.TimeoutExpired:
        return None, f"timeout after {SUBPROC_TIMEOUT}s (process killed)"
    except Exception as e:
        return None, f"subprocess error: {e}"
    out = proc.stdout[:OUTPUT_CAP]
    try:
        obj = json.loads(out.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return None, "invalid JSON from tool stdout"
    except Exception as e:
        return None, f"parse error: {e}"
    if not isinstance(obj, dict) or not isinstance(
            obj.get("findings"), list):
        return None, "unexpected JSON shape from tool stdout"
    return obj, None


def run_seriscan(code, log=None, gate_open_fn=None, location=None):
    """Statically scan a PHP snippet for dangerous call patterns.
    Never raises."""
    if not _gate_open(gate_open_fn):
        return _result(skipped={GATE_KEY:
                                "polyglot gate closed (PTK_POLYGLOT)"})
    if not shutil.which("php"):
        return _result(skipped={GATE_KEY: "php unavailable"})

    report, err = _run_seriscan(code)
    if report is None:
        return _result(skipped={GATE_KEY: f"seriscan: {err}"})

    loc = location or "pasted snippet"
    findings = []
    for hit in report.get("findings") or []:
        kind = str(hit.get("kind") or "")
        if kind not in KIND_SEVERITY:
            continue
        if len(findings) >= FINDING_CAP:
            break
        line = int(hit.get("line") or 0)
        severity, title = KIND_SEVERITY[kind]
        if kind == "system":
            pattern = "(system|shell_exec|passthru|exec|proc_open|popen)"
        else:
            pattern = kind
        findings.append(_finding(
            title, severity, f"php-seriscan/{kind}",
            f"line {line}: {hit.get('match') or ''}".strip(),
            f"{loc}:{line}",
            f"grep -nE '\\b{pattern}\\s*\\(' '{loc}'"))

    if log:
        log(f"phptools: seriscan hits={len(report.get('findings') or [])} "
            f"findings={len(findings)}")
    return _result(findings=findings, requests_sent=0, ran=["seriscan"],
                   surface={"seriscan": report})


def run_php_suite(target, fetch=None, log=None, gate_open_fn=None):
    """Convenience suite: fetch the target body and statically scan
    it as a PHP snippet (contained skip without a fetch callable)."""
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
    return run_seriscan(body, log=log, gate_open_fn=gate_open_fn,
                        location=target)
