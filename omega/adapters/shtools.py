"""omega/adapters/shtools — Python runner for the bash polyglot adapter.

Drives omega/adapters/sh/methodcheck.sh (bash + curl) to audit HTTP
methods on a target: GET/HEAD/OPTIONS probes plus a body-empty
POST-safe POST and a single TRACE detection request. Compares Allow
headers and flags TRACE enablement / broad Allow disclosure.

Everything is gated behind PTK_POLYGLOT=1 and never raises outward:
gate closed, missing bash/curl, subprocess timeouts and malformed
JSON all become contained entries in result['skipped'].

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
SUBPROC_TIMEOUT = 90                  # seconds per tool run (5 curl probes)
FINDING_EVIDENCE_CAP = native.FINDING_EVIDENCE_CAP

SH_DIR = os.path.join(native.PACKAGE_DIR, "sh")
METHODCHECK_SCRIPT = os.path.join(SH_DIR, "methodcheck.sh")
GATE_KEY = "shtools"

DANGEROUS_ALLOW = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}


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
            "method-probe candidate from a bash adapter — verify "
            "manually (and confirm the method is really accepted and "
            "consequential) before acting"),
        "source": source,
        "evidence": ev,
        "location": location,
        "manual_check": manual_check,
    }


def _run_methodcheck(url):
    """Run methodcheck.sh against url; return (list of rows, err)."""
    if not os.path.exists(METHODCHECK_SCRIPT):
        return None, "methodcheck.sh not found"
    try:
        proc = subprocess.run(
            ["bash", METHODCHECK_SCRIPT, str(url)],
            capture_output=True, timeout=SUBPROC_TIMEOUT)
    except FileNotFoundError:
        return None, "bash binary not found"
    except subprocess.TimeoutExpired:
        return None, f"timeout after {SUBPROC_TIMEOUT}s (process killed)"
    except Exception as e:
        return None, f"subprocess error: {e}"
    out = proc.stdout[:OUTPUT_CAP]
    rows = []
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
        rows.append(obj)
    return rows, None


def _row_findings(row):
    """Turn one method-probe row into findings (FP guard: benign -> none)."""
    method = str(row.get("method") or "").upper()
    status = int(row.get("status") or 0)
    allow = str(row.get("allow") or "").upper()
    url = str(row.get("url") or "")
    findings = []
    mc = f"curl -s -o /dev/null -w '%{{http_code}}' -X {method} '{url}'"
    if method == "TRACE" and 200 <= status < 300:
        findings.append(_finding(
            "TRACE method enabled on target",
            "HIGH",
            "sh-methodcheck/trace_enabled",
            f"{url} — TRACE returned HTTP {status} (Cross-Site "
            f"Tracing exposure candidate)",
            url, mc,
            note="TRACE succeeded with a 2xx status — confirm it is "
                 "not a proxy artifact before acting"))
    if method == "OPTIONS":
        disclosed = sorted(DANGEROUS_ALLOW & {m.strip()
                                              for m in allow.split(",")})
        if disclosed:
            findings.append(_finding(
                f"OPTIONS Allow header discloses dangerous methods: "
                f"{', '.join(disclosed)}",
                "MEDIUM",
                "sh-methodcheck/options_discloses_dangerous",
                f"{url} — Allow: {allow}",
                url, mc.replace("-X OPTIONS", "-X OPTIONS"),
                note="Allow-header disclosure only — the listed "
                     "methods may still be rejected at the router; "
                     "verify individually"))
    return findings


def run_methodcheck(url, log=None, gate_open_fn=None):
    """Audit one target URL's HTTP methods. Never raises."""
    url = str(url or "")
    if not _gate_open(gate_open_fn):
        return _result(skipped={GATE_KEY:
                                "polyglot gate closed (PTK_POLYGLOT)"})
    if not shutil.which("bash"):
        return _result(skipped={GATE_KEY: "bash unavailable"})
    if not shutil.which("curl") and \
            not os.environ.get("OMEGA_CURL"):
        return _result(skipped={GATE_KEY: "curl unavailable"})
    if "://" not in url:
        url = "http://" + url

    rows, err = _run_methodcheck(url)
    if rows is None:
        return _result(skipped={GATE_KEY: f"methodcheck: {err}"})

    # annotate rows with the url for downstream findings
    for r in rows:
        r.setdefault("url", url)
    findings = []
    for row in rows:
        if row.get("error"):
            continue
        findings.extend(_row_findings(row))

    if log:
        log(f"shtools: methodcheck url={url} findings={len(findings)}")
    return _result(findings=findings, requests_sent=len(rows),
                   ran=["methodcheck"], surface={"methods": rows})


def run_sh_suite(target, fetch=None, log=None, gate_open_fn=None):
    """Convenience suite: method-audit the target URL itself (the
    bash adapter talks to the target directly with curl; fetch is
    not required)."""
    target = str(target or "")
    if not target:
        return _result(skipped={GATE_KEY: "empty target"})
    return run_methodcheck(target, log=log, gate_open_fn=gate_open_fn)
