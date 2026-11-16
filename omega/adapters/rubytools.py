"""omega/adapters/rubytools — Python runner for the Ruby polyglot adapter.

Drives omega/adapters/ruby/urlaudit.rb (stdlib-only Ruby script) for
suspicious URL SHAPE analysis. Everything is gated behind PTK_POLYGLOT=1
and never raises outward: gate closed, missing ruby, subprocess timeouts
and malformed JSON all become contained entries in result['skipped'].

Findings contract: title/severity/confidence('candidate')/
verification('candidate')/source/evidence(<=300)/location/manual_check
(real shell command against the real target). These are SHAPE detections
(suspicious URL structures), not confirmed vulnerabilities.
"""
import json
import os
import shutil
import subprocess

from omega.adapters import native

OUTPUT_CAP = 1 * 1024 * 1024          # subprocess stdout cap (1 MB)
SUBPROC_TIMEOUT = 30                  # seconds per tool run
FINDING_EVIDENCE_CAP = native.FINDING_EVIDENCE_CAP

RUBY_DIR = os.path.join(native.PACKAGE_DIR, "ruby")
URLAUDIT_SCRIPT = os.path.join(RUBY_DIR, "urlaudit.rb")
GATE_KEY = "rubytools"

# check name -> severity + human hint (shape detections only)
CHECK_SEVERITY = {
    "sqli_shape": "MEDIUM",
    "ssti_shape": "MEDIUM",
    "open_redirect_shape": "LOW",
    "xss_shape": "LOW",
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
            "shape detection from a Ruby stdlib adapter: the URL merely "
            "has a suspicious structure — verify manually before acting"),
        "source": source,
        "evidence": ev,
        "location": location,
        "manual_check": manual_check,
    }


def _run_urlaudit_script(urls):
    """Run urlaudit.rb with NDJSON on stdin; return (list of rows, err).

    Output capped at OUTPUT_CAP before parsing; one malformed line
    aborts the batch as a contained error.
    """
    if not os.path.exists(URLAUDIT_SCRIPT):
        return None, "urlaudit.rb not found"
    stdin_data = "".join(
        json.dumps({"url": str(u)}) + "\n" for u in urls
    ).encode("utf-8")
    try:
        proc = subprocess.run(
            ["ruby", URLAUDIT_SCRIPT], input=stdin_data,
            capture_output=True, timeout=SUBPROC_TIMEOUT)
    except FileNotFoundError:
        return None, "ruby binary not found"
    except subprocess.TimeoutExpired:
        return None, f"timeout after {SUBPROC_TIMEOUT}s (process killed)"
    except Exception as e:
        return None, f"subprocess error: {e}"
    out = proc.stdout[:OUTPUT_CAP]  # hard 1 MB cap before parsing
    rows = []
    for line in out.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            return None, "invalid JSON from tool stdout"
        except Exception as e:
            return None, f"parse error: {e}"
    return rows, None


def _check_findings(row):
    """Turn urlaudit checks into findings (FP guard: all-false -> none)."""
    checks = row.get("checks") or {}
    url = str(row.get("url") or "")
    findings = []
    for check, severity in CHECK_SEVERITY.items():
        if checks.get(check):
            findings.append(_finding(
                f"Suspicious URL shape detected: {check}",
                severity,
                f"ruby-urlaudit/{check}",
                url,  # evidence = the URL itself (shape detection)
                url,
                f"curl -sv --max-redirs 0 '{url}' 2>&1 | head -30",
                note=(
                    f"shape detection ({check}): the URL merely contains a "
                    f"suspicious structure — verify manually before acting")))
    return findings


def run_ruby_urlaudit(urls, log=None, gate_open_fn=None):
    """Analyze URL strings with the urlaudit.rb script. Never raises."""
    if urls is None:
        urls = []
    elif not isinstance(urls, (list, tuple, set)):
        urls = [urls]
    urls = [str(u) for u in urls if u is not None and str(u)]

    if not _gate_open(gate_open_fn):
        return _result(skipped={GATE_KEY:
                                "polyglot gate closed (PTK_POLYGLOT)"})
    if not shutil.which("ruby"):
        return _result(skipped={GATE_KEY: "ruby unavailable"})

    rows, err = _run_urlaudit_script(urls)
    if rows is None:
        return _result(skipped={GATE_KEY: f"urlaudit: {err}"})

    findings = []
    for row in rows:
        if row.get("error"):
            continue  # per-line errors are contained, not findings
        findings.extend(_check_findings(row))

    if log:
        log(f"rubytools: urlaudit urls={len(urls)} findings={len(findings)}")
    return _result(findings=findings, requests_sent=len(urls),
                   ran=["urlaudit"],
                   surface={"urlaudit": rows})


def build_suite_urls(target):
    """Suspect URL variants for a target (like the C suite, tuned for
    sqli/ssti/open-redirect shapes)."""
    target = str(target or "").rstrip("/")
    if not target:
        return []
    return [
        target + "/",
        target + "/search?q=1%27+OR+%271%27%3D%271",
        target + "/render?q=%7B%7B7*7%7D%7D",
        target + "/next?url=%2F%2Fevil.example",
        target + "/?next=//evil.example",
    ]


def run_ruby_suite(target, fetch=None, log=None, gate_open_fn=None):
    """Convenience suite: run the audit on suspect URL variants."""
    urls = build_suite_urls(target)
    if not urls:
        return _result(skipped={GATE_KEY: "empty target"})
    return run_ruby_urlaudit(urls, log=log, gate_open_fn=gate_open_fn)
