"""External accuracy benchmark for OMEGA against a real vulnerable app.

Default target: OWASP Juice Shop public demo (https://juice-shop.herokuapp.com).
Override with the OMEGA_BENCH_TARGET environment variable (e.g. a local
docker instance). Budget via OMEGA_BENCH_BUDGET (seconds, default 600).

Design principles (mirrors the honesty contract in omega.scanning.fusion):
  - Findings are reported as "detected signals" against a ground-truth
    catalog of Juice Shop challenge classes. NEVER auto-marked as
    confirmed vulnerabilities.
  - HIGH/CRIT findings that match no catalog class are listed as
    "FP suspects" for manual review, never silently dropped.
  - The public demo is flaky: bounded retries, timeout containment, and
    a clear TARGET UNREACHABLE verdict (exit code 3) instead of a false
    0% score. This module never raises to the caller.

Pure scoring helpers (load_catalog, _finding_text, matches_hint, score)
are importable and unit-tested hermetically in tests/test_bench.py.

Usage:
    python lab/bench_ext.py                # Juice Shop default
    OMEGA_BENCH_TARGET=http://127.0.0.1:3000 python lab/bench_ext.py

Exit codes: 0 = scored, 3 = target unreachable, 2 = other fatal problem
(still prints a verdict, never a traceback).
"""
import json
import os
import sys
import time
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
LAB_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CATALOG = os.path.join(LAB_DIR, "bench_catalog.json")
DEFAULT_TARGET = "https://juice-shop.herokuapp.com"
UNREACHABLE_EXIT = 3
FATAL_EXIT = 2

SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def load_catalog(path=DEFAULT_CATALOG):
    """Load the ground-truth catalog; falls back to empty list (never raises)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        classes = data.get("classes") if isinstance(data, dict) else data
        return [c for c in (classes or []) if isinstance(c, dict)]
    except Exception:
        return []


def _finding_text(finding):
    """Concatenate the searchable fields of a finding, lowercased."""
    parts = []
    for key in ("title", "location", "param", "evidence",
                "verification_note", "category"):
        val = finding.get(key)
        if val:
            parts.append(str(val))
    return " ".join(parts).lower()


def matches_hint(finding, hint_tokens):
    """True if any hint token appears in the finding's searchable text."""
    text = _finding_text(finding)
    return any(str(tok).lower() in text for tok in hint_tokens)


def _is_high(severity):
    return SEV_ORDER.get(str(severity).upper(), 0) >= SEV_ORDER["HIGH"]


def score(catalog, findings):
    """Score findings against the catalog.

    Returns:
        {
          "tp": [{id, category, severity, finding}, ...],   # matched classes
          "missed": [catalog entries with zero matching findings],
          "fp_suspects": [HIGH/CRIT findings matching no class],
          "detected_classes": n, "total_classes": n,
        }
    Findings are reported as detected-signal only; nothing here asserts
    a confirmed vulnerability.
    """
    tp, matched_ids = [], set()
    for entry in catalog:
        hints = entry.get("check_hint") or []
        hit = next((f for f in findings if matches_hint(f, hints)), None)
        if hit is not None:
            matched_ids.add(entry.get("id"))
            tp.append({"id": entry.get("id"),
                       "category": entry.get("category"),
                       "severity": entry.get("expected_severity"),
                       "finding": hit})
    missed = [e for e in catalog if e.get("id") not in matched_ids]
    fp_suspects = [f for f in findings
                   if _is_high(f.get("severity"))
                   and not any(matches_hint(f, e.get("check_hint") or [])
                               for e in catalog)]
    return {"tp": tp, "missed": missed, "fp_suspects": fp_suspects,
            "detected_classes": len(tp), "total_classes": len(catalog)}


def render_report(target, result, score_res, elapsed_s):
    """Render a markdown accuracy report (detected-signal language only)."""
    lines = [
        "# OMEGA external accuracy benchmark",
        "",
        f"**Target:** `{target}`",
        f"**Elapsed:** {elapsed_s:.1f}s",
        f"**Suites ran:** {len(result.get('ran') or [])}"
        f" | **skipped:** {len(result.get('skipped') or [])}"
        f" | **findings:** {len(result.get('findings') or [])}",
        "",
        "## Coverage table (detected signals — NOT confirmed vulns)",
        "",
        "| id | category | expected sev | signal | evidence location |",
        "| --- | --- | --- | --- | --- |",
    ]
    all_rows = []
    for tp in score_res["tp"]:
        f = tp["finding"]
        all_rows.append((tp["id"], tp["category"], tp.get("severity") or "?",
                         "yes", str(f.get("location", ""))[:60]))
    for e in score_res["missed"]:
        all_rows.append((e.get("id"), e.get("category"),
                         e.get("expected_severity") or "?", "no", "-"))
    for rid, cat, sev, sig, loc in all_rows:
        lines.append(f"| {rid} | {cat} | {sev} | {sig} | {loc} |")
    detected = score_res["detected_classes"]
    total = max(score_res["total_classes"], 1)
    lines += [
        "",
        f"**Detected signal classes:** {detected}/{total}"
        f" ({100.0 * detected / total:.0f}%)",
        "",
        "## FP suspects (HIGH/CRIT findings matching no catalog class)",
        "",
    ]
    if score_res["fp_suspects"]:
        for f in score_res["fp_suspects"]:
            lines.append(f"- [{f.get('severity')}] {f.get('title')} @ "
                         f"{f.get('location')} — manual review required")
    else:
        lines.append("_none_")
    lines += [
        "",
        "All rows above are *detected signals* mapped to known challenge",
        "classes. None is asserted as a confirmed vulnerability; each",
        "requires manual verification.",
        "",
    ]
    return "\n".join(lines)


def check_reachable(target, attempts=3, timeout_s=20):
    """Bounded reachability probe with retries. Returns True/False."""
    url = target if "://" in target else "https://" + target
    last_err = None
    for _ in range(attempts):
        try:
            req = urllib.request.Request(url, method="GET", headers={
                "User-Agent": "omega-bench-ext/1.0"})
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                if resp.status < 500:
                    return True
        except Exception as exc:
            last_err = exc
        time.sleep(2)
    print(f"[bench-ext] target probe failed after {attempts} attempts: "
          f"{last_err}")
    return False


def run_bench(target=None, budget=None, fetch=None):
    """Run the full external bench. Never raises. Returns (verdict, report,
    exit_code)."""
    target = target or os.environ.get("OMEGA_BENCH_TARGET", DEFAULT_TARGET)
    budget = budget or int(os.environ.get("OMEGA_BENCH_BUDGET", "600"))
    if not check_reachable(target):
        report = (f"# OMEGA external accuracy benchmark\n\n"
                  f"**Verdict: TARGET UNREACHABLE** — `{target}` did not\n"
                  f"respond after bounded retries. No score reported\n"
                  f"(a 0% score here would be meaningless).\n")
        return "TARGET UNREACHABLE", report, UNREACHABLE_EXIT
    try:
        from omega.scanning.fusion import fuse
        start = time.monotonic()
        result = fuse(target, budget=budget, allowlist=True)
        elapsed = time.monotonic() - start
    except Exception as exc:
        report = (f"# OMEGA external accuracy benchmark\n\n"
                  f"**Verdict: BENCH FAILED** (fatal: {type(exc).__name__}).\n")
        return "BENCH FAILED", report, FATAL_EXIT
    catalog = load_catalog()
    score_res = score(catalog, result.get("findings") or [])
    report = render_report(target, result, score_res, elapsed)
    out_path = os.path.join(LAB_DIR, "bench_ext_report.md")
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(report)
    except Exception:
        out_path = None
    print(report)
    if out_path:
        print(f"[bench-ext] report saved: {out_path}")
    return "SCORED", report, 0


def main():
    verdict, _report, code = run_bench()
    print(f"[bench-ext] verdict: {verdict} (exit {code})")
    return code


if __name__ == "__main__":
    sys.exit(main())
