"""omega/adapters/jqtools.py — jq-backed data-hygiene adapter.

Uses the external ``jq`` binary (skipped gracefully when missing) with a
compiled jq program (omega/adapters/validate.jq) to validate and
normalize findings produced by the other fusion scanners.

Contract:
  * normalize_findings(raw_findings, which_fn=shutil.which)
      -> {"valid": [...], "quarantined": [{"finding", "reason"}, ...]}
      Never raises. Findings are validated as JSON lines through jq;
      anything that is not a JSON object carrying title / severity /
      confidence / verification is quarantined.
  * run_jq_suite(findings, log=None, which_fn=shutil.which)
      -> {"findings": valid findings, "quarantined": [...],
          "ran": [...], "skipped": [{"suite", "reason"}]}
      The fusion data-hygiene layer entry point.

All code and messages in English.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

ADAPTER_DIR = os.path.dirname(os.path.abspath(__file__))
VALIDATE_JQ = os.path.join(ADAPTER_DIR, "validate.jq")

REQUIRED_KEYS = ("title", "severity", "confidence", "verification")
JQ_TIMEOUT_S = 30


def _jq_available(which_fn=shutil.which):
    try:
        return which_fn("jq") is not None
    except Exception:
        return False


def _validate_via_jq(objects, which_fn=shutil.which):
    """Run each object through the compiled validate.jq program.

    Returns {index: bool} verdict map (True = valid). jq is invoked once
    over the JSON-lines payload; a missing verdict line means the object
    was not reliably validated (treated as invalid -> quarantined).
    """
    lines = "".join(json.dumps(o) + "\n" for o in objects)
    proc = subprocess.run(
        ["jq", "-c", "-f", VALIDATE_JQ],
        input=lines, capture_output=True, text=True, timeout=JQ_TIMEOUT_S)
    verdicts = {}
    if proc.returncode != 0:
        # jq itself failed: nothing gets a verdict (all quarantined)
        return verdicts
    for i, ln in enumerate(proc.stdout.splitlines()):
        ln = ln.strip()
        if ln:
            verdicts[i] = (ln == "true")
    return verdicts


def normalize_findings(raw_findings, which_fn=shutil.which):
    """Validate raw findings with the compiled jq program.

    Returns {"valid": [...], "quarantined": [{"finding", "reason"}]}.
    Never raises: internal errors quarantine rather than propagate.
    """
    valid, quarantined = [], []

    if not _jq_available(which_fn):
        # jq missing: the whole layer is skipped by run_jq_suite; for a
        # direct call we fail closed (quarantine everything) — callers
        # that want pass-through handle the skip themselves.
        for f in (raw_findings or []):
            quarantined.append({
                "finding": f,
                "reason": "jq binary not found; finding not validated"})
        return {"valid": valid, "quarantined": quarantined}

    # Pre-parse: only JSON-serializable objects go through jq; a Python
    # non-object or unserializable value is quarantined immediately.
    to_check, index_map = [], []
    for f in (raw_findings or []):
        try:
            json.dumps(f)
            to_check.append(f if isinstance(f, dict) else {})
            index_map.append(f)
        except (TypeError, ValueError):
            quarantined.append({
                "finding": f,
                "reason": "finding is not JSON-serializable"})

    if not to_check:
        return {"valid": valid, "quarantined": quarantined}

    try:
        verdicts = _validate_via_jq(to_check, which_fn)
    except Exception as exc:
        for f in index_map:
            quarantined.append({
                "finding": f,
                "reason": f"jq validation error: {exc}"})
        return {"valid": valid, "quarantined": quarantined}

    for i, f in enumerate(index_map):
        ok = verdicts.get(i, False)
        if ok:
            valid.append(f)
        else:
            missing = [k for k in REQUIRED_KEYS
                       if not (isinstance(f, dict) and k in f)]
            reason = ("missing required key(s): " + ", ".join(missing)
                      if missing else
                      "not a JSON object with required finding keys")
            quarantined.append({"finding": f, "reason": reason})
    return {"valid": valid, "quarantined": quarantined}


def run_jq_suite(findings, log=None, which_fn=shutil.which):
    """Fusion jq data-hygiene suite.

    Normalizes/validates the collected findings through jq; invalid
    entries are returned in ``quarantined`` (fusion moves them into
    ``skipped`` with the reason). Never raises.
    """
    skipped = []
    if not _jq_available(which_fn):
        skipped.append({"suite": "jq",
                        "reason": "jq binary not found; data-hygiene "
                                  "validation skipped (pass-through)"})
        if log:
            log("[jq] skipped: jq binary not found")
        return {
            "findings": list(findings or []),
            "quarantined": [],
            "ran": [],
            "skipped": skipped,
        }

    res = normalize_findings(findings, which_fn=which_fn)
    ran = ["jq.validate"]
    if log:
        log("[jq] validated %d finding(s); quarantined %d" %
            (len(res["valid"]), len(res["quarantined"])))
    return {
        "findings": res["valid"],
        "quarantined": res["quarantined"],
        "ran": ran,
        "skipped": skipped,
    }
