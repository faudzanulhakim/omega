"""omega/adapters/jqdiff.py — jq-backed differential response adapter.

Fetches a baseline response and probe responses for a target and runs
each (baseline, probe) pair through the compiled jq filter
omega/adapters/jq/diffstat.jq. Skipped gracefully when ``jq`` is
missing; malformed pairs are quarantined (fail-closed) in the same
spirit as omega/adapters/jqtools.py — never raised outward.

Contract:
  run_jqdiff(target, fetch, baseline_path=None, log=None,
             which_fn=shutil.which)
      -> {"findings": [...], "ran": [...], "skipped": [...],
          "requests_sent": N}
  ``fetch`` follows the omega.probes contract:
      fetch(method, url, headers=None, body=None)
          -> (status, headers, body_bytes)

Request budget: one baseline GET (target/ with a random inert marker
param) plus GET target/?q=MARKER and up to 3 reflection candidate
params — hard cap 6 counted requests.

Findings follow the ENGINE convention (verification is always
"candidate"): >= 5 new tokens in a probe body yields a candidate LOW
"differential token leak" (source 'jq-diff/<param>'); otherwise an INFO
inventory finding only. manual_check is a real curl command against the
real target.

All code and messages in English.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import urllib.error
import urllib.request

ADAPTER_DIR = os.path.dirname(os.path.abspath(__file__))
DIFFSTAT_JQ = os.path.join(ADAPTER_DIR, "jq", "diffstat.jq")

JQ_TIMEOUT_S = 30
MAX_REQUESTS = 6              # hard cap, counted in requests_sent
MAX_PROBES = 4                # q=MARKER + up to 3 reflection candidates
CANDIDATE_PARAMS = ("search", "id", "page")
NEW_TOKEN_THRESHOLD = 5
SUITE_NAME = "jq-diff"


def _default_fetch(method, url, headers=None, body=None):
    """Stdlib fetch with the probes contract (never raises)."""
    req = urllib.request.Request(
        url, method=method,
        headers=headers or {"User-Agent": "omega-jqdiff/1.0"},
        data=body)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, dict(resp.headers.items()), resp.read(1024 * 1024)
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(1024 * 1024) if hasattr(exc, "read") else b""
        except Exception:
            raw = b""
        return exc.code, (dict(exc.headers.items()) if exc.headers else {}), raw
    except Exception as exc:
        return 0, {}, str(exc).encode("utf-8", "replace")


def _norm_base_url(target):
    """Normalize a target into a scheme-qualified base URL."""
    t = str(target or "").strip()
    if "://" not in t:
        t = "https://" + t
    return t.rstrip("/")


def _run_fetch(fetch, method, url):
    """Call fetch with the full contract, tolerating simpler stubs."""
    try:
        return fetch(method, url, None, None)
    except TypeError:
        try:
            return fetch(method, url)
        except Exception as exc:
            return 0, {}, str(exc).encode("utf-8", "replace")
    except Exception as exc:
        return 0, {}, str(exc).encode("utf-8", "replace")


def _resp_object(res):
    """Turn a fetch result into the {status, headers, body} jq input."""
    status, hdrs, body = res
    if isinstance(hdrs, dict):
        headers = hdrs
    else:
        try:
            headers = dict(hdrs)
        except Exception:
            headers = {}
    if isinstance(body, str):
        text = body
    else:
        try:
            text = bytes(body).decode("utf-8", "replace")
        except Exception:
            text = ""
    return {"status": status, "headers": headers, "body": text}


def _run_jq_pair(pair_obj, which_fn=shutil.which):
    """Run one (baseline, probe) pair through diffstat.jq.

    Returns the parsed dict or raises; callers contain the errors.
    """
    proc = subprocess.run(
        ["jq", "-c", "-f", DIFFSTAT_JQ],
        input=json.dumps(pair_obj), capture_output=True, text=True,
        timeout=JQ_TIMEOUT_S)
    if proc.returncode != 0:
        raise RuntimeError(
            f"jq exited {proc.returncode}: {proc.stderr.strip()[:200]}")
    return json.loads(proc.stdout)


def _finding(title, severity, evidence, source, target):
    return {
        "title": title,
        "severity": severity,
        "confidence": "candidate",
        "verification": "candidate",
        "source": source,
        "evidence": str(evidence or "")[:300],
        "location": target,
        "manual_check": f"curl -s '{target}'",
    }


def run_jqdiff(target, fetch, baseline_path=None, log=None,
               which_fn=shutil.which):
    """Differential response suite. Never raises; failures land in skipped."""
    result = {"findings": [], "ran": [], "skipped": [], "requests_sent": 0}

    # Polyglot gate (same convention as the other polyglot adapters).
    if os.environ.get("PTK_POLYGLOT") != "1":
        result["skipped"].append({
            "suite": SUITE_NAME,
            "reason": "PTK_POLYGLOT not set; polyglot adapters disabled"})
        return result

    base = _norm_base_url(target)

    try:
        jq = which_fn("jq")
    except Exception:
        jq = None
    if not jq:
        result["skipped"].append({
            "suite": SUITE_NAME, "reason": "jq binary not found"})
        return result

    if not os.path.isfile(DIFFSTAT_JQ):
        result["skipped"].append({
            "suite": SUITE_NAME, "reason": "diffstat.jq not found"})
        return result

    marker = "omegamrk" + secrets.token_hex(4)   # inert, unique per run

    # Baseline: file-provided (offline diff) or one GET with an inert
    # marker param that the app should not reflect.
    baseline_obj = None
    if baseline_path:
        try:
            with open(baseline_path, "r", encoding="utf-8", errors="replace") as fh:
                baseline_obj = json.load(fh)
        except Exception as exc:
            result["skipped"].append({
                "suite": SUITE_NAME,
                "reason": f"baseline file unreadable/unparsable: {exc}"})
            return result
        if not isinstance(baseline_obj, dict):
            result["skipped"].append({
                "suite": SUITE_NAME,
                "reason": "baseline file is not a JSON response object"})
            return result
    else:
        try:
            res = _run_fetch(fetch, "GET",
                             f"{base}/?_omega_marker={marker}")
        except Exception as exc:
            res = (0, {}, str(exc).encode("utf-8", "replace"))
        result["requests_sent"] += 1
        status = res[0] if isinstance(res, (tuple, list)) else 0
        if not status:
            result["skipped"].append({
                "suite": SUITE_NAME,
                "reason": f"target unreachable (status {status}); "
                          "differential skipped"})
            return result
        baseline_obj = _resp_object(res)

    # Probes: q=MARKER plus up to 3 reflection candidate params,
    # bounded by both MAX_PROBES and the overall request cap.
    probe_params = ["q"] + list(CANDIDATE_PARAMS)[: MAX_PROBES - 1]
    token_counts = {}
    for param in probe_params:
        if result["requests_sent"] >= MAX_REQUESTS:
            result["skipped"].append({
                "suite": SUITE_NAME,
                "reason": "request cap reached; remaining probes skipped"})
            break
        try:
            res = _run_fetch(fetch, "GET", f"{base}/?{param}={marker}")
        except Exception as exc:
            res = (0, {}, str(exc).encode("utf-8", "replace"))
        result["requests_sent"] += 1

        probe_status = res[0] if isinstance(res, (tuple, list)) else 0
        if not probe_status:
            result["skipped"].append({
                "pair": param,
                "reason": f"probe unreachable (status {probe_status})"})
            continue

        pair_obj = {"baseline": baseline_obj, "probe": _resp_object(res)}
        try:
            stat = _run_jq_pair(pair_obj, which_fn=which_fn)
        except Exception as exc:
            # Fail closed: quarantine the pair, no findings from it.
            result["skipped"].append({
                "pair": param, "reason": f"quarantined: jq diff error: {exc}"})
            continue
        if not isinstance(stat, dict) or "new_tokens" not in stat:
            result["skipped"].append({
                "pair": param,
                "reason": "quarantined: unexpected diffstat output shape"})
            continue

        result["ran"].append(f"{SUITE_NAME}.{param}")
        tokens = stat.get("new_tokens") or []
        token_counts[param] = len(tokens)
        if len(tokens) >= NEW_TOKEN_THRESHOLD:
            sample = ", ".join(str(t)[:60] for t in tokens[:5])
            result["findings"].append(_finding(
                f"Differential token leak via parameter '{param}'",
                "low",
                f"{len(tokens)} new token(s) in probe body vs baseline "
                f"(status_delta={stat.get('status_delta')}); sample: {sample}",
                f"{SUITE_NAME}/{param}", f"{base}/?{param}={marker}"))

    # INFO inventory finding summarizing the differential run.
    result["findings"].append(_finding(
        "Differential response inventory", "info",
        "params=%s new_token_counts=%s baseline=%s" % (
            ",".join(probe_params), json.dumps(token_counts, sort_keys=True),
            "file" if baseline_path else "fetched"),
        f"{SUITE_NAME}/inventory", base))

    if log:
        log("[jq-diff] params=%d token_counts=%s skipped=%d" % (
            len(probe_params), token_counts, len(result["skipped"])))

    return result
