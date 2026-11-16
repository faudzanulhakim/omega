"""omega/adapters/node_hdr.py — Node-backed HTTP header security adapter.

Runs omega/adapters/node/hdrscore.mjs (pure-Node header scorer) over the
response headers of one target. Gated behind env PTK_POLYGLOT=1 like the
other polyglot adapters; skipped gracefully when ``node`` is missing.

Contract:
  run_hdrscore(target, fetch, log=None, which_fn=shutil.which)
      -> {"findings": [...], "ran": [...], "skipped": [...],
          "requests_sent": N}
  Never raises: every failure mode is contained into ``skipped`` with a
  reason. ``fetch`` follows the omega.probes contract:
      fetch(method, url, headers=None, body=None)
          -> (status, headers, body_bytes)

Findings follow the ENGINE convention (title/severity/confidence/
verification='candidate'/source/evidence<=300/location/manual_check).
One summary finding per scorer issue id (source 'node-hdr/<id>') plus one
INFO inventory finding carrying the score and grade. manual_check is a
real curl -sI command against the real target.

All code and messages in English.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request

ADAPTER_DIR = os.path.dirname(os.path.abspath(__file__))
HDRSCORE_MJS = os.path.join(ADAPTER_DIR, "node", "hdrscore.mjs")

NODE_TIMEOUT_S = 30
MAX_NODE_OUTPUT_BYTES = 1024 * 1024      # 1MB output cap
MAX_REQUESTS = 3                          # hard request cap for this suite
SUITE_NAME = "node-hdr"

# issue id -> finding severity (honest mapping; n-a issues are INFO)
SEVERITY_BY_ID = {
    "hsts-missing": "high",
    "csp-missing": "high",
    "csp-unsafe": "medium",
    "frame-deny-missing": "medium",
    "referrer-missing": "low",
    "permissions-missing": "low",
    "cto-missing": "low",
    "cookie-flags": "medium",
}


def _default_fetch(method, url, headers=None, body=None):
    """Stdlib fetch with the probes contract (never raises)."""
    req = urllib.request.Request(
        url, method=method,
        headers=headers or {"User-Agent": "omega-node-hdr/1.0"},
        data=body)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, dict(resp.headers.items()), resp.read(65536)
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(65536) if hasattr(exc, "read") else b""
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


def _collect_headers(results):
    """Merge (status, headers, body) fetch results into a header dict.

    set-cookie entries are newline-joined so hdrscore.mjs can evaluate
    each cookie separately.
    """
    merged = {}
    for _status, hdrs, _body in results:
        if isinstance(hdrs, dict):
            items = hdrs.items()
        else:
            try:
                items = dict(hdrs).items()
            except Exception:
                items = []
        for k, v in items:
            lk = str(k).lower()
            sv = str(v)
            if lk == "set-cookie":
                merged.setdefault(lk, []).append(sv)
            else:
                merged[lk] = sv
    if "set-cookie" in merged:
        merged["set-cookie"] = "\n".join(merged["set-cookie"])
    return merged


def _finding(title, severity, evidence, source, target):
    return {
        "title": title,
        "severity": severity,
        "confidence": "candidate",
        "verification": "candidate",
        "source": source,
        "evidence": str(evidence or "")[:300],
        "location": target,
        "manual_check": f"curl -sI {target}",
    }


def run_hdrscore(target, fetch, log=None, which_fn=shutil.which):
    """Header security suite. Never raises; failures land in ``skipped``."""
    result = {"findings": [], "ran": [], "skipped": [], "requests_sent": 0}

    # Polyglot gate (same convention as omega/adapters/native.py).
    if os.environ.get("PTK_POLYGLOT") != "1":
        result["skipped"].append({
            "suite": SUITE_NAME,
            "reason": "PTK_POLYGLOT not set; polyglot adapters disabled"})
        return result

    base = _norm_base_url(target)

    try:
        node = which_fn("node")
    except Exception:
        node = None
    if not node:
        result["skipped"].append({
            "suite": SUITE_NAME, "reason": "node unavailable"})
        return result

    if not os.path.isfile(HDRSCORE_MJS):
        result["skipped"].append({
            "suite": SUITE_NAME, "reason": "hdrscore.mjs not found"})
        return result

    # Request phase: one GET plus one OPTIONS (cookie/preflight info),
    # within the cap of 3 counted requests.
    responses = []
    for method in ("GET", "OPTIONS"):
        try:
            status, hdrs, body = _run_fetch(fetch, method, base + "/")
        except Exception as exc:  # defensive; _run_fetch already contains
            status, hdrs, body = 0, {}, str(exc).encode("utf-8", "replace")
        result["requests_sent"] += 1
        if result["requests_sent"] > MAX_REQUESTS:
            break
        responses.append((status, hdrs, body))

    get_status = responses[0][0] if responses else 0
    if not get_status:
        result["skipped"].append({
            "suite": SUITE_NAME,
            "reason": f"target unreachable (status {get_status}); "
                      "header scoring skipped"})
        return result

    payload = json.dumps({
        "headers": _collect_headers(responses),
        "url": base,
    })

    # Scorer phase: contained subprocess call (30s timeout, 1MB output cap).
    try:
        proc = subprocess.run(
            [node, HDRSCORE_MJS], input=payload, capture_output=True,
            text=True, timeout=NODE_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        result["skipped"].append({
            "suite": SUITE_NAME, "reason": "hdrscore.mjs timed out"})
        return result
    except Exception as exc:
        result["skipped"].append({
            "suite": SUITE_NAME, "reason": f"node execution error: {exc}"})
        return result

    if proc.returncode != 0:
        result["skipped"].append({
            "suite": SUITE_NAME,
            "reason": f"hdrscore.mjs exited {proc.returncode}"})
        return result
    if len(proc.stdout.encode("utf-8", "replace")) > MAX_NODE_OUTPUT_BYTES:
        result["skipped"].append({
            "suite": SUITE_NAME, "reason": "scorer output exceeded 1MB cap"})
        return result

    try:
        report = json.loads(proc.stdout)
        if not isinstance(report, dict) or "score" not in report:
            raise ValueError("unexpected scorer output shape")
    except Exception as exc:
        result["skipped"].append({
            "suite": SUITE_NAME, "reason": f"malformed scorer output: {exc}"})
        return result

    result["ran"].append("node-hdr.hdrscore")
    if log:
        log("[node-hdr] score=%s grade=%s issues=%d" % (
            report.get("score"), report.get("grade"),
            len(report.get("issues") or [])))

    # One summary finding per issue id; INFO for non-issues (n-a / info).
    for issue in report.get("issues") or []:
        if not isinstance(issue, dict) or "id" not in issue:
            continue
        iid = str(issue["id"])
        sev = str(issue.get("severity") or "info")
        if sev not in ("info", "low", "medium", "high"):
            sev = "info"
        # n-a (not applicable) issues are informational only, never findings
        if str(issue.get("detail") or "").lower().startswith("n-a"):
            sev = "info"
        result["findings"].append(_finding(
            f"Header issue: {iid}", sev,
            f"{iid}: {issue.get('detail', '')}",
            f"{SUITE_NAME}/{iid}", base))

    # INFO inventory finding with score and grade.
    result["findings"].append(_finding(
        "Header security inventory", "info",
        "hdrscore score=%s grade=%s (%d issue(s))" % (
            report.get("score"), report.get("grade"),
            len(report.get("issues") or [])),
        f"{SUITE_NAME}/inventory", base))

    return result
