"""omega/jsdeep.py — deep JS bundle reconnaissance (Node + Python fallback).

Orchestrates the analysis of fetched JS assets:
  * preferred: omega/adapters/node/jsdeep.mjs via ``node`` (Node excels at
    JS parsing; gated behind PTK_POLYGLOT=1 like the other polyglot
    adapters, skipped gracefully when node is missing)
  * fallback: pure-Python regex extraction with the same record shape

Findings follow the ENGINE convention (omega.deepchecks.Finding):
  * secret    -> HIGH, verification=candidate
  * endpoint  -> INFO, verification=candidate
  * sourcemap -> LOW (source disclosure)
Dedupe is on (kind, value); evidence is the matched line, clipped to
300 chars. ``run_jsdeep`` never raises; source=omega-jsdeep/<kind>.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

__all__ = [
    "Finding",
    "node_available",
    "run_node_jsdeep",
    "python_jsdeep",
    "collect_js_assets",
    "run_jsdeep",
]

from omega.deepchecks import Finding
from omega.probes import default_fetch

ADAPTER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JSDEEP_MJS = os.path.join(ADAPTER_DIR, "adapters", "node", "jsdeep.mjs")

NODE_TIMEOUT_S = 30
MAX_RECORDS = 2000

SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)["']""",
                           re.IGNORECASE)

SEVERITY_BY_KIND = {
    "secret": "high",
    "endpoint": "info",
    "host": "info",
    "operation": "info",
    "sourcemap": "low",
}

# ------------------------------------------------------- python fallback
# Mirrors jsdeep.mjs patterns; records use the same NDJSON-ish shape.
_PY_SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("private_key_header",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----")),
    ("jwt_token",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\."
                r"[A-Za-z0-9_\-]{10,}\b")),
    ("generic_assignment",
     re.compile(r"""\b([A-Za-z_$][\w$]{0,60}(?:[Pp]assword|[Ss]ecret|[Tt]oken|"""
                r"""API_?[Kk]ey|apiKey|[Aa]uth))\b["']?\s*[:=]\s*(["'`])"""
                r"""([^"'`\n]{8,})\2"""),
     re.compile(r"test|mock|example|placeholder|sample|dummy|xxx|TODO|spec",
                re.IGNORECASE)),
]

_PY_ENDPOINT_PATTERNS = [
    re.compile(r"""["'`](https?://[^\s"'`<>]{4,300})["'`]"""),
    re.compile(r"""\bfetch\s*\(\s*["'`](/[^\s"'`<>]{1,300})["'`]"""),
    re.compile(r"""\baxios(?:\s*\.\s*\w+)?\s*\(\s*["'`](/[^\s"'`<>]{1,300})["'`]"""),
    re.compile(r"""\.open\s*\(\s*["'`](?:GET|POST|PUT|DELETE|PATCH|HEAD)["'`]"""
               r"""\s*,\s*["'`]([^"'`\s<>]{1,300})["'`]""", re.IGNORECASE),
    re.compile(r"""\b(?:url|baseURL|endpoint)\s*[:=]\s*["'`](/[^\s"'`<>]{2,300})["'`]""",
               re.IGNORECASE),
    re.compile(r"`(https?://[^`\n]{4,300})`"),
    re.compile(r"""["'`](/(?:api|v[1-9]|rest|service)/[^\s"'`<>]{1,300})["'`]""",
               re.IGNORECASE),
]

_PY_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s*]+)")
_PY_HOST_RE = re.compile(r"https?://([a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,})")
_PY_OPERATION_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_]\w{1,80})")


def _clip(text, limit=300):
    text = str(text)
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _line_of(js, idx):
    return js.count("\n", 0, idx) + 1


def _line_text(js, idx, limit=300):
    start = js.rfind("\n", 0, idx) + 1
    end = js.find("\n", idx)
    if end == -1:
        end = len(js)
    return _clip(js[start:end].strip(), limit)


def node_available(which_fn=shutil.which):
    """True when ``node`` is present AND the polyglot gate is open."""
    return (os.environ.get("PTK_POLYGLOT") == "1"
            and which_fn("node") is not None
            and os.path.exists(JSDEEP_MJS))


def run_node_jsdeep(js_content, which_fn=shutil.which):
    """Run jsdeep.mjs over ``js_content`` (stdin). Returns list of records,
    or None when node is unavailable / failed (caller falls back)."""
    if not node_available(which_fn):
        return None
    node = which_fn("node")
    try:
        proc = subprocess.run(
            [node, JSDEEP_MJS],
            input=js_content.encode("utf-8", "replace"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=NODE_TIMEOUT_S)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    records = []
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and "kind" in rec:
            records.append(rec)
            if len(records) >= MAX_RECORDS:
                break
    return records


def python_jsdeep(js_content):
    """Pure-Python regex fallback. Same record shape as jsdeep.mjs."""
    js = js_content or ""
    out = []

    for pat in _PY_SECRET_PATTERNS:
        name, rex = pat[0], pat[1]
        test_re = pat[2] if len(pat) > 2 else None
        for m in rex.finditer(js):
            if test_re and test_re.search(m.group(1) or ""):
                continue
            value = m.group(0)
            if len(value) > 64:
                value = value[:64] + "…"
            out.append({"kind": "secret", "value": name + ":" + value,
                        "line_no": _line_of(js, m.start()),
                        "evidence": _line_text(js, m.start())})

    for rex in _PY_ENDPOINT_PATTERNS:
        for m in rex.finditer(js):
            v = m.group(1)
            if not v or v.startswith("//") or v.startswith("data:"):
                continue
            out.append({"kind": "endpoint", "value": v,
                        "line_no": _line_of(js, m.start()),
                        "evidence": _line_text(js, m.start())})

    for m in _PY_SOURCEMAP_RE.finditer(js):
        out.append({"kind": "sourcemap", "value": m.group(1),
                    "line_no": _line_of(js, m.start()),
                    "evidence": _line_text(js, m.start())})

    for m in _PY_HOST_RE.finditer(js):
        out.append({"kind": "host", "value": m.group(1),
                    "line_no": _line_of(js, m.start()),
                    "evidence": _line_text(js, m.start())})

    for m in _PY_OPERATION_RE.finditer(js):
        out.append({"kind": "operation", "value": m.group(1) + " " + m.group(2),
                    "line_no": _line_of(js, m.start()),
                    "evidence": _line_text(js, m.start())})
    return out


def collect_js_assets(target, fetch, max_assets=10):
    """Fetch ``target`` HTML, extract <script src=*.js> URLs (absolute or
    same-host relative), fetch each. Returns [(url, content_text)]."""
    base = target if "://" in target else "http://" + target
    base = base.rstrip("/")
    try:
        st, _h, body = fetch("GET", base)
    except Exception:
        return []
    html = (body or b"").decode("latin-1", "replace")
    assets = []
    seen = set()
    for m in SCRIPT_SRC_RE.finditer(html):
        src = m.group(1)
        if src.startswith("//"):
            src = "http:" + src
        elif src.startswith("/"):
            src = base + src
        elif not src.startswith("http"):
            src = base + "/" + src
        if src in seen:
            continue
        seen.add(src)
        try:
            st2, _h2, b2 = fetch("GET", src)
        except Exception:
            continue
        assets.append((src, (b2 or b"").decode("latin-1", "replace")))
        if len(assets) >= max_assets:
            break
    return assets


def _finding(kind, value, url, evidence, line_no):
    sev = SEVERITY_BY_KIND.get(kind, "info")
    titles = {
        "secret": "Secret pattern in JS bundle (%s)" % value.split(":", 1)[0],
        "endpoint": "API endpoint referenced in JS bundle",
        "sourcemap": "Source map referenced in JS bundle (source disclosure)",
        "host": "Hardcoded host in JS bundle",
        "operation": "GraphQL/REST operation name in JS bundle",
    }
    notes = {
        "secret": "A credential-shaped literal was found in client-side "
                  "JavaScript. Candidate: static evidence only — verify the "
                  "value is live before treating it as exposed.",
        "endpoint": "Static extraction of a referenced API path; INFO "
                    "inventory, not an attack.",
        "sourcemap": "A sourceMappingURL points to a .map file; if served, "
                     "it discloses original sources.",
        "host": "Hardcoded hostname extracted for inventory.",
        "operation": "Named operation extracted for inventory.",
    }
    manual = ('curl -sS "%s" | grep -F %s | head -c 500'
              % (url, json.dumps(_clip(value, 80))))
    return Finding(
        title=titles.get(kind, kind),
        severity=sev,
        confidence="medium" if kind == "secret" else "high",
        verification="candidate",
        verification_note=notes.get(kind, "Static evidence only."),
        manual_check=manual,
        location=_clip(url, 200),
        evidence={"line_no": line_no, "value": value,
                  "matched_line": _clip(evidence, 300)},
        source="omega-jsdeep/" + kind)


def run_jsdeep(target, fetch=None, assets=None, which_fn=shutil.which):
    """Analyze JS assets of ``target``.

    ``assets`` optionally overrides discovery: list of URLs (fetched) or
    (url, text) tuples. Returns
    {"findings": [...], "analyzed": [...], "engine": "node"|"python",
     "requests_sent": N, "skipped": [...]}.
    """
    fetch = fetch or default_fetch
    result = {"findings": [], "analyzed": [], "engine": "python",
              "requests_sent": 0, "skipped": []}
    if assets is None:
        assets = collect_js_assets(target, fetch)
        result["requests_sent"] += 1 + len(assets)
    prepared = []
    for a in assets:
        if isinstance(a, tuple):
            prepared.append(a)
        else:
            try:
                st, _h, body = fetch("GET", a)
                result["requests_sent"] += 1
                prepared.append((a, (body or b"").decode("latin-1", "replace")))
            except Exception:
                result["skipped"].append(a)

    engine = "node" if node_available(which_fn) else "python"
    if engine == "node":
        records = run_node_jsdeep(
            "\n".join(t for _u, t in prepared), which_fn=which_fn)
        if records is None:  # node failed: fail open to python fallback
            engine = "python"
    if engine == "python":
        records = []
        for _u, text in prepared:
            records.extend(python_jsdeep(text))

    result["engine"] = engine
    seen = set()
    for rec in records:
        key = (rec.get("kind"), rec.get("value"))
        if key in seen or rec.get("kind") not in SEVERITY_BY_KIND:
            continue
        seen.add(key)
        url = prepared[0][0] if prepared else (target or "inline")
        result["findings"].append(_finding(
            rec["kind"], rec["value"], url,
            rec.get("evidence") or "", rec.get("line_no") or 0))
    result["analyzed"] = [u for u, _t in prepared]
    return result
