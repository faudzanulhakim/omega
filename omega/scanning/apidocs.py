"""omega/scanning/apidocs.py — API spec discovery + auth check
(fusion suite name: ``apidocs``).

Fetches common API specification paths (/openapi.json, /swagger.json,
/api-docs, /swagger/v1/swagger.json, /openapi.yaml). When a spec is
found it is parsed with the stdlib json module (plus a simple YAML key
scan for the yaml flavor) to enumerate endpoints, reported as a MEDIUM
candidate (exposed specification), and up to 10 discovered endpoints
are then fetched unauthenticated — an endpoint answering 200 with a
JSON body is a MEDIUM candidate ``unauthenticated API endpoint``.
Discovered paths are included in the finding evidence. Never raises;
GET-only; bounded.
"""

from __future__ import annotations

import json
import re

from omega.scanning.deepchecks import default_fetch

__all__ = [
    "Finding",
    "SPEC_PATHS",
    "parse_spec",
    "extract_endpoints",
    "run_apidocs",
]

SPEC_PATHS = ("/openapi.json", "/swagger.json", "/api-docs",
              "/swagger/v1/swagger.json", "/openapi.yaml")
MAX_ENDPOINTS_FETCH = 10
MAX_ENDPOINTS_PARSED = 40


class Finding(dict):
    """ENGINE-convention finding dict (candidate only)."""

    def __init__(self, title, severity, verification, verification_note,
                 manual_check, location, evidence, source,
                 confidence="medium"):
        super().__init__(
            title=title,
            severity=severity,
            confidence=confidence,
            verification=verification,
            verification_note=verification_note,
            manual_check=manual_check,
            location=location,
            evidence=str(evidence)[:300],
            source=source,
        )


def _text(body):
    if isinstance(body, bytes):
        return body.decode("latin-1")
    return str(body or "")


def _get(fetch, url):
    try:
        st, _h, raw = fetch("GET", url)
        return st, _text(raw)
    except Exception:
        return None, ""


def parse_spec(body, is_yaml=False):
    """Return a dict of the spec: stdlib json when possible, else a
    simple YAML key scan (paths: / per-key indentation blocks)."""
    if not is_yaml:
        try:
            return json.loads(body)
        except Exception:
            pass
    # Simple YAML key scan: collect top-level-ish keys and any line
    # that looks like a mapping key.
    parsed = {}
    for line in body.splitlines():
        m = re.match(r"^(\s*)([A-Za-z0-9_./\-]+)\s*:\s*(.*)$", line)
        if m:
            key = m.group(2)
            if key not in parsed:
                parsed[key] = m.group(3).strip()
    return parsed


def extract_endpoints(spec):
    """Endpoint path list from a parsed spec (paths object keys), or
    from YAML keys that look like paths. Bounded."""
    endpoints = []
    paths_obj = spec.get("paths") if isinstance(spec, dict) else None
    if isinstance(paths_obj, dict):
        for p in paths_obj:
            p = str(p)
            if p.startswith("/"):
                endpoints.append(p)
    if not endpoints and isinstance(spec, dict):
        for k in spec:
            k = str(k)
            if k.startswith("/") and len(k) > 1:
                endpoints.append(k)
    seen, out = set(), []
    for p in endpoints:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out[:MAX_ENDPOINTS_PARSED]


def run_apidocs(base_url, fetch=default_fetch, path_info=None, gate=False):
    """Run API spec discovery + unauthenticated endpoint checks.
    Returns a list of Finding dicts; never raises."""
    out = []
    try:
        base = base_url.rstrip("/")
        spec_url = None
        spec_body = ""
        is_yaml = False
        for sp in SPEC_PATHS:
            st, body = _get(fetch, base + sp)
            if st == 200 and body.strip():
                spec_url = base + sp
                spec_body = body
                is_yaml = sp.endswith(".yaml") or not body.lstrip().startswith(
                    ("{", "["))
                break
        if not spec_url:
            return out

        spec = parse_spec(spec_body, is_yaml=is_yaml)
        endpoints = extract_endpoints(spec)
        out.append(Finding(
            title="API specification exposed at %s (%d endpoint(s))"
                  % (spec_url, len(endpoints)),
            severity="medium", verification="candidate",
            verification_note=(
                "A machine-readable API specification is reachable "
                "without authentication. It enumerates every endpoint, "
                "parameter and often auth scheme — useful to an "
                "attacker. Candidate only: exposure may be intentional "
                "for public APIs."),
            manual_check="curl -sS %s" % spec_url,
            location=spec_url,
            evidence="paths=%s" % (",".join(endpoints[:10]) or "<none>"),
            source="omega-apidocs", confidence="high"))

        seen = set()
        open_hits = []
        for p in endpoints:
            if len(seen) >= MAX_ENDPOINTS_FETCH:
                break
            url = base + p
            if url in seen:
                continue
            seen.add(url)
            st, body = _get(fetch, url)
            if st == 200 and body.strip():
                stripped = body.lstrip()
                if stripped.startswith(("{", "[")):
                    try:
                        json.loads(body)
                        open_hits.append(p)
                    except Exception:
                        continue
        if open_hits:
            out.append(Finding(
                title="%d API endpoint(s) answer 200 unauthenticated"
                      % len(open_hits),
                severity="medium", verification="candidate",
                verification_note=(
                    "Endpoints discovered from the exposed specification "
                    "returned HTTP 200 with a JSON body when fetched "
                    "without any credentials. Candidate only: confirm "
                    "the data is not intentionally public and whether "
                    "the endpoints expose sensitive objects."),
            manual_check="curl -sS %s%s" % (base, open_hits[0]),
            location=base + open_hits[0],
            evidence="open_endpoints=%s paths_discovered=%d"
                     % (",".join(open_hits[:10]), len(endpoints)),
            source="omega-apidocs", confidence="medium"))
    except Exception:
        pass
    return out
