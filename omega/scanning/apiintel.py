"""omega/apiintel.py — API specification discovery and intel (read-only).

Evidence-only, GET-only: probes common OpenAPI/Swagger documentation
paths, parses a found spec, and reports:

  * exposed spec          — a reachable /openapi.json style document
                            (candidate; HIGH when the spec lists
                            authenticated/security-protected endpoints)
  * unauthenticated risky — id-like parameters (``id``, ``user_id``...)
                            reachable without any security requirement
                            (candidate HIGH)
  * legacy version drift  — both /v1 and /v2 style versions discovered
  * sensitive fields      — password/token/secret-like property names in
                            response schemas

Nothing is exploited; discovery only reads documentation the server
voluntarily serves. Findings follow the ENGINE convention
(omega.deepchecks.Finding), source=omega-apiintel/<name>.
``compare_specs(old, new)`` diffs two parsed specs (added/removed
endpoint paths). ``run_apiintel`` never raises.
"""

from __future__ import annotations

import json
import re

__all__ = [
    "SPEC_PATHS",
    "Finding",
    "compare_specs",
    "discover_specs",
    "parse_spec",
    "run_apiintel",
]

from omega.deepchecks import Finding
from omega.probes import allowlist_ok

SPEC_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/.well-known/openapi.json",
]

_ID_LIKE = re.compile(
    r"(?:^|_)(id|uid|uuid|guid|user_?id|account_?id|order_?id|"
    r"customer_?id|profile_?id|record_?id)$", re.IGNORECASE)

_SENSITIVE = re.compile(
    r"password|passwd|secret|token|api_?key|private_?key|credential",
    re.IGNORECASE)

_VERSIONED = re.compile(r"^/v(\d+)(?:/|$)")


def _clip(text, limit=300):
    text = str(text)
    return text if len(text) <= limit else text[:limit - 3] + "..."


# ------------------------------------------------------------------ parsing

def parse_spec(body):
    """Parse an OpenAPI/Swagger document (JSON str/bytes or dict).

    Returns {endpoints: [paths], params: [{path, param, in}],
             auth: bool, security_schemes: [...], risky: [...]}
    where ``risky`` lists id-like parameters reachable WITHOUT a
    security requirement. Malformed input yields empty lists.
    """
    out = {"endpoints": [], "params": [], "auth": False,
           "security_schemes": [], "risky": []}
    if isinstance(body, (bytes, bytearray)):
        try:
            body = body.decode("utf-8", "replace")
        except Exception:
            return out
    if isinstance(body, str):
        try:
            data = json.loads(body)
        except Exception:
            try:
                import yaml  # optional; swagger yaml docs
                data = yaml.safe_load(body)
            except Exception:
                return out
    else:
        data = body
    if not isinstance(data, dict):
        return out

    schemes = data.get("securitySchemes") or \
        ((data.get("components") or {}).get("securitySchemes")) or {}
    if isinstance(schemes, dict) and schemes:
        out["security_schemes"] = sorted(schemes)
        out["auth"] = True
    if data.get("security"):
        out["auth"] = True

    paths = data.get("paths")
    if not isinstance(paths, dict):
        return out
    global_security = bool(data.get("security")) or bool(schemes)
    for path, methods in sorted(paths.items()):
        if not isinstance(methods, dict):
            continue
        out["endpoints"].append(path)
        for method, op in methods.items():
            if not isinstance(op, dict):
                continue
            if op.get("security"):
                out["auth"] = True
            params = op.get("parameters") or []
            for p in params:
                if not isinstance(p, dict):
                    continue
                name = str(p.get("name") or "")
                rec = {"path": path, "param": name,
                       "in": str(p.get("in") or ""), "method": method}
                out["params"].append(rec)
                if _ID_LIKE.search(name):
                    # security: operation-level, path-level, or global
                    secured = bool(op.get("security")) or global_security
                    if not secured:
                        out["risky"].append(rec)
    return out


def compare_specs(old, new):
    """Diff two parsed specs (or raw spec dicts): added/removed paths."""
    old_paths = set((old or {}).get("endpoints") or
                    ((old or {}).get("paths") or {}))
    new_paths = set((new or {}).get("endpoints") or
                    ((new or {}).get("paths") or {}))
    return {"added": sorted(new_paths - old_paths),
            "removed": sorted(old_paths - new_paths)}


# ---------------------------------------------------------------- discovery

def discover_specs(target, fetch=None):
    """Probe common spec paths. Returns a list of
    {path, status, spec} entries (spec parsed only for 2xx JSON-ish).
    Never raises; transport errors are skipped silently."""
    from omega.deepchecks import default_fetch
    fetch = fetch or default_fetch
    base_url = target if "://" in target else "http://" + target
    base_url = base_url.rstrip("/")
    found = []
    for path in SPEC_PATHS:
        url = base_url + path
        try:
            st, _h, body = fetch("GET", url)
        except Exception:
            continue
        entry = {"path": path, "status": int(st or 0), "spec": None,
                 "_raw": None}
        if 200 <= entry["status"] < 300 and body:
            parsed = parse_spec(body)
            if parsed["endpoints"]:
                entry["spec"] = parsed
                try:
                    entry["_raw"] = json.loads(body.decode(
                        "utf-8", "replace"))
                except Exception:
                    entry["_raw"] = None
        if entry["spec"] is not None:
            found.append(entry)
    return found


def _finding(name, title, severity, url, note, evidence):
    return Finding(
        title=title,
        severity=severity,
        confidence="medium",
        verification="candidate",
        verification_note=note,
        manual_check='curl -sS "%s" | head -c 2000' % url,
        location=_clip(url, 200),
        evidence=evidence,
        source="omega-apiintel/" + name)


# ----------------------------------------------------------------- run

def run_apiintel(target, fetch=None, allowlist=None, log=None):
    """Discover + analyze API specs against ``target``. Never raises.

    Returns {findings, ran, skipped, specs}.
    """
    result = {"findings": [], "ran": [], "skipped": {}, "specs": []}
    base_url = target if "://" in target else "http://" + target
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = (
            "target %r not in allowlist" % target)
        if log:
            log("apiintel skipped: target not in allowlist: %r" % target)
        return result
    try:
        fetch = fetch or _default_fetch()
        base_url = base_url.rstrip("/")
        specs = discover_specs(base_url, fetch=fetch)
        result["specs"] = [{"path": s["path"], "status": s["status"]}
                           for s in specs]
        result["ran"].append("discover_specs")
        if not specs:
            return result  # clean surface: no exposed spec, no findings

        for entry in specs:
            spec = entry["spec"] or {}
            url = base_url + entry["path"]
            endpoints = spec.get("endpoints") or []
            # exposed spec: HIGH when authenticated endpoints are listed
            high = bool(spec.get("auth"))
            result["findings"].append(_finding(
                "exposed-spec",
                "API specification exposed at %s (%d endpoint(s))"
                % (entry["path"], len(endpoints)),
                "high" if high else "low",
                url,
                "The server publicly serves a machine-readable API "
                "specification listing %d endpoint(s)%s. Candidate: "
                "documentation exposure is a recon gift, not proof of "
                "a vulnerability." % (
                    len(endpoints),
                    ", including security-protected/authenticated ones"
                    if high else ""),
                {"path": entry["path"], "endpoints": len(endpoints),
                 "auth": bool(spec.get("auth")),
                 "security_schemes": spec.get("security_schemes") or []}))

            for rec in (spec.get("risky") or []):
                result["findings"].append(_finding(
                    "risky-endpoint",
                    "id-like parameter '%s' on %s reachable without any "
                    "security requirement" % (rec["param"], rec["path"]),
                    "high", base_url + rec["path"],
                    "The spec documents an id-like parameter (%s on %s) "
                    "with NO security requirement — potential IDOR "
                    "surface. Candidate: spec-level evidence only, "
                    "manual verification required." % (rec["param"],
                                                       rec["path"]),
                    {"path": rec["path"], "param": rec["param"],
                     "method": rec.get("method") or "GET"}))

            # legacy version drift: /v1 and /v2 style endpoints coexist
            versions = sorted({_VERSIONED.match(p).group(1)
                               for p in endpoints
                               if _VERSIONED.match(p)})
            if len(versions) >= 2:
                result["findings"].append(_finding(
                    "version-drift",
                    "API version drift: /v%s and /v%s endpoints coexist"
                    % (versions[0], versions[-1]),
                    "low", base_url + entry["path"],
                    "The spec documents multiple major API versions "
                    "(%s); legacy versions often keep unpatched or "
                    "less-protected behavior. Candidate: inventory "
                    "signal only." % ", ".join("/v" + v
                                               for v in versions),
                    {"versions": versions}))

            # sensitive fields in response schemas
            fields = _sensitive_fields(entry.get("_raw") or {})
            for path, prop in fields:
                result["findings"].append(_finding(
                    "sensitive-field",
                    "sensitive field '%s' in response schema of %s"
                    % (prop, path),
                    "medium", base_url + path,
                    "The spec's response schema exposes a "
                    "sensitive-looking property name ('%s'). Candidate: "
                    "schema inspection only; whether the value is ever "
                    "returned must be verified manually." % prop,
                    {"path": path, "field": prop}))
        if log:
            log("apiintel: %d spec(s), %d finding(s)"
                % (len(specs), len(result["findings"])))
    except Exception as exc:  # never raise
        result["skipped"]["run_apiintel"] = "error: %s" % exc
        if log:
            log("apiintel failed: %s" % exc)
    return result


def _default_fetch():
    from omega.deepchecks import default_fetch
    return default_fetch


def _sensitive_fields(raw_spec):
    """Yield (path, property) for sensitive-looking response schema
    property names in the RAW spec document."""
    out = []
    try:
        paths = (raw_spec or {}).get("paths") or {}
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for _m, op in methods.items():
                if not isinstance(op, dict):
                    continue
                responses = op.get("responses") or {}
                for _code, resp in responses.items():
                    content = (resp or {}).get("content") or {}
                    for _ct, media in content.items():
                        schema = (media or {}).get("schema") or {}
                        for prop in (schema.get("properties") or {}):
                            if _SENSITIVE.search(str(prop)):
                                out.append((path, str(prop)))
    except Exception:
        return out
    seen, uniq = set(), []
    for item in out:
        if item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq
