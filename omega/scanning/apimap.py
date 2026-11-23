"""omega/apimap.py — automatic API surface mapping (safe probing only).

Detects and parses OpenAPI/Swagger documents (openapi.json, swagger.json,
/v3/api-docs and other common doc paths) and GraphQL introspection
(__schema query on common /graphql endpoints), then enumerates endpoints
and methods from the spec. Probing is OPTIONS + safe GET only — never
POST/PUT/DELETE.

Findings (ENGINE convention, omega.deepchecks.Finding):
  * undocumented_live   — a probed candidate path responds 200-299 (or 403
                          authenticated-wall) but is NOT in the spec
                          (medium, candidate)
  * spec_dead_path      — a spec path answers 404/405 to GET (info,
                          documented-but-not-live)
  * graphql_introspection — __schema accepted; severity escalates to
                            medium with a schema summary (medium, candidate)
  * mass_assignment     — spec schema fields that look writable but carry
                          no write-restriction markers in the doc (info)

``run_apimap`` never raises. source=omega-apimap/<name>.
"""

from __future__ import annotations

import json
import urllib.parse

__all__ = [
    "Finding",
    "DOC_PATHS",
    "GRAPHQL_PATHS",
    "CANDIDATE_PATHS",
    "fetch_openapi",
    "introspect_graphql",
    "spec_endpoints",
    "probe_endpoint",
    "mass_assignment_hints",
    "run_apimap",
]

from omega.deepchecks import Finding
from omega.probes import default_fetch

DOC_PATHS = [
    "/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs",
    "/api/openapi.json", "/api/swagger.json", "/api/v3/api-docs",
    "/swagger/v1/swagger.json", "/openapi/v3", "/docs/openapi.json",
]

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql"]

# Small inventory of paths commonly deployed but often left out of specs.
CANDIDATE_PATHS = [
    "/actuator", "/actuator/health", "/health", "/healthz", "/metrics",
    "/debug", "/admin", "/api/users", "/api/config", "/env", "/info",
    "/version", "/status", "/api/internal", "/management", "/console",
]

INTROSPECTION_QUERY = (
    '{ __schema { queryType { name } mutationType { name } '
    'types { name kind } } }'
)

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")

# Field-name fragments that suggest sensitive writes (mass assignment).
SENSITIVE_FIELD_RE = ("admin", "role", "priv", "email", "password",
                      "is_superuser", "permissions")


def _clip(text, limit=300):
    text = str(text)
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _finding(name, title, severity, url, note, evidence, confidence="medium"):
    return Finding(
        title=title,
        severity=severity,
        confidence=confidence,
        verification="candidate",
        verification_note=note,
        manual_check='curl -sS -i "%s" | head -c 1000' % url,
        location=_clip(url, 200),
        evidence=evidence,
        source="omega-apimap/" + name)


def fetch_openapi(target, fetch=None):
    """Try common doc paths; return (url, spec_dict) or (None, None)."""
    fetch = fetch or default_fetch
    base = target if "://" in target else "http://" + target
    base = base.rstrip("/")
    for path in DOC_PATHS:
        url = base + path
        try:
            st, _h, body = fetch("GET", url)
        except Exception:
            continue
        if not (int(st or 0) == 200 and body):
            continue
        text = body.decode("latin-1", "replace")
        try:
            spec = json.loads(text)
        except ValueError:
            continue
        if isinstance(spec, dict) and (
                "openapi" in spec or "swagger" in spec
                or "paths" in spec or "info" in spec):
            return url, spec
    return None, None


def spec_endpoints(spec):
    """Extract [(path, method)] from an OpenAPI/Swagger spec."""
    out = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for key, op in item.items():
            if key.lower() in HTTP_METHODS and isinstance(op, dict):
                out.append((path, key.lower()))
            elif key == "parameters" or not isinstance(op, dict):
                continue
    return out


def probe_endpoint(url, fetch=None):
    """Safe probe: OPTIONS then GET. Returns (status, best_method).

    Status is the most informative of the two (200-299 preferred, then
    403/401, then 405, then anything else).
    """
    fetch = fetch or default_fetch
    statuses = []
    for method in ("OPTIONS", "GET"):
        try:
            st, _h, _b = fetch(method, url)
        except Exception:
            st = 0
        statuses.append((method, int(st or 0)))
    ranked = sorted(statuses, key=lambda ms: (
        not (200 <= ms[1] < 300), ms[1] not in (401, 403),
        ms[1] != 405, ms[1] == 0))
    return ranked[0][1], ranked[0][0]


def introspect_graphql(target, fetch=None):
    """GET-based __schema introspection on common GraphQL paths.
    Returns (url, schema_summary_dict) or (None, None)."""
    fetch = fetch or default_fetch
    base = target if "://" in target else "http://" + target
    base = base.rstrip("/")
    for path in GRAPHQL_PATHS:
        url = base + path + "?query=" + urllib.parse.quote(
            INTROSPECTION_QUERY, safe="")
        try:
            st, _h, body = fetch("GET", url)
        except Exception:
            continue
        if int(st or 0) != 200 or not body:
            continue
        try:
            data = json.loads(
                body.decode("latin-1", "replace")
                if isinstance(body, (bytes, bytearray))
                else str(body))
        except ValueError:
            continue
        schema = (data or {}).get("data", {}).get("__schema") \
            if isinstance(data, dict) else None
        if not schema:
            continue
        types = [t.get("name") for t in schema.get("types") or []
                 if t and t.get("name") and not t.get("name").startswith("__")]
        summary = {
            "query_type": (schema.get("queryType") or {}).get("name"),
            "mutation_type": (schema.get("mutationType") or {}).get("name"),
            "type_count": len(types),
            "types": types[:30],
        }
        return base + path, summary
    return None, None


def mass_assignment_hints(spec):
    """Schema fields that look sensitive but the doc shows no explicit
    write restriction (readOnly/writeOnly/enum/description markers).
    Returns list of {schema, fields}."""
    hints = []
    schemas = (spec.get("components") or {}).get("schemas") \
        if isinstance(spec, dict) else None
    if not schemas and isinstance(spec, dict):
        schemas = spec.get("definitions")  # swagger 2.0
    for name, schema in (schemas or {}).items():
        fields = []
        props = (schema or {}).get("properties") or {}
        for field, meta in props.items():
            low = field.lower()
            if not any(s in low for s in SENSITIVE_FIELD_RE):
                continue
            if not isinstance(meta, dict):
                fields.append(field)
                continue
            if meta.get("readOnly") or meta.get("writeOnly"):
                continue  # explicitly restricted in the doc
            fields.append(field)
        if fields:
            hints.append({"schema": name, "fields": fields[:20]})
    return hints[:20]


def run_apimap(target, fetch=None, max_probes=40):
    """Full API mapping pass. Returns
    {"findings": [...], "spec": {...}|None, "spec_url": ..., "endpoints":
     [...], "graphql": {...}|None, "requests_sent": N}.
    """
    fetch = fetch or default_fetch
    result = {"findings": [], "spec": None, "spec_url": None,
              "endpoints": [], "graphql": None, "requests_sent": 0}

    # 1. OpenAPI/Swagger discovery
    spec_url, spec = fetch_openapi(target, fetch)
    result["requests_sent"] += len(DOC_PATHS)
    if spec:
        result["spec_url"] = spec_url
        result["spec"] = spec
        endpoints = spec_endpoints(spec)
        result["endpoints"] = endpoints[:200]
        spec_paths = {p for p, _m in endpoints}

        # 2. Probe spec paths + candidate paths (OPTIONS/GET only)
        base = target if "://" in target else "http://" + target
        base = base.rstrip("/")
        probe_list = sorted(spec_paths)[:max_probes // 2] + CANDIDATE_PATHS
        live = {}
        for path in probe_list[:max_probes]:
            url = base + path
            st, method = probe_endpoint(url, fetch)
            result["requests_sent"] += 2
            if st:
                live[path] = (st, method)
        dead_paths = []
        undocumented = []
        for path, (st, method) in sorted(live.items()):
            if path in spec_paths:
                if st == 404 or st == 405:
                    dead_paths.append({"path": path, "status": st,
                                       "probe": method})
                continue
            if 200 <= st < 300 or st in (401, 403):
                undocumented.append({"path": path, "status": st,
                                     "probe": method})
        if dead_paths:
            result["findings"].append(_finding(
                "spec_dead_path",
                "Documented paths answer 404/405 to safe probe: %s"
                % ", ".join(d["path"] for d in dead_paths),
                "info", base,
                "The spec documents these paths but they are not live "
                "(404/405 to GET/OPTIONS). Doc drift.",
                {"paths": dead_paths}, confidence="high"))
        for u in undocumented:
            sev = "medium" if 200 <= u["status"] < 300 else "low"
            url = base + u["path"]
            result["findings"].append(_finding(
                "undocumented_live",
                "Live endpoint %s (HTTP %d via %s) not present in the "
                "OpenAPI spec" % (u["path"], u["status"], u["probe"]),
                sev, url,
                "The path answers to a safe OPTIONS/GET probe but is "
                "absent from the published spec — undocumented API "
                "surface. Candidate evidence only.",
                {"path": u["path"], "status": u["status"],
                 "probe": u["probe"]}))

        # 3. Mass assignment hints
        for hint in mass_assignment_hints(spec):
            result["findings"].append(_finding(
                "mass_assignment",
                "Sensitive writable fields in schema '%s' lack explicit "
                "write restrictions in the spec: %s"
                % (hint["schema"], ", ".join(hint["fields"][:6])),
                "info", spec_url,
                "Fields in the API schema look writable and sensitive but "
                "carry no readOnly/writeOnly marker in the document — "
                "possible mass-assignment surface. INFO hint only.",
                {"schema": hint["schema"], "fields": hint["fields"]},
                confidence="low"))
    else:
        result["findings"].append(Finding(
            title="No OpenAPI/Swagger document found at common paths",
            severity="info", confidence="high", verification="verified",
            verification_note="Tried %d common doc paths; none returned a "
                              "parseable spec." % len(DOC_PATHS),
            manual_check="n/a", location=target,
            evidence={"tried": DOC_PATHS[:10]},
            source="omega-apimap/no_spec"))

    # 4. GraphQL introspection
    gql_url, summary = introspect_graphql(target, fetch)
    result["requests_sent"] += len(GRAPHQL_PATHS)
    if gql_url:
        result["graphql"] = {"url": gql_url, "summary": summary}
        result["findings"].append(_finding(
            "graphql_introspection",
            "GraphQL introspection enabled at %s (%d types, query=%s, "
            "mutation=%s)" % (gql_url, summary["type_count"],
                              summary["query_type"],
                              summary["mutation_type"]),
            "medium", gql_url,
            "A full __schema introspection query was ACCEPTED — the entire "
            "GraphQL schema is discoverable. Candidate: introspection is "
            "information disclosure, not exploitation.",
            summary))

    return result
