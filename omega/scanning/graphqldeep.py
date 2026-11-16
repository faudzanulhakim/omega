"""omega/graphqldeep.py — GraphQL deep-inspection checks (evidence-only).

GET-only, non-destructive: sends inert inspection queries (a typo'd
field for suggestion leakage, a 5-level-deep query, 10-alias bulk
query, a malformed query) and classifies the responses:

  * field_suggestion_probe — 'Did you mean' field suggestions leak the
    schema (candidate)
  * query_depth_probe     — a 5-deep query is ACCEPTED (no depth-limit
    error) -> candidate 'no depth limit'
  * aliased_bulk_probe    — 10 aliases in one query are ACCEPTED ->
    rate-limit bypass hint (candidate)
  * error_disclosure      — a malformed query returns a raw stack trace
    or DB error (candidate HIGH)

Findings follow the ENGINE convention (omega.deepchecks.Finding),
source=omega-graphql/<name>. ``run_graphqldeep`` never raises.
"""

from __future__ import annotations

import json
import re

__all__ = [
    "Finding",
    "aliased_bulk_probe",
    "error_disclosure",
    "field_suggestion_probe",
    "query_depth_probe",
    "run_graphqldeep",
]

from omega.deepchecks import Finding
from omega.probes import allowlist_ok

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql"]

STACK_MARKERS = [
    "traceback (most recent call last)", "stack trace", "exception",
    "at java.", "php notice", "php warning", "fatal error",
    "sql syntax", "sqlstate", "sqlite3.", "psycopg", "ora-",
    "mysql_fetch", "pdoexception", "warning:",
]

_DEPTH_LIMIT_HINTS = [
    "depth", "too deep", "maximum query", "nested",
    "max_depth", "complexity",
]


def _clip(text, limit=300):
    text = str(text)
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _graphql_endpoints(target, fetch):
    """Return candidate endpoint URLs whose POST-ish probe got a
    GraphQL-ish response (GET with ?query= — GET-only contract)."""
    base_url = target if "://" in target else "http://" + target
    base_url = base_url.rstrip("/")
    endpoints = []
    for path in GRAPHQL_PATHS:
        url = base_url + path
        try:
            st, _h, body = fetch("GET", url)
        except Exception:
            continue
        text = body.decode("latin-1", "replace") if body else ""
        if _looks_graphql(st, text):
            endpoints.append(url)
    return endpoints


def _looks_graphql(status, text):
    t = text.lower()
    return ("graphql" in t or "did you mean" in t
            or '"data"' in t or '"errors"' in t
            or "query" in t and "syntax" in t
            or int(status or 0) == 400 and t)


def _post_like_get(url, query, fetch):
    """Send the inspection query as a GET ?query=... (GET-only contract).
    Returns (status, body_text)."""
    import urllib.parse
    sep = "&" if "?" in url else "?"
    probe = url + sep + "query=" + urllib.parse.quote(query, safe="")
    try:
        st, _h, body = fetch("GET", probe)
    except Exception:
        return None, ""
    return int(st or 0), (body or b"").decode("latin-1", "replace")


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
        source="omega-graphql/" + name)


# ------------------------------------------------------------------ probes

def field_suggestion_probe(url, fetch):
    """Typo'd field -> 'Did you mean' suggestion leaks schema names."""
    st, text = _post_like_get(
        url, '{ heros { id } }', fetch)  # typo of a plausible field
    if st is None:
        return None
    m = re.search(r"did you mean[^\"']*[\"']([\w]+)[\"']",
                  text, re.IGNORECASE)
    if not m:
        return None
    return _finding(
        "field_suggestion",
        "GraphQL field suggestion leaks schema names ('%s')" % m.group(1),
        "low", url,
        "The endpoint suggests valid field names on a typo ('Did you "
        "mean ...'). Schema-discovery aid that should be disabled in "
        "production. Candidate: introspection-adjacent evidence only.",
        {"suggestion": m.group(1), "status": st})


def query_depth_probe(url, fetch, depth=5):
    """A 5-deep nested query ACCEPTED (no depth-limit rejection) ->
    candidate 'no depth limit'."""
    query = "{ a" + " { b" * (depth - 1) + " }" * (depth - 1) + " }"
    st, text = _post_like_get(url, query, fetch)
    if st is None:
        return None
    low = text.lower()
    if any(h in low for h in _DEPTH_LIMIT_HINTS):
        return None  # depth limit present: good, no finding
    if st and 200 <= st < 500 and not _is_hard_error(st, text):
        return _finding(
            "query_depth",
            "GraphQL accepts a %d-level deep query (no depth limit)"
            % depth,
            "medium", url,
            "A %d-level nested query was ACCEPTED (no depth/complexity "
            "rejection), enabling nesting-abuse DoS. Candidate: the "
            "response indicates acceptance, not exploitation." % depth,
            {"depth": depth, "status": st})
    return None


def aliased_bulk_probe(url, fetch, aliases=10):
    """10 aliases in one query ACCEPTED -> rate-limit bypass hint."""
    query = "{" + " ".join("a%d: hero" % i for i in range(1, aliases + 1)) \
        + "}"
    st, text = _post_like_get(url, query, fetch)
    if st is None:
        return None
    low = text.lower()
    if any(h in low for h in ("too many", "rate limit", "throttl",
                              "complexity", "alias")):
        return None
    if st and 200 <= st < 500 and not _is_hard_error(st, text):
        return _finding(
            "aliased_bulk",
            "GraphQL accepts %d aliases in one query (rate-limit "
            "bypass hint)" % aliases,
            "medium", url,
            "A single query with %d aliases was ACCEPTED — bulk aliasing "
            "can bypass per-query rate limits. Candidate: acceptance "
            "signal only; no data was exfiltrated." % aliases,
            {"aliases": aliases, "status": st})
    return None


def _is_hard_error(status, text):
    low = (text or "").lower()
    if status and 500 <= status < 600:
        return True
    return "syntax error" in low and "did you mean" not in low


def error_disclosure(url, fetch):
    """Malformed query -> raw stack/DB error in the response body."""
    st, text = _post_like_get(url, '{{{{ malformed }}', fetch)
    if st is None:
        return None
    hits = [s for s in STACK_MARKERS if s in text.lower()]
    if not hits:
        return None
    return _finding(
        "error_disclosure",
        "GraphQL malformed-query response discloses internals (%s)"
        % ", ".join(hits[:3]),
        "high", url,
        "A malformed query returns raw error internals (%s). Candidate "
        "HIGH: stack-trace/DB disclosure; no exploitation was "
        "attempted." % ", ".join(hits[:3]),
        {"markers": hits, "status": st,
         "snippet": _clip(text, 200)})


# ----------------------------------------------------------------- runner

def run_graphqldeep(target, fetch=None, allowlist=None, log=None):
    """Run all GraphQL deep checks against ``target``. Never raises.

    Returns {findings, ran, skipped}.
    """
    result = {"findings": [], "ran": [], "skipped": {}}
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = (
            "target %r not in allowlist" % target)
        if log:
            log("graphqldeep skipped: target not in allowlist: %r" % target)
        return result
    try:
        if fetch is None:
            from omega.deepchecks import default_fetch
            fetch = default_fetch
        endpoints = _graphql_endpoints(target, fetch)
        if not endpoints:
            result["skipped"]["__all__"] = "no GraphQL endpoint found"
            return result
        result["ran"].append("endpoint-discovery")
        probes = (field_suggestion_probe, query_depth_probe,
                  aliased_bulk_probe, error_disclosure)
        for url in endpoints:
            for probe in probes:
                try:
                    f = probe(url, fetch)
                except Exception as exc:
                    result["skipped"][probe.__name__] = "error: %s" % exc
                    continue
                if f is not None:
                    result["findings"].append(f)
        if log:
            log("graphqldeep: %d endpoint(s), %d finding(s)"
                % (len(endpoints), len(result["findings"])))
    except Exception as exc:  # never raise
        result["skipped"]["run_graphqldeep"] = "error: %s" % exc
        if log:
            log("graphqldeep failed: %s" % exc)
    return result
