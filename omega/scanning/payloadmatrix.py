"""omega/payloadmatrix.py — WAF-evasion encoding matrix for EXISTING
reflection checks.

Evidence-only: a harmless operator marker is encoded through a fixed
matrix of 12 encodings and placed in 8 placements; a placement
"survives" when the marker is reflected back in the response body
(after any single layer of server normalization). Nothing is decoded,
executed, or escalated — the matrix only measures whether a marker
travels through, which is a WAF-weakness signal that REQUIRES MANUAL
WAF ANALYSIS. Findings are never auto-confirmed as exploitable.

Design (mirrors omega/deepchecks.py):
- ``matrix_runner(target, marker, fetch, budget)`` with the injectable
  fetch contract ``fetch(method, url, headers=None, body=None) ->
  (status, headers_dict, body_bytes)`` (GET only here).
- A per-run request cap (``budget`` = max probe requests, default 96)
  is the rate cap; once exhausted the remaining combinations are
  skipped and reported.
- Finding shape matches the ENGINE convention via
  omega.deepchecks.Finding; source=omega-matrix/reflect.
"""

from __future__ import annotations

import base64
import html.entities
import re
import time
import urllib.parse

__all__ = [
    "ENCODINGS",
    "PLACEMENTS",
    "DEFAULT_BUDGET",
    "Finding",
    "encodings_audit",
    "matrix_runner",
]

from omega.deepchecks import Finding

DEFAULT_BUDGET = 96

# ---------------------------------------------------------------- encodings


def _plain(marker):
    return marker


def _url_single(marker):
    return urllib.parse.quote(marker, safe="")


def _url_double(marker):
    return urllib.parse.quote(urllib.parse.quote(marker, safe=""), safe="")


def _unicode_u(marker):
    """IE-style %uXXXX notation (non-ASCII chars, ASCII passed through)."""
    return "".join(c if ord(c) < 128 else "%%u%04X" % ord(c)
                   for c in marker)


def _unicode_escape(marker):
    """\\uXXXX escapes for non-ASCII characters."""
    return "".join(c if ord(c) < 128 else "\\u%04X" % ord(c)
                   for c in marker)


def _html_numeric(marker):
    return "".join("&#%d;" % ord(c) for c in marker)


def _html_named(marker):
    """Named HTML entities where one exists, else numeric."""
    out = []
    for c in marker:
        name = html.entities.codepoint2name.get(ord(c))
        out.append("&%s;" % name if name else "&#%d;" % ord(c))
    return "".join(out)


def _hex_entity(marker):
    return "".join("&#x%02X;" % ord(c) for c in marker)


def _base64(marker):
    return base64.b64encode(marker.encode("utf-8")).decode("ascii")


def _url_then_html(marker):
    """Nested: URL-encode, then numeric-HTML-encode the whole thing."""
    return _html_numeric(_url_single(marker))


def _base64_then_url(marker):
    """Nested: base64 of the marker, then URL-encode."""
    return _url_single(_base64(marker))


def _double_url_then_hex(marker):
    """Nested: double URL-encode, then hex-entity encode."""
    return _hex_entity(_url_double(marker))


ENCODINGS = [
    ("plain", _plain),
    ("url_single", _url_single),
    ("url_double", _url_double),
    ("unicode_u", _unicode_u),
    ("unicode_escape", _unicode_escape),
    ("html_numeric", _html_numeric),
    ("html_named", _html_named),
    ("hex_entity", _hex_entity),
    ("base64", _base64),
    ("url_then_html", _url_then_html),
    ("base64_then_url", _base64_then_url),
    ("double_url_then_hex", _double_url_then_hex),
]

# --------------------------------------------------------------- placements

DEFAULT_PARAM = "q"
CUSTOM_HEADER = "X-Omega-Trace"


def _place_query(base_url, encoded, extra):
    p = extra.get("param", DEFAULT_PARAM)
    return base_url.rstrip("/") + "/?" + urllib.parse.urlencode({p: encoded}), p


def _place_path(base_url, encoded, extra):
    return (base_url.rstrip("/") + "/" +
            urllib.parse.quote(encoded, safe=""), "path")


def _place_fragment(base_url, encoded, extra):
    return base_url.rstrip("/") + "/#" + urllib.parse.quote(encoded,
                                                            safe=""), "fragment"


def _place_header_marker(base_url, encoded, extra):
    return base_url.rstrip("/") + "/", "X-Omega-Marker"


def _place_cookie(base_url, encoded, extra):
    return base_url.rstrip("/") + "/", "cookie"


def _place_referer(base_url, encoded, extra):
    return base_url.rstrip("/") + "/", "referer"


def _place_origin(base_url, encoded, extra):
    return base_url.rstrip("/") + "/", "origin"


def _place_custom_header(base_url, encoded, extra):
    return base_url.rstrip("/") + "/", CUSTOM_HEADER


PLACEMENTS = [
    ("query_param", _place_query),
    ("path", _place_path),
    ("fragment", _place_fragment),
    ("header_x_omega_marker", _place_header_marker),
    ("cookie", _place_cookie),
    ("referer", _place_referer),
    ("origin", _place_origin),
    ("header_custom", _place_custom_header),
]


def _headers_for(placement_name, encoded):
    """Request headers for a header-based placement (empty elsewhere)."""
    if placement_name == "header_x_omega_marker":
        return {"X-Omega-Marker": encoded}
    if placement_name == "cookie":
        return {"Cookie": "omega=" + encoded}
    if placement_name == "referer":
        return {"Referer": "https://example.test/?m=" + encoded}
    if placement_name == "origin":
        return {"Origin": "https://" + encoded + ".example.test"}
    if placement_name == "header_custom":
        return {CUSTOM_HEADER: encoded}
    return {}


# ---------------------------------------------------------------- detection


def _reflected(marker, body_bytes):
    """True when the marker is reflected in the body, allowing ONE
    layer of percent-decoding (server normalization). Never decodes
    anything on our side beyond this single comparison decode; no
    HTML/JS/base64 evaluation."""
    if not body_bytes:
        return False
    text = body_bytes.decode("latin-1")
    if marker in text:
        return True
    try:
        return marker in urllib.parse.unquote(text)
    except Exception:
        return False


def encodings_audit():
    """Sanity audit: 12 encodings x 8 placements; each encoding fn maps
    a marker to a non-empty, distinct-from-input-when-expected string."""
    problems = []
    marker = "OMEGA-M4RKER<&% \"'/?#\u00e9"  # non-ASCII: unicode layers
    if len(ENCODINGS) != 12:
        problems.append("expected 12 encodings, found %d" % len(ENCODINGS))
    if len(PLACEMENTS) != 8:
        problems.append("expected 8 placements, found %d" % len(PLACEMENTS))
    seen = set()
    for name, fn in ENCODINGS:
        try:
            out = fn(marker)
        except Exception as exc:
            problems.append("encoding %s raised: %s" % (name, exc))
            continue
        if not out:
            problems.append("encoding %s produced empty output" % name)
        seen.add(name)
        if name in ("plain", "base64"):
            continue  # base64 is intentionally opaque; plain is identity
        if out == marker:
            problems.append("encoding %s is identity on a payload marker"
                            % name)
    for pname, _fn in PLACEMENTS:
        if pname in seen:
            problems.append("placement name collides with encoding %s"
                            % pname)
    return len(ENCODINGS), len(PLACEMENTS), problems


# ------------------------------------------------------------------ runner


def matrix_runner(target, marker, fetch, budget=None, rate_limit_s=0.0):
    """Probe which encoding/placement combinations survive reflection.

    Returns {findings, ran, skipped}. GET only; rate-capped by
    ``budget`` (max requests) and an optional per-request delay.
    Never decodes/evaluates payloads; evidence-only.
    """
    result = {"findings": [], "ran": [], "skipped": {}}
    base_url = target if "://" in target else "https://" + target
    if not marker or not str(marker).strip():
        result["skipped"]["__all__"] = "empty marker"
        return result
    cap = DEFAULT_BUDGET if budget is None else max(1, int(budget))
    sent = 0
    # survivors per param-key, for the multi-encoding HIGH aggregation
    survivors = {}
    records = []
    for enc_name, enc_fn in ENCODINGS:
        if sent >= cap:
            result["skipped"]["__all__"] = "budget exhausted (%d requests)" % cap
            break
        try:
            encoded = enc_fn(str(marker))
        except Exception as exc:
            result["skipped"]["encoding:" + enc_name] = "error: %s" % exc
            continue
        for place_name, place_fn in PLACEMENTS:
            if sent >= cap:
                result["skipped"]["__all__"] = (
                    "budget exhausted (%d requests)" % cap)
                break
            try:
                url, param = place_fn(base_url, encoded, {"param": DEFAULT_PARAM})
                hdrs = _headers_for(place_name, encoded)
                st, _h, body = fetch("GET", url, headers=hdrs)
            except Exception as exc:
                result["skipped"]["%s/%s" % (enc_name, place_name)] = (
                    "error: %s" % exc)
                continue
            sent += 1
            if rate_limit_s and sent < cap:
                time.sleep(rate_limit_s)
            alive = (200 <= int(st or 0) < 400 and _reflected(str(marker), body))
            records.append((enc_name, place_name, param, st, alive))
            if alive:
                survivors.setdefault(param, set()).add(enc_name)
    result["ran"] = [
        {"encoding": e, "placement": p, "param": k, "status": s,
         "survived": a} for e, p, k, s, a in records]
    result["requests_sent"] = sent

    # per-encoding findings; HIGH when the same param survived through
    # multiple encodings (WAF-weak signal, requires manual analysis).
    for enc_name, place_name, param, st, alive in records:
        if not alive:
            continue
        multi = len(survivors.get(param, ())) > 1
        others = sorted(survivors.get(param, set()) - {enc_name})
        findings = result["findings"]
        findings.append(Finding(
            title="reflection survives encoding %s (%s)" % (enc_name,
                                                            place_name),
            severity="high" if multi else "low",
            confidence="medium",
            verification="candidate",
            verification_note=(
                "The harmless marker was reflected after server "
                "normalization through encoding '%s' in placement '%s'. "
                "%s This is a WAF-weakness signal that REQUIRES MANUAL "
                "WAF ANALYSIS; no exploit payload was sent and nothing "
                "was decoded or evaluated."
                % (enc_name, place_name,
                   ("Multiple encodings (%d) survive on the same "
                    "parameter (%s): %s — likely WAF normalization gap."
                    % (len(survivors[param]), param,
                       ", ".join(others))) if multi else "")),
            manual_check='curl -s "%s" | grep -F "%s"' % (url if False else
                                                          _last_url(
                                                              base_url, enc_name,
                                                              place_name, param,
                                                              marker),
                                                          marker),
            location=_last_url(base_url, enc_name, place_name, param, marker),
            evidence={"encoding": enc_name, "placement": place_name,
                      "param": param, "status": st,
                      "surviving_encodings_on_param":
                          sorted(survivors.get(param, set()))},
            source="omega-matrix/reflect"))
    return result


def _last_url(base_url, enc_name, place_name, param, marker):
    """Rebuild the probe URL for evidence (deterministic, no state)."""
    enc_fn = dict(ENCODINGS)[enc_name]
    encoded = enc_fn(str(marker))
    url, _p = dict(PLACEMENTS)[place_name](base_url.rstrip("/"), encoded,
                                           {"param": DEFAULT_PARAM})
    return url
