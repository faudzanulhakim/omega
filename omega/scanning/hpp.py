"""omega/scanning/hpp.py — HTTP parameter pollution + mass assignment
(fusion suite name: ``hpp``).

For each path+param pair from ``path_info``, send the parameter
duplicated with different values (``&p=1&p=2``) and compare the
response with the single-value baseline; a consistent differential is
a candidate low/medium finding.

Mass-assignment probe: ONLY for paths that ``path_info`` reports as
having accepted POST before (``path_info["post_paths"]``), append
benign privileged fields (``role=omega-probe``, ``isAdmin=0``,
``price=0``) to a POST body; if the endpoint returns 2xx with a body
differing from a baseline POST without the field, report candidate
medium ``parameter accepted without rejection``.

Benign values only; GET/POST of the already-known paths/params; never
raises.
"""

from __future__ import annotations

import urllib.parse

from omega.scanning.deepchecks import Finding, default_fetch

__all__ = [
    "REQUEST_BUDGET",
    "MASS_ASSIGN_FIELDS",
    "candidate_pairs",
    "hpp_differential",
    "mass_assignment_probe",
    "run_hpp",
]

REQUEST_BUDGET = 40

# Benign privileged-looking fields appended in the mass-assignment
# probe. Values are inert markers, not real privilege grants.
MASS_ASSIGN_FIELDS = (
    ("role", "omega-probe"),
    ("isAdmin", "0"),
    ("price", "0"),
)


def candidate_pairs(path_info=None):
    """(path, param) pairs from path_info, deduped, capped."""
    info = path_info or {}
    paths = [p for p in (info.get("paths") or []) if p not in ("/",)]
    if not paths:
        paths = ["/"]
    params = list(info.get("params") or [])
    pairs = []
    for path in paths[:8]:
        for param in params[:6]:
            pairs.append((path, param))
    if not pairs and params:
        for param in params[:6]:
            pairs.append(("/", param))
    return pairs[:12]


def _text(body):
    if isinstance(body, bytes):
        return body.decode("latin-1", "replace")
    return str(body or "")


def hpp_differential(base_url, path, param, fetch):
    """Send p=v1 and p=v1&p=v2; return (baseline, dup, dup_again)
    response triples, or None on request error. The caller decides
    whether the differential is a finding."""
    base = base_url.rstrip("/")
    url = base + (path if path.startswith("/") else "/" + path)
    q = urllib.parse.urlencode({param: "omega1"})
    dup_q = "%s=%s&%s=%s" % (
        urllib.parse.quote(param, safe=""), "omega1",
        urllib.parse.quote(param, safe=""), "omega2")
    sep = "&" if "?" in url else "?"
    try:
        st1, h1, b1 = fetch("GET", url + sep + q)
        st2, h2, b2 = fetch("GET", url + sep + dup_q)
        st3, h3, b3 = fetch("GET", url + sep + dup_q)
    except Exception:
        return None
    return ((st1, h1, b1), (st2, h2, b2), (st3, h3, b3))


def _differs(a, b):
    """True when status or body meaningfully differs."""
    if a[0] != b[0]:
        return True
    return _text(a[2]) != _text(b[2])


def mass_assignment_probe(base_url, path, fetch):
    """POST with benign privileged fields appended vs baseline POST.
    Returns a Finding or None. Only invoked for paths that path_info
    reports as accepting POST."""
    base = base_url.rstrip("/")
    url = base + (path if path.startswith("/") else "/" + path)
    extra = "&".join("%s=%s" % (urllib.parse.quote(k, safe=""),
                                urllib.parse.quote(v, safe=""))
                     for k, v in MASS_ASSIGN_FIELDS)
    try:
        st0, _h0, b0 = fetch("POST", url, body="baseline=1")
        st1, _h1, b1 = fetch("POST", url,
                             body="baseline=1&" + extra)
    except Exception:
        return None
    if not (200 <= (st0 or 0) < 300) or not (200 <= (st1 or 0) < 300):
        return None
    if _text(b0) == _text(b1):
        return None
    return Finding(
        title="Mass-assignment probe: extra parameter accepted at %s"
              % path,
        severity="medium", verification="candidate",
        verification_note=(
            "POSTing with appended privileged-looking fields "
            "(role=omega-probe, isAdmin=0, price=0 — all inert values) "
            "produced a different 2xx response than the baseline POST "
            "— the endpoint accepted the extra parameter without "
            "rejection. Candidate only; confirm the fields are not "
            "bound into server-side models."),
        manual_check=(
            "curl -sS -i -X POST -d 'baseline=1&role=admin&isAdmin=1' "
            "%s" % url),
        location=url,
        evidence="post_status=%d baseline_status=%d body_differs=True"
                 % (st1, st0),
        source="omega-hpp/mass_assignment")


def run_hpp(base_url, fetch=default_fetch, path_info=None, gate=False):
    """HTTP parameter pollution + mass-assignment suite. Returns a list
    of Finding dicts; never raises; budget-capped."""
    findings = []
    budget = REQUEST_BUDGET
    base = (base_url or "").rstrip("/")
    if not base:
        return findings
    info = path_info or {}
    post_paths = [p for p in (info.get("post_paths") or [])][:5]

    for path, param in candidate_pairs(path_info):
        if budget <= 0:
            break
        budget -= 3
        triple = hpp_differential(base, path, param, fetch)
        if triple is None:
            continue
        baseline, dup, dup_again = triple
        if not _differs(baseline, dup):
            continue
        # consistency: the duplicated request must reproduce the same
        # differential on a second send
        if not _differs(baseline, dup_again) or \
                _text(dup[2]) != _text(dup_again[2]) or dup[0] != dup_again[0]:
            continue
        findings.append(Finding(
            title="HTTP parameter pollution differential at %s (%s)"
                  % (path, param),
            severity="medium" if baseline[0] != dup[0] else "low",
            verification="candidate",
            verification_note=(
                "Sending the parameter %s duplicated with different "
                "values (%s=%s&%s=%s) consistently produced a different "
                "response than the single-value baseline (status %s vs "
                "%s) — the stack does not normalize duplicate "
                "parameters. Candidate only." % (
                    param, param, "omega1", param, "omega2",
                    dup[0], baseline[0])),
            manual_check='curl -sS -i "%s?%s=%s&%s=%s"'
                         % (base + path, param, "omega1", param, "omega2"),
            location=base + path,
            evidence="param=%s status=%s baseline_status=%s repeat_ok=True"
                     % (param, dup[0], baseline[0]),
            source="omega-hpp/hpp_differential"))

    for path in post_paths:
        if budget <= 0:
            break
        budget -= 2
        found = mass_assignment_probe(base, path, fetch)
        if found is not None:
            findings.append(found)
    return findings
