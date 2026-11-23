"""omega/scanning/corscheck.py — CORS misconfiguration matrix
(fusion suite name: ``corscheck``).

For paths from ``path_info`` plus '/', send GET with several Origin
values (https://evil.example, null) and parse
Access-Control-Allow-Origin / Access-Control-Allow-Credentials:

  acao_reflects_arbitrary  — ACAO mirrors an arbitrary attacker origin
                             (high candidate)
  acao_reflect_with_credentials — reflected origin plus
                             Access-Control-Allow-Credentials: true
                             (high candidate)
  acao_null_with_credentials — Origin: null reflected with credentials
                             (high candidate)
  acao_wildcard            — ACAO: * (info; no credentials allowed on
                             wildcard per spec, so informational)

No Access-Control-Allow-Origin in the response -> no finding (clean).
GET-only, benign origins only, never raises.
"""

from __future__ import annotations

from omega.scanning.deepchecks import Finding, default_fetch

__all__ = [
    "REQUEST_BUDGET",
    "EVIL_ORIGIN",
    "acao_probe",
    "candidate_paths",
    "run_corscheck",
]

REQUEST_BUDGET = 30
EVIL_ORIGIN = "https://evil.example"


def candidate_paths(path_info=None):
    """Paths to probe: discovered paths plus '/', deduped, capped."""
    paths = ["/"]
    for p in ((path_info or {}).get("paths") or []):
        clean = (p or "").split("?")[0] or "/"
        if clean not in paths:
            paths.append(clean)
    return paths[:10]


def _hdr(headers, name):
    """Case-insensitive header lookup (headers dict may be either case)."""
    lname = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == lname:
            return v
    return None


def acao_probe(base_url, path, origin, fetch):
    """One probe: returns (status, headers, body) or (None, {}, b'')."""
    url = base_url.rstrip("/") + path
    try:
        st, headers, body = fetch("GET", url, headers={"Origin": origin})
        return st, headers, body
    except Exception:
        return None, {}, b""


def run_corscheck(base_url, fetch=default_fetch, path_info=None, gate=False):
    """CORS misconfiguration matrix. Returns a list of Finding dicts;
    never raises; budget-capped."""
    findings = []
    budget = REQUEST_BUDGET
    base = (base_url or "").rstrip("/")
    if not base:
        return findings
    for path in candidate_paths(path_info):
        if budget <= 0:
            break
        # probe 1: arbitrary evil origin
        budget -= 1
        st, headers, _body = acao_probe(base, path, EVIL_ORIGIN, fetch)
        acao = _hdr(headers, "Access-Control-Allow-Origin")
        acac = _hdr(headers, "Access-Control-Allow-Credentials")
        # probe 2: null origin (policies sometimes special-case it)
        acao2 = acac2 = None
        if budget > 0:
            budget -= 1
            _st2, headers2, _b2 = acao_probe(base, path, "null", fetch)
            acao2 = _hdr(headers2, "Access-Control-Allow-Origin")
            acac2 = _hdr(headers2, "Access-Control-Allow-Credentials")
        if acao2 and acao2.strip() == "null" and _true(acac2):
            findings.append(Finding(
                title='CORS reflects Origin: null with credentials at %s'
                      % path,
                severity="high", verification="candidate",
                verification_note=(
                    'A request with Origin: null received '
                    'Access-Control-Allow-Origin: null plus '
                    'Access-Control-Allow-Credentials: true - '
                    'sandboxed/redirect null-origin requests can read '
                    'credentialed responses. Candidate only.'),
                manual_check='curl -sS -i -H "Origin: null" "%s%s"'
                             % (base, path),
                location=base + path,
                evidence="acao=%s acac=%s" % (acao2, acac2),
                source="omega-corscheck/acao_null_with_credentials"))
        if acao is None:
            continue
        if acao.strip() == "*":
            findings.append(Finding(
                title="CORS wildcard Access-Control-Allow-Origin: * at %s"
                      % path,
                severity="info", verification="verified",
                verification_note=(
                    'The endpoint answers Access-Control-Allow-Origin: * '
                    "for %s. Wildcard CORS cannot carry credentials per "
                    "spec, so this is informational; confirm no "
                    "authenticated data is exposed here." % EVIL_ORIGIN),
                manual_check='curl -sS -i -H "Origin: %s" "%s%s"'
                             % (EVIL_ORIGIN, base, path),
                location=base + path,
                evidence="acao=* origin=%s status=%s" % (EVIL_ORIGIN, st),
                source="omega-corscheck/acao_wildcard"))
            continue
        if acao.strip() == EVIL_ORIGIN:
            if _true(acac):
                findings.append(Finding(
                    title="CORS reflects arbitrary origin with "
                          "credentials at %s" % path,
                    severity="high", verification="candidate",
                    verification_note=(
                        "Access-Control-Allow-Origin mirrors "
                        "%s AND Access-Control-Allow-Credentials is true "
                        "— any origin can make credentialed reads. "
                        "Candidate only; confirm with a browser-based "
                        "fetch." % EVIL_ORIGIN),
                    manual_check='curl -sS -i -H "Origin: %s" "%s%s"'
                                 % (EVIL_ORIGIN, base, path),
                    location=base + path,
                    evidence="acao=%s acac=%s status=%s"
                             % (acao, acac, st),
                    source="omega-corscheck/acao_reflect_with_credentials"))
            else:
                findings.append(Finding(
                    title="CORS reflects arbitrary origin at %s" % path,
                    severity="high", verification="candidate",
                    verification_note=(
                        "Access-Control-Allow-Origin mirrors the "
                        "attacker-supplied origin %s — the policy does "
                        "not validate origins. Candidate only; without "
                        "credentials the impact may be limited to "
                        "non-authenticated resources." % EVIL_ORIGIN),
                    manual_check='curl -sS -i -H "Origin: %s" "%s%s"'
                                 % (EVIL_ORIGIN, base, path),
                    location=base + path,
                    evidence="acao=%s acac=%s status=%s"
                             % (acao, acac, st),
                    source="omega-corscheck/acao_reflects_arbitrary"))
    return findings


def _true(value):
    return str(value or "").strip().lower() == "true"
