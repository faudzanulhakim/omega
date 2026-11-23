"""omega/reporting/cvss — CVSS v3.1 base score computation.

Maps each finding to a base metric vector using conservative,
CWE-driven defaults (no invented values: a missing CWE falls back to
AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N for HIGH-class findings, then
scaled down by severity). Implements the official v3.1 formula from
FIRST, including the scope-changed variant.
"""
import re

__all__ = ["vector_for", "base_score", "score_finding"]

_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

# CWE -> (AV, AC, PR, UI, S, C, I, A)
_CWE_DEFAULTS = {
    "CWE-89": ("N", "L", "N", "N", "U", "H", "H", "N"),
    "CWE-79": ("N", "L", "N", "R", "C", "L", "L", "N"),
    "CWE-22": ("N", "L", "N", "N", "U", "H", "N", "N"),
    "CWE-434": ("N", "L", "N", "N", "U", "H", "H", "H"),
    "CWE-918": ("N", "L", "N", "N", "C", "L", "L", "N"),
    "CWE-611": ("N", "L", "N", "N", "U", "H", "N", "N"),
    "CWE-200": ("N", "L", "N", "N", "U", "L", "N", "N"),
    "CWE-352": ("N", "H", "N", "R", "U", "L", "L", "N"),
    "CWE-521": ("N", "L", "N", "N", "U", "L", "L", "L"),
    "CWE-287": ("N", "L", "N", "N", "U", "H", "H", "N"),
    "CWE-798": ("N", "L", "N", "N", "U", "H", "H", "N"),
}
# severity fallback when no CWE maps
_SEV_VECTOR = {
    "CRITICAL": ("N", "L", "N", "N", "U", "H", "H", "H"),
    "HIGH": ("N", "L", "N", "N", "U", "H", "H", "N"),
    "MEDIUM": ("N", "L", "L", "N", "U", "L", "L", "N"),
    "LOW": ("N", "H", "L", "R", "U", "L", "N", "N"),
    "INFO": ("N", "H", "H", "R", "U", "N", "N", "N"),
}


def vector_for(finding):
    """CVSS vector string for a finding (CWE or severity driven)."""
    cwes = finding.get("cwe") or finding.get("cwes") or []
    if isinstance(cwes, str):
        cwes = [cwes]
    for c in cwes:
        c = str(c).upper()
        if c in _CWE_DEFAULTS:
            av, ac, pr, ui, s, cc, ci, ia = _CWE_DEFAULTS[c]
            return "CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s" \
                % (av, ac, pr, ui, s, cc, ci, ia)
    sev = str(finding.get("severity", "MEDIUM")).upper()
    av, ac, pr, ui, s, cc, ci, ia = _SEV_VECTOR.get(
        sev, _SEV_VECTOR["MEDIUM"])
    return "CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s" % (
        av, ac, pr, ui, s, cc, ci, ia)


def base_score(vector):
    """Official CVSS v3.1 base score from a vector string."""
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
    scope_changed = parts.get("S", "U") == "C"
    av = _WEIGHTS["AV"][parts.get("AV", "N")]
    ac = _WEIGHTS["AC"][parts.get("AC", "L")]
    if scope_changed:
        pr = _PR_CHANGED[parts.get("PR", "N")]
    else:
        pr = _WEIGHTS["PR"][parts.get("PR", "N")]
    ui = _WEIGHTS["UI"][parts.get("UI", "N")]
    c = _WEIGHTS["CIA"][parts.get("C", "N")]
    i = _WEIGHTS["CIA"][parts.get("I", "N")]
    a = _WEIGHTS["CIA"][parts.get("A", "N")]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10)
    else:
        raw = min(impact + exploitability, 10)
    if raw <= 0:
        return 0.0
    # roundup to 1 decimal per spec
    import math
    return math.ceil(raw * 10) / 10.0


_VECTOR_RE = re.compile(
    r"^CVSS:3\.[01]/AV:[NAL]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/"
    r"C:[NLH]/I:[NLH]/A:[NLH]$")


def _valid_vector(vec):
    """Syntactic + semantic CVSS v3.1 vector validation."""
    if not isinstance(vec, str) or not _VECTOR_RE.match(vec.strip()):
        return False
    try:
        base_score(vec.strip())
        return True
    except Exception:
        return False


def score_finding(finding):
    """Attach cvss_vector + cvss_score to a finding copy.

    An operator-supplied, syntactically valid CVSS v3.1 vector is
    PRESERVED and rescored from the vector itself; a stale/absent
    vector falls back to CWE/severity derivation. An incoming score
    is never trusted — it is always recomputed from the final vector.
    """
    f = dict(finding)
    supplied = f.get("cvss_vector")
    if _valid_vector(supplied):
        vec = supplied.strip()
        f["cvss_source"] = "vector"
    else:
        # derivation needs at least a recognizable severity or CWE;
        # without either there is no evidence for ANY vector
        sev = str(f.get("severity", "")).upper()
        cwes = f.get("cwe") or f.get("cwes") or []
        recognized = sev in _SEV_VECTOR or any(
            str(c).upper() in _CWE_DEFAULTS
            for c in (cwes if isinstance(cwes, list) else [cwes]))
        if not recognized:
            # honest unavailable: no fabricated default
            f["cvss_vector"] = None
            f["cvss_score"] = None
            f["cvss_source"] = "unavailable"
            return f
        vec = vector_for(f)
        f["cvss_source"] = "derived"
    f["cvss_vector"] = vec
    f["cvss_score"] = base_score(vec)
    return f
