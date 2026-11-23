"""omega/scanning/authbypass.py — 401/403 access-control bypass matrix
(fusion suite name: ``authbypass``).

On any path whose baseline GET returns 401 or 403, a bounded matrix of
benign bypass vectors is tried and each vector's status + body length
is compared against the baseline:

  - alternative methods: POST / HEAD / PUT / PATCH / OPTIONS
  - path mutations: trailing ``/``, ``/.``, ``/%2e``, ``//``, ``/./``,
    an overlong-unicode dot (``/%c0%ae``) and a ``;`` parameter
  - header overrides: X-Original-URL, X-Rewrite-URL,
    X-Forwarded-For: 127.0.0.1, X-Custom-IP-Authorization

A HIGH candidate is emitted when any vector yields 200 with a
substantially different body length than the baseline (the differential
is validated later by the claim gate). Never raises; budget-conscious;
benign markers only.
"""

from __future__ import annotations

__all__ = [
    "Finding",
    "BYPASS_METHODS",
    "BYPASS_PATH_MUTATIONS",
    "BYPASS_HEADERS",
    "run_authbypass",
]

from omega.scanning.deepchecks import default_fetch

BYPASS_METHODS = ("POST", "HEAD", "PUT", "PATCH", "OPTIONS")
BYPASS_PATH_MUTATIONS = (
    ("trailing-slash", "%s/"),
    ("dot-suffix", "%s/."),
    ("encoded-dot", "%s/%%2e"),
    ("double-slash", "%s//"),
    ("dot-segment", "%s/./"),
    ("unicode-dot", "%s/%%c0%%ae"),
    ("semicolon-param", "%s;omega=1"),
)
BYPASS_HEADERS = (
    ("X-Original-URL", "/"),
    ("X-Rewrite-URL", "/"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
)

DEFAULT_PROBE_PATHS = ("/admin", "/api/private", "/internal", "/console",
                       "/dashboard")
MAX_VECTORS_PER_PATH = 16


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


def _req(fetch, method, url, headers=None, body=None):
    """Contained request -> (status, body_len, body_text) or None."""
    try:
        st, _h, raw = fetch(method, url, headers=headers, body=body)
        text = _text(raw)
        return st, len(text), text
    except Exception:
        return None


def _candidate_paths(base_url, path_info, max_paths):
    paths = []
    info = path_info if isinstance(path_info, dict) else {}
    for p in info.get("paths") or []:
        p = str(p)
        if p and p not in paths:
            paths.append(p)
    for p in DEFAULT_PROBE_PATHS:
        if p not in paths:
            paths.append(p)
    return paths[:max_paths]


def _is_substantial_diff(base_len, vec_len):
    """Body-length differential big enough to matter."""
    if base_len <= 0:
        return vec_len > 0
    return abs(vec_len - base_len) > max(16, base_len // 4)


def _vectors(path):
    """Bounded vector list: (kind, name, path_or_none, headers, method)."""
    out = []
    for m in BYPASS_METHODS:
        out.append(("method", m, None, None, m))
    for kind, tmpl in BYPASS_PATH_MUTATIONS:
        out.append(("path", kind, tmpl % path, None, "GET"))
    for hdr, val in BYPASS_HEADERS:
        out.append(("header", hdr, None, {hdr: val}, "GET"))
    return out[:MAX_VECTORS_PER_PATH]


def run_authbypass(base_url, fetch=default_fetch, path_info=None,
                   gate=False, max_paths=5, budget=90):
    """401/403 bypass matrix. Returns a list of Finding dicts; never
    raises. ``gate`` is accepted for the downstream claim gate and does
    not change candidate-only behavior here."""
    out = []
    base = base_url if "://" in base_url else "http://" + base_url
    base = base.rstrip("/")
    sent = 0
    try:
        for path in _candidate_paths(base, path_info, max_paths):
            if sent >= budget or len(out) >= 8:
                break
            url = base + path
            baseline = _req(fetch, "GET", url)
            sent += 1
            if baseline is None or baseline[0] not in (401, 403):
                continue
            b_status, b_len, _ = baseline
            for vkind, vname, vpath, vheaders, vmethod in _vectors(path):
                if sent >= budget:
                    break
                vurl = base + vpath if vpath else url
                res = _req(fetch, vmethod, vurl, headers=vheaders)
                sent += 1
                if res is None or res[0] != 200:
                    continue
                v_len = res[1]
                if not _is_substantial_diff(b_len, v_len):
                    continue
                detail = ("baseline %s %s (len %d) -> vector %s=%s "
                          "(len %d)" % (b_status, path, b_len,
                                        vkind, vname, v_len))
                out.append(Finding(
                    title="Possible 401/403 bypass via %s on %s"
                          % (vkind, path),
                    severity="high", verification="candidate",
                    verification_note=(
                        "A %s bypass vector (%s) returned 200 with a body "
                        "length substantially different from the 401/403 "
                        "baseline (%s). Access-control bypasses need "
                        "human confirmation; validated later by the "
                        "claim gate. Candidate only."
                        % (vkind, vname, detail)),
                    manual_check="curl -sS -i %s" % vurl,
                    location=vurl, evidence=detail,
                    source="omega-authbypass", confidence="medium"))
    except Exception:
        pass
    return out
