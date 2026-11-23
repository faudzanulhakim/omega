"""omega/scanning/userenum.py — user/email enumeration differential
(fusion suite name: ``userenum``).

On register/login/forgot paths (from path_info plus common defaults)
that accept POST, two profiles of obviously-fake probes are sent three
times each:

  profile A: fake email probe1/probe2@omegaprobe.invalid + valid-format
             password  (nonexistent-user pattern)
  profile B: same fake email + intentionally invalid short password
             (bad-password pattern)

Responses are diffed structurally and per-profile timing medians (of 3)
are compared. A candidate LOW/MEDIUM finding labeled
``possible user enumeration (manual confirm)`` is emitted when the
message text differs structurally between the two profiles. Never
brute-forces real user lists; never raises; bounded.
"""

from __future__ import annotations

import re
import statistics
import time

from omega.scanning.deepchecks import default_fetch

__all__ = [
    "Finding",
    "ENUM_PATH_DEFAULTS",
    "PROBE_EMAILS",
    "run_userenum",
]

ENUM_PATH_DEFAULTS = ("/login", "/signin", "/signup", "/register",
                      "/forgot-password", "/reset")
ENUM_PATH_RE = re.compile(
    r"register|login|signin|signup|forgot|password|reset", re.I)
PROBE_EMAILS = ("probe1@omegaprobe.invalid", "probe2@omegaprobe.invalid",
                "probe3@omegaprobe.invalid")
VALID_PASSWORD = "OmegaProbe!2026x"
BAD_PASSWORD = "x"  # invalid format, elicits password-validation text
TIMING_THRESHOLD_MS = 120
ENUM_MARKER = "possible user enumeration (manual confirm)"


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
    """Contained POST/GET with timing -> (status, text, ms) or None."""
    try:
        t0 = time.perf_counter()
        st, _h, raw = fetch(method, url, headers=headers, body=body)
        ms = (time.perf_counter() - t0) * 1000.0
        return st, _text(raw), ms
    except Exception:
        return None


def _norm(text):
    """Collapse whitespace so only message structure is compared."""
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def _candidate_paths(path_info, max_paths):
    paths = []
    info = path_info if isinstance(path_info, dict) else {}
    for p in info.get("paths") or []:
        p = str(p)
        if p and ENUM_PATH_RE.search(p) and p not in paths:
            paths.append(p)
    for p in ENUM_PATH_DEFAULTS:
        if p not in paths:
            paths.append(p)
    return paths[:max_paths]


def _probe_body(email, password):
    return "email=%s&username=%s&password=%s&submit=1" % (
        email, email.split("@")[0], password)


def _median_ms(samples):
    return statistics.median([s[2] for s in samples if s]) if samples \
        else None


def run_userenum(base_url, fetch=default_fetch, path_info=None,
                 gate=False, max_paths=4, budget=60):
    """Benign enumeration differential. Returns a list of Finding
    dicts; never raises."""
    out = []
    base = base_url if "://" in base_url else "http://" + base_url
    base = base.rstrip("/")
    sent = 0
    form_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        for path in _candidate_paths(path_info, max_paths):
            if sent >= budget or len(out) >= 4:
                break
            url = base + path
            # Path must accept POST, else skip entirely.
            post0 = _req(fetch, "POST", url, headers=form_headers,
                         body=_probe_body(PROBE_EMAILS[0], VALID_PASSWORD))
            sent += 1
            if post0 is None or post0[0] in (404, 405, 501) \
                    or post0[0] >= 500:
                continue

            # Profile A: nonexistent-user pattern (3x, median of 3).
            prof_a = []
            for i in range(3):
                if sent >= budget:
                    break
                prof_a.append(_req(
                    fetch, "POST", url, headers=form_headers,
                    body=_probe_body(PROBE_EMAILS[i % len(PROBE_EMAILS)],
                                     VALID_PASSWORD)))
                sent += 1
            prof_a = [r for r in prof_a if r]
            if len(prof_a) < 3:
                continue

            # Profile B: bad-password pattern (3x, median of 3).
            prof_b = []
            for _i in range(3):
                if sent >= budget:
                    break
                prof_b.append(_req(
                    fetch, "POST", url, headers=form_headers,
                    body=_probe_body(PROBE_EMAILS[0], BAD_PASSWORD)))
                sent += 1
            prof_b = [r for r in prof_b if r]
            if len(prof_b) < 3:
                continue

            msg_a = {_norm(r[1]) for r in prof_a}
            msg_b = {_norm(r[1]) for r in prof_b}
            statuses_a = {r[0] for r in prof_a}
            statuses_b = {r[0] for r in prof_b}

            med_a = _median_ms(prof_a)
            med_b = _median_ms(prof_b)

            structural = bool(msg_a - msg_b or msg_b - msg_a
                              or statuses_a != statuses_b)
            if structural:
                out.append(Finding(
                    title="%s at %s" % (ENUM_MARKER.capitalize(), path),
                    severity="medium", verification="candidate",
                    verification_note=(
                        "%s: responses to obviously-fake probe "
                        "submissions differ structurally between a "
                        "nonexistent-user pattern and a bad-password "
                        "pattern on %s (distinct message text/status). "
                        "This can let an attacker confirm which emails "
                        "exist. Manual confirm required; no real user "
                        "lists were probed. Candidate only."
                        % (ENUM_MARKER, path)),
                    manual_check=("curl -sS -d 'email=probe1@omegaprobe."
                                  "invalid&password=x' %s" % url),
                    location=url,
                    evidence="profileA=%d distinct resp, profileB=%d "
                             "distinct resp" % (len(msg_a), len(msg_b)),
                    source="omega-userenum", confidence="medium"))
            elif med_a is not None and med_b is not None and \
                    abs(med_a - med_b) > TIMING_THRESHOLD_MS:
                out.append(Finding(
                    title="%s (timing) at %s" % (ENUM_MARKER.capitalize(),
                                                 path),
                    severity="low", verification="candidate",
                    verification_note=(
                        "Median response timing differs by more than "
                        "%dms between fake-user (%.0fms) and bad-"
                        "password (%.0fms) probe profiles on %s. Timing "
                        "side-channels are noisy; manual confirm "
                        "required. Candidate only."
                        % (TIMING_THRESHOLD_MS, med_a, med_b, path)),
                    manual_check=("curl -sS -o /dev/null -w '%%{time_"
                                  "total}\\n' -d 'email=probe1@"
                                  "omegaprobe.invalid&password=x' %s" % url),
                    location=url,
                    evidence="median A=%.0fms B=%.0fms" % (med_a, med_b),
                    source="omega-userenum", confidence="low"))
    except Exception:
        pass
    return out
