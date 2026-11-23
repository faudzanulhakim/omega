"""omega/offense — the explicitly-gated OFFENSE layer.

This layer is SEPARATE from the read-only evidence layers: it actively
attacks AUTHORIZED pentest targets with brute-force and injection
payload classes (the same category as sqlmap/hydra as tools).

Safety architecture:
  * separate gate: env PTK_OFFENSE=1 (NOT PTK_POLYGLOT) or an explicit
    ``allow=True`` argument from a caller that has verified operator
    intent. ``offense_gate_ok`` raises PermissionError otherwise.
  * CLI flag --offense is the operator-facing switch.
  * hard rate caps: MAX_REQUESTS (300) per suite run, per-attempt
    rate limiting (default 1 req/sec), max_attempts caps.
  * operator-supplied wordlists only (env OMEGA_WORDLIST /
    OMEGA_PASSLIST or explicit args); the built-in 20-entry tiny
    default list is used ONLY when the operator passes
    ``allow_default=True``.
  * findings are honest: ``confirmed`` only when the documented
    differential condition fully holds, ``candidate`` otherwise.
  * no destructive data operations anywhere: no file deletion, no DB
    drops — evidence and read markers only (audited in payloadgen).
"""

from __future__ import annotations

import os

__all__ = [
    "GATE_ENV",
    "MAX_REQUESTS",
    "budget_left",
    "count_request",
    "offense_gate_ok",
    "requests_used",
    "reset_budget",
]

GATE_ENV = "PTK_OFFENSE"
MAX_REQUESTS = 300  # default cap; override with OMEGA_MAX_REQUESTS env


def max_requests():
    """Effective request cap: OMEGA_MAX_REQUESTS env overrides the
    default (operator-controlled; no upper bound imposed)."""
    raw = os.environ.get("OMEGA_MAX_REQUESTS")
    if raw and raw.isdigit():
        return int(raw)
    return MAX_REQUESTS

_used = {"n": 0}


def offense_gate_ok(allow=False):
    """Gate check: True when PTK_OFFENSE=1 is set OR ``allow=True``.

    Otherwise raises PermissionError('offense layer disabled: run with
    --offense'). Callers that already verified operator intent (e.g.
    the --offense CLI flag) pass allow=True; library paths check the
    environment gate.
    """
    if os.environ.get(GATE_ENV) == "1" or allow:
        return True
    raise PermissionError(
        "offense layer disabled: run with --offense")


def gate_open():
    """Non-raising check used by suites: True only when env gate is set."""
    return os.environ.get(GATE_ENV) == "1"


def count_request(n=1):
    """Record n requests against the per-run global cap. Returns used."""
    _used["n"] += int(n)
    return _used["n"]


def requests_used():
    return _used["n"]


def budget_left():
    return max(0, max_requests() - _used["n"])


def reset_budget():
    _used["n"] = 0


# ---------------------------------------------------------------------------
# capability exports (lazy: avoids import cycles between this package
# and the alias module omega.offense that the capability modules import
# their budget helpers from)
# ---------------------------------------------------------------------------

_CAPABILITY_MODULES = {
    "brute": "omega.offensive.offense.brute",
    "injection": "omega.offensive.offense.injection",
    "payloadgen": "omega.offensive.offense.payloadgen",
    "fuzz": "omega.offensive.offense.fuzz",
}

_CAPABILITIES = (
    # brute.py
    "DEFAULT_WORDLIST", "DEFAULT_TOP_PASSWORDS", "DEFAULT_TOP_USERNAMES",
    "DEFAULT_RATE", "http_basic_bruteforce", "jwt_none_forge",
    "load_wordlist", "load_list", "brute_form", "credential_stuff",
    # payloadgen.py
    "CLASSES", "DESTRUCTIVE_PATTERNS", "audit_no_destructive",
    "generate_matrix", "polymorphic", "polyglot_payloads",
    "staged_payloads", "context_xss_payloads",
    # injection.py
    "run_injections", "run_offense_suite",
    # fuzz.py
    "FUZZ_DICT", "CRASH_FINGERPRINTS", "mutate", "fuzz_params",
)

_cap_cache = {}


def __getattr__(name):  # PEP 562 lazy capability export
    if name not in _CAPABILITIES:
        raise AttributeError(
            "module %r has no attribute %r" % (__name__, name))
    if name not in _cap_cache:
        for mod_name in _CAPABILITY_MODULES.values():
            module = __import__(mod_name, fromlist=["__trash__"])
            if hasattr(module, name):
                _cap_cache[name] = getattr(module, name)
                break
        else:  # pragma: no cover
            raise AttributeError(name)
    return _cap_cache[name]


def __dir__():
    return sorted(set(globals()) | set(_CAPABILITIES))
