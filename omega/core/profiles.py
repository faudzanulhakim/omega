"""omega/core/profiles.py — scan profile packs for campaign mode.

A profile pack selects a SUBSET of the fusion suite names
(omega.fusion.SUITES) plus a per-target request budget, so a campaign
can run a bounded, purpose-fitted scan instead of the full arsenal.

Rules honored here:
- suites: tuple of fusion suite names (validated against SUITES by the
  tests) or None meaning "every suite" (the 'full' pack, offense gate
  still closed unless the operator passes --aggressive).
- extras: non-fusion probe capability names run per-target by the
  campaign (e.g. 'tfinger', 'apimap'); empty for most packs.
- budget: per-suite request budget handed to fusion.
- offense/exploit gates are NOT part of a pack; they stay closed by
  default and are only opened by an explicit operator flag.

Pure data + two small helpers. Never raises on bad input: unknown
profile names fall back to 'web'.
"""

# Passive web suites (no payload injection, no OOB, no path brute
# force) — the default campaign profile.
_WEB_PASSIVE = (
    "python-deep",
    "python-headerscan",
    "python-probes",
    "python-api",
    "python-graphql-deep",
    "python-hyper",
    "python-redirects",
    "python-jsrender",
    "python-subperm",
    "node-hdr",
    "python-sentinel",
    "deser-safe",
    "upl-hygiene",
    "secops-hygiene",
    "blotamper",
    "php-seriscan",
    "c-urlinfo",
    "ruby-urlaudit",
    "cpp-hdrstruct",
    "awk-urlmine",
    "sh-methodcheck",
    "rust-pathscope",
)

DEFAULT_PROFILE = "web"

PROFILES = {
    "quick": {
        "suites": ("python-deep", "python-headerscan", "python-probes"),
        "extras": (),
        "budget": 60,
    },
    "web": {
        "suites": _WEB_PASSIVE,
        "extras": (),
        "budget": 200,
    },
    # None = every fusion suite, including offense-compatible ones
    # (the offense suite itself still degrades to a contained skip
    # while PTK_OFFENSE is unset).
    "full": {
        "suites": None,
        "extras": (),
        "budget": 400,
    },
    "cloud": {
        "suites": ("cloud-exposure", "k8s-exposure", "cicd-chain"),
        "extras": ("tfinger",),
        "budget": 120,
    },
    "mobile": {
        "suites": ("mobile-android", "mobile-ios", "mobile-general"),
        "extras": (),
        "budget": 150,
    },
    "api": {
        "suites": ("python-api", "python-graphql-deep", "deser-safe",
                   "python-jsrender"),
        "extras": ("apimap",),
        "budget": 120,
    },
    "llm": {
        "suites": ("llm-app", "python-api"),
        "extras": (),
        "budget": 80,
    },
}


def resolve_profile(name=None):
    """Resolve a profile NAME to a profile dict.

    Unknown/missing names fall back to DEFAULT_PROFILE ('web').
    Returns a fresh dict {name, suites, extras, budget} so callers can
    mutate it safely. Never raises.
    """
    key = str(name or DEFAULT_PROFILE).strip().lower()
    if key not in PROFILES or not isinstance(PROFILES.get(key), dict):
        key = DEFAULT_PROFILE
    src = PROFILES[key]
    budget = src.get("budget")
    if not isinstance(budget, int) or budget <= 0:
        budget = PROFILES[DEFAULT_PROFILE]["budget"]
    return {
        "name": key,
        "suites": tuple(src.get("suites") or ()) or None,
        "extras": tuple(src.get("extras") or ()),
        "budget": int(budget),
    }


def list_profiles():
    """Sorted list of available profile names."""
    return sorted(k for k, v in PROFILES.items() if isinstance(v, dict))
