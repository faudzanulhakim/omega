"""omega/core/wafadapt — adaptive anti-protection strategist.

Fingerprints the protection layer in front of a target (CDN/WAF/
bot-mitigation) from benign response headers + body markers, then
returns a per-provider strategy the scan layers apply:

  - pacing (min interval between requests, ms)
  - header normalization (drop scanner-telltales)
  - cookie reuse requirement
  - payload style preference (encode, lowercase mix)
  - notes (what NOT to do — e.g. no concurrent bursts)

Planning only: applying the strategy is the caller's job (the noise
governor consumes `pacing_ms`). Benign fingerprinting only — one
request per probe marker, no evasion payloads.
"""
import re

__all__ = ["fingerprint_protection", "strategy_for", "adaptation_plan"]

_PROVIDERS = [
    ("cloudflare", r"cf-ray|__cfduid|cf-cache-status|"
                   r"attention required.*cloudflare"),
    ("imperva", r"x-iinfo|x-cdn: incapsula|visid_incap|"
                r"incapsula incident id"),
    ("akamai", r"akamai|server:.*akamai|x-akamai"),
    ("perimeterx", r"pxhd|x-px|captcha-delimiter|perimeterx"),
    ("datadome", r"x-dd-b|x-datadome|datadome"),
    ("sucuri", r"x-sucuri|x-sucuri-id|sucuri cloudproxy"),
    ("cloudfront", r"x-amz-cf-id|x-amzn-requestid|via:.*cloudfront"),
    ("varnish", r"x-varnish|x-served-by"),
]
_STRATEGIES = {
    "cloudflare": {"pacing_ms": 350, "reuse_cookies": True,
                   "encode_style": "standard", "concurrency": 1,
                   "notes": ["avoid burst > 5 req/s",
                             "JS-challenge pages = data, do not solve"]},
    "imperva": {"pacing_ms": 450, "reuse_cookies": True,
                "encode_style": "single-encode", "concurrency": 1,
                "notes": ["keep session cookie jar warm",
                          "retry blocked probe only once"]},
    "akamai": {"pacing_ms": 400, "reuse_cookies": True,
               "encode_style": "standard", "concurrency": 1,
               "notes": ["no sensor-data forging"]},
    "perimeterx": {"pacing_ms": 500, "reuse_cookies": True,
                   "encode_style": "standard", "concurrency": 1,
                   "notes": ["captcha = stop, mark blocked"]},
    "datadome": {"pacing_ms": 500, "reuse_cookies": True,
                 "encode_style": "double-encode", "concurrency": 1,
                 "notes": ["geo-challenge = mark blocked"]},
    "sucuri": {"pacing_ms": 300, "reuse_cookies": True,
               "encode_style": "standard", "concurrency": 1,
               "notes": []},
    "cloudfront": {"pacing_ms": 150, "reuse_cookies": False,
                   "encode_style": "standard", "concurrency": 2,
                   "notes": []},
    "varnish": {"pacing_ms": 100, "reuse_cookies": False,
                "encode_style": "standard", "concurrency": 2,
                "notes": []},
}
_DEFAULT = {"pacing_ms": 120, "reuse_cookies": False,
            "encode_style": "standard", "concurrency": 2,
            "notes": []}


def fingerprint_protection(headers, body=""):
    """Identify the protection provider from headers/body markers.

    headers: dict-like; body: str. Returns (provider, confidence).
    """
    blob = " ".join("%s:%s" % (k, v) for k, v in
                    dict(headers or {}).items()).lower() + \
        " " + (body or "")[:4096].lower()
    for name, pattern in _PROVIDERS:
        m = re.search(pattern, blob, re.I)
        if m:
            conf = 0.9 if re.search(pattern, blob.split(" ", 1)[0]) \
                else 0.6
            return name, conf
    return "generic", 0.2


def strategy_for(provider):
    """Strategy dict for a provider (defaults for unknown)."""
    return dict(_STRATEGIES.get(provider, _DEFAULT))


def adaptation_plan(headers, body="", lessons=None):
    """Full plan: fingerprint + strategy + actionable notes."""
    provider, conf = fingerprint_protection(headers, body)
    plan = strategy_for(provider)
    plan["provider"] = provider
    plan["confidence"] = conf
    plan["recommended"] = (
        "apply pacing_ms via OMEGA_NOISE_INTERVAL and keep "
        "concurrency <= %d" % plan["concurrency"])
    return plan
