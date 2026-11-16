"""OMEGA adaptive evasion engine — defense detection + tactic mutation.

Detects WAF / rate-limiting defenses from real request evidence and
selects a deterministic mutation profile for the next attempt. Every
probe fired here is BENIGN: marker strings only, no destructive
commands. The engine never raises and works fully offline (loopback
servers in tests).
"""

import json
import random
import time
import urllib.parse

# ---------------------------------------------------------------------------
# Benign probe payloads (markers only)
# ---------------------------------------------------------------------------

_PROBES = {
    "xss_marker": "omega-xss-marker",
    "sqli_quote": "omega' sqli-marker",
    "traversal_dots": "../../etc/omega-marker",
    "oversized_param": "A" * 4096,
}

# Response-body keywords that indicate a WAF block page.
_BLOCK_KEYWORDS = [
    "blocked", "forbidden", "security", "waf", "captcha",
    "access denied", "attack detected", "request rejected",
    "cloudflare", "sucuri", "akamai", "imperva",
]

# Vendor fingerprints in Server / Via / CDN headers.
_VENDOR_HEADERS = ["server", "via", "x-cdn", "cf-ray", "x-sucuri-id",
                   "x-akamai-transformed", "x-iinfo"]
_VENDORS = ["cloudflare", "sucuri", "akamai", "imperva", "aws",
            "fastly", "stackpath", "maxcdn"]

_RATE_LIMIT_HEADERS = ["retry-after", "x-ratelimit-limit",
                       "x-ratelimit-remaining", "ratelimit-limit",
                       "ratelimit-remaining"]


def _header(headers, name):
    """Case-insensitive header lookup; returns '' when absent."""
    if not headers:
        return ""
    lower = name.lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == lower:
            return str(v)
    return ""


def _headers_str(headers):
    """Lowercased serialized headers for keyword scans."""
    try:
        return " ".join("%s:%s" % (k, v) for k, v in (headers or {}).items()
                        ).lower()
    except Exception:
        return ""


def _fetch_safe(fetch, method, url, headers=None, body=None):
    """Wrap a fetch call; never raises. Returns (status, headers, body)
    with status=0 and error recorded in signals by the caller on
    network failure."""
    try:
        return fetch(method, url, headers=headers, body=body)
    except Exception:
        return 0, {}, b""


def _probe_url(base_url, path, param, value):
    base = (base_url or "").rstrip("/")
    if not base:
        base = "http://127.0.0.1"
    p = path if isinstance(path, str) and path.startswith("/") else "/" + str(path or "")
    q = urllib.parse.urlencode({param: value})
    return base + p + "?" + q


def probe_defense(fetch, base_url, path="/"):
    """Fire 4 benign attack-shaped probes and analyze the responses.

    Returns {'waf': bool, 'rate_limited': bool, 'vendor': str,
    'signals': [...], 'aggression_limit': int}. Never raises.
    """
    result = {"waf": False, "rate_limited": False, "vendor": "",
              "signals": [], "aggression_limit": 10}
    signals = result["signals"]
    if not callable(fetch):
        signals.append("error:no-fetch-callable")
        return result

    # Baseline: a normal request first.
    status, headers, body = _fetch_safe(fetch, "GET",
                                        _probe_url(base_url, path,
                                                   "probe", "omega-baseline"))
    baseline_blocked = _looks_blocked(status, body, headers)
    baseline_status = status

    payload_statuses = []
    for name, payload in _PROBES.items():
        st, hd, bd = _fetch_safe(fetch, "GET",
                                 _probe_url(base_url, path, "probe", payload))
        payload_statuses.append((name, st))
        if _looks_blocked(st, bd, hd):
            signals.append("block:%s(status=%s)" % (name, st))
        # Vendor fingerprint scan per response.
        vendor = _vendor_from_response(hd, bd)
        if vendor and not result["vendor"]:
            result["vendor"] = vendor
            signals.append("vendor:%s" % vendor)
        for rh in _RATE_LIMIT_HEADERS:
            if _header(hd, rh):
                result["rate_limited"] = True
                signals.append("rate-limit-header:%s=%s"
                               % (rh, _header(hd, rh)))

    # Blocked on payloads but normal on baseline -> WAF present.
    payload_blocked = sum(1 for _, st in payload_statuses
                          if st in (403, 406, 429)
                          and baseline_status not in (403, 406, 429))
    if payload_blocked >= 1 and not baseline_blocked:
        result["waf"] = True
        signals.append("differential:payloads-blocked=%d" % payload_blocked)
    elif baseline_blocked:
        signals.append("baseline-blocked(status=%s)" % baseline_status)

    # 429 anywhere means rate limiting.
    if any(st == 429 for _, st in payload_statuses):
        result["rate_limited"] = True
        signals.append("rate-limit:429-on-payload")

    # Suggest an aggression cap: fewer attempts when defenses exist.
    if result["rate_limited"]:
        result["aggression_limit"] = 2
    elif result["waf"]:
        result["aggression_limit"] = 3
    result["signals"] = signals
    return result


def _looks_blocked(status, body, headers):
    """Heuristic block-page detection from status/body/headers."""
    try:
        text = (body or b"").decode("utf-8", "replace").lower()
    except Exception:
        text = ""
    for kw in _BLOCK_KEYWORDS:
        if kw in text:
            return True
    if status in (403, 406):
        return True
    hdrs = _headers_str(headers)
    return "captcha" in hdrs or "blocked" in hdrs


def _vendor_from_response(headers, body):
    """Extract a vendor name from response headers (then body)."""
    for h in _VENDOR_HEADERS:
        val = _header(headers, h).lower()
        for v in _VENDORS:
            if v in val:
                return v
    try:
        text = (body or b"").decode("utf-8", "replace").lower()
    except Exception:
        text = ""
    for v in _VENDORS[:4]:
        if v in text:
            return v
    return ""


# ---------------------------------------------------------------------------
# Tactic profiles
# ---------------------------------------------------------------------------

_SQL_KEYWORDS = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE",
                 "DROP", "OR", "AND"]


def _double_urlencode(payload):
    try:
        return urllib.parse.quote(urllib.parse.quote(str(payload), safe=""),
                                  safe="")
    except Exception:
        return str(payload)


def _unicode_escape(payload):
    try:
        return str(payload).encode("unicode_escape").decode("ascii")
    except Exception:
        return str(payload)


def _case_jitter(payload):
    """Randomize the case of known SQL keywords; markers untouched."""
    text = str(payload)
    for kw in _SQL_KEYWORDS:
        if kw in text:
            text = text.replace(kw, "".join(
                c.upper() if i % 2 else c.lower()
                for i, c in enumerate(kw)))
    return text


def _comment_insert(payload):
    """Insert SQL comment spacers inside suspicious sequences."""
    return (str(payload).replace(" ", "/**/").replace("'", "'/**/"))


_ENCODERS = [_double_urlencode, _unicode_escape, _case_jitter,
             _comment_insert]


def _browser_headers(profile_seed=0):
    """Realistic browser headers with X-Forwarded-For rotation."""
    rnd = random.Random(profile_seed)
    octets = [10 + rnd.randint(0, 200), rnd.randint(0, 255),
              rnd.randint(0, 255), 1 + rnd.randint(0, 253)]
    return {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/%d.0.%d.%d Safari/537.36"
                       % (120 + rnd.randint(0, 8), rnd.randint(0, 9999),
                          rnd.randint(0, 300))),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
        "X-Forwarded-For": ".".join(str(o) for o in octets),
    }


def _chunked_body(profile, payload):
    """Split a payload into chunked transfer-encoding request kwargs."""
    data = str(payload).encode("utf-8", "replace")
    chunk_size = max(1, len(data) // 3 or 1)
    chunks = [data[i:i + chunk_size]
              for i in range(0, len(data), chunk_size)] or [b""]
    body = b"".join(("%x\r\n" % len(c)).encode() + c + b"\r\n"
                    for c in chunks) + b"0\r\n\r\n"
    return {"headers": {"Transfer-Encoding": "chunked"}, "body": body}


def tactic_profiles():
    """Named mutation profiles. Each: {'name', 'mutate_payload',
    'request_kwargs', 'delay'}. Deterministic; pure functions."""
    profiles = {}

    profiles["direct"] = {
        "name": "direct",
        "mutate_payload": lambda p: str(p),
        "request_kwargs": {},
        "delay": 0.0,
    }

    def encode_rotate(payload):
        # Deterministic: apply all encoders in a fixed pipeline.
        out = str(payload)
        for enc in _ENCODERS:
            out = enc(out)
        return out

    profiles["encode-rotate"] = {
        "name": "encode-rotate",
        "mutate_payload": encode_rotate,
        "request_kwargs": {"headers": {"X-Omega-Encoding": "rotate"}},
        "delay": 0.0,
    }

    profiles["slow-drip"] = {
        "name": "slow-drip",
        "mutate_payload": lambda p: str(p),
        "request_kwargs": {"parallel": 1},
        "delay": 0.25,
    }

    def chunked_mutate(payload):
        data = str(payload)
        return urllib.parse.urlencode({"q": data})

    profiles["chunked"] = {
        "name": "chunked",
        "mutate_payload": chunked_mutate,
        "request_kwargs": {"headers": {"Transfer-Encoding": "chunked"}},
        "delay": 0.0,
    }

    profiles["header-mimic"] = {
        "name": "header-mimic",
        "mutate_payload": lambda p: str(p),
        "request_kwargs": {"headers": _browser_headers()},
        "delay": 0.0,
    }

    return profiles


def _apply_request_kwargs(profile, payload):
    """Build the fetch kwargs for one request under a profile."""
    kw = dict(profile.get("request_kwargs") or {})
    headers = dict(kw.get("headers") or {})
    body = None
    if profile["name"] == "chunked":
        parts = _chunked_body(profile, payload)
        headers.update(parts["headers"])
        body = parts["body"]
    if body is None:
        body = payload
    kw["headers"] = headers
    kw["body"] = body
    return kw


def select_tactic(defense_result, tactic_index=0):
    """Deterministic profile selection from a probe_defense result.

    no defense -> direct; WAF -> encode-rotate, header-mimic;
    rate limit -> slow-drip. tactic_index steps through the ordered
    candidate list when the caller wants the next fallback.
    """
    profiles = tactic_profiles()
    defense = defense_result or {}
    candidates = []
    if defense.get("waf"):
        candidates = ["encode-rotate", "header-mimic"]
    elif defense.get("rate_limited"):
        candidates = ["slow-drip"]
    else:
        candidates = ["direct"]
    idx = max(0, int(tactic_index or 0)) % len(candidates)
    return profiles[candidates[idx]]


# ---------------------------------------------------------------------------
# Adaptive loop
# ---------------------------------------------------------------------------

def run_adaptive(fetch, base_url, attack_fn, max_attempts=3):
    """Step through tactic profiles, calling attack_fn(profile) per
    attempt. attack_fn is any callable taking the profile dict and
    returning a truthy dict (its 'ok' key marks success). Never raises.
    Returns {'attempts': [...], 'best': profile-or-None}."""
    out = {"attempts": [], "best": None}
    if not callable(attack_fn):
        out["attempts"].append({"profile": None, "error": "not-callable"})
        return out
    max_attempts = max(1, int(max_attempts or 1))
    defense = probe_defense(fetch, base_url)
    for i in range(max_attempts):
        profile = select_tactic(defense, tactic_index=i)
        entry = {"attempt": i + 1, "profile": profile["name"],
                 "waf": defense.get("waf", False),
                 "rate_limited": defense.get("rate_limited", False),
                 "signals": list(defense.get("signals") or [])}
        try:
            res = attack_fn(profile)
        except Exception as exc:
            entry["status"] = "error"
            entry["error"] = str(exc)[:120]
            out["attempts"].append(entry)
            continue
        entry["result"] = res
        entry["status"] = "success" if (res or {}).get("ok") else "blocked"
        out["attempts"].append(entry)
        if entry["status"] == "success":
            out["best"] = profile
            break
        # Honor the profile delay between attempts.
        delay = float(profile.get("delay") or 0)
        if delay > 0:
            try:
                time.sleep(min(delay, 1.0))
            except Exception:
                pass
    return out


def render_report(defense, tactics):
    """Human-readable summary for the CLI."""
    lines = ["adaptive evasion report",
             "  waf          : %s" % defense.get("waf"),
             "  rate_limited : %s" % defense.get("rate_limited"),
             "  vendor       : %s" % (defense.get("vendor") or "-"),
             "  aggression   : %s" % defense.get("aggression_limit")]
    for s in defense.get("signals") or []:
        lines.append("  signal       : %s" % s)
    for t in tactics:
        lines.append("  tactic %d     : %s (delay %s)"
                     % (t["index"], t["name"], t["delay"]))
    return "\n".join(lines)


def plan_tactics(defense_result, count=3):
    """Ordered tactic plan (no execution) for the CLI report."""
    plan = []
    for i in range(max(1, int(count or 1))):
        p = select_tactic(defense_result, tactic_index=i)
        plan.append({"index": i + 1, "name": p["name"],
                     "delay": p.get("delay", 0.0),
                     "mutates": p["name"] != "direct"})
    return plan


def jsonify(obj):
    """JSON-safe dump helper (never raises)."""
    try:
        return json.dumps(obj, indent=2, default=str)
    except Exception:
        return str(obj)
