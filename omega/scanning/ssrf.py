"""omega/scanning/ssrf.py — SSRF probe (fusion suite name: ``ssrf``).

For path+parameter pairs whose names look URL-ish (url, uri, src, dest,
redirect, callback, next, target, host), sends benign values pointing
BACK at the scanned base_url host itself with unique marker paths
(same-host marker URL and 127.0.0.1 same-port marker URL) and detects
when the server fetches it (marker echoed in the response or a
distinctive latency differential). HTML meta/link SSRF shapes are also
probed. HIGH candidate findings. Never targets external hosts — the
scanned host itself and loopback only.
"""

from __future__ import annotations

import secrets
import time
import urllib.parse

from omega.scanning.deepchecks import default_fetch

__all__ = [
    "Finding",
    "URLISH_PARAMS",
    "ssrf_params",
    "run_ssrf",
]

URLISH_PARAMS = ("url", "uri", "src", "dest", "redirect", "callback",
                 "next", "target", "host")
MAX_PATHS = 6
MAX_PARAMS_PER_PATH = 3
LATENCY_FACTOR = 3.0
MIN_SLOW_MS = 150.0
MARKER_TAG = "omega-ssrf-marker"


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


def _get(fetch, url, timeout_note=None):
    try:
        t0 = time.monotonic()
        st, _h, raw = fetch("GET", url)
        ms = (time.monotonic() - t0) * 1000.0
        return st, _text(raw), ms
    except Exception:
        return None, "", 0.0


def ssrf_params(path, params=None):
    """URL-ish (path, param) pairs, bounded."""
    pairs = []
    param_list = [str(p) for p in (params or [])]
    if param_list:
        for p in param_list:
            if p.lower() in URLISH_PARAMS:
                pairs.append((path, p))
    else:
        # No known params: probe common URL-ish names directly on the
        # path itself (query-string shapes servers commonly honor).
        for p in ("url", "redirect", "next"):
            pairs.append((path, p))
    return pairs[:MAX_PARAMS_PER_PATH]


def run_ssrf(base_url, fetch=default_fetch, path_info=None, gate=False):
    """Run the SSRF probe. Returns a list of Finding dicts; never
    raises. Same-host and loopback marker URLs only."""
    out = []
    try:
        parsed = urllib.parse.urlsplit(base_url if "://" in base_url
                                       else "http://" + base_url)
        scheme = parsed.scheme or "http"
        port = parsed.port
        host = parsed.hostname or "127.0.0.1"

        marker = "omega-ssrf-%s" % secrets.token_hex(6)
        marker_path = "/omega-ssrf-canary/%s" % marker

        # Marker resources live on the scanned host itself / loopback.
        same_host_marker = "%s://%s%s" % (
            scheme, parsed.netloc or ("127.0.0.1:%d" % (port or 80)),
            marker_path)
        loopback_host = parsed.netloc.replace(host, "127.0.0.1") \
            if host != "127.0.0.1" else parsed.netloc
        if not loopback_host:
            loopback_host = "127.0.0.1:%d" % (port or 80)
        loopback_marker = "%s://%s%s" % (scheme, loopback_host, marker_path)

        base = base_url.rstrip("/")

        # Marker targets must actually respond with the marker so a
        # server-side fetch can be observed via the echoed response.
        def marker_probe(url):
            st, body, ms = _get(fetch, url)
            return st, body

        paths = ["/"]
        for p in (path_info or {}).get("paths") or []:
            try:
                p = str(p)
            except Exception:
                continue
            if p not in paths:
                paths.append(p)
        seen = set()
        for path in paths[:MAX_PATHS]:
            url = base + ("/" + path.lstrip("/") if path else "")
            # Baseline latency for the timing differential.
            _st, _b, baseline_ms = _get(fetch, url)
            for _ppath, param in ssrf_params(path,
                                             (path_info or {}).get("params")):
                for label, marker_url in (("same-host", same_host_marker),
                                          ("loopback", loopback_marker),
                                          ("meta-refresh", "meta:" + marker),
                                          ("link-href", "link:" + marker)):
                    if (param, label) in seen:
                        continue
                    if label in ("meta-refresh", "link-href"):
                        payload = html_shape(label, scheme, host, port,
                                             marker)
                        qs = "%s?%s=%s" % (url, param,
                                           urllib.parse.quote(payload))
                    else:
                        qs = "%s?%s=%s" % (url, param,
                                           urllib.parse.quote(marker_url))
                    st, body, ms = _get(fetch, qs)
                    if st is None:
                        continue
                    low = body.lower()
                    echoed = marker in body or marker_path in body
                    fetched = marker_probe_visited(marker, low, body)
                    slow = (ms > baseline_ms * LATENCY_FACTOR
                            and ms - baseline_ms >= MIN_SLOW_MS)
                    if echoed or fetched or (label == "same-host" and slow):
                        seen.add((param, label))
                        out.append(Finding(
                            title="SSRF candidate: server fetched marker "
                                  "via %s parameter '%s' (%s shape)"
                                  % (param, param, label),
                            severity="high", verification="candidate",
                            verification_note=(
                                "The URL-ish parameter '%s' appears to "
                                "make the server issue a request to a "
                                "marker URL pointing back at the scanned "
                                "host itself (%s detection). Candidate "
                                "only: all probe targets were the "
                                "scanned host / loopback with a benign "
                                "marker path; confirm whether user-"
                                "controlled URLs are fetched and whether "
                                "internal ranges are reachable."
                                % (param, "marker echo" if (echoed or
                                                           fetched)
                                   else "timing differential")),
                            manual_check="curl -sS '%s'" % qs,
                            location=url,
                            evidence="param=%s shape=%s status=%s "
                                     "latency_ms=%.0f baseline_ms=%.0f"
                                     % (param, label, st, ms, baseline_ms),
                            source="omega-ssrf", confidence="medium"))
    except Exception:
        pass
    return out


def html_shape(label, scheme, host, port, marker):
    """Benign HTML SSRF shapes pointing at the scanned host itself."""
    netloc = host if not port else "%s:%d" % (host, port)
    if label == "meta-refresh":
        return ('<meta http-equiv="refresh" content="0;url=%s://%s/'
                'omega-ssrf-canary/%s">' % (scheme, netloc, marker))
    return ('<link rel="stylesheet" href="%s://%s/omega-ssrf-canary/%s">'
            % (scheme, netloc, marker))


def marker_probe_visited(marker, low, body):
    """Heuristic: the response references the canary path/marker or an
    internal fetch error naming the loopback marker host."""
    return ("omega-ssrf-canary" in low
            or ("127.0.0.1" in low and marker in body))
