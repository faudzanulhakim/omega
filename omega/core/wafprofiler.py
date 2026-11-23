"""omega/core/wafprofiler — WAF/rate-limit profiling before the scan.

Expert testers recon the WAF before firing anything: which patterns
get blocked, what encoding passes, where the rate limit sits. This
profiler runs a small benign probe ladder, records the map, and
stores it in lessons (per host) so the main scan uses it.

Every probe is a harmless detection string — no exploit payloads.
"""
import time

import requests

from omega.core.lessons import record_blocked, record_worked

__all__ = ["profile", "findings_from_doc"]

# benign markers: each is a distinctive-but-harmless string
PROBES = [
    ("plain-marker", "omegaprobe1"),
    ("angle-marker", "<omegaprobe2>"),
    ("quote-marker", "omega'probe3"),
    ("slash-marker", "../omegaprobe4"),
    ("sqlish-marker", "1 OR 1=1 omegaprobe5"),
]


def profile(url, timeout=8, log=None):
    """Map WAF behavior on one URL. Returns the profile doc and
    records blocked/worked markers into lessons."""
    doc = {"url": url, "probes": [], "blocked_count": 0,
           "passed_count": 0, "profiled_at":
           time.strftime("%Y-%m-%dT%H:%M:%S")}
    sep = "&" if "?" in url else "?"
    base = url.split("?")[0]
    for name, marker in PROBES:
        try:
            r = requests.get(base + sep + "omegatest=" +
                             requests.utils.quote(marker),
                             timeout=timeout,
                             headers={"User-Agent": "omega-profiler"})
            blocked = r.status_code in (403, 406, 429, 501) or \
                "blocked" in r.text[:400].lower()
            entry = {"probe": name, "status": r.status_code,
                     "blocked": blocked}
        except Exception as exc:
            entry = {"probe": name, "status": None,
                     "blocked": None, "error": str(exc)}
        doc["probes"].append(entry)
        if entry["blocked"] is True:
            doc["blocked_count"] += 1
            record_blocked(base, marker)
        elif entry["blocked"] is False:
            doc["passed_count"] += 1
            record_worked(base, marker)
    doc["verdict"] = ("aggressive" if doc["blocked_count"] >= 3 else
                      "selective" if doc["blocked_count"] else
                      "no-evidence-of-waf")
    if log:
        log("wafprofiler: %s (%d/%d probes blocked)"
            % (doc["verdict"], doc["blocked_count"],
               len(PROBES)))
    return doc


def findings_from_doc(doc):
    """Profile -> candidate finding when the WAF is aggressive."""
    if (doc or {}).get("verdict") not in ("aggressive", "selective"):
        return []
    return [{
        "title": "WAF/rate-limit profile: %s (%s)" % (
            doc["verdict"], doc["url"]),
        "severity": "INFO",
        "verification": "candidate",
        "source": "wafprofiler",
        "evidence": "%d/%d benign markers blocked; encode-ladder "
                    "recommended for the main scan"
                    % (doc["blocked_count"], len(doc["probes"])),
        "location": doc["url"],
        "manual_check": "review which markers were blocked in the "
                        "profile and confirm the vendor in the "
                        "block page",
    }]
