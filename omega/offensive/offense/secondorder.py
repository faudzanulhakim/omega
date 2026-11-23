"""omega/offensive/offense/secondorder — second-order injection hunter.

Stored/second-order injections do not show in the injecting response:
the payload is saved and later rendered on a DIFFERENT page. This
module plants unique markers at injection points, then crawls the
session surface looking for those markers where they were never
planted — reflection on another page with the marker intact is
second-order-injection evidence (candidate only).

OFFENSE-GATED (PTK_OFFENSE). Non-destructive: markers are inert text
(omegso<N>), never script.
"""
import os
import random
import string

__all__ = ["run_second_order"]


def _marker():
    return "omegso" + "".join(random.choices(string.ascii_lowercase,
                                             k=8))


def run_second_order(inject_points, crawl_urls, fetch, rounds=2,
                     budget=20, log=None, gate_open_fn=None):
    """Plant markers at inject_points, look for them on crawl_urls.

    inject_points: [{"url": str, "param": str, "method": "GET"|"POST"}]
    crawl_urls: pages rendered later (profiles, listings, exports)
    fetch(url, method=..., params/body=?) -> object with .text/.status
        (omega.core.brain.url_fetch satisfies this)
    Returns {"findings": [...], "planted": n, "probes": n}
    """
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    if not callable(fetch) or not inject_points or not crawl_urls:
        return {"note": "inject points and crawl URLs required"}
    planted = []
    probes = 0
    findings = []
    for point in inject_points[:10]:
        mk = _marker()
        url = str(point.get("url") or "")
        param = str(point.get("param") or "q")
        if not url:
            continue
        sep = "&" if "?" in url else "?"
        try:
            fetch(url + sep + param + "=" + mk)
            probes += 1
        except Exception:
            continue
        planted.append(mk)
    if not planted:
        return {"note": "no injection point reachable", "planted": 0,
                "probes": probes}
    for target in list(crawl_urls)[:40]:
        for _ in range(rounds):
            try:
                resp = fetch(str(target))
                body = (resp if isinstance(resp, str) else
                        getattr(resp, "text", "") or "")
                probes += 1
            except Exception:
                continue
            for mk in planted:
                if mk in body:
                    findings.append({
                        "title": f"second-order injection marker "
                                 f"re-rendered on {target}",
                        "severity": "MEDIUM",
                        "source": "secondorder/marker-replay",
                        "evidence": f"planted marker {mk} appears in a "
                                    f"different page's response",
                        "location": str(target),
                        "verification": "candidate",
                        "manual_check": "confirm the stored value is "
                                        "rendered unescaped and can be "
                                        "turned into an injection",
                        "cwe": "CWE-79",
                    })
    # dedupe per (target, marker)
    seen = set()
    uniq = []
    for f in findings:
        key = (f["location"], f["evidence"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    if log:
        log(f"secondorder: planted={len(planted)} probes={probes} "
            f"findings={len(uniq)}")
    return {"findings": uniq, "planted": len(planted), "probes": probes}
