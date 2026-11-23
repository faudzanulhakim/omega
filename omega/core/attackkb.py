"""omega/core/attackkb — offline attack-path knowledge base.

Expert methodology lookup: given observed signals, return the stages
an experienced tester would try next (Web Application Hacker's
Handbook-style, MITRE-ATT&CK-inspired technique names). Pure table
lookup — no network, no LLM. The brain consults this before choosing
its next stage so its choices mirror expert methodology.
"""

# signal regex -> [(technique, methodology step, priority)]
_KB = [
    (r"login|signin|auth form", [
        ("credential-guessing (bounded)", "test one known-default "
         "credential set; never brute force without the gate", 7),
        ("username enumeration differential", "compare error/timing "
         "between existing and nonexistent users", 8),
        ("auth-logic abuse", "parameter tampering, response swap, "
         "JWT none-alg, step skipping", 6),
    ]),
    (r"search|query param", [
        ("injection ladder", "single-quote -> error-based -> time-"
         "based -> boolean differential, in that order", 8),
        ("encoding ladder", "plain -> url -> double-url -> unicode "
         "escape, per WAF behavior", 6),
    ]),
    (r"upload|file form", [
        ("extension filter mapping", "test which extensions pass "
         "and what is served back", 7),
        ("content-type / magic byte tests", "polyglot upload checks",
         6),
    ]),
    (r"api|graphql|json", [
        ("introspection/schema walk", "map the schema before "
         "probing fields", 7),
        ("mass-assignment probing", "add role/is_admin fields to "
         "update calls", 7),
        ("batching/depth abuse", "array-of-queries and deep aliases",
         5),
    ]),
    (r"jwt|token|bearer", [
        ("alg-none / weak-secret tests", "classic JWT manipulation "
         "ladder", 8),
        ("kid injection", "path traversal / SQLi in kid claims", 6),
    ]),
    (r"redirect|url param|return", [
        ("redirect ladder", "allowed-host probe -> //evil -> "
         "whitelist-suffix tricks -> URL-encoding layers", 7),
    ]),
    (r"waf|blocked|403 payload", [
        ("evasion ladder", "case jitter -> comment insertion -> "
         "double-encode -> chunked encoding", 8),
        ("rate-limit profiling", "map the throttle window before "
         "the main scan", 5),
    ]),
    (r"cookie|session", [
        ("session attribute tampering", "decode/modify and replay",
         7),
        ("session fixation / invalidation tests", "login and logout "
         "lifecycle checks", 8),
    ]),
    (r"file|download|path", [
        ("traversal ladder", "../ depth ladder -> encoded -> null "
         "byte (legacy)", 7),
    ]),
    (r"admin|dashboard|backoffice", [
        ("direct-access checks", "hit the surface unauthenticated "
         "and with low-priv cookies", 8),
    ]),
]


def suggest(observations, max_suggestions=8):
    """Return expert-methodology suggestions for the observed signals.

    ``observations``: iterable of strings (finding titles, evidence,
    surface notes). Returns [{technique, step, priority, signal}]
    sorted by priority desc, deduped by technique.
    """
    seen = set()
    out = []
    for obs in observations or []:
        low = str(obs or "").lower()
        for rx, entries in _KB:
            if not re.search(rx, low):
                continue
            for tech, step, prio in entries:
                if tech in seen:
                    continue
                seen.add(tech)
                out.append({"technique": tech, "step": step,
                            "priority": prio, "signal": str(obs)[:120]})
    out.sort(key=lambda s: -s["priority"])
    return out[:max_suggestions]


def narrate_suggestions(suggestions):
    """One-line summary for the brain log."""
    if not suggestions:
        return "attackkb: no methodology suggestions for the observed " \
               "signals"
    return "attackkb: next expert steps: " + "; ".join(
        "%s (p%d)" % (s["technique"], s["priority"])
        for s in suggestions[:4])


import re  # noqa: E402  (kept at the bottom so the table reads first)
