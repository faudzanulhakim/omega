"""omega/offensive/offense/wordlistgen — context wordlist from content.

Harvests candidate words/paths/params from the target's OWN content
(JS bundles, HTML links, form names, JSON keys) — a contextual
wordlist that beats generic lists. Shape-only: string literals are
collected, no secret values retained (literals matching credential
key patterns are recorded as HINT presence only).
OFFENSE-GATED (PTK_OFFENSE).
"""
import os
import re

__all__ = ["run_wordlistgen"]

_WORD = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{3,24}")
_PATHISH = re.compile(r"[\"'](/[a-zA-Z0-9_\-./]{2,60})[\"']")
_KEYISH = re.compile(r"[\"']([a-zA-Z_][a-zA-Z0-9_]{2,30})[\"']\s*:")
_CRED_KEY = re.compile(r"(passw|passwd|secret|token|api[_-]?key|apikey)",
                       re.I)


def run_wordlistgen(target, fetch=None, max_words=200, log=None,
                    gate_open_fn=None):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    base = str(target).rstrip("/")
    seeds = ["/", "/index.html", "/main.js", "/app.js", "/bundle.js",
             "/static/js/main.js", "/js/app.js"]
    words, paths, cred_hints = {}, {}, []
    probes = 0
    for seed in seeds:
        try:
            resp = fetch(base + seed)
            probes += 1
        except Exception:
            continue
        if resp is None:
            continue
        body = getattr(resp, "text", "") or ""
        if not body:
            continue
        for m in _PATHISH.findall(body):
            paths[m] = paths.get(m, 0) + 1
        for m in _KEYISH.findall(body):
            if _CRED_KEY.search(m):
                if m not in cred_hints:
                    cred_hints.append(m + " (hint only — value NOT stored)")
            else:
                words[m] = words.get(m, 0) + 1
        # skip word-harvest on lines that carry credential-shaped
        # keys — the VALUE must never enter the wordlist either
        safe_body = "\n".join(
            ln for ln in body.splitlines()
            if not _CRED_KEY.search(ln))
        for m in _WORD.findall(safe_body):
            if len(m) >= 4 and not m.startswith("function"):
                words[m] = words.get(m, 0) + 1
    top_words = sorted(words.items(), key=lambda kv: -kv[1])[:max_words]
    top_paths = sorted(paths.items(), key=lambda kv: -kv[1])[:40]
    wl = [w for w, _ in top_words]
    out = {
        "findings": [],
        "probes": probes,
        "wordlist": wl,
        "paths": [p for p, _ in top_paths],
        "credential_key_hints": cred_hints[:10],
        "note": f"harvested {len(wl)} words / {len(top_paths)} paths "
                f"from target content (contextual, not generic)",
    }
    if log:
        log(out["note"])
    return out
