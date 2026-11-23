"""omega/core/adaptive — evidence-driven next-attack playbook.

Not another scanner: this ranks WHAT to run next, per stack, from the
evidence already collected (findings CWEs + techmem stack + surface).
The recommendation is deterministic and explainable — the operator
sees why each step was chosen. PLAN-ONLY: it never executes probes.
"""
import os

__all__ = ["recommend"]

# CWE -> follow-up attack classes, in priority order
_FOLLOW = {
    "CWE-918": ["metassrf", "cachepoison", "blindrelay"],
    "CWE-89": ["secondorder", "bizfuzz", "authzmatrix"],
    "CWE-79": ["wsprobe", "mimeconfusion", "evadechain"],
    "CWE-22": ["chainrun", "cisweep", "uploadfuzz"],
    "CWE-434": ["uploadfuzz", "cisweep", "chainrun"],
    "CWE-502": ["deserprobe", "blindrelay", "chainrun"],
    "CWE-285": ["authzmatrix", "horizontal", "sessionmatrix"],
    "CWE-287": ["authblast", "sessionmatrix", "jwtattack"],
    "CWE-444": ["smuggle", "cachepoison", "h2probe"],
    "CWE-1321": ["protopollute", "apispecial", "wsprobe"],
    "CWE-942": ["corsprobe", "sessionmatrix", "apispecial"],
    "CWE-538": ["cisweep", "secondorder", "pivot"],
    "CWE-798": ["authblast", "pivot", "chainrun"],
    "CWE-200": ["cisweep", "authzmatrix", "horizontal"],
    "CWE-601": ["metassrf", "blindrelay", "cachepoison"],
    "CWE-611": ["metassrf", "blindrelay", "deserprobe"],
    "CWE-78": ["blindrelay", "privesc", "pivot"],
    "CWE-770": ["h2probe", "racehunt", "smuggle"],
    "CWE-436": ["mimeconfusion", "uploadfuzz", "evadechain"],
}

_STACK_BIAS = {
    "node": ["protopollute", "apispecial", "wsprobe"],
    "spring": ["deserprobe", "jwtattack", "smuggle"],
    "php": ["deserprobe", "uploadfuzz", "smuggle"],
    "java": ["deserprobe", "h2probe", "smuggle"],
    "dotnet": ["deserprobe", "mimeconfusion", "smuggle"],
    "nginx": ["smuggle", "cachepoison", "h2probe"],
    "envoy": ["smuggle", "cachepoison", "h2probe"],
    "graphql": ["apispecial", "authzmatrix", "protopollute"],
}


def _cwes_of(findings):
    out = []
    for f in findings or []:
        cwe = f.get("cwe") if isinstance(f, dict) else None
        if cwe:
            out.append(str(cwe).upper())
    return out


def recommend(findings=None, stack=None, top=6):
    """Return ordered [{attack, score, why}] recommendations."""
    findings = findings or []
    scores = {}
    why = {}
    counts = {}
    for cwe in _cwes_of(findings):
        counts[cwe] = counts.get(cwe, 0) + 1
    for cwe, n in counts.items():
        for i, attack in enumerate(_FOLLOW.get(cwe, [])):
            gain = max(1, 6 - i) * n
            scores[attack] = scores.get(attack, 0) + gain
            why.setdefault(attack, []).append(
                f"{cwe} x{n} -> {attack}")
    if stack:
        key = str(stack).lower()
        for name, attacks in _STACK_BIAS.items():
            if name in key:
                for i, attack in enumerate(attacks):
                    scores[attack] = scores.get(attack, 0) + (4 - i)
                    why.setdefault(attack, []).append(
                        f"stack {name} bias")
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{"attack": a, "score": s,
             "why": "; ".join(why.get(a, [])[:3])}
            for a, s in ranked[:top]]


def render_recommendation(recs):
    """Human-readable playbook (English, report-friendly)."""
    if not recs:
        return "no evidence-driven follow-up available (no findings yet)"
    lines = ["next-attack playbook (evidence-ranked):"]
    for i, r in enumerate(recs, 1):
        lines.append(f"  {i}. {r['attack']} (score {r['score']}) — "
                     f"{r['why']}")
    return "\n".join(lines)
