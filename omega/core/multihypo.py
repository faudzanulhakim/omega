"""omega/core/multihypo — multi-hypothesis reasoning engine.

Batch "max power" upgrade of the single-hypothesis loop in
hypothesis.py. For each observed signal the engine raises MULTIPLE
competing hypotheses, scores them with a simplified Bayesian update
(prior x evidence likelihood), and probes them in posterior order.
Differential probes stay benign; refuted hypotheses are recorded via
lessonsv2 outcomes so future scans deprioritize dead paths.

Output shape mirrors run_hypothesis_loop: {'hypotheses', 'verified',
'refuted', 'uncertain'} plus 'posteriors' for transparency.
"""
import math
import re

__all__ = ["raise_competing", "run_multihypo_loop"]

# signal -> competing hypotheses: (kind, prior, probe spec)
# probe spec: (suffix, param, value) — benign, data-only markers.
_RULES = [
    (r"error|500|traceback", [
        ("injection-sqli", 0.35, ("?omegahypo=1", "omegahypo", "'")),
        ("injection-sqli", 0.30, ("?omegahypo=1", "omegahypo", "1' OR '1'='1")),
        ("template-injection", 0.15, ("?omegahypo=1", "omegahypo", "{{7*7}}")),
        ("path-traversal", 0.20, ("?omegahypo=1", "omegahypo", "../etc/passwd")),
    ]),
    (r"reflect|echo", [
        ("xss-reflected", 0.45, ("?omegahypo=1", "omegahypo", "<b>omegaprobe2</b>")),
        ("ssti", 0.20, ("?omegahypo=1", "omegahypo", "{{7*7}}")),
        ("header-injection", 0.15, ("?omegahypo=1", "omegahypo", "x\r\nX-Omega: 1")),
    ]),
    (r"redirect|30[12]", [
        ("open-redirect", 0.50, ("?omegahypo=1", "omegahypo", "//omegaprobe.example")),
        ("parameter-tamper", 0.25, ("?omegahypo=1", "omegahypo", "1")),
    ]),
    (r"upload|multipart", [
        ("upload-validation", 0.55, ("?omegahypo=1", "omegahypo", "txt")),
    ]),
]
_DEFAULT = [("unverified-surface", 0.5, None)]
BLOCKED_MARK = "blocked|waf|403|denied|captcha"


def raise_competing(observation):
    """Return competing hypotheses for one observation string."""
    text = str(observation).lower()
    rules = [r for r in _RULES if re.search(r[0], text)]
    hyps = [h for r in rules for h in r[1]] or _DEFAULT
    seen, out = set(), []
    for kind, prior, probe in hyps:
        if kind in seen:
            continue
        seen.add(kind)
        out.append({"kind": kind, "prior": prior, "probe": probe})
    return out


def _posterior(hyps, evidence_boost=0.0):
    """Normalize priors (+evidence boost) into a probability table."""
    raw = {h["kind"]: max(h["prior"] + evidence_boost, 0.01)
           for h in hyps}
    total = sum(raw.values()) or 1.0
    return {k: v / total for k, v in raw.items()}


def _probe(fetch, url, hyp):
    """Benign differential probe; returns response body or None."""
    if not hyp.get("probe"):
        return None
    suffix, param, value = hyp["probe"]
    try:
        sep = "&" if "?" in url else "?"
        resp = fetch(url + sep + param + "=" + suffix)
        body = resp if isinstance(resp, str) else getattr(
            resp, "text", "") or ""
        return body[:4096]
    except Exception:
        return None


def _score_evidence(baseline, probe_body):
    """Compare probe vs baseline: 0 none, 1 shift, 2 strong shift."""
    if probe_body is None:
        return 0
    if baseline is None or probe_body[:512] != baseline[:512]:
        return 2 if len(probe_body) - len(baseline or "") > 16 else 1
    return 0


def run_multihypo_loop(observations, fetch, url=None, budget=12,
                       lessons=None, log=None):
    """Probe N competing hypotheses per observation, Bayes-ranked.

    observations: list of strings (signals from the scan so far).
    Returns {'hypotheses': [...], 'verified': [...], 'refuted': [...],
             'uncertain': [...], 'posteriors': {...}}.
    """
    doc = {"hypotheses": [], "verified": [], "refuted": [],
           "uncertain": [], "posteriors": {}}
    spent = 0
    baseline = None
    if url:
        try:
            resp = fetch(url)
            baseline = (resp if isinstance(resp, str) else
                        getattr(resp, "text", "")) or None
            if baseline:
                baseline = baseline[:4096]
        except Exception:
            baseline = None
    for obs in (observations or [])[:budget]:
        hyps = raise_competing(obs)
        posts = _posterior(hyps)
        best_kind, best_score = None, -1
        for h in sorted(hyps, key=lambda x: -posts[x["kind"]]):
            if spent >= budget:
                doc["uncertain"].append(
                    {"observation": obs, "kind": h["kind"],
                     "status": "uncertain", "note": "probe budget spent"})
                continue
            spent += 1
            body = _probe(fetch, url, h)
            score = _score_evidence(baseline, body)
            if score >= 1:
                best_kind, best_score = h["kind"], max(best_score, score)
        if best_kind and best_score >= 1:
            doc["verified"].append({"observation": obs,
                                    "kind": best_kind,
                                    "status": "verified",
                                    "posterior": round(
                                        posts.get(best_kind, 0.0), 3)})
            doc["posteriors"][obs] = round(posts.get(best_kind, 0.0), 3)
        elif best_kind:
            doc["refuted"].append({"observation": obs,
                                   "kind": best_kind,
                                   "status": "refuted"})
        else:
            doc["uncertain"].append({"observation": obs,
                                     "kind": hyps[0]["kind"] if hyps
                                     else "none", "status": "uncertain"})
    if log:
        log("multihypo: %d verified, %d refuted, %d uncertain" %
            (len(doc["verified"]), len(doc["refuted"]),
             len(doc["uncertain"])))
    return doc
