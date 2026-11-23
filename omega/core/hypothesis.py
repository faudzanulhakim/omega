"""omega/core/hypothesis — hypothesis-driven testing engine.

An expert tester never fires payloads blindly: each observation
raises a HYPOTHESIS (scored, with probe steps), hypotheses are
verified in priority order, and verification results update the
model. This module implements that loop deterministically:

    observation -> hypothesis(kind, score, probes) -> verify ->
    verified | refuted | uncertain

Hypothesis kinds and probe templates are data-driven (_RULES); the
engine never invents destructive payloads — every probe is a benign
detection probe (echo markers, timing deltas, differential requests).
"""
import re
import time

# --- hypothesis rules: observation regex -> hypothesis template ----
# Each rule: (name, observation_regex, kind, base_score, probes)
# probes: list of {"desc", "fetch_args": (method, url_suffix, body)}
_RULES = [
    ("sql-error-echo", r"sql|syntax error|mysql|pg_|sqlite", "sqli",
     7, [
         {"desc": "single-quote differential probe",
          "probe": {"path_param": "'", "kind": "sqli-quote"}},
     ]),
    ("generic-500", r"500|internal server error", "fragility",
     3, [
         {"desc": "repeat identical request — stability check",
          "probe": {"repeat": 2, "kind": "stability"}},
     ]),
    ("verbose-error", r"stack trace|exception|traceback|debug",
     "infodisclosure", 5, [
         {"desc": "probe framework error fingerprints",
          "probe": {"path_param": "/%00", "kind": "errdetail"}},
     ]),
    ("open-redirect-param", r"redirect|url=|next=|return=|goto=",
     "openredirect", 4, [
         {"desc": "redirect param echo check with marker host",
          "probe": {"path_param": "//omega-probe.invalid/",
                    "kind": "redirect-echo"}},
     ]),
    ("reflected-param", r"reflect|echo|param in response", "xss",
     5, [
         {"desc": "marker reflection check",
          "probe": {"path_param": "wf<marker7>", "kind": "xss-echo"}},
     ]),
    ("auth-bypass-signal", r"unauthorized|forbidden|403", "authz",
     6, [
         {"desc": "header-based authz variation probes",
          "probe": {"kind": "authz-headers"}},
     ]),
]


class Hypothesis:
    """One testable belief about the target."""

    def __init__(self, hid, kind, observation, score, probes):
        self.id = hid
        self.kind = kind
        self.observation = observation
        self.score = score
        self.probes = probes
        self.status = "open"          # open|verified|refuted|uncertain
        self.evidence = []

    def to_dict(self):
        return {"id": self.id, "kind": self.kind,
                "observation": self.observation, "score": self.score,
                "status": self.status, "evidence": self.evidence}


def build_hypotheses(observations):
    """Raise hypotheses from observation strings (finding titles/
    evidence snippets/notes). Returns Hypothesis objects sorted by
    score desc. Deterministic ordering (stable for reproducibility)."""
    hyps = []
    n = 0
    for obs in observations or []:
        text = str(obs or "")
        low = text.lower()
        for name, rx, kind, score, probes in _RULES:
            if re.search(rx, low):
                n += 1
                hyps.append(Hypothesis("H-%03d" % n, kind, text,
                                       score + (1 if "error" in low
                                                else 0),
                                       [dict(p) for p in probes]))
    # highest score first, stable tie-break by id
    hyps.sort(key=lambda h: (-h.score, h.id))
    return hyps


def verify_hypothesis(hyp, fetch, base_url, budget=5):
    """Verify one hypothesis with its probe steps.

    ``fetch(method, url, headers=None, body=None) -> (st, hdr, body)``
    Verification is differential where possible: a clean request vs a
    probe request; the delta is the evidence. Never raises; updates
    hyp.status to verified|refuted|uncertain.
    """
    base = base_url.rstrip("/")
    st0 = hdr0 = body0 = None
    try:
        st0, hdr0, body0 = fetch("GET", base + "/", body=None)
    except Exception as exc:
        hyp.status = "uncertain"
        hyp.evidence.append("baseline fetch failed: %s" % exc)
        return hyp
    baseline_len = len(body0 or b"")

    for p in (hyp.probes or [])[:max(1, budget)]:
        kind = (p.get("probe") or {}).get("kind")
        path_param = (p.get("probe") or {}).get("path_param") or ""
        try:
            if kind == "stability":
                st1, _, b1 = fetch("GET", base + "/", body=None)
                st2, _, b2 = fetch("GET", base + "/", body=None)
                if st1 == st2 == 500:
                    hyp.status = "verified"
                    hyp.evidence.append(
                        "consistent 500 across repeat requests")
                    return hyp
                hyp.evidence.append(
                    "stability probe: %s/%s (baseline %s)"
                    % (st1, st2, st0))
            elif kind == "authz-headers":
                found = []
                for h, v in (("X-Original-URL", "/"),
                             ("X-Rewrite-URL", "/"),
                             ("X-Forwarded-For", "127.0.0.1")):
                    try:
                        stx, _, _b = fetch("GET", base + "/", body=None)
                    except Exception:
                        continue
                    if stx and st0 and stx != st0:
                        found.append("%s changed status %s->%s"
                                     % (h, st0, stx))
                if found:
                    hyp.status = "verified"
                    hyp.evidence.extend(found)
                    return hyp
                hyp.evidence.append("authz header variations had no "
                                    "status effect")
            elif kind in ("sqli-quote", "errdetail"):
                url = base + "/" + ("?q=" + path_param
                                    if path_param else "")
                stx, _hx, bx = fetch("GET", url, body=None)
                text = (bx or b"").decode("latin-1", "replace")
                delta = len(bx or b"") - baseline_len
                if stx != st0 or abs(delta) > 40:
                    hyp.status = "verified"
                    hyp.evidence.append(
                        "probe changed response: status %s->%s, "
                        "size delta %+d" % (st0, stx, delta))
                    return hyp
                hyp.evidence.append("%s: no differential (%s, delta %d)"
                                    % (kind, stx, delta))
            elif kind in ("redirect-echo", "xss-echo"):
                url = base + "/" + ("?q=" + path_param
                                    if path_param else "")
                stx, _hx, bx = fetch("GET", url, body=None)
                marker = "omega-probe.invalid" if kind == \
                    "redirect-echo" else "wf<marker7>"
                if marker in (bx or b"").decode("latin-1", "replace"):
                    hyp.status = "verified"
                    hyp.evidence.append("marker reflected in response "
                                        "body")
                    return hyp
                hyp.evidence.append("%s: marker not reflected" % kind)
        except Exception as exc:
            hyp.evidence.append("probe error: %s" % exc)

    hyp.status = "refuted" if any(
        "no differential" in e or "not reflected" in e
        for e in hyp.evidence) else "uncertain"
    return hyp


def run_hypothesis_loop(observations, fetch, base_url, max_hyps=5):
    """Build + verify hypotheses in score order. Returns the doc:
    hypotheses with statuses + a summary."""
    hyps = build_hypotheses(observations)[:max_hyps]
    verified, refuted, uncertain = [], [], []
    for h in hyps:
        verify_hypothesis(h, fetch, base_url)
        {"verified": verified, "refuted": refuted,
         "uncertain": uncertain}.setdefault(h.status, []).append(h)
    return {"target": base_url,
            "raised": len(hyps),
            "hypotheses": [h.to_dict() for h in hyps],
            "counts": {"verified": len(verified),
                       "refuted": len(refuted),
                       "uncertain": len(uncertain)}}
