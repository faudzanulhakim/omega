"""OMEGA AI-ASSIST layer — deterministic analyst heuristics.

Turns raw scan findings into a prioritized attack plan that Hermes (the
LLM agent running OMEGA) reasons on top of. This layer NEVER talks to the
network, NEVER invents findings, and NEVER raises in normal use — every
entry point contains its own errors and returns honest, derived data.

Determinism contract: same findings in, same scores/plan out (no time,
no randomness, no network).
"""

from __future__ import annotations

# Scoring weights (documented, deterministic).
SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 30,
    "medium": 15,
    "low": 5,
    "info": 0,
}

VERIFICATION_WEIGHTS = {
    "confirmed": 35,
    "verified": 35,
    "corroborated": 20,
    "candidate": 0,
}

# Exploitability markers searched (case-insensitive) in title and source.
EXPLOIT_MARKERS = (
    "exploited", "sqli", "cmdi", "rce", "ssrf", "jwt",
    "auth bypass", "idor", "traversal", "ssti",
)

# Internet-reachability hint words (case-insensitive) searched across the
# finding's text fields.
INTERNET_HINTS = (
    "internet", "public", "external", "exposed",
    "publicly", "0.0.0.0",
)

_MAX_SCORE = 100
_MAX_PLAN_STEPS = 10

_PHASE_ORDER = ("recon", "initial-access", "privilege", "loot",
                "persist-check", "report")

_TEXT_FIELDS = ("title", "source", "evidence", "location", "notes",
                "detail", "description", "verification_note")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _clean(value):
    """Lowercased str() of anything; never raises."""
    try:
        return str(value).lower()
    except Exception:
        return ""


def _finding_text(f):
    """Concatenated lowercase text of the finding's known text fields."""
    if not isinstance(f, dict):
        return ""
    return " ".join(_clean(f.get(k)) for k in _TEXT_FIELDS)


def _is_confirmed(f):
    if not isinstance(f, dict):
        return False
    v = _clean(f.get("verification", f.get("status", "")))
    if v in ("confirmed", "verified"):
        return True
    return bool(f.get("confirmed") or f.get("verified"))


def _title_of(f):
    if not isinstance(f, dict):
        return ""
    return str(f.get("title") or f.get("id") or "untitled finding")


# --------------------------------------------------------------------------
# 1. risk_score
# --------------------------------------------------------------------------

def risk_score(findings):
    """Score every finding: adds ai_risk (0-100 int) and ai_reason.

    Returns a NEW list of dicts (inputs are never mutated). Non-dict
    entries are passed through untouched. Deterministic.
    """
    if not isinstance(findings, (list, tuple)):
        return []
    out = []
    for f in findings:
        if not isinstance(f, dict):
            out.append(f)
            continue
        score, reasons = _score_one(f)
        g = dict(f)
        g["ai_risk"] = score
        g["ai_reason"] = "; ".join(reasons)
        out.append(g)
    return out


def _score_one(f):
    score = 0
    reasons = []

    sev = _clean(f.get("severity", ""))
    sev_pts = SEVERITY_WEIGHTS.get(sev, 0)
    if sev_pts:
        score += sev_pts
        reasons.append("severity %s (+%d)" % (sev, sev_pts))

    ver = _clean(f.get("verification", f.get("status", "")))
    ver_pts = VERIFICATION_WEIGHTS.get(ver, 0)
    if not ver_pts and _is_confirmed(f):
        ver_pts = 35
    if ver_pts:
        score += ver_pts
        reasons.append("verification %s (+%d)" % (ver or "confirmed",
                                                  ver_pts))

    text = _finding_text(f)
    hits = sorted({m for m in EXPLOIT_MARKERS if m in text})
    if hits:
        score += 15
        reasons.append("exploitability markers: %s (+15)" % ", ".join(hits))

    ihits = sorted({h for h in INTERNET_HINTS if h in text})
    if ihits:
        score += 5
        reasons.append("internet-reachable hint: %s (+5)" % ", ".join(ihits))

    return min(score, _MAX_SCORE), reasons


# --------------------------------------------------------------------------
# 2. prioritize
# --------------------------------------------------------------------------

def prioritize(findings):
    """Rank findings by ai_risk (desc), ties broken by title (asc).

    Returns {"ranked": [...scored...], "summary": {...}} with buckets:
      critical_now — titles with risk >= 80
      quick_wins   — titles with risk 50-79
      noise        — titles with risk < 50
    Never raises: garbage input degrades to an empty summary.
    """
    ranked = risk_score(findings)
    dicts = [f for f in ranked if isinstance(f, dict)]
    dicts.sort(key=lambda f: (-int(f.get("ai_risk") or 0),
                              _title_of(f)))
    critical_now, quick_wins, noise = [], [], []
    for f in dicts:
        r = int(f.get("ai_risk") or 0)
        t = _title_of(f)
        if r >= 80:
            critical_now.append(t)
        elif r >= 50:
            quick_wins.append(t)
        else:
            noise.append(t)
    return {
        "ranked": dicts,
        "summary": {
            "total": len(dicts),
            "critical_now": critical_now,
            "quick_wins": quick_wins,
            "noise": noise,
        },
    }


# --------------------------------------------------------------------------
# 3. plan_attack
# --------------------------------------------------------------------------

def _cmd_brain(target):
    return "bash bin/omega brain %s --scope-ack --aggressive" % target


def _cmd_inject(target):
    return "bash bin/omega inject %s --scope-ack --offense" % target


def _cmd_report():
    return "bash bin/omega report - --out reports/omega-report.md"


def _markered(f):
    text = _finding_text(f)
    return any(m in text for m in EXPLOIT_MARKERS)


def plan_attack(findings, target):
    """Ordered kill-chain plan over EXISTING findings only.

    Phases: recon | initial-access | privilege | loot | persist-check |
    report. Exploit-confirmed findings drive privilege/loot steps;
    candidates get a manual-check-first step; empty findings yields
    recon-only steps. Hard cap: 10 steps. Only the given target value is
    used in commands; no findings are invented.
    """
    target = str(target or "")
    try:
        scored = [f for f in risk_score(findings) if isinstance(f, dict)]
    except Exception:
        scored = []
    scored.sort(key=lambda f: (-int(f.get("ai_risk") or 0), _title_of(f)))

    confirmed = [f for f in scored if _is_confirmed(f)]
    candidates = [f for f in scored
                  if not _is_confirmed(f)
                  and _clean(f.get("verification",
                                   f.get("status", ""))) == "candidate"]
    exploitable = [f for f in scored if _markered(f)]
    others = [f for f in scored if f not in confirmed and f not in candidates]

    steps = []

    def add(phase, action, based_on, command=None):
        if len(steps) >= _MAX_PLAN_STEPS:
            return
        steps.append({
            "n": len(steps) + 1,
            "phase": phase,
            "action": action,
            "based_on": list(based_on),
            "command": command,
        })

    # recon — always first.
    add("recon", "Re-run bounded recon + enum on %s to refresh surface "
                 "facts before touching anything" % (target or "the target"),
        [], _cmd_brain(target) if target else None)

    # manual-check-first for candidates (highest risk candidates only).
    for f in candidates[:2]:
        add("initial-access",
            "Manually verify candidate before any automation: %s"
            % _title_of(f), [_title_of(f)],
            _cmd_brain(target) if target else None)

    # initial-access from non-confirmed exploitable findings.
    for f in exploitable[:2]:
        if _is_confirmed(f):
            continue
        add("initial-access",
            "Attempt controlled initial access via the flagged vector: %s"
            % _title_of(f), [_title_of(f)],
            _cmd_inject(target) if target else None)

    # confirmed findings -> privilege (exploitable) / loot (evidence).
    loot_used = False
    priv_used = False
    for f in confirmed:
        if _markered(f) and not priv_used:
            add("privilege",
                "Escalate using the confirmed exploitable finding: %s"
                % _title_of(f), [_title_of(f)],
                _cmd_inject(target) if target else None)
            priv_used = True
            if not loot_used:
                add("loot",
                    "Collect and document impact evidence from the "
                    "confirmed finding: %s" % _title_of(f),
                    [_title_of(f)],
                    _cmd_brain(target) if target else None)
                loot_used = True
        elif not loot_used:
            add("loot",
                "Collect and document impact evidence from the confirmed "
                "finding: %s" % _title_of(f), [_title_of(f)],
                _cmd_brain(target) if target else None)
            loot_used = True

    # lower-risk leftovers get one consolidated triage step.
    if others and len(steps) < _MAX_PLAN_STEPS:
        add("initial-access",
            "Triage remaining low-risk findings on the surface",
            [_title_of(f) for f in others[:3]],
            _cmd_brain(target) if target else None)

    # persist-check only when something was confirmed.
    if confirmed and len(steps) < _MAX_PLAN_STEPS:
        add("persist-check",
            "Check whether the confirmed issues persist after a re-scan "
            "(no persistence/payloads are ever left behind)", [],
            _cmd_brain(target) if target else None)

    # report — always last.
    add("report", "Generate the engagement report and deliver it",
        [_title_of(f) for f in scored[:3]], _cmd_report())

    # renumber (cap may have trimmed nothing, but keep n contiguous).
    for i, s in enumerate(steps, 1):
        s["n"] = i
    return steps


# --------------------------------------------------------------------------
# 4. analyst_brief
# --------------------------------------------------------------------------

_EMPTY_BRIEF = {
    "headline": "No findings available to analyze.",
    "risk_score": 0,
    "plan": [],
    "next_actions": ["Run a bounded recon pass with "
                     "bash bin/omega brain <target> --scope-ack"],
    "stats": {"total": 0, "critical": 0, "high": 0, "medium": 0,
              "low": 0, "info": 0, "confirmed": 0, "candidate": 0},
    "contained": True,
}


def analyst_brief(findings, target):
    """Headline + score + plan + next actions over the findings.

    NEVER raises: None / empty / garbage input returns a contained
    dict with contained=True. Deterministic.
    """
    try:
        return _brief(findings, target)
    except Exception:
        return dict(_EMPTY_BRIEF)


def _brief(findings, target):
    if not isinstance(findings, (list, tuple)) or not findings:
        out = dict(_EMPTY_BRIEF)
        out["plan"] = plan_attack([], target)
        if isinstance(target, str) and target:
            out["next_actions"] = [
                "Run a bounded recon pass: bash bin/omega brain %s "
                "--scope-ack --aggressive" % target]
        return out

    ranked = risk_score(findings)
    dicts = [f for f in ranked if isinstance(f, dict)]
    dicts.sort(key=lambda f: (-int(f.get("ai_risk") or 0), _title_of(f)))
    summary = prioritize(findings)["summary"]

    top3 = [int(f.get("ai_risk") or 0) for f in dicts[:3]]
    avg = int(round(sum(top3) / len(top3))) if top3 else 0

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0,
                  "info": 0}
    confirmed_n = 0
    candidate_n = 0
    for f in dicts:
        sev_counts[_clean(f.get("severity", ""))] = \
            sev_counts.get(_clean(f.get("severity", "")), 0) + 1
        if _is_confirmed(f):
            confirmed_n += 1
        elif _clean(f.get("verification", f.get("status", ""))) == "candidate":
            candidate_n += 1

    parts = []
    if sev_counts["critical"]:
        parts.append("%d critical" % sev_counts["critical"])
    if sev_counts["high"]:
        parts.append("%d high" % sev_counts["high"])
    parts.append("%d finding(s) total" % len(dicts))
    if confirmed_n:
        parts.append("%d confirmed" % confirmed_n)
    headline = ("Target %s: %s" % (target, ", ".join(parts))) if target \
        else ("%s" % ", ".join(parts))

    nxt = []
    for t in summary["critical_now"][:3]:
        nxt.append("Treat as urgent: %s" % t)
    for t in summary["quick_wins"][:3 - len(nxt)]:
        nxt.append("Quick win available: %s" % t)
    if candidate_n and len(nxt) < 3:
        nxt.append("Manually verify %d candidate finding(s) before "
                   "automation" % candidate_n)
    if len(nxt) < 3:
        nxt.append("Re-run recon: bash bin/omega brain %s --scope-ack "
                   "--aggressive" % (target or "<target>"))

    return {
        "headline": headline,
        "risk_score": avg,
        "plan": plan_attack(dicts, target),
        "next_actions": nxt[:3],
        "stats": {
            "total": len(dicts),
            "critical": sev_counts.get("critical", 0),
            "high": sev_counts.get("high", 0),
            "medium": sev_counts.get("medium", 0),
            "low": sev_counts.get("low", 0),
            "info": sev_counts.get("info", 0),
            "confirmed": confirmed_n,
            "candidate": candidate_n,
        },
        "contained": False,
    }


# --------------------------------------------------------------------------
# 5. brief_markdown
# --------------------------------------------------------------------------

def brief_markdown(brief):
    """Render the analyst brief as a markdown report section.

    Never raises; non-dict input degrades to a minimal valid section.
    """
    try:
        brief = brief if isinstance(brief, dict) else {}
        lines = ["## AI Analyst Brief", ""]
        lines.append(str(brief.get("headline")
                         or "No findings available to analyze."))
        lines.append("")
        lines.append("**Analyst risk score: %s / 100**"
                     % brief.get("risk_score", 0))
        lines.append("")

        plan = brief.get("plan") or []
        if plan:
            lines.append("### Attack plan")
            lines.append("")
            lines.append("| # | Phase | Action | Based on |")
            lines.append("|---|-------|--------|----------|")
            for s in plan:
                if not isinstance(s, dict):
                    continue
                based = ", ".join(str(b) for b in (s.get("based_on") or []))
                lines.append("| %s | %s | %s | %s |" % (
                    s.get("n", ""), s.get("phase", ""),
                    str(s.get("action", "")).replace("|", "\\|"),
                    based.replace("|", "\\|")))
            lines.append("")

        nxt = brief.get("next_actions") or []
        if nxt:
            lines.append("### Next actions")
            lines.append("")
            for a in nxt:
                lines.append("- %s" % a)
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"
    except Exception:
        return "## AI Analyst Brief\n\nBrief could not be rendered.\n"
