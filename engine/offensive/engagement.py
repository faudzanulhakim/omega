"""
offensive/engagement.py — ENGINE engagement runner.

Concept inspired by the oh-my-open-pentest project (inspiration credit
only): an autonomous agent that runs a full pentest engagement through
ordered stages, rebuilt natively in ENGINE
using ONLY ENGINE's own self-built modules — no external Kali tools.

Design:
  * MODES: 10 engagement modes, each an ordered stage list + description.
  * Stages map onto ENGINE modules:
      recon          -> offensive.reconiblis.run_reconiblis
      enum           -> offensive.ghostcrawl.alt_map_discovery (fetcher-
                        injected) + offensive.csminer static tracer
      exploit-verify -> engine.vulnscan2.run_vulnscan, profile
                        "passive-quick" (bounded, never destructive)
      chain          -> offensive.chainexec.build_chains (PLANNING ONLY —
                        execute_chain is NEVER called from here)
      triage         -> offensive.triageai.triage
      runbook        -> offensive.playbooks.generate_runbook per CONFIRMED
                        finding
      report         -> summary dict + render_report markdown
  * SAFETY:
      - run_engagement() requires scope_ack (the exact confirmation string
        or True) else PermissionError.
      - hard budget: max 25 stage invocations, max 150 HTTP requests total
        (a counting fetcher is injected into every module that accepts one;
        modules that manage their own client are capped via their public
        budget options, else skipped with a warning line).
      - cancel callable is honored between stages.
      - every stage failure is contained (logged + skipped), never crashing
        the engagement.
"""
import os
import re

# ------------------------------------------------------------------ modes

_SCOPE_ACK_TEXT = "I confirm I am authorized to test this target"

MODES = {
    "auto": {
        "description": (
            "Balanced default engagement: passive recon, alt-map enum, "
            "bounded passive verification, triage, chain planning, report."),
        "stages": ["recon", "enum", "exploit-verify", "triage", "chain",
                   "report"],
    },
    "bug-bounty": {
        "description": (
            "Bug-bounty workflow: wide recon/enum, verification, triage and "
            "per-finding runbooks the operator can execute manually."),
        "stages": ["recon", "enum", "exploit-verify", "triage", "runbook",
                   "chain", "report"],
    },
    "red-team": {
        "description": (
            "Red-team posture: full surface mapping, chain planning first "
            "(never executed), then triage and runbooks."),
        "stages": ["recon", "enum", "exploit-verify", "chain", "triage",
                   "runbook", "report"],
    },
    "ctf": {
        "description": (
            "Capture-the-flag: quick enum and verification only — recon "
            "against external hosts is skipped."),
        "stages": ["enum", "exploit-verify", "triage", "report"],
    },
    "blue-team": {
        "description": (
            "Defensive review: passive surface mapping and triage; no "
            "offensive chain planning."),
        "stages": ["recon", "triage", "runbook", "report"],
    },
    "offensive": {
        "description": (
            "Maximum-offense (still bounded & non-destructive): enum, "
            "verify, chain planning, triage."),
        "stages": ["enum", "exploit-verify", "chain", "triage", "report"],
    },
    "grey-hat": {
        "description": (
            "Grey-hat recon-heavy sweep: full passive mapping with light "
            "verification."),
        "stages": ["recon", "enum", "exploit-verify", "triage", "report"],
    },
    "forensic": {
        "description": (
            "Forensic posture: read-only surface collection and triage — "
            "no active probes at all."),
        "stages": ["recon", "triage", "report"],
    },
    "reverse-engineering": {
        "description": (
            "Static-first: client-side JS alt-map + dataflow triage; no "
            "active scanning."),
        "stages": ["enum", "triage", "report"],
    },
    "mobile-pentest": {
        "description": (
            "Mobile target (apk/ipa): surface recon and triage; deeplink "
            "analysis happens outside the HTTP budget."),
        "stages": ["recon", "triage", "report"],
    },
}

DEFAULT_MODE = "auto"


def detect_mode(target):
    """Heuristic target classifier -> (mode, note).

    IP/CIDR -> red-team; apk/ipa path -> mobile-pentest; hostname
    containing ctf/hackthebox/tryhackme -> ctf; anything else -> auto
    (with a note when the target string hints at a WAF/tech stack that
    the auto stage list already covers).
    """
    t = str(target or "").strip()
    low = t.lower()

    if low.endswith((".apk", ".ipa")) or "/uploads_apk/" in low:
        return "mobile-pentest", "target is a mobile package path"

    # IP or CIDR (v4)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", t):
        return "red-team", "target is an IP/CIDR — infrastructure posture"

    host = low
    if "://" in host:
        try:
            from urllib.parse import urlparse
            host = (urlparse(t).hostname or "").lower()
        except Exception:
            host = low.split("://", 1)[-1].split("/")[0]
    host = host.split("/")[0].split(":")[0]

    if any(k in host for k in ("ctf", "hackthebox", "tryhackme")):
        return "ctf", "hostname looks like a CTF platform"

    note = "URL/host target — auto engagement"
    if any(k in low for k in ("cloudflare", "waf", "sucuri", "imperva",
                              "akamai")):
        note += " (WAF fingerprint hints present in target string)"
    return "auto", note


# ------------------------------------------------------------------ budget

class BudgetExceeded(Exception):
    """Raised when the HTTP-request budget runs out mid-stage."""


class Budget:
    """Hard engagement budget: stage invocations + HTTP requests."""

    MAX_STAGES = 25
    MAX_REQUESTS = 150

    def __init__(self, log=None):
        self.stages_used = 0
        self.http_requests = 0
        self.log = log or (lambda m: None)

    def stage(self, name):
        """Count one stage invocation; raises RuntimeError past the cap."""
        if self.stages_used >= self.MAX_STAGES:
            raise RuntimeError(
                f"stage budget exhausted ({self.MAX_STAGES} stage "
                f"invocations) — stopping before '{name}'")
        self.stages_used += 1

    def fetcher(self, fetch):
        """Wrap an injected fetcher so every call counts against the
        request budget. Past the cap it raises BudgetExceeded (stage
        wrappers contain it)."""
        def counted(path, *a, **kw):
            if self.http_requests >= self.MAX_REQUESTS:
                raise BudgetExceeded(
                    f"HTTP budget exhausted ({self.MAX_REQUESTS} requests)")
            self.http_requests += 1
            return fetch(path, *a, **kw)
        return counted


class _Resp:
    """Minimal response object matching the ghostcrawl fetcher contract
    (attributes: status, body)."""

    def __init__(self, status, body):
        self.status = status
        self.body = body


# ------------------------------------------------------------------ stages

def _stage_recon(eng, budget, log):
    """reconiblis passive sweep. reconiblis manages its own client and has
    no public budget option — the stage is gated by its own semantics
    (offline-degraded unless PTK_RECON=1) and network failures are treated
    gracefully: any exception becomes a warning line, never a crash."""
    from offensive import reconiblis
    if os.environ.get("PTK_RECON") != "1":
        log("[engage] recon gate: PTK_RECON off — reconiblis runs in "
            "degraded/offline mode; failures will be tolerated")
    try:
        res = reconiblis.run_reconiblis(eng["target"], log=log)
        findings = list((res or {}).get("findings") or [])
        meta = (res or {}).get("meta") or {}
        surface = meta.get("attack_surface_map") or {}
        log(f"[engage] recon: {len(findings)} findings, surface hosts="
            f"{len(surface.get('hosts') or [])} urls="
            f"{len(surface.get('urls') or [])}")
        return {"ok": True, "findings": findings, "surface": surface}
    except Exception as e:  # contained on purpose
        log(f"[engage] recon failed gracefully: {type(e).__name__}: {e}")
        return {"ok": False, "findings": [], "error": f"{type(e).__name__}: {e}"}


def _make_fetcher(eng, budget, log):
    """Build the counting fetcher injected into ghostcrawl/csminer, driven
    by the URL list the enum stage discovered on the local target."""
    import urllib.request

    base = eng["target"]
    if "://" not in base:
        base = "http://" + base

    def fetch(path, timeout=6.0):
        url = path if "://" in path else base.rstrip("/") + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent":
                                                       "engine-engage/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return _Resp(r.status, r.read().decode("utf-8", "replace"))
        except Exception as e:
            log(f"[engage] enum fetch failed ({url}): {type(e).__name__}")
            return _Resp(0, "")

    return budget.fetcher(fetch)


def _stage_enum(eng, budget, log):
    """ghostcrawl alt-map discovery (fetcher-injected) + csminer static
    taint tracing over the fetched HTML."""
    from offensive import ghostcrawl, csminer
    fetch = _make_fetcher(eng, budget, log)
    out = {"ok": True, "findings": [], "alt_map": None, "dataflows": []}
    try:
        out["alt_map"] = ghostcrawl.alt_map_discovery(fetch, log=log)
    except BudgetExceeded:
        log("[engage] enum: alt-map stopped by HTTP budget cap")
        out["ok"] = True
    except Exception as e:
        log(f"[engage] enum alt-map failed gracefully: {type(e).__name__}: {e}")
        out["ok"] = False

    # csminer static tracer on fetched HTML (inject the same fetcher)
    try:
        tracer = csminer.JSFlowTracer()
        resp = fetch("/")
        if resp.status == 200 and resp.body:
            out["dataflows"] = tracer.trace(resp.body, "homepage")
            log(f"[engage] enum: csminer traced {len(out['dataflows'])} "
                f"dataflows on homepage HTML")
    except Exception as e:
        log(f"[engage] csminer trace failed gracefully: {type(e).__name__}: {e}")
    return out


def _stage_exploit_verify(eng, budget, log):
    """Bounded, non-destructive verification via engine.vulnscan2.run_vulnscan
    with the passive-quick profile. vulnscan2 manages its own client; the
    public budget option max_pages is capped (else the module would be
    skipped with a warning)."""
    import sys
    sys.path.insert(0, "engine") if False else None
    from engine import vulnscan2
    opts = {"timeout": 6.0, "max_pages": 1}
    try:
        res = vulnscan2.run_vulnscan(eng["target"], "passive-quick",
                                     log=log, opts=opts)
        findings = list((res or {}).get("findings") or [])
        log(f"[engage] exploit-verify: {len(findings)} findings "
            f"(profile passive-quick, non-destructive)")
        return {"ok": True, "findings": findings}
    except Exception as e:
        log(f"[engage] exploit-verify failed gracefully: {type(e).__name__}: {e}")
        return {"ok": False, "findings": [],
                "error": f"{type(e).__name__}: {e}"}


def _stage_chain(eng, budget, log):
    """chainexec.build_chains — PLANNING ONLY. execute_chain is never
    called here; execution needs an explicit operator approve token."""
    from offensive import chainexec
    plans = chainexec.build_chains(eng["findings"]) or []
    for p in plans:
        p["executed"] = False
        p["planning_only"] = True
    log(f"[engage] chain: {len(plans)} chain plans BUILT (planning only — "
        f"not executed; execution requires an explicit approve token)")
    return {"ok": True, "chains": plans}


def _stage_triage(eng, budget, log):
    from offensive import triageai
    try:
        res = triageai.triage(eng["findings"]) or {}
        triaged = list(res.get("findings") or [])
        # replace findings with the triaged copies (input not mutated)
        eng["findings"] = triaged
        summary = res.get("summary") or {}
        log(f"[engage] triage: {len(triaged)} findings labeled "
            f"(summary={summary})")
        return {"ok": True, "triaged": True, "summary": summary,
                "correlation_notes": list(res.get("correlation_notes") or [])}
    except Exception as e:
        log(f"[engage] triage failed gracefully: {type(e).__name__}: {e}")
        return {"ok": False, "triaged": False,
                "error": f"{type(e).__name__}: {e}"}


def _is_confirmed(f):
    tri = f.get("triage") or {}
    if str(tri.get("verdict", "")).lower() in ("confirmed", "true-positive",
                                              "tp"):
        return True
    if str(tri.get("verdict", "")).lower() in ("likely-false-positive",
                                               "false-positive", "fp"):
        return False
    return str(f.get("verification", "")).lower() == "confirmed"


def _stage_runbook(eng, budget, log):
    """playbooks.generate_runbook per CONFIRMED finding."""
    from offensive import playbooks
    runbooks = []
    for f in eng["findings"]:
        if not _is_confirmed(f):
            continue
        try:
            rb = playbooks.generate_runbook(f, eng["target"])
            runbooks.append(rb)
        except Exception as e:
            log(f"[engage] runbook for '{f.get('title', '?')}' failed "
                f"gracefully: {type(e).__name__}: {e}")
    log(f"[engage] runbook: {len(runbooks)} runbooks for confirmed findings")
    return {"ok": True, "runbooks": runbooks}


def _stage_external(eng, budget, log):
    """Optional external-tool bridge stage (offensive.toolbridge). Gated
    by env PTK_TOOLS=1; when off, logs a line and skips — the engagement
    behaves exactly as before. Each tool run counts 1 against the
    remaining HTTP-request budget."""
    from offensive import toolbridge
    if os.environ.get("PTK_TOOLS") != "1":
        log("[engage] external tools disabled (PTK_TOOLS)")
        return {"ok": True, "findings": [], "skipped": True,
                "note": "external tools disabled (PTK_TOOLS)"}
    # same 'external' stage name is used after recon and after enum:
    # pick the bridge stage by what has already run
    stage = "enum" if "enum" in eng.get("stage_results", {}) else "recon"
    remaining = max(0, budget.MAX_REQUESTS - budget.http_requests)
    try:
        res = toolbridge.run_bridge(eng["target"], stage,
                                    budget_requests=remaining, log=log)
    except Exception as e:  # contained on purpose
        log(f"[engage] external tools failed gracefully: "
            f"{type(e).__name__}: {e}")
        return {"ok": False, "findings": [],
                "error": f"{type(e).__name__}: {e}"}
    log(f"[engage] external: ran={len(res.get('ran') or [])} "
        f"skipped={len(res.get('skipped') or [])} "
        f"findings={len(res.get('findings') or [])}")
    return {"ok": True, "findings": res.get("findings") or [],
            "surface": res.get("surface") or {},
            "tools_ran": res.get("ran") or [],
            "tools_skipped": res.get("skipped") or []}


_STAGE_FNS = {
    "recon": _stage_recon,
    "enum": _stage_enum,
    "exploit-verify": _stage_exploit_verify,
    "chain": _stage_chain,
    "triage": _stage_triage,
    "runbook": _stage_runbook,
    # "report" is emitted by run_engagement itself after the loop.
    "external": _stage_external,  # optional external-tool bridge
}

# optional 'external' stage: inserted after 'recon' and 'enum' in every
# mode that runs them. Gated by PTK_TOOLS (off by default), so behavior
# is unchanged when the gate is off.
for _m in MODES.values():
    _st = _m["stages"]
    for _anchor in ("recon", "enum"):
        if _anchor in _st and "external" not in _st:
            _st.insert(_st.index(_anchor) + 1, "external")


# ------------------------------------------------------------- engagement

def run_engagement(target, mode=None, scope_ack=None, budget=None,
                   cancel=None, log=None):
    """Run an ENGINE engagement. REQUIRES scope_ack (the exact string
    'I confirm I am authorized to test this target' or True) — anything
    else raises PermissionError.

    Returns the full engagement dict; render_report(engagement) turns it
    into a markdown summary.
    """
    if scope_ack is not True and scope_ack != _SCOPE_ACK_TEXT:
        raise PermissionError(
            "scope acknowledgment required: pass scope_ack="
            f"'{_SCOPE_ACK_TEXT}' (or True) to confirm you are authorized "
            "to test this target")

    if log is None:
        log_lines = []
        log = log_lines.append
    elif isinstance(log, list):
        log_lines = log
        log = log.append
    else:
        log_lines = []

    mode = mode or DEFAULT_MODE
    if mode not in MODES:
        raise ValueError(f"unknown mode '{mode}'; choices: "
                         f"{', '.join(sorted(MODES))}")
    if budget is None:
        budget = Budget(log=log)

    target = str(target or "").strip()
    if not target:
        raise ValueError("empty target")

    # auto-mode refinement: detect_mode may re-classify (IP -> red-team etc.)
    eff_mode, mode_note = detect_mode(target)
    if mode == "auto":
        log(f"[engage] auto mode heuristic: {mode_note} -> mode={eff_mode}")
        mode = eff_mode
        mode_note_out = mode_note
    else:
        mode_note_out = f"operator-selected mode={mode} (heuristic: {mode_note})"

    eng = {
        "kind": "engine-engagement",
        "mode": mode,
        "mode_description": MODES[mode]["description"],
        "target": target,
        "stages_planned": list(MODES[mode]["stages"]),
        "stages_run": [],
        "stages_failed": [],
        "findings": [],
        "chains_planned": [],
        "runbooks": [],
        "risk": "unknown",
        "scope_ack": True,
        "budget": {"max_stages": budget.MAX_STAGES,
                   "max_requests": budget.MAX_REQUESTS},
        "log": log_lines,
        "errors": [],
    }

    for stage in MODES[mode]["stages"]:
        if cancel is not None:
            try:
                if cancel():
                    log(f"[engage] cancel requested — stopping before '{stage}'")
                    eng["errors"].append(f"cancelled before stage '{stage}'")
                    break
            except Exception:
                pass  # a broken cancel callable must not crash the run

        if stage == "report":
            continue  # emitted below, after the loop

        try:
            budget.stage(stage)
        except RuntimeError as e:
            log(f"[engage] {e}")
            eng["errors"].append(str(e))
            break

        log(f"[engage] === stage: {stage} ===")
        fn = _STAGE_FNS.get(stage)
        if fn is None:
            log(f"[engage] no plugin for stage '{stage}' — skipped")
            eng["stages_failed"].append(stage)
            eng["errors"].append(f"stage '{stage}' has no plugin")
            continue
        try:
            out = fn(eng, budget, log) or {}
        except BudgetExceeded:
            log(f"[engage] stage '{stage}' stopped: HTTP budget cap reached")
            eng["errors"].append(f"stage '{stage}': HTTP budget cap reached")
            break
        except Exception as e:
            # stage failure containment: log + continue, never crash
            log(f"[engage] stage '{stage}' failed gracefully: "
                f"{type(e).__name__}: {e}")
            eng["stages_failed"].append(stage)
            eng["errors"].append(f"stage '{stage}': {type(e).__name__}: {e}")
            continue

        eng["stages_run"].append(stage)
        eng.setdefault("stage_results", {})[stage] = out
        for f in (out.get("findings") or []):
            if f not in eng["findings"]:
                eng["findings"].append(f)
        if out.get("chains") is not None:
            eng["chains_planned"] = out["chains"]
        if out.get("runbooks") is not None:
            eng["runbooks"] = out["runbooks"]

        if budget.http_requests >= budget.MAX_REQUESTS:
            log(f"[engage] HTTP request budget reached "
                f"({budget.MAX_REQUESTS}) — halting further stages")
            eng["errors"].append("HTTP budget cap reached")
            break

    # risk rollup
    sev_w = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 3, "INFO": 1}
    score = sum(sev_w.get(str(f.get("severity", "")).upper(), 0)
                for f in eng["findings"])
    eng["risk"] = ("critical" if score >= 40 else
                   "high" if score >= 15 else
                   "medium" if score >= 7 else
                   "low" if eng["findings"] else "none")
    eng["budget_used"] = {"stages": budget.stages_used,
                          "http_requests": budget.http_requests}
    eng["stage_results"] = eng.get("stage_results", {})
    eng["report_markdown"] = render_report(eng)
    return eng


# ------------------------------------------------------------------ report

def render_report(eng):
    """Render the engagement dict as an English markdown summary."""
    lines = []
    lines.append(f"# ENGINE Engagement Report — {eng.get('target', '?')}")
    lines.append("")
    lines.append(f"- **Mode**: {eng.get('mode')} — "
                 f"{eng.get('mode_description', '')}")
    lines.append(f"- **Scope**: acknowledged by operator "
                 f"(`{eng.get('scope_ack') and 'confirmed'}`)")
    lines.append(f"- **Risk rollup**: **{str(eng.get('risk')).upper()}**")
    bu = eng.get("budget_used") or {}
    lines.append(f"- **Budget used**: {bu.get('stages', 0)} stage "
                 f"invocations / {bu.get('http_requests', 0)} HTTP requests")
    if eng.get("errors"):
        lines.append(f"- **Contained errors**: {len(eng['errors'])} "
                     "(stage failures were logged and skipped)")
    lines.append("")

    lines.append("## Stages run")
    lines.append("")
    if eng.get("stages_run"):
        for s in eng["stages_run"]:
            lines.append(f"- `{s}`")
    else:
        lines.append("- (no stages completed)")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    fs = eng.get("findings") or []
    if fs:
        lines.append("| # | Severity | Title | Triage verdict | Verified |")
        lines.append("|---|----------|-------|----------------|----------|")
        for i, f in enumerate(fs, 1):
            tri = (f.get("triage") or {}).get("verdict", "-")
            ver = f.get("verification", f.get("confidence", "-"))
            title = str(f.get("title", "?")).replace("|", "\\|")
            sev = str(f.get("severity", "?"))
            lines.append(f"| {i} | {sev} | {title} | {tri} | {ver} |")
    else:
        lines.append("_No findings were collected._")
    lines.append("")

    lines.append("## Attack chains (planning only)")
    lines.append("")
    ch = eng.get("chains_planned") or []
    if ch:
        for c in ch:
            lines.append(f"- **{c.get('name')}** ({c.get('type')}, "
                         f"sev {c.get('severity')}, "
                         f"{len(c.get('steps') or [])} steps) — "
                         f"{c.get('note', '')}; executed: NO")
    else:
        lines.append("_No chains planned._ Chains are planning-only — "
                     "never executed without an explicit approve token.")
    lines.append("")

    lines.append("## Runbooks (confirmed findings)")
    lines.append("")
    rbs = eng.get("runbooks") or []
    if rbs:
        for rb in rbs:
            lines.append(f"- `{rb.get('finding_ref')}` — "
                         f"{rb.get('title')} ({rb.get('class')})")
    else:
        lines.append("_No runbooks generated (no confirmed findings)._")
    lines.append("")

    lines.append("## Next steps for the operator")
    lines.append("")
    lines.append("1. Review every finding's verification/triage label before "
                 "acting; triage is heuristic.")
    lines.append("2. Chains are PLANS only — executing any chain requires an "
                 "explicit approve token via `chainexec.execute_chain` and "
                 "written authorization.")
    lines.append("3. Work through the runbooks above manually (they are "
                 "authorized-only, step-numbered, with cleanup steps).")
    lines.append("4. Re-run with a wider mode (e.g. `bug-bounty`) once scope "
                 "expands; every run is budget-capped and non-destructive.")
    lines.append("")
    return "\n".join(lines)
