"""OMEGA brain — the autonomous decision engine.

Sits on top of the engine (used read-only, via omega.cli's
loader) and turns an engagement into a bounded, deterministic loop:

  CapabilityRegistry  — capabilities the brain may choose from
  BrainState          — evolving picture of target/surface/findings
  decide(state)       — pure, deterministic next-action selection
  Brain.run(...)      — the autonomous loop (scope-gated, budgeted)

Safety invariants:
  * scope_ack is REQUIRED (True or the engine's ack text) exactly like
    the engine — anything else raises PermissionError before any work.
  * Budget (cost units) is enforced: no capability runs when its cost
    exceeds budget_remaining, and the loop stops when nothing fits.
  * Chains are NEVER executed — the 'chain' stage only plans them and
    the brain treats planned chains as report material.
  * Every capability failure is contained as a history entry; the loop
    never lets a capability exception escape.
"""

from __future__ import annotations

import datetime
import importlib
import json
import os
import re

from omega import cli

SCOPE_ACK_TEXT = "I confirm I am authorized to test this target"

# Engine stages the brain knows how to drive.
ENGINE_STAGES = ("recon", "external", "enum", "exploit-verify",
                 "triage", "chain", "runbook", "report")

_RISKS = ("passive", "active", "planning-only", "offense")
_KINDS = ("stage", "probe", "enum", "recon", "report")


# --------------------------------------------------------------------------
# Capability
# --------------------------------------------------------------------------

class Capability:
    """One thing the brain can choose to do.

    id       — unique dotted identifier, e.g. 'stage.enum'
    kind     — one of stage | probe | enum | recon | report
    requires — surface-fact names that must be truthy to be eligible,
               e.g. ('has_web',) or ('findings_high',)
    fn       — callable fn(state, brain) -> result dict (or None)
    cost     — budget units consumed when executed
    risk     — passive | active | planning-only
    """

    def __init__(self, id, kind, fn, cost=1, risk="passive",
                 requires=(), description=""):
        if kind not in _KINDS:
            raise ValueError(f"unknown capability kind {kind!r}; "
                             f"choices: {_KINDS}")
        if risk not in _RISKS:
            raise ValueError(f"unclassified risk {risk!r} for {id!r}; "
                             f"choices: {_RISKS}")
        if not callable(fn):
            raise TypeError(f"capability {id!r} fn must be callable")
        self.id = id
        self.kind = kind
        self.fn = fn
        self.cost = int(cost)
        self.risk = risk
        self.requires = tuple(requires)
        self.description = description

    def eligible(self, facts, budget_remaining=None):
        """True when every required surface fact is truthy and the
        cost fits the remaining budget (when a budget is given)."""
        for req in self.requires:
            if not facts.get(req):
                return False
        if budget_remaining is not None and self.cost > budget_remaining:
            return False
        return True

    def __repr__(self):
        return (f"<Capability {self.id} kind={self.kind} cost={self.cost} "
                f"risk={self.risk} requires={self.requires}>")


class CapabilityRegistry:
    """Ordered registry of capabilities; duplicate ids are rejected."""

    def __init__(self):
        self._caps = {}

    def register(self, cap):
        if cap.id in self._caps:
            raise ValueError(f"duplicate capability id: {cap.id}")
        self._caps[cap.id] = cap
        return cap

    def get(self, cap_id):
        return self._caps.get(cap_id)

    def all(self):
        return list(self._caps.values())

    def ids(self):
        return list(self._caps)

    def eligible(self, facts, budget_remaining=None):
        """Capabilities whose requirements are met and affordable,
        sorted deterministically by (cost, id)."""
        hits = [c for c in self._caps.values()
                if c.eligible(facts, budget_remaining)]
        return sorted(hits, key=lambda c: (c.cost, c.id))

    def audit(self):
        """Sanity audit: (count, problems list). Problems flag missing
        risk classification or uncallable fns."""
        problems = []
        for cap in self._caps.values():
            if cap.risk not in _RISKS:
                problems.append(f"{cap.id}: unclassified risk {cap.risk!r}")
            if not callable(cap.fn):
                problems.append(f"{cap.id}: fn is not callable")
            if cap.cost < 0:
                problems.append(f"{cap.id}: negative cost")
        return len(self._caps), problems


# --------------------------------------------------------------------------
# BrainState
# --------------------------------------------------------------------------

_HIGH_SEVERITIES = {"high", "critical"}


def _finding_is_high(f):
    if not isinstance(f, dict):
        return False
    sev = str(f.get("severity", "")).lower()
    return sev in _HIGH_SEVERITIES


def _finding_is_confirmed(f):
    if not isinstance(f, dict):
        return False
    status = str(f.get("status", f.get("verification", ""))).lower()
    if status in ("confirmed", "verified"):
        return True
    return bool(f.get("confirmed") or f.get("verified"))


class BrainState:
    """Everything the brain knows so far about one engagement."""

    def __init__(self, target, mode="auto", budget=100):
        self.target = target
        self.mode = mode
        self.surface = {"hosts": [], "urls": [], "ports": [], "techs": []}
        self.findings = []
        self.chains_planned = []
        self.stage_results = {}
        self.history = []          # ordered step records
        self.budget_remaining = int(budget)
        self.cancelled = False
        self.steps = 0
        self.engine = None         # cached full engagement dict, if any

    # -- surface fact derivation (pure, deterministic) --------------------

    def facts(self):
        """Surface facts used by Capability.requires and decide()."""
        ports = self.surface.get("ports") or []
        findings = self.findings
        stage_ran = lambda s: s in self.stage_results  # noqa: E731
        return {
            "recon_done": stage_ran("recon") or stage_ran("external"),
            "enum_done": stage_ran("enum"),
            "triage_done": stage_ran("triage"),
            "chain_planned": stage_ran("chain") or bool(self.chains_planned),
            "runbook_done": stage_ran("runbook"),
            "report_done": stage_ran("report"),
            "has_web": bool(self.surface.get("urls"))
                       or any(re.search(r":(80|443|8080|8443)$", str(p))
                              for p in ports),
            "has_dns": bool(self.surface.get("hosts")),
            "open_ports": len(ports),
            "findings": len(findings),
            "findings_untriaged": bool(findings) and not stage_ran("triage"),
            "findings_high": any(_finding_is_high(f) for f in findings),
            "findings_confirmed": any(_finding_is_confirmed(f)
                                      for f in findings),
            "has_jwt": any("jwt" in json.dumps(f, default=str).lower()
                           for f in findings
                           if isinstance(f, dict)),
        }

    # -- merging -----------------------------------------------------------

    def _merge_lists(self, key, values):
        if not values:
            return
        cur = self.surface.setdefault(key, [])
        for v in values:
            if v and v not in cur:
                cur.append(v)

    def update_from_stage(self, stage_name, result):
        """Merge one stage/probe result into the state; returns the
        number of new facts recorded (for the timeline)."""
        new_facts = 0
        result = result or {}
        self.stage_results[stage_name] = result

        hosts = result.get("hosts") or result.get("subdomains") or []
        self._merge_lists("hosts", hosts)
        self._merge_lists("urls", result.get("urls") or result.get("endpoints") or [])
        self._merge_lists("ports", result.get("ports") or [])
        self._merge_lists("techs", result.get("techs")
                          or result.get("technologies") or [])

        incoming = result.get("findings") or []
        known = {repr(f) for f in self.findings}
        for f in incoming:
            if repr(f) not in known:
                self.findings.append(f)
                new_facts += 1

        chains = result.get("chains") or result.get("chains_planned") or []
        for ch in chains:
            if ch not in self.chains_planned:
                self.chains_planned.append(ch)
                new_facts += 1

        for key in ("hosts", "urls", "ports", "techs"):
            new_facts += len(result.get(key) or [])
        self.history.append({
            "step": self.steps,
            "capability": stage_name,
            "result": "ok" if not result.get("error") else "error",
            "new_facts": new_facts,
            "detail": result.get("error") or "",
        })
        return new_facts

    def record_failure(self, cap_id, exc):
        """Contain a capability failure as a history entry."""
        self.history.append({
            "step": self.steps,
            "capability": cap_id,
            "result": "error",
            "new_facts": 0,
            "detail": f"{type(exc).__name__}: {exc}",
        })

    def timeline(self):
        return list(self.history)


# --------------------------------------------------------------------------
# Engine-backed stage wrappers
# --------------------------------------------------------------------------

def _engine_stage_fn(stage_name):
    """Build a capability fn that drives one engine stage.

    The engine exposes no per-stage entry point (TODO-ENGINE: add
    run_engagement(stage=...) upstream), so the wrapper runs the full
    auto pipeline once per Brain, caches the engagement dict, and
    slices out this stage's result. Stages already executed are served
    from the cache instead of re-running the engine.
    """

    def fn(state, brain=None):
        brain = brain or _BRAIN_CONTEXT[0]
        eng = brain.ensure_pipeline(state)
        out = (eng.get("stage_results") or {}).get(stage_name)
        if out is None:
            if stage_name in (eng.get("stages_planned") or []):
                out = {"note": f"stage '{stage_name}' planned but not "
                               "yet produced by the engine"}
            else:
                out = {}
        out = dict(out or {})
        out.setdefault("stage", stage_name)
        if stage_name == "chain":
            out["chains"] = eng.get("chains_planned") or []
        if stage_name == "report":
            from offensive import engagement as _eng_mod  # noqa: E402
            out["markdown"] = _eng_mod.render_report(eng)
        return out

    fn.__doc__ = (f"Drive engine stage '{stage_name}' "
                  "(sliced from the cached auto-pipeline result).")
    return fn


def _ai_chainreco_fn(state, brain=None):
    """Passive capability: recommend exploit chains from findings.

    Purely deterministic keyword matching over the findings already
    collected in this session — never a network call, never executed,
    planning only. Produces no findings by itself.
    """
    from omega.core.chainreco import recommend

    return recommend(state.findings, target=state.target)


def _probe_target_parse(state, brain=None):
    """Local, hermetic probe: parse the target string into surface facts."""
    target = str(state.target)
    facts = {}
    m = re.match(r"^https?://([^/:]+)(?::(\d+))?", target)
    if m:
        facts.setdefault("hosts", []).append(m.group(1))
        facts["urls"] = [target]
        facts["ports"] = [m.group(2) or ("443" if target.startswith("https")
                                         else "80")]
    else:
        facts["hosts"] = [target]
    return facts


def _probe_surface_classify(state, brain=None):
    """Local probe: classify the surface (web/dns presence, port count)."""
    f = state.facts()
    return {"has_web": f["has_web"], "has_dns": f["has_dns"],
            "open_ports": f["open_ports"], "note": "surface classification"}


def _probe_port_facts(state, brain=None):
    """Local probe: summarize open ports from the surface (no scanning)."""
    return {"ports": list(state.surface.get("ports") or []),
            "note": "derived from known surface; no active scanning"}


def _probe_tech_fingerprint(state, brain=None):
    """Local probe: echo known techs; engine enum refines this later."""
    return {"techs": list(state.surface.get("techs") or []),
            "note": "tech fingerprint placeholder from surface"}


def _recon_dns_passive(state, brain=None):
    """Passive recon: hostname facts already collected (no live DNS)."""
    return {"hosts": list(state.surface.get("hosts") or []),
            "note": "passive hostname inventory"}


def _recon_http_meta(state, brain=None):
    """Passive recon: URL inventory from the surface (no live requests)."""
    return {"urls": list(state.surface.get("urls") or []),
            "note": "passive URL inventory"}


def _enum_url_discover(state, brain=None):
    """Enum: URLs discovered by the engine enum stage (cached slice)."""
    eng = brain.ensure_pipeline(state)
    out = (eng.get("stage_results") or {}).get("enum") or {}
    return {"urls": out.get("urls") or out.get("endpoints") or []}


def _enum_tech_stack(state, brain=None):
    """Enum: technology list from the engine enum stage (cached slice)."""
    eng = brain.ensure_pipeline(state)
    out = (eng.get("stage_results") or {}).get("enum") or {}
    return {"techs": out.get("techs") or out.get("technologies") or []}


def _native_enum_fn(state, brain=None):
    """Run omega.adapters.native.run_native_suite (polyglot adapters).

    Contained: gate-closed / missing pieces degrade to a note, never an
    exception (the brain loop would contain it anyway).
    """
    if os.environ.get("PTK_POLYGLOT") != "1":
        return {"note": "native adapter gate closed: run with --polyglot "
                        "(PTK_POLYGLOT=1) to enable native tools"}
    try:
        from omega.adapters import native
    except ImportError:
        return {"note": "omega.adapters.native.run_native_suite not "
                        "available; skipped gracefully"}
    out = native.run_native_suite(
        state.target,
        ["portspeed", "htsweep", "jsanalyze"],
        budget=6,
        log=getattr(brain, "log", None)) or {}
    res = {"findings": out.get("findings") or [],
           "note": f"native adapters ran: {out.get('ran') or []}"}
    surf = out.get("surface") or {}
    for k in ("hosts", "urls", "ports", "techs"):
        if surf.get(k):
            res[k] = surf[k]
    return res


def _system_tool_fn(tool_id, stage, note_fmt):
    """Build a single-tool run_system_suite wrapper (read-only).

    Contained like the other system-tool capabilities: gate-closed or
    not-applicable degrade to a note dict, never an exception.
    """
    def fn(state, brain=None):
        try:
            from omega.adapters.system_tools import run_system_suite
        except ImportError:
            return {"note": "omega.adapters.system_tools not available; "
                            "skipped gracefully"}
        if os.environ.get("PTK_POLYGLOT") != "1":
            return {"note": f"system tool gate closed: run with --polyglot "
                            f"(PTK_POLYGLOT=1) to enable {tool_id}"}
        out = run_system_suite(state.target, stages=(stage,),
                               allowlist=[tool_id], budget=1,
                               log=getattr(brain, "log", None))
        res = {"findings": out["findings"],
               "note": note_fmt.format(ran=out["ran"],
                                       skipped=[s["tool"]
                                                for s in out["skipped"]])}
        surf = out["surface"]
        for k in ("hosts", "urls", "ports", "techs"):
            if surf.get(k):
                res[k] = surf[k]
        return res
    fn.__doc__ = (f"Run the '{tool_id}' read-only system tool once "
                  "(single-tool run_system_suite slice).")
    return fn


_katana_fn = _system_tool_fn(
    "katana_crawl", "enum",
    "katana crawl: ran {ran}; skipped: {skipped}")
_crlf_fn = _system_tool_fn(
    "crlfuzz_scan", "enum",
    "CRLF fuzz: ran {ran}; skipped: {skipped}")
_jwt_fn = _system_tool_fn(
    "jwt_decode", "verify",
    "JWT decode-only: ran {ran}; skipped: {skipped}")


def _system_enum_fn(state, brain=None):
    """Run omega.adapters.system_tools.run_system_suite (read-only
    system binaries: nmap/ffuf/nuclei/subfinder/amass/httpx/openssl)."""
    try:
        from omega.adapters.system_tools import run_system_suite
    except ImportError:
        return {"note": "omega.adapters.system_tools.run_system_suite "
                        "not available; skipped gracefully"}
    if os.environ.get("PTK_POLYGLOT") != "1":
        return {"note": "system tool gate closed: run with --polyglot "
                        "(PTK_POLYGLOT=1) to enable system binaries"}
    out = run_system_suite(
        state.target, stages=("recon", "enum", "verify"), budget=8,
        log=getattr(brain, "log", None))
    res = {"findings": out["findings"],
           "note": f"system tools ran: {out['ran']}; "
                   f"skipped: {[s['tool'] for s in out['skipped']]}"}
    surf = out["surface"]
    for k in ("hosts", "urls", "ports", "techs"):
        if surf.get(k):
            res[k] = surf[k]
    return res


def _fusion_all_fn(state, brain=None):
    """Run the omega.fusion FUSION engine (all-language cross-scan).

    Contained like the other adapter capabilities: fusion itself handles
    per-suite gates and missing-language degradation, so no
    PTK_POLYGLOT requirement here; any residual error becomes a note.
    """
    try:
        from omega.fusion import fuse
    except ImportError:
        return {"note": "omega.fusion.fuse not available; skipped gracefully"}
    out = fuse(state.target, budget=8,
               log=getattr(brain, "log", None),
               followup=os.environ.get("OMEGA_FOLLOWUP") == "1") or {}
    res = {"findings": out.get("findings") or [],
           "note": f"fusion ran: {out.get('ran') or []}; "
                   f"languages: {out.get('languages_used') or []}; "
                   f"corroborated: {len(out.get('corroborated') or [])}"}
    surf = out.get("surface") or {}
    for k in ("hosts", "urls", "ports", "techs"):
        if surf.get(k):
            res[k] = surf[k]
    return res


def _deepchecks_all_fn(state, brain=None):
    """Run the omega.deepchecks read-only evidence army (15 checks).

    Contained like the other adapter capabilities: any residual error
    becomes a note, never an exception.
    """
    try:
        from omega.deepchecks import run_deepchecks
    except ImportError:
        return {"note": "omega.deepchecks.run_deepchecks not available; "
                        "skipped gracefully"}
    out = run_deepchecks(state.target, budget=8,
                         log=getattr(brain, "log", None)) or {}
    res = {"findings": out.get("findings") or [],
           "note": f"deepchecks ran: {out.get('ran') or []}; "
                   f"skipped: {sorted(out.get('skipped') or [])}"}
    return res


def _oob_blind_scan_fn(state, brain=None):
    """Run omega.oobchecks against the target with a local OOB server.

    Starts an OOBCallbackServer (127.0.0.1, ephemeral port) inside this
    capability, always stops it in a finally block. Duplicate-guarded:
    reuses a still-running server from a previous invocation instead of
    starting a second one. ImportError-contained like the other
    adapter capabilities.
    """
    try:
        from omega import oobchecks
        from omega.oob import OOBCallbackServer
    except ImportError:
        return {"note": "omega.oob/oobchecks not available; "
                        "skipped gracefully"}
    server = getattr(_oob_blind_scan_fn, "_server", None)
    owns_server = False
    if not getattr(server, "running", False):
        server = OOBCallbackServer()
        try:
            server.start()
        except Exception as exc:
            return {"note": "could not start local OOB server: %s" % exc}
        owns_server = True
        _oob_blind_scan_fn._server = server
    try:
        out = oobchecks.run_oobchecks(
            state.target, server=server, wait_s=2.0,
            log=getattr(brain, "log", None)) or {}
    finally:
        if owns_server:
            server.stop()
            _oob_blind_scan_fn._server = None
    res = {"findings": out.get("findings") or [],
           "note": f"oobchecks ran: {out.get('ran') or []}; "
                   f"skipped: {sorted(out.get('skipped') or {})}; "
                   f"hits: {len(out.get('hits') or [])}"}
    return res


_oob_blind_scan_fn._server = None


def _browser_scan_fn(state, brain=None):
    """Headless-browser DOM scan (Playwright) — fully contained.

    A missing browser, closed allowlist or scan failure degrades to a
    note dict; no exception escapes.
    """
    try:
        from omega.browser import run_browser_suite
    except ImportError:
        return {"note": "omega.browser not available; skipped gracefully"}
    out = run_browser_suite(
        state.target, budget=5, log=getattr(brain, "log", None),
        allowlist=getattr(brain, "allowlist", None)) or {}
    res = {"findings": out.get("findings") or [],
           "note": f"browser scan ran: {out.get('ran') or []}; "
                   f"skipped: {sorted((out.get('skipped') or {}).keys())}"}
    surf = out.get("surface") or {}
    for k in ("hosts", "urls", "ports", "techs"):
        if surf.get(k):
            res[k] = surf[k]
    return res


def _report_markdown(state, brain=None):
    """Render the final brain report (see render_brain_report)."""
    return {"markdown": render_brain_report(state)}


def _report_timeline(state, brain=None):
    """Report capability: the decision timeline as structured rows."""
    return {"timeline": state.timeline()}


def _optional_probe_fn(module_name, attr):
    """Build a lazy loader for an omega-local probe module.

    If omega.<module>.<attr> exists, call it; otherwise return an empty
    result so the capability degrades gracefully instead of failing.
    """
    def fn(state, brain=None):
        try:
            mod = importlib.import_module(f"omega.{module_name}")
            fn_obj = getattr(mod, attr)
        except (ImportError, AttributeError):
            return {"note": f"omega.{module_name}.{attr} not available; "
                            "skipped gracefully"}
        return fn_obj(state) or {}
    fn.__doc__ = f"Lazily invoke omega.{module_name}.{attr} if present."
    return fn


def default_registry():
    """Build the seed registry: >=15 capabilities wired to real ENGINE
    engine pieces plus omega-local probes."""
    reg = CapabilityRegistry()

    # -- engine engagement stages (kind=stage) -----------------------------
    reg.register(Capability(
        "stage.recon", "stage", _engine_stage_fn("recon"),
        cost=2, risk="passive", requires=(),
        description="ENGINE passive recon stage"))
    reg.register(Capability(
        "stage.external", "stage", _engine_stage_fn("external"),
        cost=2, risk="active", requires=("recon_done",),
        description="ENGINE external-surface stage"))
    reg.register(Capability(
        "stage.enum", "stage", _engine_stage_fn("enum"),
        cost=3, risk="active", requires=("has_web",),
        description="ENGINE enumeration stage (web surface)"))
    reg.register(Capability(
        "stage.verify", "stage", _engine_stage_fn("exploit-verify"),
        cost=3, risk="active", requires=("findings",),
        description="ENGINE exploit-verify stage (non-destructive)"))
    reg.register(Capability(
        "stage.triage", "stage", _engine_stage_fn("triage"),
        cost=1, risk="passive", requires=("findings",),
        description="ENGINE triage stage"))
    reg.register(Capability(
        "stage.chain", "stage", _engine_stage_fn("chain"),
        cost=1, risk="planning-only", requires=("findings_high",),
        description="ENGINE chain PLANNING (never executed by the brain)"))
    reg.register(Capability(
        "stage.runbook", "stage", _engine_stage_fn("runbook"),
        cost=1, risk="planning-only", requires=("findings_confirmed",),
        description="ENGINE runbook stage for confirmed findings"))
    reg.register(Capability(
        "stage.report", "stage", _engine_stage_fn("report"),
        cost=1, risk="planning-only", requires=(),
        description="ENGINE report stage (engine markdown)"))

    # -- omega-local probes (kind=probe) ------------------------------------
    reg.register(Capability(
        "probe.target_parse", "probe", _probe_target_parse,
        cost=0, risk="passive",
        description="parse target string into hosts/urls/ports"))
    reg.register(Capability(
        "probe.surface_classify", "probe", _probe_surface_classify,
        cost=0, risk="passive",
        description="classify surface: web/dns/ports"))
    reg.register(Capability(
        "probe.port_facts", "probe", _probe_port_facts,
        cost=0, risk="passive",
        description="summarize known open ports (no scanning)"))
    reg.register(Capability(
        "probe.tech_fingerprint", "probe", _probe_tech_fingerprint,
        cost=0, risk="passive",
        description="echo known technologies from surface"))
    reg.register(Capability(
        "probe.pytools", "probe",
        _optional_probe_fn("pytools", "run_probe"),
        cost=0, risk="passive",
        description="optional omega.pytools.run_probe (lazy, optional)"))
    reg.register(Capability(
        "probe.custom", "probe",
        _optional_probe_fn("probes", "run"),
        cost=0, risk="passive",
        description="optional omega.probes.run (lazy, optional)"))

    reg.register(Capability(
        "ai.chainreco", "probe", _ai_chainreco_fn,
        cost=0, risk="passive", requires=("findings",),
        description="CHAIN RECOMMENDER (planning only): deterministic, "
                    "evidence-grounded exploit-chain recommendations "
                    "from the session findings via "
                    "omega.core.chainreco.recommend; emits CLI "
                    "suggestions only, never executes anything, and "
                    "produces no findings by itself"))

    # -- recon / enum / report extras ---------------------------------------
    reg.register(Capability(
        "recon.dns_passive", "recon", _recon_dns_passive,
        cost=1, risk="passive",
        description="passive hostname inventory"))
    reg.register(Capability(
        "recon.http_meta", "recon", _recon_http_meta,
        cost=1, risk="passive", requires=("has_web",),
        description="passive URL inventory"))
    reg.register(Capability(
        "enum.url_discover", "enum", _enum_url_discover,
        cost=2, risk="active", requires=("has_web",),
        description="URLs from the engine enum stage"))
    reg.register(Capability(
        "enum.tech_stack", "enum", _enum_tech_stack,
        cost=2, risk="active", requires=("has_web",),
        description="technologies from the engine enum stage"))
    reg.register(Capability(
        "report.markdown", "report", _report_markdown,
        cost=0, risk="planning-only",
        description="final brain markdown report"))
    reg.register(Capability(
        "report.timeline", "report", _report_timeline,
        cost=0, risk="planning-only",
        description="structured decision timeline"))

    # -- polyglot adapter capabilities (additive, guarded against a
    #    registry that already carries them) ------------------------------
    if reg.get("recon.native_enum") is None:
        reg.register(Capability(
            "recon.native_enum", "recon", _native_enum_fn,
            cost=1, risk="passive", requires=("has_dns",),
            description="polyglot native adapters (Go/Node) via "
                        "omega.adapters.native.run_native_suite; "
                        "gated on PTK_POLYGLOT=1"))
    if reg.get("enum.system_tools") is None:
        reg.register(Capability(
            "enum.system_tools", "enum", _system_enum_fn,
            cost=3, risk="active", requires=("has_dns",),
            description="read-only system binaries (nmap/ffuf/nuclei/"
                        "subfinder/amass/httpx/openssl) via "
                        "omega.adapters.system_tools.run_system_suite; "
                        "gated on PTK_POLYGLOT=1"))
    if reg.get("enum.katana_crawl") is None:
        reg.register(Capability(
            "enum.katana_crawl", "enum", _katana_fn,
            cost=2, risk="active", requires=("has_web",),
            description="read-only katana crawl (depth 2, 10 workers, "
                        "rate-limited) via omega.adapters.system_tools; "
                        "gated on PTK_POLYGLOT=1"))
    if reg.get("enum.crlf_fuzz") is None:
        reg.register(Capability(
            "enum.crlf_fuzz", "enum", _crlf_fn,
            cost=2, risk="active", requires=("has_web",),
            description="GET-only CRLF fuzz (crlfuzz, 10 concurrent, "
                        "stdout) via omega.adapters.system_tools; "
                        "gated on PTK_POLYGLOT=1"))
    if reg.get("verify.jwt") is None:
        reg.register(Capability(
            "verify.jwt", "enum", _jwt_fn,
            cost=1, risk="passive", requires=("has_jwt",),
            description="decode-only JWT inspection (jwt_tool on "
                        "OMEGA_JWT) once findings reference a JWT; "
                        "requires PTK_POLYGLOT=1"))

    if reg.get("fusion.all") is None:
        reg.register(Capability(
            "fusion.all", "enum", _fusion_all_fn,
            cost=5, risk="active", requires=("has_web",),
            description="FUSION engine: concurrent multi-scanner, "
                        "multi-language scan (python/go+node/perl/jq/"
                        "system) with cross-corroboration via "
                        "omega.fusion.fuse; per-suite gates handled "
                        "internally"))
    if reg.get("deepchecks.all") is None:
        reg.register(Capability(
            "deepchecks.all", "enum", _deepchecks_all_fn,
            cost=4, risk="active", requires=("has_web",),
            description="DEEP-CHECKS: 15 read-only evidence-collection "
                        "checks (traversal canary, reflection "
                        "differentials, SQL error signatures, cache "
                        "poisoning, graphql safe reads, JWT weak-secret "
                        "verify, IDOR heuristic, discovery, takeover "
                        "hints, rate-limit, buckets) via "
                        "omega.deepchecks.run_deepchecks"))

    if reg.get("oob.blind_scan") is None:
        reg.register(Capability(
            "oob.blind_scan", "enum", _oob_blind_scan_fn,
            cost=4, risk="active", requires=("has_web",),
            description="OOB BLIND-SCAN: self-hosted out-of-band callback "
                        "server (127.0.0.1, ephemeral port, unique 32-hex "
                        "tokens) + blind SSRF/XSS-candidate/RCE-callback/"
                        "webhook checks via omega.oobchecks.run_oobchecks; "
                        "records callbacks only, no command execution"))

    if reg.get("browser.scan") is None:
        reg.register(Capability(
            "browser.scan", "probe", _browser_scan_fn,
            cost=5, risk="active", requires=("has_web",),
            description="headless-browser scan (Playwright chromium): "
                        "DOM-XSS sink instrumentation with marker "
                        "differential, SPA route discovery, console "
                        "errors, postMessage audit, web-storage "
                        "secrets, fetch/XHR endpoints via "
                        "omega.browser.run_browser_suite; degrades to "
                        "a contained skip when chromium is missing"))

    return reg


# Module-level default registry (immutable-by-convention).
DEFAULT_REGISTRY = default_registry()

# Current Brain for capability fns that need loop services without a
# direct handle (kept tiny and reset every step).
_BRAIN_CONTEXT = [None]


# --------------------------------------------------------------------------
# decide() — pure, deterministic
# --------------------------------------------------------------------------

def decide(state, registry=None):
    """Pick the next capability id for `state`, or None when done.

    Pure and deterministic given (state, registry). Rule order:
      1. no recon done            -> cheapest eligible recon/stage
      2. surface has web          -> enum (kind enum or stage)
      3. untriaged findings       -> triage
      4. high findings            -> chain planning (planning-only)
      5. CONFIRMED findings       -> runbook (planning-only)
      6. otherwise                -> report
    Eligible candidates are tie-broken by (cost, id) and capped by
    budget_remaining; if nothing affordable matches the active rule,
    decide() returns None (budget stop / done).
    """
    reg = registry or DEFAULT_REGISTRY
    f = state.facts()

    # Rule -> (name, candidate kinds, extra required facts, active,
    #          preferred capability id or None)
    rules = [
        ("recon", ("stage", "recon"), (), not f["recon_done"], None),
        ("enum", ("enum", "stage"), ("has_web",),
         f["has_web"] and not f["enum_done"], None),
        ("triage", ("stage",), (), f["findings_untriaged"], "stage.triage"),
        ("chain", ("stage",), ("findings_high",),
         f["findings_high"] and not f["chain_planned"], "stage.chain"),
        ("runbook", ("stage",), ("findings_confirmed",),
         f["findings_confirmed"] and not f["runbook_done"],
         "stage.runbook"),
        ("report", ("report", "stage"), (), True, "report.markdown"),
    ]

    # Rule 0: if we know nothing at all about the surface yet, prefer
    # the cheapest eligible probe (deterministic bootstrap).
    if not f["recon_done"] and not state.surface.get("hosts"):
        probes = [c for c in reg.eligible(f, state.budget_remaining)
                  if c.kind == "probe" and c.id not in state.stage_results]
        if probes:
            for p in probes:  # deterministic: target-parse first if present
                if p.id == "probe.target_parse":
                    return p.id
            return probes[0].id

    for _name, kinds, extra_reqs, active, preferred in rules:
        if not active:
            continue
        reqs = set(extra_reqs)
        cands = []
        for cap in reg.eligible(f, state.budget_remaining):
            if cap.kind not in kinds:
                continue
            if cap.id in state.stage_results and cap.kind != "report":
                continue  # already executed this run
            if reqs and not reqs & set(cap.requires):
                continue
            cands.append(cap)
        if preferred:
            pref = reg.get(preferred)
            if pref in cands:
                return pref.id
        if cands:
            return sorted(cands, key=lambda c: (c.cost, c.id))[0].id
        return None  # active rule has no affordable candidate: stop

    return None


# --------------------------------------------------------------------------
# Brain — the autonomous loop
# --------------------------------------------------------------------------

class Brain:
    """Autonomous, budgeted, scope-gated engagement loop."""

    def __init__(self, registry=None, engine_runner=None, budget=100,
                 log=None):
        self.registry = registry or DEFAULT_REGISTRY
        self.engine_runner = engine_runner or self._default_engine_runner
        self.budget = int(budget)
        self.scope_ack = None
        self.log = log or (lambda msg: None)
        self._eng_cache = None

    # -- engine access ------------------------------------------------------

    def _default_engine_runner(self, target, mode, scope_ack,
                               budget=None, cancel=None, log=None):
        """Thin wrapper around the real engine."""
        engagement, _toolbridge = cli.load_engine()
        return engagement.run_engagement(
            target, mode=mode, scope_ack=scope_ack,
            budget=budget, cancel=cancel, log=log)

    def ensure_pipeline(self, state):
        """Run (once) and cache the engine auto pipeline for this target."""
        if self._eng_cache is None:
            self.log(f"[brain] running engine pipeline for {state.target!r}")
            self._eng_cache = self.engine_runner(
                state.target, state.mode, self.scope_ack,
                cancel=lambda: state.cancelled, log=self.log)
            state.engine = self._eng_cache
            for ch in (self._eng_cache.get("chains_planned") or []):
                if ch not in state.chains_planned:
                    state.chains_planned.append(ch)
            for stage, out in (self._eng_cache.get("stage_results")
                               or {}).items():
                if stage not in state.stage_results:
                    state.update_from_stage(stage, out)
            if not state.stage_results.get("recon") and \
                    not state.stage_results.get("external"):
                # engine produced no recon slice; keep facts from target
                state.update_from_stage("recon", _probe_target_parse(state))
        return self._eng_cache

    # -- the loop -------------------------------------------------------------

    def run(self, target, mode="auto", scope_ack=None, max_steps=25,
            cancel=None):
        """Run the autonomous loop. Returns (BrainState, report_markdown).

        scope_ack must be True or SCOPE_ACK_TEXT — identical contract to
        the engine; anything else raises PermissionError before any work.
        """
        if scope_ack is not True and scope_ack != SCOPE_ACK_TEXT:
            raise PermissionError(
                "scope acknowledgment required: pass "
                f"scope_ack='{SCOPE_ACK_TEXT}' (or True) to confirm "
                "you are authorized to test this target")
        self.scope_ack = scope_ack
        self._eng_cache = None
        state = BrainState(target, mode=mode, budget=self.budget)
        _BRAIN_CONTEXT[0] = self

        while state.steps < max_steps:
            # cancel check (a broken cancel callable must not crash us)
            if cancel is not None:
                try:
                    if cancel():
                        state.cancelled = True
                        self.log("[brain] cancel requested — stopping")
                        break
                except Exception:
                    pass

            cap_id = decide(state, self.registry)
            if cap_id is None:
                self.log("[brain] decide() returned None — stopping")
                break

            if state.budget_remaining <= 0:
                self.log("[brain] budget exhausted — stopping")
                break

            cap = self.registry.get(cap_id)
            if cap is None:
                state.record_failure(cap_id,
                                     RuntimeError("capability vanished"))
                break

            if cap.cost > state.budget_remaining:
                self.log(f"[brain] budget exhausted for {cap_id} "
                         f"(cost {cap.cost} > {state.budget_remaining})")
                break

            state.steps += 1
            state.budget_remaining -= cap.cost
            self.log(f"[brain] step {state.steps}: {cap_id} "
                     f"(cost {cap.cost}, remaining {state.budget_remaining})")
            try:
                result = cap.fn(state, self)
                state.update_from_stage(cap_id, result or {})
            except Exception as exc:  # contained: never escapes the loop
                self.log(f"[brain] capability {cap_id} failed: {exc}")
                state.record_failure(cap_id, exc)
                # mark a synthetic stage result so decide() can progress
                state.stage_results.setdefault(cap_id, {"error": str(exc)})

            if state.cancelled:
                break
            if cap.kind == "report":
                self.log("[brain] report rendered — loop complete")
                break

        report = render_brain_report(state)
        _BRAIN_CONTEXT[0] = None
        return state, report


# --------------------------------------------------------------------------
# Report rendering
# --------------------------------------------------------------------------

def render_brain_report(state):
    """Markdown brain report: decision timeline, findings summary,
    chains planned (not executed), next steps. English."""
    f = state.facts()
    lines = []
    lines.append("# OMEGA brain report")
    lines.append("")
    lines.append(f"- **Target:** `{state.target}`")
    lines.append(f"- **Mode:** {state.mode}")
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    lines.append(f"- **Generated:** {ts}")
    lines.append(f"- **Steps taken:** {state.steps}")
    lines.append(f"- **Budget remaining:** {state.budget_remaining}")
    lines.append(f"- **Cancelled:** {'yes' if state.cancelled else 'no'}")
    lines.append("")

    lines.append("## Decision timeline")
    lines.append("")
    lines.append("| step | capability | result | new-facts |")
    lines.append("|------|------------|--------|-----------|")
    for h in state.history:
        detail = str(h.get("detail") or "").replace("|", "\\|")
        result = h["result"]
        if detail:
            result += f" ({detail})"
        lines.append(f"| {h['step']} | {h['capability']} | {result} "
                     f"| {h['new_facts']} |")
    if not state.history:
        lines.append("| — | (no steps executed) | — | 0 |")
    lines.append("")

    lines.append("## Surface")
    lines.append("")
    lines.append(f"- hosts: {len(state.surface.get('hosts') or [])}, "
                 f"urls: {len(state.surface.get('urls') or [])}, "
                 f"ports: {len(state.surface.get('ports') or [])}, "
                 f"techs: {len(state.surface.get('techs') or [])}")
    lines.append("")

    lines.append("## Findings summary")
    lines.append("")
    if state.findings:
        high = sum(1 for x in state.findings if _finding_is_high(x))
        confirmed = sum(1 for x in state.findings
                        if _finding_is_confirmed(x))
        lines.append(f"- total: {len(state.findings)} "
                     f"(high/critical: {high}, confirmed: {confirmed})")
        for x in state.findings[:10]:
            if isinstance(x, dict):
                title = x.get("title") or x.get("name") or repr(x)
                sev = x.get("severity", "?")
                lines.append(f"  - [{sev}] {title}")
            else:
                lines.append(f"  - {x}")
    else:
        lines.append("- no findings recorded")
    lines.append("")

    lines.append("## Chains planned (not executed)")
    lines.append("")
    if state.chains_planned:
        for ch in state.chains_planned:
            lines.append(f"- {ch}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("> The brain never executes chains; they are reported "
                 "for operator review only.")
    lines.append("")

    lines.append("## Next steps")
    lines.append("")
    nxt = decide(state)
    if state.cancelled:
        lines.append("- run was cancelled by the operator; re-run to "
                     "resume from this state")
    elif nxt is None:
        lines.append("- nothing further to do: either the engagement is "
                     "complete or the budget is exhausted")
    else:
        lines.append(f"- next suggested capability: `{nxt}`")
        lines.append("- review planned chains manually before any "
                     "manual execution")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Authenticated-scanning capabilities (appended; duplicate-id-guarded,
# ImportError-contained — see omega/auth.py + omega/authchecks.py).
# ---------------------------------------------------------------------------

def _auth_session_scan_fn(state, brain=None):
    """Run omega.authchecks.run_authchecks with OMEGA_CREDS.

    Contained: no credentials (OMEGA_CREDS absent) degrades to a note,
    missing module degrades to a note, never an exception. One
    credential, one login attempt — no brute force.
    """
    try:
        from omega.authchecks import run_authchecks
    except ImportError:
        return {"note": "omega.authchecks.run_authchecks not available; "
                        "skipped gracefully"}
    creds = os.environ.get("OMEGA_CREDS")
    if not creds:
        return {"note": "no credentials provided (OMEGA_CREDS); "
                        "authenticated scan skipped"}
    path_info = {"paths": []}
    try:
        path_info = _auth_paths_from_state(state)
    except Exception:
        path_info = {"paths": []}
    out = run_authchecks(state.target, creds=creds,
                         budget=6,
                         log=getattr(brain, "log", None),
                         path_info=path_info) or {}
    res = {"findings": out.get("findings") or [],
           "auth_state": out.get("auth_state") or {},
           "note": "authchecks ran: %s; skipped: %s" % (
               out.get("ran") or [], sorted(out.get("skipped") or {}))}
    return res


def _auth_paths_from_state(state):
    """Build a path_info dict from discovered surface URLs (paths only)."""
    import urllib.parse as _up
    paths = []
    for u in (state.surface.get("urls") or []):
        try:
            p = _up.urlparse(str(u)).path
        except ValueError:
            continue
        if p and p != "/" and p not in paths:
            paths.append(p)
    return {"paths": paths}


def _auth_unauth_diff_fn(state, brain=None):
    """Anonymous-only authz_bypass_diff over /api/* style paths.

    Runs ONLY the anonymous differential (no credentials are read or
    used); any error degrades to a note.
    """
    try:
        from omega.authchecks import anon_api_diff, _api_paths
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.authchecks not available; skipped "
                        "gracefully"}
    path_info = _auth_paths_from_state(state)
    paths = _api_paths(path_info)
    findings = []
    try:
        findings = anon_api_diff(state.target, default_fetch,
                                 path_info=path_info) or []
    except Exception as exc:
        return {"note": "auth.unauth_diff differential failed: %s" % exc}
    return {"findings": findings,
            "note": "anonymous authz differential over %d /api/* "
                    "path(s): %s" % (len(paths), paths)}


def _register_auth_capabilities(reg):
    """Append-only, duplicate-id-guarded registration of the auth layer."""
    if reg.get("auth.session_scan") is None:
        reg.register(Capability(
            "auth.session_scan", "enum", _auth_session_scan_fn,
            cost=4, risk="active", requires=("has_web",),
            description="AUTHENTICATED scan: logs in ONCE with the "
                        "OMEGA_CREDS credential (never retries, no "
                        "brute force) and runs the six omega.authchecks "
                        "(authz bypass differential, role probe, "
                        "session-cookie flag audit, JWT decode-only "
                        "scan, CSRF audit, authenticated IDOR); "
                        "degrades to a note when OMEGA_CREDS is absent"))
    if reg.get("auth.unauth_diff") is None:
        reg.register(Capability(
            "auth.unauth_diff", "enum", _auth_unauth_diff_fn,
            cost=2, risk="active", requires=("has_web",),
            description="anonymous-only authorization differential: "
                        "compares /api/* style paths (from path_info) "
                        "without any session; no credentials involved"))


_register_auth_capabilities(DEFAULT_REGISTRY)


# ---------------------------------------------------------------------------
# Chaos behavioral mutation fuzzer capability (appended; duplicate-id-guarded,
# ImportError-contained — see omega/chaos.py).
# ---------------------------------------------------------------------------

def _chaos_fuzz_fn(state, brain=None):
    """Run omega.chaos.run_chaos (behavioral parameter-value mutation
    fuzzing with differential anomaly detection and wildcard-cluster
    soft-404 suppression).

    Contained like the other adapter capabilities: a missing module or
    any residual error degrades to a note, never an exception.
    """
    try:
        from omega.chaos import run_chaos
    except ImportError:
        return {"note": "omega.chaos.run_chaos not available; "
                        "skipped gracefully"}
    out = run_chaos(state.target,
                    log=getattr(brain, "log", None),
                    allowlist=getattr(brain, "allowlist", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "chaos fuzz ran: %s; skipped: %s; %d finding(s)"
                    % (out.get("ran") or [],
                       sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


if DEFAULT_REGISTRY.get("chaos.fuzz") is None:
    DEFAULT_REGISTRY.register(Capability(
        "chaos.fuzz", "enum", _chaos_fuzz_fn,
        cost=5, risk="active", requires=("has_web",),
        description="CHAOS FUZZ: behavioral parameter-value mutation "
                    "fuzzer (40+ pure string/semantic mutators: case "
                    "flips, double URL-encode, null bytes, unicode "
                    "confusables, comment injection, whitespace/CRLF, "
                    "negative/large/float numbers, JSON type confusion, "
                    "param pollution, long strings, inert format-string "
                    "and template markers) with differential anomaly "
                    "detection (status/length/error-signature/"
                    "reflection/timing vs baseline), rate-capped "
                    "budget, and ResponseCluster soft-404 wildcard "
                    "suppression via omega.chaos.run_chaos; "
                    "evidence-only candidates, never auto-confirmed"))


# ---------------------------------------------------------------------------
# API-spec intel, GraphQL deep checks, payload matrix, CVE xref and race
# probe capabilities (appended; duplicate-id-guarded, ImportError-contained
# — see omega/apiintel.py, omega/graphqldeep.py, omega/payloadmatrix.py,
# omega/cvexref.py, omega/racecheck.py).
# ---------------------------------------------------------------------------

def _apiintel_spec_fn(state, brain=None):
    """Run omega.apiintel.run_apiintel (spec discovery + intel).

    Contained like the other adapter capabilities: a missing module or
    any residual error degrades to a note, never an exception.
    """
    try:
        from omega.apiintel import run_apiintel
    except ImportError:
        return {"note": "omega.apiintel.run_apiintel not available; "
                        "skipped gracefully"}
    out = run_apiintel(state.target,
                       log=getattr(brain, "log", None),
                       allowlist=getattr(brain, "allowlist", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "apiintel ran: %s; %d spec(s), %d finding(s)"
                    % (out.get("ran") or [], len(out.get("specs") or []),
                       len(out.get("findings") or []))}


def _graphql_deep_fn(state, brain=None):
    """Run omega.graphqldeep.run_graphqldeep (suggestion/depth/alias/
    error-disclosure checks, GET-only, evidence-only)."""
    try:
        from omega.graphqldeep import run_graphqldeep
    except ImportError:
        return {"note": "omega.graphqldeep.run_graphqldeep not "
                        "available; skipped gracefully"}
    out = run_graphqldeep(state.target,
                          log=getattr(brain, "log", None),
                          allowlist=getattr(brain, "allowlist", None)) \
        or {}
    return {"findings": out.get("findings") or [],
            "note": "graphqldeep ran: %s; skipped: %s; %d finding(s)"
                    % (out.get("ran") or [],
                       sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _matrix_reflect_fn(state, brain=None):
    """Run omega.payloadmatrix.matrix_runner (WAF-evasion encoding
    matrix over a harmless marker). Degrades with a note when the
    marker reflects nowhere (no reflections to analyze)."""
    try:
        from omega.payloadmatrix import matrix_runner
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.payloadmatrix.matrix_runner not "
                        "available; skipped gracefully"}
    out = matrix_runner(state.target, "omega-reflect-marker",
                        default_fetch, budget=24) or {}
    findings = out.get("findings") or []
    if not findings:
        return {"findings": [],
                "note": "matrix.reflect: no surviving reflections on "
                        "this surface (nothing to analyze)"}
    return {"findings": findings,
            "note": "matrix.reflect: %d combination(s) probed, %d "
                    "surviving reflection(s)" % (out.get(
                        "requests_sent") or 0, len(findings))}


def _cap_cvefeed_fn(state, brain=None):
    """Offline CVE feed index status + enrichment of surface techs.

    Reads the compact local index built by omega.scanning.cvefeed
    (refreshed by the operator via ``omega cvefeed --feed <path>``);
    reports counts + staleness days and correlates fingerprinted techs
    against it via lookup(). Fully offline; never raises.
    """
    try:
        from omega.cvefeed import lookup, status
    except ImportError:
        return {"note": "omega.cvefeed not available; skipped gracefully"}
    st = status() or {}
    techs = list(state.surface.get("techs") or [])
    enrich = []
    for fp in techs:
        if isinstance(fp, dict):
            product = str(fp.get("product") or fp.get("name")
                          or fp.get("tech") or "")
            version = fp.get("version") or fp.get("ver")
        else:
            product, version = str(fp), None
        if not product:
            continue
        for hit in lookup(product, version):
            enrich.append({
                "product": product,
                "version": version,
                "cve": hit.get("cve_id"),
                "severity": hit.get("severity"),
                "summary": hit.get("summary"),
            })
    return {"findings": [],
            "index_status": {"entries": st.get("entries"),
                             "cves": st.get("cves"),
                             "products": st.get("products"),
                             "staleness_days": st.get("staleness_days"),
                             "present": st.get("present")},
            "enriched_cves": enrich,
            "note": "cvefeed: %s index, %s entr(ies), %s day(s) stale; "
                    "%d tech(s) matched against the local feed index"
                    % ("present" if st.get("present") else "missing",
                       st.get("entries"), st.get("staleness_days"),
                       len(enrich))}


def _cve_xref_fn(state, brain=None):
    """Run omega.cvexref.correlate over the surface techs (FULLY
    OFFLINE mini-DB; banner without a version is skipped).

    Note: BrainState.facts() defines no dedicated techs fact, so this
    capability is passive and requires no fact — it reads whatever
    techs are already in state.surface.
    """
    try:
        from omega.cvexref import correlate
    except ImportError:
        return {"note": "omega.cvexref.correlate not available; "
                        "skipped gracefully"}
    techs = list(state.surface.get("techs") or [])
    if not techs:
        return {"findings": [],
                "note": "cve.xref: no technologies fingerprinted yet"}
    out = correlate(techs) or {}
    return {"findings": out.get("findings") or [],
            "note": "cve.xref offline correlation over %d tech(s); "
                    "skipped: %s" % (len(techs),
                                     sorted(out.get("skipped") or {}))}


def _race_probe_fn(state, brain=None):
    """Run omega.racecheck.run_racecheck (GET-only, <=20 requests,
    candidate-only concurrency consistency check)."""
    try:
        from omega.racecheck import run_racecheck
    except ImportError:
        return {"note": "omega.racecheck.run_racecheck not available; "
                        "skipped gracefully"}
    out = run_racecheck(state.target, n=5,
                        log=getattr(brain, "log", None),
                        allowlist=getattr(brain, "allowlist", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "race.probe: %d request(s); %s"
                    % (out.get("requests_sent") or 0,
                       out.get("serialization") or "no result")}


def _register_batch_capabilities(reg):
    """Append-only, duplicate-id-guarded registration of the batch."""
    if reg.get("apiintel.spec") is None:
        reg.register(Capability(
            "apiintel.spec", "enum", _apiintel_spec_fn,
            cost=2, risk="active", requires=("has_web",),
            description="API-spec intel: probes common OpenAPI/Swagger "
                        "documentation paths, parses a found spec and "
                        "reports exposed specs (HIGH when authenticated "
                        "endpoints are listed), unauthenticated id-like "
                        "endpoints, /v1-vs-/v2 version drift and "
                        "sensitive response-schema fields; "
                        "evidence-only candidates"))
    if reg.get("graphql.deep") is None:
        reg.register(Capability(
            "graphql.deep", "enum", _graphql_deep_fn,
            cost=3, risk="active", requires=("has_web",),
            description="GraphQL deep checks: field-suggestion schema "
                        "leak, 5-deep query acceptance (no depth "
                        "limit), 10-alias bulk acceptance (rate-limit "
                        "bypass hint) and malformed-query error "
                        "disclosure; GET-only, evidence-only "
                        "candidates"))
    if reg.get("matrix.reflect") is None:
        reg.register(Capability(
            "matrix.reflect", "enum", _matrix_reflect_fn,
            cost=3, risk="active", requires=("has_web",),
            description="WAF-evasion encoding matrix: 12 encodings x 8 "
                        "placements of a harmless marker to see which "
                        "combinations survive server normalization "
                        "(degrades to a note when nothing reflects); "
                        "REQUIRES MANUAL WAF ANALYSIS"))
    if reg.get("cve.xref") is None:
        reg.register(Capability(
            "cve.xref", "recon", _cve_xref_fn,
            cost=1, risk="passive", requires=(),
            description="OFFLINE CVE correlation: matches already-"
                        "fingerprinted surface techs against the "
                        "bundled mini-DB of product/version-range -> "
                        "CVE ids; no network calls; banners without a "
                        "parseable version are skipped"))
    if reg.get("scanning.cvefeed") is None:
        reg.register(Capability(
            "scanning.cvefeed", "recon", _cap_cvefeed_fn,
            cost=1, risk="passive", requires=(),
            description="OFFLINE CVE feed index status: reports the "
                        "compact NVD index counts and staleness days "
                        "(scanning.cvefeed.status) and enriches "
                        "already-fingerprinted surface techs with known "
                        "CVEs from the refreshed local index; never "
                        "touches the network — the operator downloads "
                        "the feed (omega cvefeed --feed <path>)"))
    if reg.get("race.probe") is None:
        reg.register(Capability(
            "race.probe", "probe", _race_probe_fn,
            cost=2, risk="active", requires=("has_web",),
            description="Race-condition consistency check: 5 identical "
                        "concurrent GETs (hard cap 20, GET-only; "
                        "non-GET refused) diffed for inconsistent "
                        "status/body — candidate LOW only, never "
                        "confirmed"))


_register_batch_capabilities(DEFAULT_REGISTRY)


# ---------------------------------------------------------------------------
# OFFENSE layer capabilities (appended; separate gate PTK_OFFENSE=1 via
# omega/offense — explicit --offense opt-in only; duplicate-id-guarded).
# ---------------------------------------------------------------------------

def _offense_brute_fn(state, brain=None):
    """Gated brute-force capability: degrades to a note when the gate
    is closed; runs a bounded form brute only when the operator has
    supplied a wordlist via OMEGA_WORDLIST (no default list)."""
    import os
    if os.environ.get("PTK_OFFENSE") != "1":
        return {"note": "offense layer disabled (PTK_OFFENSE); run "
                        "with --offense to enable"}
    wordlist = os.environ.get("OMEGA_WORDLIST")
    if not wordlist:
        return {"note": "offense brute skipped: no OMEGA_WORDLIST "
                        "provided (no default credential list)"}
    try:
        from omega.offense.injection import run_offense_suite
    except ImportError:
        return {"note": "omega.offense not available"}
    out = run_offense_suite(state.target,
                            log=getattr(brain, "log", None),
                            allowlist=getattr(brain, "allowlist", None),
                            allow=True) or {}
    return {"findings": out.get("findings") or [],
            "note": "offense suite ran: %s; skipped: %s; %d finding(s)"
                    % (out.get("ran") or [],
                       sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _offense_inject_fn(state, brain=None):
    """Gated injection runner capability (PTK_OFFENSE gate checked
    inside omega.offense)."""
    import os
    if os.environ.get("PTK_OFFENSE") != "1":
        return {"note": "offense layer disabled (PTK_OFFENSE); run "
                        "with --offense to enable"}
    try:
        from omega.offense.injection import run_injections
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.offense not available"}
    param = None
    for f in state.findings or []:
        if isinstance(f, dict) and f.get("param"):
            param = f["param"]
            break
    out = run_injections(state.target, param or "q", default_fetch,
                         log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "injections ran on param %r; skipped: %s; "
                    "%d finding(s)" % (param or "q",
                                       sorted(out.get("skipped") or {}),
                                       len(out.get("findings") or []))}


def _offense_jwt_fn(state, brain=None):
    """Gated JWT alg=none forgery + acceptance verification."""
    import os
    if os.environ.get("PTK_OFFENSE") != "1":
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    try:
        from omega.offense.brute import jwt_none_forge
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.offense not available"}
    token = os.environ.get("OMEGA_JWT")
    if not token:
        for f in state.findings or []:
            if isinstance(f, dict) and "jwt" in str(
                    f.get("title", "")).lower():
                ev = str(f.get("evidence", ""))
                if ev.count(".") >= 2 and len(ev) > 30:
                    token = ev.split()[0].strip(".")
                    break
    if not token:
        return {"note": "no JWT available (OMEGA_JWT unset, no jwt "
                        "finding)"}
    target = state.target if "://" in state.target else \
        "http://" + state.target
    out = jwt_none_forge(token, fetch=default_fetch,
                         verify_url=target) or {}
    return {"findings": [out["finding"]] if out.get("finding") else [],
            "note": "jwt none forge: accepted=%s" % out.get("accepted")}


def _offense_stuff_fn(state, brain=None):
    """Gated credential-stuffing/spray capability (PTK_OFFENSE gate).
    Uses operator wordlists (OMEGA_USERLIST / OMEGA_PASSLIST files);
    built-in default lists only when OMEGA_STUFF_DEFAULT=1."""
    import os
    if os.environ.get("PTK_OFFENSE") != "1":
        return {"note": "offense layer disabled (PTK_OFFENSE); run "
                        "with --offense to enable"}
    try:
        from omega.offense.brute import credential_stuff
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.offense not available"}
    out = credential_stuff(
        state.target, default_fetch,
        budget=max(10, budget_left(state.target)),
        log=getattr(brain, "log", None),
        mode=os.environ.get("OMEGA_STUFF_MODE", "spray"),
        allow_default=os.environ.get("OMEGA_STUFF_DEFAULT") == "1",
        base_url=getattr(state, "base_url", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "credential stuffing (%s): tried=%s; %d finding(s)"
                    % (out.get("mode", "?"), out.get("tried"),
                       len(out.get("findings") or []))}


def _offense_fuzz_fn(state, brain=None):
    """Gated mutation-fuzzing capability (PTK_OFFENSE gate). Fuzzes
    parameters discovered during the engagement with seeded mutations."""
    import os
    if os.environ.get("PTK_OFFENSE") != "1":
        return {"note": "offense layer disabled (PTK_OFFENSE); run "
                        "with --offense to enable"}
    try:
        from omega.offense.fuzz import fuzz_params
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.offense not available"}
    params = {}
    for f in state.findings or []:
        if isinstance(f, dict) and f.get("param") and f["param"] not in params:
            params[f["param"]] = str(f.get("value") or "1")
    if not params:
        params = {"q": "1", "id": "1"}
    out = fuzz_params(state.target, default_fetch, params,
                      budget=max(10, budget_left(state.target)),
                      log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "mutation fuzz: params=%s; %d finding(s)"
                    % (sorted(params), len(out.get("findings") or []))}


def _offense_payloads_fn(state, brain=None):
    """Gated payload-arsenal capability (PTK_OFFENSE gate): polyglot,
    staged and context-aware XSS payload sets for the engagement log."""
    import os
    if os.environ.get("PTK_OFFENSE") != "1":
        return {"note": "offense layer disabled (PTK_OFFENSE); run "
                        "with --offense to enable"}
    try:
        from omega.offense.payloadgen import (polyglot_payloads,
                                              staged_payloads,
                                              context_xss_payloads)
    except ImportError:
        return {"note": "omega.offense not available"}
    poly = polyglot_payloads()
    staged = staged_payloads()
    ctx = context_xss_payloads()
    return {"findings": [],
            "note": "payload arsenal: %d polyglot, %d staged, "
                    "%d context-aware XSS (%d total)"
                    % (len(poly), len(staged), len(ctx),
                       len(poly) + len(staged) + len(ctx))}


def _offense_playbook_fn(state, brain=None):
    """PLANNING-ONLY capability: multi-stage attack playbooks.

    Produces the human-readable playbook plans plus the grounded
    prerequisite check for each registered playbook. NEVER executes a
    stage — execution happens only via
    ``omega playbook NAME --stage N --scope-ack`` with the operator's
    explicit gates.
    """
    try:
        from omega.offensive.playbook import check_prereqs, get_playbook, \
            list_playbooks, plan
    except ImportError:
        return {"note": "omega.offensive.playbook not available"}
    findings = getattr(state, "findings", None) or []
    target = getattr(state, "target", None)
    out = {"playbooks": [], "note": "playbook plans only (no execution)"}
    for name in list_playbooks():
        pb = get_playbook(name)
        pre = check_prereqs(pb, findings)
        entry = {"name": name, "prereqs_ok": pre["ok"],
                 "missing": pre["missing"],
                 "candidate_only": pre["candidate_only"],
                 "requires_no_limits": bool(
                     (pb or {}).get("requires_no_limits"))}
        if pre["ok"]:
            p = plan(name, findings, target)
            entry["stages"] = [
                {"name": s["name"], "gate": s["gate"],
                 "gate_env": s["gate_env"]}
                for s in p["stages"]]
        out["playbooks"].append(entry)
    return out


def _register_offense_capabilities(reg):
    """Append the offense capabilities (duplicate-id-guarded)."""
    if reg.get("offense.brute") is None:
        reg.register(Capability(
            "offense.brute", "enum", _offense_brute_fn,
            cost=8, risk="active", requires=("has_web",),
            description="OFFENSE (PTK_OFFENSE gate): bounded brute force "
                        "with operator wordlist only; no default list"))
    if reg.get("offense.inject") is None:
        reg.register(Capability(
            "offense.inject", "enum", _offense_inject_fn,
            cost=8, risk="active", requires=("has_web",),
            description="OFFENSE (PTK_OFFENSE gate): injection payload "
                        "runner with differential confirm (SQLi/CMDi/"
                        "SSTI/XSS/traversal)"))
    if reg.get("offense.jwt") is None:
        reg.register(Capability(
            "offense.jwt", "probe", _offense_jwt_fn,
            cost=3, risk="active", requires=("has_web",),
            description="OFFENSE (PTK_OFFENSE gate): JWT alg=none forge "
                        "and single acceptance verification"))
    if reg.get("offense.stuff") is None:
        reg.register(Capability(
            "offense.stuff", "enum", _offense_stuff_fn,
            cost=8, risk="active", requires=("has_web",),
            description="OFFENSE (PTK_OFFENSE gate): credential stuffing / "
                        "password spray with operator wordlists "
                        "(OMEGA_USERLIST/OMEGA_PASSLIST; defaults only with "
                        "OMEGA_STUFF_DEFAULT=1); lockout-aware"))
    if reg.get("offense.fuzz") is None:
        reg.register(Capability(
            "offense.fuzz", "enum", _offense_fuzz_fn,
            cost=8, risk="active", requires=("has_web",),
            description="OFFENSE (PTK_OFFENSE gate): seeded mutation "
                        "fuzzing of known parameters; crash + anomaly "
                        "differential detection"))
    if reg.get("offense.payloads") is None:
        reg.register(Capability(
            "offense.payloads", "probe", _offense_payloads_fn,
            cost=1, risk="planning-only",
            description="OFFENSE (PTK_OFFENSE gate): polyglot, staged and "
                        "context-aware XSS payload arsenal generation"))

    if reg.get("offense.playbook") is None:
        reg.register(Capability(
            "offense.playbook", "probe", _offense_playbook_fn,
            cost=2, risk="offense", requires=("findings",),
            description="ATTACK PLAYBOOKS (planning only): multi-stage "
                        "gated playbooks via omega.offensive.playbook; "
                        "emits plans + grounded prereq checks, NEVER "
                        "executes a stage (stages run only via the "
                        "explicit `omega playbook` CLI with --scope-ack)"))


_register_offense_capabilities(DEFAULT_REGISTRY)


# ---------------------------------------------------------------------------
# HYPER batch capabilities (appended; hyper-surface / header / redirect /
# OOB / jsrender / subperm suites — all read-only, differential-first).
# ---------------------------------------------------------------------------

def _cap_hyper(state, brain=None):
    try:
        from omega.hyper import run_hyper
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.hyper not available"}
    out = run_hyper(state.target, default_fetch,
                    log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "hyper surface scan: %d check(s) ran, %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_headerscan(state, brain=None):
    try:
        from omega.headerscan import run_headerscan
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.headerscan not available"}
    out = run_headerscan(state.target, default_fetch,
                         log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "header audit: %d finding(s)"
                    % len(out.get("findings") or [])}


def _cap_redirects(state, brain=None):
    try:
        from omega.redirects import run_redirects
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.redirects not available"}
    out = run_redirects(state.target, default_fetch,
                        log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "redirect audit: %d finding(s)"
                    % len(out.get("findings") or [])}


def _cap_oobscan(state, brain=None):
    try:
        from omega.oobscan import run_oobscan
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.oobscan not available"}
    out = run_oobscan(state.target, default_fetch,
                      log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "OOB blind scan: %s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _cap_jsrender(state, brain=None):
    try:
        from omega.jsrender import run_jsrender
    except ImportError:
        return {"note": "omega.jsrender not available"}
    out = run_jsrender(state.target, log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "js render scan: %s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _cap_subperm(state, brain=None):
    try:
        from omega.subperm import run_subperm
    except ImportError:
        return {"note": "omega.subperm not available"}
    host = state.target.split("://")[-1].split("/")[0].split(":")[0]
    out = run_subperm(host, log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "alive": out.get("alive") or [],
            "note": "subdomain permutation: %d alive, %d finding(s)"
                    % (len(out.get("alive") or []),
                       len(out.get("findings") or []))}


def _register_hyper_capabilities(reg):
    for cid, kind, fn, cost, desc in (
        ("hyper.surface", "enum", _cap_hyper, 4,
         "hyper surface scan: dir listing, backup/env/git artifacts, "
         "robots/sitemap intel, banners, host-header echo"),
        ("hyper.headers", "probe", _cap_headerscan, 2,
         "deep response-header audit: clickjacking, CSP/HSTS/CORS, "
         "cookie flags, banner disclosure"),
        ("hyper.redirects", "probe", _cap_redirects, 3,
         "open-redirect + redirect-chain auditor with differential "
         "confirm"),
        ("hyper.oob", "enum", _cap_oobscan, 4,
         "blind interaction scanner via local OOB callback server "
         "(SSRF evidence confirm)"),
        ("hyper.jsrender", "enum", _cap_jsrender, 5,
         "browser-rendered differential scan (Playwright): "
         "static-vs-rendered secrets, console errors, API calls"),
        ("hyper.subperm", "enum", _cap_subperm, 6,
         "DNS subdomain permutation + zone intel, wildcard FP-guard"),
    ):
        if reg.get(cid) is None:
            reg.register(Capability(cid, kind, fn, cost=cost,
                                    risk="active", requires=("has_web",),
                                    description=desc))


_register_hyper_capabilities(DEFAULT_REGISTRY)


# ---------------------------------------------------------------------------
# POLYGLOT batch-2 capabilities (gotools/node_hdr/jqdiff — all gated by
# PTK_POLYGLOT inside the runners; graceful skip when toolchain missing).
# ---------------------------------------------------------------------------

def _cap_go_dirscan(state, brain=None):
    try:
        from omega.adapters.gotools import run_dirscan
    except ImportError:
        return {"note": "omega.adapters.gotools not available"}
    paths = ["/admin", "/backup.sql", "/backup.zip", "/.env", "/.git/HEAD",
             "/phpinfo.php", "/wp-admin/", "/api", "/config.php.bak",
             "/dump.sql", "/.DS_Store", "/server-status"]
    out = run_dirscan(state.target, paths,
                      log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "go dirscan: %s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _cap_go_dnssweep(state, brain=None):
    try:
        from omega.adapters.gotools import run_dnssweep
    except ImportError:
        return {"note": "omega.adapters.gotools not available"}
    host = state.target.split("://")[-1].split("/")[0].split(":")[0]
    out = run_dnssweep(host, log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "go dnssweep: %s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _cap_node_hdrscore(state, brain=None):
    try:
        from omega.adapters.node_hdr import run_hdrscore
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.adapters.node_hdr not available"}
    out = run_hdrscore(state.target, default_fetch,
                       log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "node hdrscore: %s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _cap_jqdiff(state, brain=None):
    try:
        from omega.adapters.jqdiff import run_jqdiff
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.adapters.jqdiff not available"}
    out = run_jqdiff(state.target, default_fetch,
                     log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "jq diff: %s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _register_polyglot2_capabilities(reg):
    for cid, kind, fn, cost, desc in (
        ("polyglot.dirscan", "enum", _cap_go_dirscan, 3,
         "Go differential path scanner (compile-on-demand, gate "
         "PTK_POLYGLOT)"),
        ("polyglot.dnssweep", "enum", _cap_go_dnssweep, 4,
         "Go raw-UDP DNS subdomain sweep (compile-on-demand)"),
        ("polyglot.hdrscore", "probe", _cap_node_hdrscore, 1,
         "Node header security scorer with A-F grade (PTK_POLYGLOT)"),
        ("polyglot.jqdiff", "probe", _cap_jqdiff, 2,
         "jq differential token-leak detector, fail-closed quarantine "
         "(PTK_POLYGLOT)"),
    ):
        if reg.get(cid) is None:
            reg.register(Capability(cid, kind, fn, cost=cost,
                                    risk="active", requires=("has_web",),
                                    description=desc))


_register_polyglot2_capabilities(DEFAULT_REGISTRY)


# ---------------------------------------------------------------------------
# SCANNING batch capabilities (smuggle / hhint / ssti / deser — appended;
# differential-first, candidate-only; smuggle self-gates its Go path).
# ---------------------------------------------------------------------------

def _cap_smuggle(state, brain=None):
    try:
        from omega.smuggle import run_smuggle
    except ImportError:
        return {"note": "omega.smuggle not available"}
    out = run_smuggle(state.target, log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "smuggle safe-read differential: %s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _cap_hhint(state, brain=None):
    try:
        from omega.hhint import run_hhint
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.hhint not available"}
    out = run_hhint(state.target, default_fetch,
                    log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "host-header injection: %d check(s) ran, %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_ssti(state, brain=None):
    try:
        from omega.ssti import run_ssti
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.ssti not available"}
    out = run_ssti(state.target, default_fetch,
                   log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "ssti engine fingerprint: %d engine(s) probed, "
                    "%d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_deser(state, brain=None):
    try:
        from omega.deser import run_deser
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.deser not available"}
    out = run_deser(state.target, default_fetch,
                    log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "deser safe-signature probe: %d lang(s) probed, "
                    "%d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_uplprobe(state, brain=None):
    try:
        from omega.uplprobe import run_uplprobe
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.uplprobe not available"}
    out = run_uplprobe(state.target, default_fetch,
                       log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "upload probe: %d form(s) probed, %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_secops(state, brain=None):
    try:
        from omega.secops import run_secops
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.secops not available"}
    out = run_secops(state.target, default_fetch,
                     log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "secops hygiene: %d check(s) ran, %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_mobandroid(state, brain=None):
    try:
        from omega.scanning.mobandroid import run_android
    except ImportError:
        return {"note": "omega.scanning.mobandroid not available"}
    out = run_android(state.target) or {}
    return {"findings": out.get("findings") or [],
            "note": "android static analysis: %d check(s) ran, "
                    "%d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_mobios(state, brain=None):
    try:
        from omega.scanning.mobios import run_ios
    except ImportError:
        return {"note": "omega.scanning.mobios not available"}
    out = run_ios(state.target) or {}
    return {"findings": out.get("findings") or [],
            "note": "iOS static analysis: %d check(s) ran, %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_mobgeneral(state, brain=None):
    try:
        from omega.scanning.mobgeneral import run_mobile_general
    except ImportError:
        return {"note": "omega.scanning.mobgeneral not available"}
    out = run_mobile_general(state.target) or {}
    return {"findings": out.get("findings") or [],
            "note": "cross-platform mobile checks: %d check(s) ran, "
                    "%d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_blotamper(state, brain=None):
    try:
        from omega.blotamper import run_blotamper
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.blotamper not available"}
    out = run_blotamper(state.target, default_fetch,
                        log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "business-logic tamper heuristics: %d flow(s) "
                    "considered, %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_jsdeep(state, brain=None):
    try:
        from omega.jsdeep import run_jsdeep
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.jsdeep not available"}
    out = run_jsdeep(state.target, default_fetch) or {}
    return {"findings": out.get("findings") or [],
            "note": "js deep analysis: %d asset(s) parsed, %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_apimap(state, brain=None):
    try:
        from omega.apimap import run_apimap
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.apimap not available"}
    out = run_apimap(state.target, default_fetch) or {}
    return {"findings": out.get("findings") or [],
            "note": "api map: %d spec endpoint(s), %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_tfinger(state, brain=None):
    try:
        from omega.tfinger import run_tfinger
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.tfinger not available"}
    out = run_tfinger(state.target, default_fetch) or {}
    return {"findings": out.get("findings") or [],
            "note": "tech fingerprint: %d tech(s) identified, %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_timing(state, brain=None):
    try:
        from omega.timing import run_timing
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.timing not available"}
    out = run_timing(state.target, fetch=default_fetch,
                     log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "timing analysis: %d check(s) ran, %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_anomaly(state, brain=None):
    try:
        from omega.anomaly import run_anomaly
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.anomaly not available"}
    paths = ["/", "/login", "/api"]
    out = run_anomaly(state.target, paths, default_fetch) or {}
    return {"findings": out.get("findings") or [],
            "note": "anomaly model: %d path(s) profiled, %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_oobhunt(state, brain=None):
    try:
        from omega.oobhunt import run_oobhunt
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.oobhunt not available"}
    out = run_oobhunt(state.target, fetch=default_fetch,
                      log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "oob hunt: %d sink(s) probed, %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_dbsec(state, brain=None):
    try:
        from omega.dbsec import run_dbsec
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.dbsec not available"}
    out = run_dbsec(state.target, fetch=default_fetch, state=state,
                    log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "db backend: %d finding(s)"
                    % len(out.get("findings") or [])}


def _cap_llmsec(state, brain=None):
    try:
        from omega.llmsec import run_llmsec
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.llmsec not available"}
    out = run_llmsec(state.target, fetch=default_fetch,
                     log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "llm app: %d endpoint(s) probed, %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_cloudsec(state, brain=None):
    try:
        from omega.cloudsec import run_cloudsec
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.cloudsec not available"}
    out = run_cloudsec(state.target, fetch=default_fetch,
                       log=getattr(brain, "log", None),
                       allowlist=getattr(state, "allowlist", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "cloud exposure: %d finding(s)"
                    % len(out.get("findings") or [])}


def _cap_k8ssec(state, brain=None):
    try:
        from omega.k8ssec import run_k8ssec
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.k8ssec not available"}
    out = run_k8ssec(state.target, fetch=default_fetch,
                     log=getattr(brain, "log", None),
                     allowlist=getattr(state, "allowlist", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "k8s/container exposure: %d finding(s)"
                    % len(out.get("findings") or [])}


def _cap_cicdsec(state, brain=None):
    try:
        from omega.cicdsec import run_cicdsec
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.cicdsec not available"}
    out = run_cicdsec(target=state.target, fetch=default_fetch,
                      log=getattr(brain, "log", None),
                      allowlist=getattr(state, "allowlist", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "cicd/supply-chain: %d finding(s)"
                    % len(out.get("findings") or [])}


def _cap_request_class(name, runner_name, note):
    """Factory for request-level attack-class capabilities (wsprobe /
    corscheck / hpp / crlf)."""
    def _cap(state, brain=None):
        try:
            import importlib
            mod = importlib.import_module("omega.scanning.%s" % name)
            run = getattr(mod, runner_name)
        except ImportError:
            return {"note": "omega.scanning.%s not available" % name}
        try:
            findings = run(state.target,
                           fetch=__import__(
                               "omega.scanning.deepchecks",
                               fromlist=["default_fetch"]).default_fetch,
                           path_info=getattr(state, "path_info", None),
                           gate=False) or []
        except Exception as exc:
            return {"findings": [], "note": "%s failed: %s"
                    % (name, type(exc).__name__)}
        return {"findings": findings, "note": note % len(findings)}
    _cap.__name__ = "_cap_%s" % name
    return _cap


_cap_wsprobe = _cap_request_class(
    "wsprobe", "run_wsprobe",
    "websocket probe: %d finding(s)")
_cap_corscheck = _cap_request_class(
    "corscheck", "run_corscheck",
    "CORS matrix: %d finding(s)")
_cap_hpp = _cap_request_class(
    "hpp", "run_hpp",
    "parameter pollution/mass assignment: %d finding(s)")
_cap_crlf = _cap_request_class(
    "crlf", "run_crlf",
    "CRLF injection: %d finding(s)")
_cap_csrf = _cap_request_class(
    "csrf", "run_csrf",
    "CSRF protection analysis: %d finding(s)")
_cap_secondorder = _cap_request_class(
    "secondorder", "run_secondorder",
    "second-order (stored) injection probe: %d finding(s)")


def _cap_authbypass(state, brain=None):
    try:
        from omega.scanning.authbypass import run_authbypass
        from omega.scanning.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.scanning.authbypass not available"}
    found = run_authbypass(state.target, default_fetch) or []
    return {"findings": found,
            "note": "authbypass matrix: %d candidate(s)" % len(found)}


def _cap_resetpoison(state, brain=None):
    try:
        from omega.scanning.resetpoison import run_resetpoison
        from omega.scanning.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.scanning.resetpoison not available"}
    found = run_resetpoison(state.target, default_fetch) or []
    return {"findings": found,
            "note": "reset poisoning: %d candidate(s)" % len(found)}


def _cap_userenum(state, brain=None):
    try:
        from omega.scanning.userenum import run_userenum
        from omega.scanning.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.scanning.userenum not available"}
    found = run_userenum(state.target, default_fetch) or []
    return {"findings": found,
            "note": "user enumeration: %d candidate(s)" % len(found)}


def _cap_libcve(state, brain=None):
    try:
        from omega.scanning.libcve import run_libcve
        from omega.scanning.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.scanning.libcve not available"}
    found = run_libcve(state.target, default_fetch) or []
    return {"findings": found,
            "note": "client library CVEs: %d finding(s)" % len(found)}


def _cap_backupfiles(state, brain=None):
    try:
        from omega.scanning.backupfiles import run_backupfiles
        from omega.scanning.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.scanning.backupfiles not available"}
    found = run_backupfiles(state.target, default_fetch) or []
    return {"findings": found,
            "note": "backup/secret file sweep: %d finding(s)" % len(found)}


def _cap_cmsprobe(state, brain=None):
    try:
        from omega.scanning.cmsprobe import run_cmsprobe
        from omega.scanning.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.scanning.cmsprobe not available"}
    found = run_cmsprobe(state.target, default_fetch) or []
    return {"findings": found,
            "note": "CMS fingerprint/exposures: %d finding(s)" % len(found)}


def _cap_secretjs(state, brain=None):
    try:
        from omega.scanning.secretjs import run_secretjs
        from omega.scanning.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.scanning.secretjs not available"}
    found = run_secretjs(state.target, default_fetch) or []
    return {"findings": found,
            "note": "JS secret scan: %d finding(s)" % len(found)}


def _cap_cspanalyze(state, brain=None):
    try:
        from omega.scanning.cspanalyze import run_cspanalyze
        from omega.scanning.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.scanning.cspanalyze not available"}
    found = run_cspanalyze(state.target, default_fetch) or []
    return {"findings": found,
            "note": "CSP analysis: %d finding(s)" % len(found)}


def _cap_xxe(state, brain=None):
    try:
        from omega.scanning.xxe import run_xxe
        from omega.scanning.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.scanning.xxe not available"}
    found = run_xxe(state.target, default_fetch) or []
    return {"findings": found,
            "note": "XXE probe: %d finding(s)" % len(found)}


def _cap_ssrf(state, brain=None):
    try:
        from omega.scanning.ssrf import run_ssrf
        from omega.scanning.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.scanning.ssrf not available"}
    found = run_ssrf(state.target, default_fetch) or []
    return {"findings": found,
            "note": "SSRF probe: %d finding(s)" % len(found)}


def _cap_tlsconf(state, brain=None):
    try:
        from omega.scanning.tlsconf import run_tlsconf
        from omega.scanning.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.scanning.tlsconf not available"}
    found = run_tlsconf(state.target, default_fetch) or []
    return {"findings": found,
            "note": "TLS config scan: %d finding(s)" % len(found)}


def _cap_apidocs(state, brain=None):
    try:
        from omega.scanning.apidocs import run_apidocs
        from omega.scanning.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.scanning.apidocs not available"}
    found = run_apidocs(state.target, default_fetch) or []
    return {"findings": found,
            "note": "API spec/auth scan: %d finding(s)" % len(found)}


def _cap_mobdeep(state, brain=None):
    import os as _os
    try:
        from omega.scanning.mobdeep import analyze_apk
    except ImportError:
        return {"note": "omega.scanning.mobdeep not available"}
    apk = _os.environ.get("OMEGA_APK")
    if not apk:
        return {"note": "no APK available (set OMEGA_APK); "
                        "deep APK analysis skipped"}
    found = analyze_apk(apk) or []
    return {"findings": found,
            "note": "deep APK static analysis of %s: %d finding(s)"
                    % (apk, len(found))}


def _cap_mobapi(state, brain=None):
    try:
        from omega.scanning.mobapi import run_mobapi
        from omega.scanning.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.scanning.mobapi not available"}
    found = run_mobapi(state.target, default_fetch) or []
    return {"findings": found,
            "note": "mobile backend API checks: %d finding(s)"
                    % len(found)}



def _register_deepscan_capabilities(reg):
    """Deep-recon + behavioral capabilities (appended; active probes
    gated per-module, additive duplicate-id-guarded)."""
    for cid, kind, fn, cost, desc in (
        ("scanning.jsdeep", "probe", _cap_jsdeep, 3,
         "JavaScript bundle deep analysis (Node AST + regex fallback): "
         "endpoints, secrets, source maps, hardcoded hosts"),
        ("scanning.apimap", "probe", _cap_apimap, 4,
         "automatic API mapping: OpenAPI/Swagger parse, GraphQL "
         "introspection, live-vs-documented endpoint differential "
         "(safe methods only)"),
        ("scanning.tfinger", "probe", _cap_tfinger, 2,
         "technology fingerprinting with confidence levels and offline "
         "CVE-relevant version pins"),
        ("scanning.timing", "enum", _cap_timing, 6,
         "timing-based blind detection with median+MAD statistics and "
         "repeat confirmation (username enumeration, token existence); "
         "candidate-only"),
        ("scanning.anomaly", "enum", _cap_anomaly, 4,
         "response anomaly model: per-path baseline profile, 5xx/debug "
         "fingerprint deviations; stack traces confirmed, rest candidate"),
        ("scanning.oobhunt", "enum", _cap_oobhunt, 5,
         "out-of-band callback hunting for blind XXE/SSRF with unique "
         "per-check markers; confirmed only on observed callback; skips "
         "cleanly without OMEGA_OOB_BASE_URL"),
        ("scanning.cloudsec", "enum", _cap_cloudsec, 5,
         "cloud-native exposure: public S3/GCS/Azure bucket anonymous "
         "access, cloud-flavored secret paths, IMDSv1 via known SSRF "
         "params; confirmed only on unambiguous fingerprints"),
        ("scanning.k8ssec", "enum", _cap_k8ssec, 5,
         "Kubernetes/container exposure: unauth API server, kubelet, "
         "dashboard, Docker API (read-only), etcd; closed ports silent"),
        ("scanning.cicdsec", "enum", _cap_cicdsec, 4,
         "DevOps/supply-chain: git history secret scan, IaC plaintext "
         "secrets, dependency confusion registry lookup, exposed CI "
         "configs / Jenkins script console fingerprint"),
        ("scanning.llmsec", "enum", _cap_llmsec, 6,
         "AI/LLM application scanning: prompt injection (marker "
         "confirmation), system-prompt disclosure, PII leakage, "
         "excessive agency, RAG bypass, unbounded consumption"),
        ("scanning.dbsec", "enum", _cap_dbsec, 5,
         "database backend: exposed port fingerprint, Redis/Mongo "
         "unauth read-only checks, dangerous-feature probes via "
         "confirmed SQLi channel only; default-cred checks gated by "
         "OMEGA_NO_LIMITS"),
        ("scanning.authbypass", "enum", _cap_authbypass, 4,
         "401/403 bypass matrix: method/path-mutation/header vectors "
         "differentially compared against the baseline; HIGH "
         "candidate on 200-with-different-body; claim-gate validated"),
        ("scanning.resetpoison", "enum", _cap_resetpoison, 4,
         "password reset poisoning: benign POST probes with injected "
         "Host/X-Forwarded-Host on reset endpoints; HIGH candidate on "
         "injected host in reset-link context; token-in-URL LOW note"),
        ("scanning.userenum", "enum", _cap_userenum, 3,
         "user/email enumeration differential: fake-probe profiles on "
         "auth endpoints, response structure + timing medians; LOW/"
         "MEDIUM candidate labeled 'possible user enumeration (manual "
         "confirm)'; never brute-forces real users"),
        ("scanning.libcve", "probe", _cap_libcve, 3,
         "client library fingerprint -> offline CVE lookup: JS asset "
         "version signatures (jquery, angular 1.x, react, lodash, "
         "moment, bootstrap, vue) matched against the local cvefeed "
         "index; severity from the CVE record, verification "
         "'signature'"),
        ("scanning.backupfiles", "enum", _cap_backupfiles, 3,
         "secret and backup file sweep: bounded high-value path probe "
         "(.bak/.old/.sql/.git/.env/...) compared against a random-404 "
         "baseline; HIGH candidate on plausible content, MEDIUM on "
         "directory listings"),
        ("scanning.cmsprobe", "enum", _cap_cmsprobe, 3,
         "CMS fingerprint and known exposures: WordPress/Drupal/Joomla "
         "benign markers, wp-json user enumeration (HIGH candidate), "
         "xmlrpc, uploads listing, changelog/readme version disclosures"),
        ("scanning.secretjs", "probe", _cap_secretjs, 4,
         "secrets in JS bundles and source maps: bounded fetch of "
         "referenced assets, regex scan for AWS/Google/Slack/Stripe "
         "keys, private key blocks, JWTs, generic secret assignments; "
         "REDACTED evidence excerpts"),
        ("scanning.cspanalyze", "probe", _cap_cspanalyze, 2,
         "CSP deep analysis: parses Content-Security-Policy directives "
         "and reports unsafe-inline/eval, missing script-src, wildcard "
         "sources, permissive schemes, weak object-src/frame-ancestors "
         "and absent reporting endpoints"),
        ("scanning.xxe", "probe", _cap_xxe, 3,
         "XXE / XML injection probe: XML-accepting endpoints POSTed "
         "with benign external-entity markers (file:// marker path and "
         "an OOB hostname recorded in evidence only, never contacted); "
         "HIGH candidate on entity echo/expansion disclosure, LOW on "
         "verbose parser errors"),
        ("scanning.ssrf", "probe", _cap_ssrf, 3,
         "SSRF probe on URL-ish parameters: benign marker URLs pointing "
         "back at the scanned host itself and loopback (same-host and "
         "127.0.0.1 same-port), meta/link shapes; HIGH candidate on "
         "marker fetch detection; external hosts never targeted"),
        ("scanning.tlsconf", "probe", _cap_tlsconf, 3,
         "TLS configuration scan via openssl s_client (stdlib SSLContext "
         "fallback): certificate expiry, weak protocol negotiation "
         "(ssl3/tls1/tls1.1), weak TLS 1.2 ciphers, self-signed / "
         "hostname mismatch; plain-HTTP targets skipped with a note"),
        ("scanning.apidocs", "probe", _cap_apidocs, 2,
         "API spec discovery (/openapi.json, /swagger.json, /api-docs, "
         "...): exposed spec (MEDIUM), endpoint extraction, and up to "
         "10 discovered endpoints fetched unauthenticated; 200+JSON = "
         "MEDIUM candidate unauthenticated API endpoint"),
        ("scanning.mobdeep", "probe", _cap_mobdeep, 3,
         "deep APK static analysis: aapt/apktool when available else "
         "pure-stdlib zip fallback (heuristic); debuggable, allowBackup, "
         "exported components without permission, risky permission "
         "combos, hardcoded secrets (REDACTED excerpts), cleartext "
         "endpoints; claim-gated against the APK file itself"),
        ("scanning.mobapi", "probe", _cap_mobapi, 3,
         "mobile backend API checks on APK-extracted endpoints: "
         "missing rate limiting on login/register (3 rapid requests), "
         "TLS downgrade acceptance, v1/v2 parallel versioning "
         "exposure, unauthenticated sensitive endpoints (apidocs "
         "logic scoped to mobile)"),
    ):
        if reg.get(cid) is None:
            reg.register(Capability(cid, kind, fn, cost=cost,
                                    risk="active", requires=("has_web",),
                                    description=desc))
    # Request-level attack classes (wsprobe / corscheck / hpp / crlf):
    # registered passive (read-only probes, benign markers) with a small
    # cost, additive duplicate-id-guarded.
    for cid, fn, desc in (
        ("scanning.wsprobe", _cap_wsprobe,
         "WebSocket endpoint discovery + security: unauthenticated "
         "handshake (candidate), foreign Origin accepted (candidate), "
         "benign marker echo (info); raw-socket handshake, stdlib only"),
        ("scanning.corscheck", _cap_corscheck,
         "CORS misconfiguration matrix: arbitrary-origin reflection, "
         "reflection with credentials, null-origin with credentials, "
         "wildcard (info); no CORS = clean, no finding"),
        ("scanning.hpp", _cap_hpp,
         "HTTP parameter pollution duplicate-value differential plus "
         "mass-assignment probe limited to paths that accepted POST "
         "before; benign inert values, candidate-only"),
        ("scanning.crlf", _cap_crlf,
         "CRLF injection / response splitting: %0d%0a + raw variants "
         "followed by X-Omega-Probe marker header; injected header "
         "verified, body reflection candidate low"),
        ("scanning.csrf", _cap_csrf,
         "CSRF protection analysis: form parsing for missing token "
         "fields, session cookie SameSite note, cross-origin form "
         "action check with benign marker append; claim-gated, "
         "candidate-only"),
        ("scanning.secondorder", _cap_secondorder,
         "second-order (stored) injection probe: benign marker "
         "submitted to a write endpoint, then other pages fetched for "
         "an echo in a DIFFERENT page; HIGH candidate only when the "
         "write was accepted and the echo reproduces via the claim "
         "gate"),
    ):
        if reg.get(cid) is None:
            reg.register(Capability(cid, "probe", fn, cost=2,
                                    risk="passive", requires=("has_web",),
                                    description=desc))


_register_deepscan_capabilities(DEFAULT_REGISTRY)


def _register_scanning_capabilities(reg):
    for cid, kind, fn, cost, desc in (
        ("scanning.smuggle", "enum", _cap_smuggle, 5,
         "HTTP request-smuggling safe-read differential (duplicate CL, "
         "CL.TE, TE.CL, TE.TE obfuscation); Go raw-socket path gated by "
         "PTK_POLYGLOT, pure-Python fallback; candidate-only"),
        ("scanning.hhint", "probe", _cap_hhint, 3,
         "host-header injection suite: absolute-URL override, "
         "X-Forwarded-Host reset flows, cache poisoning (candidate), "
         "port confusion"),
        ("scanning.ssti", "probe", _cap_ssti, 3,
         "template-engine SSTI fingerprinting with safe arithmetic "
         "proof payloads (Jinja2/Twig/FreeMarker/ERB/Pebble/Smarty)"),
        ("scanning.deser", "probe", _cap_deser, 3,
         "unsafe-deserialization endpoint detection via inert marker "
         "payloads and error fingerprints (Java/PHP/Python); no gadget "
         "chains are ever sent"),
        ("scanning.uplprobe", "probe", _cap_uplprobe, 4,
         "unrestricted file-upload probe with INERT benign marker files "
         "only (never webshell): baseline txt, executable-extension "
         "differential, double-extension candidates, validation-signal "
         "analysis"),
        ("scanning.secops", "enum", _cap_secops, 2,
         "security-hygiene bundle: /.well-known/security.txt presence "
         "and validity, robots.txt interesting disallow paths, "
         "autocomplete=on on sensitive inputs; read-only, info/low "
         "severity"),
        ("scanning.blotamper", "probe", _cap_blotamper, 4,
         "business-logic tampering heuristics (SAFE-READ differential): "
         "replays money-bearing forms with tampered price/qty/coupon and "
         "flags only differential acceptance; never completes purchases, "
         "final-submit endpoints skipped; requires manual business "
         "confirmation"),
    ):
        if reg.get(cid) is None:
            reg.register(Capability(cid, kind, fn, cost=cost,
                                    risk="active", requires=("has_web",),
                                    description=desc))


def _register_mobile_capabilities(reg):
    """Mobile static-analysis capabilities (offline, read-only, passive;
    the target is a local .apk/.ipa/.app path — non-mobile targets get a
    skip note, never a raise)."""
    for cid, kind, fn, cost, desc in (
        ("scanning.mobandroid", "enum", _cap_mobandroid, 3,
         "Android APK static analysis (offline): manifest flags, "
         "exported components, deep links, cleartext/NSC, hardcoded "
         "secrets, logcat leakage, dangerous permissions, StrandHogg, "
         "obfuscation, risky SDKs; skip-note on non-APK targets"),
        ("scanning.mobios", "enum", _cap_mobios, 3,
         "iOS .ipa/.app static analysis (offline): ATS exceptions, URL "
         "schemes, keychain accessibility, hardcoded secrets, sensitive "
         "plist keys; skip-note on non-iOS targets"),
        ("scanning.mobgeneral", "enum", _cap_mobgeneral, 2,
         "cross-platform mobile checks (offline, source/config dir): "
         "missing certificate pinning, client-side trust flags, "
         "anti-hooking absence, excessive permissions, push payload "
         "leakage; candidate-only"),
    ):
        if reg.get(cid) is None:
            reg.register(Capability(cid, kind, fn, cost=cost,
                                    risk="passive", requires=(),
                                    description=desc))


_register_mobile_capabilities(DEFAULT_REGISTRY)


_register_scanning_capabilities(DEFAULT_REGISTRY)


# ---------------------------------------------------------------------------
# SENTINEL + C/RUBY batch capabilities (appended; read-only,
# differential-first; polyglot adapters self-gate via PTK_POLYGLOT).
# ---------------------------------------------------------------------------

def _cap_sentinel(state, brain=None):
    try:
        from omega.sentinel import run_sentinel
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.sentinel not available"}
    out = run_sentinel(state.target, default_fetch,
                       log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "sentinel: %d check(s) ran, %d finding(s)"
                    % (len(out.get("ran") or []),
                       len(out.get("findings") or []))}


def _cap_c_urlinfo(state, brain=None):
    try:
        from omega.adapters.ctools import run_c_suite
    except ImportError:
        return {"note": "omega.adapters.ctools not available"}
    out = run_c_suite(state.target, log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "c urlinfo: %s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _cap_ruby_urlaudit(state, brain=None):
    try:
        from omega.adapters.rubytools import run_ruby_suite
    except ImportError:
        return {"note": "omega.adapters.rubytools not available"}
    out = run_ruby_suite(state.target, log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "ruby urlaudit: %s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _register_sentinel_capabilities(reg):
    for cid, kind, fn, cost, desc in (
        ("sentinel.all", "enum", _cap_sentinel, 5,
         "14 advanced vuln checks: CSP bypass intel, JWT claims, "
         "API-key leak, PII, XXE safe probe, deserialization hints, "
         "takeover fingerprints, auth-bypass diff, IDOR probe"),
        ("polyglot.curlinfo", "probe", _cap_c_urlinfo, 2,
         "C URL-quirk parser (gcc compile-on-demand): userinfo@ "
         "tricks, long paths, odd schemes — SSRF/redirect hints"),
        ("polyglot.rubyurlaudit", "probe", _cap_ruby_urlaudit, 2,
         "Ruby URL-shape audit (skips when ruby missing): sqli/ssti/"
         "xss/open-redirect patterns"),
    ):
        if reg.get(cid) is None:
            reg.register(Capability(cid, kind, fn, cost=cost,
                                    risk="active", requires=("has_web",),
                                    description=desc))


_register_sentinel_capabilities(DEFAULT_REGISTRY)


# ---------------------------------------------------------------------------
# POLYGLOT batch-3 capabilities (cpp/awk/bash/rust/php adapters — all gated
# by PTK_POLYGLOT inside the runners; graceful skip when toolchain missing).
# ---------------------------------------------------------------------------

def _cap_cpp_hdrstruct(state, brain=None):
    try:
        from omega.adapters.cpptools import run_cpp_suite
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.adapters.cpptools not available"}
    out = run_cpp_suite(state.target, fetch=default_fetch,
                        log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "cpp hdrstruct: %s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _cap_awk_urlmine(state, brain=None):
    try:
        from omega.adapters.awktools import run_awk_suite
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.adapters.awktools not available"}
    out = run_awk_suite(state.target, fetch=default_fetch,
                        log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "awk urlmine: %s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _cap_sh_methodcheck(state, brain=None):
    try:
        from omega.adapters.shtools import run_sh_suite
    except ImportError:
        return {"note": "omega.adapters.shtools not available"}
    out = run_sh_suite(state.target,
                       log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "sh methodcheck: %s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _cap_rust_pathscope(state, brain=None):
    try:
        from omega.adapters.rusttools import run_rust_suite
    except ImportError:
        return {"note": "omega.adapters.rusttools not available"}
    out = run_rust_suite(state.target,
                         log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "rust pathscope: %s; fallback=%s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       (out.get("surface") or {}).get("fallback"),
                       len(out.get("findings") or []))}


def _cap_php_seriscan(state, brain=None):
    try:
        from omega.adapters.phptools import run_php_suite
        from omega.deepchecks import default_fetch
    except ImportError:
        return {"note": "omega.adapters.phptools not available"}
    out = run_php_suite(state.target, fetch=default_fetch,
                        log=getattr(brain, "log", None)) or {}
    return {"findings": out.get("findings") or [],
            "note": "php seriscan: %s; %d finding(s)"
                    % (sorted(out.get("skipped") or {}),
                       len(out.get("findings") or []))}


def _register_polyglot3_capabilities(reg):
    for cid, kind, fn, cost, desc in (
        ("polyglot.cpphdr", "probe", _cap_cpp_hdrstruct, 2,
         "C++ header-structure classifier (g++ compile-on-demand, gate "
         "PTK_POLYGLOT): security-header presence/order/completeness, "
         "cookie flags, versioned Server banner"),
        ("polyglot.awkurlmine", "probe", _cap_awk_urlmine, 2,
         "awk secret/endpoint miner (POSIX-awk portable): AWS keys, "
         "JWTs, API-key assignments, private IPs with FP-safe baseline "
         "diff (PTK_POLYGLOT)"),
        ("polyglot.shmethodcheck", "probe", _cap_sh_methodcheck, 2,
         "bash curl method audit: GET/HEAD/OPTIONS/POST-safe probes, "
         "Allow-header comparison, TRACE detection (PTK_POLYGLOT)"),
        ("polyglot.rustpathscope", "probe", _cap_rust_pathscope, 1,
         "Rust path traversal normalizer/scope validator (rustc "
         "compile-on-demand, pure computation, pure-Python fallback "
         "when rustc is absent; PTK_POLYGLOT)"),
        ("polyglot.phpseriscan", "probe", _cap_php_seriscan, 1,
         "PHP static deserialization/exec scanner (php-cli, text-in "
         "JSON-out; skips when php is absent; PTK_POLYGLOT)"),
    ):
        if reg.get(cid) is None:
            reg.register(Capability(cid, kind, fn, cost=cost,
                                    risk="passive",
                                    requires=("has_web",),
                                    description=desc))


_register_polyglot3_capabilities(DEFAULT_REGISTRY)


# ---------------------------------------------------------------------------
# AI-ASSIST capability (appended; deterministic analyst heuristics from
# omega.scanning.aiassist — read-only over state.findings, never raises;
# duplicate-id-guarded like the polyglot batch appends).
# ---------------------------------------------------------------------------

def _cap_ai_analyst(state, brain=None):
    """Deterministic analyst brief over the current findings.

    Runs risk_score + prioritize + analyst_brief from
    omega.scanning.aiassist and stores the brief on the brain state
    (state.ai_brief) plus a ranked copy of the findings. Pure
    computation, no network, contained: any failure becomes a note.
    """
    try:
        from omega.scanning.aiassist import (analyst_brief, prioritize,
                                             risk_score)
        brief = analyst_brief(state.findings, state.target)
        ranked = prioritize(state.findings)["ranked"]
        state.ai_brief = brief
        state.ai_ranked_findings = ranked
        return {
            "findings": [],   # read-only cap: appends no findings
            "ai_brief": brief,
            "note": "ai.analyst: brief built over %d finding(s); "
                    "score=%s; steps=%d"
                    % (len(state.findings or []),
                       brief.get("risk_score"), len(brief.get("plan") or [])),
        }
    except Exception as exc:  # contained, never escapes the loop
        return {"note": "ai.analyst degraded: %s: %s"
                        % (type(exc).__name__, exc)}


def _register_aiassist_capability(reg):
    if reg.get("ai.analyst") is None:
        reg.register(Capability(
            "ai.analyst", "report", _cap_ai_analyst,
            cost=1, risk="passive", requires=(),
            description="AI-ASSIST deterministic analyst brief: scores "
                        "and prioritizes current findings, builds an "
                        "ordered kill-chain plan (real omega CLI "
                        "commands, --scope-ack only) and stores it on "
                        "the state as ai_brief; read-only, no network"))


_register_aiassist_capability(DEFAULT_REGISTRY)
