"""
OMEGA — autonomous pentest engagement operator for the Hermes agent.

Thin operator layer over the engine, used purely as a library:
this module resolves the ENGINE home (env OMEGA_ENGINE_HOME, default
the auto-detected engine home), prepends it to sys.path, and imports
offensive.engagement / offensive.toolbridge from there. ENGINE is
never vendored and never modified.
"""

import json
import os
import re
import sys

DEFAULT_ENGINE_HOME = os.path.expanduser("~/workspace/engine")


def _autodetect_engine_home():
    """Find an installed engine checkout without hardcoding a name:
    scan the OMEGA repo's own directory and ~/workspace for a folder
    containing offensive/__init__.py. This makes bundled deployments
    (engine/ placed next to omega/) work with zero configuration."""
    bases = [
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        os.path.expanduser("~/workspace"),
        os.path.expanduser("~/source"),
    ]
    seen = set()
    for base in bases:
        if base in seen or not os.path.isdir(base):
            continue
        seen.add(base)
        try:
            entries = sorted(os.listdir(base))
        except OSError:
            continue
        for name in entries:
            cand = os.path.join(base, name)
            if os.path.isfile(os.path.join(cand, "offensive",
                                           "__init__.py")):
                return cand
    return None


class EngineHomeError(RuntimeError):
    """Raised when the engine home cannot be located."""


def engine_home():
    """Resolve the engine home directory.

    Priority: OMEGA_ENGINE_HOME env → autodetected checkout under
    ~/workspace → DEFAULT_ENGINE_HOME.
    """
    env = os.environ.get("OMEGA_ENGINE_HOME")
    if env:
        return env
    detected = _autodetect_engine_home()
    if detected:
        return detected
    return DEFAULT_ENGINE_HOME


def load_engine(home=None):
    """Prepend the ENGINE home to sys.path and import engine modules.

    Returns (engagement_module, toolbridge_module). Raises
    EngineHomeError with a clear English message if the home is
    missing or does not contain the offensive package.
    """
    home = home or engine_home()
    if not os.path.isdir(home):
        raise EngineHomeError(
            f"engine home not found: {home!r}. Set OMEGA_ENGINE_HOME "
            "to the directory containing the engine project.")
    pkg_init = os.path.join(home, "offensive", "__init__.py")
    if not os.path.isfile(pkg_init):
        raise EngineHomeError(
            f"engine home {home!r} does not contain an "
            "'offensive' package; set OMEGA_ENGINE_HOME correctly.")
    if home not in sys.path:
        sys.path.insert(0, home)
    # The vendored engine internals (netclient, vulnscan2, ...) live under
    # <home>/engine but legacy imports use bare top-level names; put that
    # directory on the path too so `import netclient` resolves regardless
    # of where the bundle is deployed.
    inner = os.path.join(home, "engine")
    if os.path.isdir(inner) and inner not in sys.path:
        sys.path.insert(0, inner)
    tools_dir = os.path.join(home, "tools")
    if os.path.isdir(tools_dir) and tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    try:
        from offensive import engagement, toolbridge  # noqa: E402
    except ImportError as exc:
        raise EngineHomeError(
            f"failed to import engine modules from {home!r}: {exc}")
    return engagement, toolbridge


def _run_assets(args):
    """Print the persistent asset graph (summary or one host)."""
    from omega.core.assetgraph import assets_path, load_graph
    graph = load_graph()
    hosts = graph.get("hosts") or {}
    if args.json:
        import json
        payload = graph if not args.host else \
            hosts.get(args.host.strip().lower())
        print(json.dumps(payload, indent=2, default=str))
        return 0
    if args.host:
        entry = hosts.get(args.host.strip().lower())
        if not entry:
            print(f"no graph entry for {args.host} "
                  f"(graph file: {assets_path()})")
            return 1
        print(f"HOST {args.host}")
        print(f"  first_seen : {entry.get('first_seen')}")
        print(f"  scans      : {entry.get('hits', 0)}")
        for key in ("urls", "ports", "techs", "params", "findings"):
            items = entry.get(key) or {}
            print(f"  {key:<9}: {len(items)}")
            for k, v in sorted(items.items())[:15]:
                print(f"    - {k} (hits={v.get('hits')}, "
                      f"last={v.get('last_seen')})")
            if len(items) > 15:
                print(f"    ... +{len(items) - 15} more")
        return 0
    print(f"asset graph: {assets_path()}")
    print(f"  hosts tracked: {len(hosts)}")
    for h, entry in sorted(hosts.items()):
        print(f"  - {h}: {len(entry.get('urls') or {})} urls, "
              f"{len(entry.get('findings') or {})} findings, "
              f"{entry.get('hits', 0)} scans, "
              f"last {entry.get('updated') or entry.get('first_seen')}")
    return 0


def _run_post_scan_extras(args, state):
    """Shared post-scan extras for brain AND engage dispatch:
    --authscan --critique --chain-proposals --hypothesize --logic
    --kb --waf-profile --cvesuggest --multihypo --cwe-chain
    --spa-map --waf-adapt --outcomes. Operates on any state-like
    object exposing target/findings/history/surface (and optionally
    fetch/log). Never raises."""
    if getattr(state, "fetch", None) is None:
        from omega.core.brain import url_fetch
        state.fetch = url_fetch(None)

    # auth deep-scan: full session lifecycle (--authscan)
    if getattr(args, "authscan", False):
        try:
            from omega.core.authscan import run_auth_deep_scan
            ares = run_auth_deep_scan(
                state.target, fetch=default_fetch,
                creds=os.environ.get("OMEGA_CREDS"),
                log=getattr(state, "log", None))
            state.findings.extend(ares.get("findings") or [])
            state.history.append({
                "step": len(state.history) + 1,
                "capability": "authscan",
                "result": "ok" if ares.get("ok") else "error",
                "new_facts": len(ares.get("findings") or []),
                "reasoning": "auth deep-scan: %s"
                             % (ares.get("note") or "session acquired"),
            })
            print("authscan: %s (%d finding(s))"
                  % (ares.get("note") or "session acquired",
                     len(ares.get("findings") or [])))
        except Exception as exc:
            print("authscan failed: %s" % exc, file=sys.stderr)

    # post-scan self-critique (--critique)
    if getattr(args, "critique", False):
        try:
            from omega.core.critique import critique, narrate_critique
            from omega.core.planner import score_surface
            cdoc = critique(state.findings, state.history,
                            target=state.target,
                            planner_plan=score_surface(state))
            print(narrate_critique(cdoc))
            state.critique = cdoc
        except Exception as exc:
            print("critique failed: %s" % exc, file=sys.stderr)

    # chain graph proposals (--chain-proposals): never executed
    if getattr(args, "chain_proposals", False):
        try:
            from omega.core.autochain import chain_propose
            props = chain_propose(state.findings)
            print("## Chain proposals (%d) — approval required:\n"
                  % len(props))
            for p in props:
                print("- %s" % p["chain"])
                for link in p["links"]:
                    print("    <- %s (%s)" % (link["finding"],
                                              link["location"]))
        except Exception as exc:
            print("chain proposals failed: %s" % exc, file=sys.stderr)

    # hypothesis engine (--hypothesize)
    if getattr(args, "hypothesize", False):
        try:
            from omega.core.hypothesis import run_hypothesis_loop
            obs = [f.get("title", "") for f in state.findings]
            doc = run_hypothesis_loop(obs, state.fetch, state.target)
            print("## Hypotheses (%d raised):" % doc["raised"])
            for h in doc["hypotheses"]:
                print("- [%s] %s %s" % (h["status"], h["id"],
                                        h["kind"]))
                for e in h["evidence"]:
                    print("    %s" % e)
            state.history.append({"capability": "hypothesize",
                                  "raised": doc["raised"]})
        except Exception as exc:
            print("hypothesize failed: %s" % exc, file=sys.stderr)

    # business-logic templates (--logic)
    if getattr(args, "logic", False):
        try:
            from omega.core.logic import findings_from_result, \
                run_logic_templates
            surface = " ".join(str(f.get("title", ""))
                               for f in state.findings)
            doc = run_logic_templates(state.target,
                                      surface_text=surface,
                                      fetch=state.fetch)
            newf = findings_from_result(doc)
            state.findings.extend(newf)
            state.history.append({"capability": "logic",
                                  "templates":
                                  len(doc.get("templates") or []),
                                  "findings": len(newf)})
            print("logic: %d template(s), dry_run=%s, %d finding(s)"
                  % (len(doc.get("templates") or []),
                     doc.get("dry_run"), len(newf)))
        except Exception as exc:
            print("logic failed: %s" % exc, file=sys.stderr)

    # expert-methodology suggestions (--kb)
    if getattr(args, "kb", False):
        try:
            from omega.core.attackkb import narrate_suggestions, suggest
            obs = [f.get("title", "") for f in state.findings]
            obs += list((state.surface or {}).get("notes") or [])
            sugg = suggest(obs)
            print(narrate_suggestions(sugg))
            for s in sugg:
                print("- [p%d] %s — %s" % (s["priority"],
                                           s["technique"], s["step"]))
            state.history.append({"capability": "kb",
                                  "suggestions": len(sugg)})
        except Exception as exc:
            print("kb failed: %s" % exc, file=sys.stderr)

    # WAF profile ladder (--waf-profile)
    if getattr(args, "waf_profile", False):
        try:
            from omega.core.wafprofiler import findings_from_doc, \
                profile
            doc = profile(state.target)
            newf = findings_from_doc(doc)
            state.findings.extend(newf)
            state.history.append({"capability": "waf-profile",
                                  "verdict": doc.get("verdict")})
            print("wafprofiler: %s (%d/%d blocked)"
                  % (doc.get("verdict"), doc.get("blocked_count") or 0,
                     len(doc.get("probes") or [])))
        except Exception as exc:
            print("waf-profile failed: %s" % exc, file=sys.stderr)

    # offline CVE suggestions (--cvesuggest)
    if getattr(args, "cvesuggest", False):
        try:
            from omega.core.cvesuggest import findings_from_leads, \
                narrate, suggest_cves
            text = " ".join(str(t) for t in
                            ((state.surface or {}).get("techs") or []))
            leads = suggest_cves(text)
            state.findings.extend(findings_from_leads(
                leads, state.target))
            print(narrate(leads))
            state.history.append({"capability": "cvesuggest",
                                  "leads": len(leads)})
        except Exception as exc:
            print("cvesuggest failed: %s" % exc, file=sys.stderr)

    # multi-hypothesis engine (--multihypo)
    if getattr(args, "multihypo", False):
        try:
            from omega.core.multihypo import run_multihypo_loop
            obs = [f.get("title", "") for f in (state.findings or [])
                   if f.get("title")][:8] or ["error", "reflect"]
            doc = run_multihypo_loop(obs, state.fetch, url=state.target)
            print("multihypo: %d verified, %d refuted, %d uncertain"
                  % (len(doc["verified"]), len(doc["refuted"]),
                     len(doc["uncertain"])))
            state.history.append({"capability": "multihypo",
                                  "verified": len(doc["verified"])})
        except Exception as exc:
            print("multihypo failed: %s" % exc, file=sys.stderr)

    # CWE chain proposals (--cwe-chain)
    if getattr(args, "cwe_chain", False):
        try:
            from omega.core.cwechain import propose_chains, \
                chain_summary
            chains = propose_chains(state.findings or [])
            for line in chain_summary(chains)[:8]:
                print("cwe-chain:", line)
            print("cwe-chain: %d proposal(s) (plan only)" % len(chains))
            state.history.append({"capability": "cwechain",
                                  "proposals": len(chains)})
        except Exception as exc:
            print("cwe-chain failed: %s" % exc, file=sys.stderr)

    # SPA endpoint mapping (--spa-map)
    if getattr(args, "spa_map", False):
        try:
            from omega.scanning.spamap import map_spa_endpoints
            doc = map_spa_endpoints(state.target, fetch=state.fetch)
            print("spa-map: %d assets, %d candidate endpoint(s)"
                  % (len(doc["assets"]), len(doc["endpoints"])))
            for path in list(doc["endpoints"])[:10]:
                print("  " + path)
            state.history.append({"capability": "spamap",
                                  "endpoints": len(doc["endpoints"])})
        except Exception as exc:
            print("spa-map failed: %s" % exc, file=sys.stderr)

    # protection adaptation plan (--waf-adapt)
    if getattr(args, "waf_adapt", False):
        try:
            from omega.core.wafadapt import adaptation_plan
            try:
                resp = state.fetch(state.target)
            except Exception as exc:
                print("waf-adapt: target unreachable (%s) — no "
                      "fingerprint" % type(exc).__name__)
                state.history.append({"capability": "wafadapt",
                                      "provider": "unreachable"})
                resp = None
            headers = getattr(resp, "headers", None) or {} if resp \
                else {}
            body = resp if isinstance(resp, str) else getattr(
                resp, "text", "") or ""
            if resp is not None:
                plan = adaptation_plan(headers, body)
                print("waf-adapt: provider=%s conf=%.2f pacing=%sms "
                      "concurrency<=%d" % (plan["provider"],
                                           plan["confidence"],
                                           plan["pacing_ms"],
                                           plan["concurrency"]))
                state.history.append({"capability": "wafadapt",
                                      "provider": plan["provider"]})
        except Exception as exc:
            print("waf-adapt failed: %s" % exc, file=sys.stderr)

    # technique outcome ranking (--outcomes)
    if getattr(args, "outcomes", False):
        try:
            from omega.core.lessonsv2 import rank_techniques
            from urllib.parse import urlparse
            ranked = rank_techniques(
                urlparse(state.target).netloc, "/")
            print("outcomes: %d ranked technique(s)" % len(ranked))
            for r in ranked[:5]:
                print("  %s: %.0f%% (%d win/%d loss, from %s)"
                      % (r["technique"], r["rate"] * 100, r["win"],
                         r["loss"], r["from"]))
            state.history.append({"capability": "outcomes",
                                  "ranked": len(ranked)})
        except Exception as exc:
            print("outcomes failed: %s" % exc, file=sys.stderr)

    # post-exploit enumeration (--privesc): CONFIRMED RCE only
    if getattr(args, "privesc", False):
        try:
            from omega.adapters.gotools_offense import run_privesc
            rce = (state.surface or {}).get("rce") or {}
            doc = run_privesc(
                rce.get("template") or state.target,
                cookie=rce.get("cookie") or "",
                confirm_rce=bool(rce.get("confirmed")),
                log=getattr(state, "log", None))
            if doc.get("skipped"):
                print("privesc: %s"
                      % list(doc["skipped"].values())[0])
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "privesc",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings")
                                                    or []),
                                  "reasoning": "post-exploit enumeration"})
        except Exception as exc:
            print("privesc failed: %s" % exc, file=sys.stderr)

    # default-credential stuffing (--authblast)
    if getattr(args, "authblast", False):
        try:
            from omega.adapters.gotools_offense import run_authblast
            doc = run_authblast(
                (state.surface or {}).get("logins") or [state.target],
                techs=(state.surface or {}).get("techs") or ["generic"],
                log=getattr(state, "log", None))
            if doc.get("skipped"):
                print("authblast: %s"
                      % list(doc["skipped"].values())[0])
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "authblast",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings")
                                                    or []),
                                  "reasoning": "default-credential wave"})
        except Exception as exc:
            print("authblast failed: %s" % exc, file=sys.stderr)

    # active JWT attacks (--jwt-attack)
    if getattr(args, "jwt_attack", False):
        try:
            from omega.offensive.offense.jwtattack import run_jwtattack
            doc = run_jwtattack(
                state.target, (state.surface or {}).get("jwt") or "",
                fetch=state.fetch,
                log=getattr(state, "log", None))
            print("jwt-attack: %s"
                  % (doc.get("note") or
                     "%d candidate(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "jwtattack",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings")
                                                    or []),
                                  "reasoning": "active JWT wave"})
        except Exception as exc:
            print("jwt-attack failed: %s" % exc, file=sys.stderr)

    # race-condition hunter (--race-hunt)
    if getattr(args, "race_hunt", False):
        try:
            from omega.adapters.gotools_offense import run_racehunter
            targets = (state.surface or {}).get("race_targets") or [
                {"url": state.target, "method": "POST", "body": ""}]
            for t in targets[:4]:
                doc = run_racehunter(
                    t.get("url"), body=t.get("body") or "",
                    method=t.get("method") or "POST",
                    success_marker=t.get("marker") or "",
                    log=getattr(state, "log", None))
                if doc.get("skipped"):
                    print("race-hunt: %s"
                          % list(doc["skipped"].values())[0])
                state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "racehunt",
                                  "result": "ok",
                                  "reasoning": "race-condition wave"})
        except Exception as exc:
            print("race-hunt failed: %s" % exc, file=sys.stderr)

    # second-order injection (--second-order)
    if getattr(args, "second_order", False):
        try:
            from omega.offensive.offense.secondorder import (
                run_second_order)
            urls = list((state.surface or {}).get("urls") or [])
            injects = [{"url": u, "param": "q"} for u in urls[:6]] or \
                [{"url": state.target, "param": "q"}]
            doc = run_second_order(injects, urls or [state.target],
                                   fetch=state.fetch,
                                   log=getattr(state, "log", None))
            print("second-order: %s"
                  % (doc.get("note") or "%d candidate(s)"
                     % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "secondorder",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings")
                                                    or []),
                                  "reasoning": "second-order wave"})
        except Exception as exc:
            print("second-order failed: %s" % exc, file=sys.stderr)

    # business-logic fuzzer (--biz-fuzz)
    if getattr(args, "biz_fuzz", False):
        try:
            from omega.offensive.offense.bizfuzz import run_bizfuzz
            actions = (state.surface or {}).get("biz_actions") or [
                {"url": state.target, "method": "POST", "param": "qty",
                 "value": "1"}]
            doc = run_bizfuzz(actions, fetch=state.fetch,
                              log=getattr(state, "log", None))
            print("biz-fuzz: %s"
                  % (doc.get("note") or "%d candidate(s)"
                     % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "bizfuzz",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings")
                                                    or []),
                                  "reasoning": "logic-permutation wave"})
        except Exception as exc:
            print("biz-fuzz failed: %s" % exc, file=sys.stderr)

    # closed-loop exploit reasoning (--exploit-loop)
    if getattr(args, "exploit_loop", False):
        try:
            from omega.core.brain import _cap_exploitloop
            doc = _cap_exploitloop(state)
            print("exploit-loop: %s"
                  % (doc.get("note") or
                     "winner=%s (%d probes)" % (doc.get("winner"),
                                                doc.get("probes"))))
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "exploitloop",
                                  "result": "ok",
                                  "winner": doc.get("winner"),
                                  "reasoning": "hypothesis loop"})
        except Exception as exc:
            print("exploit-loop failed: %s" % exc, file=sys.stderr)

    # pivot plan (--pivot-plan): PLAN-ONLY
    if getattr(args, "pivot_plan", False):
        try:
            from omega.core.pivot import build_pivot_plan
            doc = build_pivot_plan(
                (state.surface or {}).get("privesc") or [],
                surface=state.surface)
            print("pivot-plan: %d/%d step(s) triggered — %s"
                  % (doc.get("triggered"), len(doc.get("plan") or []),
                     doc.get("note")))
            state.pivot_plan = doc
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "pivot",
                                  "result": "ok",
                                  "reasoning": "pivot plan built"})
        except Exception as exc:
            print("pivot-plan failed: %s" % exc, file=sys.stderr)

    # stack routing (--stack-route)
    if getattr(args, "stack_route", False):
        try:
            from omega.core.stackroute import explain_route
            print(explain_route(
                (state.surface or {}).get("techs") or []))
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "stackroute",
                                  "result": "ok",
                                  "reasoning": "stack routed"})
        except Exception as exc:
            print("stack-route failed: %s" % exc, file=sys.stderr)

    # stateful crawler (--crawl-state)
    if getattr(args, "crawl_state", False):
        try:
            from omega.core.brain import _cap_crawlstate
            doc = _cap_crawlstate(state)
            print("crawl-state: %s" % (doc.get("note") or "done"))
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "crawlstate",
                                  "result": "ok",
                                  "reasoning": "session crawl"})
        except Exception as exc:
            print("crawl-state failed: %s" % exc, file=sys.stderr)

    # adversary profile (--profiles)
    if getattr(args, "profiles", False):
        try:
            from omega.core.brain import _cap_profiles
            doc = _cap_profiles(state)
            print("profiles: %s"
                  % (doc.get("note") or
                     "%s: %d step(s), executed=%d"
                     % (doc.get("profile"), len(doc.get("steps") or []),
                        sum(1 for x in doc.get("steps") or []
                            if x.get("executed")))))
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "profiles",
                                  "result": "ok",
                                  "reasoning": "ATT&CK campaign"})
        except Exception as exc:
            print("profiles failed: %s" % exc, file=sys.stderr)

    # horizontal expansion (--horizontal)
    if getattr(args, "horizontal", False):
        try:
            from omega.core.brain import _cap_horizontal
            doc = _cap_horizontal(state)
            print("horizontal: %s"
                  % (doc.get("note") or "%d candidate(s)"
                     % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "horizontal",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings")
                                                    or []),
                                  "reasoning": "horizontal sweep"})
        except Exception as exc:
            print("horizontal failed: %s" % exc, file=sys.stderr)

    # impact ranking (--rank-targets)
    if getattr(args, "rank_targets", False):
        try:
            from omega.core.scheduler import rank_targets
            doc = rank_targets(state.surface)
            top = doc.get("queue") or []
            print("rank-targets: %d target(s) queued" % len(top))
            for t in top[:5]:
                print("  %s (score %s: %s)"
                      % (t["url"][:60], t["score"], ", ".join(t["why"])))
            state.attack_queue = doc
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "scheduler",
                                  "result": "ok",
                                  "reasoning": "targets ranked"})
        except Exception as exc:
            print("rank-targets failed: %s" % exc, file=sys.stderr)

    # chain execution (--chain-run)
    if getattr(args, "chain_run", False):
        try:
            from omega.core.brain import _cap_chainrun
            doc = _cap_chainrun(state)
            print("chain-run: %s"
                  % (doc.get("note") or
                     "%d confirmed step(s), %d dead end(s)"
                     % (len(doc.get("steps") or []),
                        len(doc.get("dead_ends") or []))))
            state.findings.extend([
                {"title": f"chain step confirmed: {s['probe']}",
                 "severity": "HIGH",
                 "source": "chainrun",
                 "evidence": str(s.get("evidence"))[:200],
                 "location": state.target,
                 "verification": "candidate",
                 "manual_check": "replay the step manually",
                 "cwe": s.get("edge", {}).get("from")} for s in
                doc.get("steps") or []])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "chainrun",
                                  "result": "ok",
                                  "reasoning": "chain executed"})
        except Exception as exc:
            print("chain-run failed: %s" % exc, file=sys.stderr)

    # evasion ladder (--evade-chain)
    if getattr(args, "evade_chain", False):
        try:
            from omega.core.brain import _cap_evadechain
            doc = _cap_evadechain(state)
            print("evade-chain: %s"
                  % (doc.get("note") or
                     "%d encoder(s) passed" % len(doc.get("passed")
                                                  or [])))
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "evadechain",
                                  "result": "ok",
                                  "reasoning": "evasion ladder"})
        except Exception as exc:
            print("evade-chain failed: %s" % exc, file=sys.stderr)

    # API specialist (--api-special)
    if getattr(args, "api_special", False):
        try:
            from omega.core.brain import _cap_apispecial
            doc = _cap_apispecial(state)
            print("api-special: %s"
                  % (doc.get("note") or "%d candidate(s)"
                     % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "apispecial",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings")
                                                    or []),
                                  "reasoning": "API abuse sweep"})
        except Exception as exc:
            print("api-special failed: %s" % exc, file=sys.stderr)

    # upload bypass (--upload-fuzz)
    if getattr(args, "upload_fuzz", False):
        try:
            from omega.core.brain import _cap_uploadfuzz
            doc = _cap_uploadfuzz(state)
            print("upload-fuzz: %s"
                  % (doc.get("note") or "%d variant(s) accepted"
                     % len(doc.get("accepted") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "uploadfuzz",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings")
                                                    or []),
                                  "reasoning": "upload bypass wave"})
        except Exception as exc:
            print("upload-fuzz failed: %s" % exc, file=sys.stderr)

    # BLACKOUT (--smuggle)
    if getattr(args, "smuggle", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.smuggle").fn(state)
            print("smuggle: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.smuggle",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "BLACKOFF wave"})
        except Exception as exc:
            print("smuggle failed: %s" % exc, file=sys.stderr)

    # BLACKOUT (--cache-poison)
    if getattr(args, "cache_poison", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.cachepoison").fn(state)
            print("cache-poison: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.cachepoison",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "BLACKOFF wave"})
        except Exception as exc:
            print("cache-poison failed: %s" % exc, file=sys.stderr)

    # BLACKOUT (--ws-probe)
    if getattr(args, "ws_probe", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.wsprobe").fn(state)
            print("ws-probe: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.wsprobe",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "BLACKOFF wave"})
        except Exception as exc:
            print("ws-probe failed: %s" % exc, file=sys.stderr)

    # BLACKOUT (--proto-pollute)
    if getattr(args, "proto_pollute", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.protopollute").fn(state)
            print("proto-pollute: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.protopollute",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "BLACKOFF wave"})
        except Exception as exc:
            print("proto-pollute failed: %s" % exc, file=sys.stderr)

    # BLACKOUT (--session-matrix)
    if getattr(args, "session_matrix", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.sessionmatrix").fn(state)
            print("session-matrix: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.sessionmatrix",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "BLACKOFF wave"})
        except Exception as exc:
            print("session-matrix failed: %s" % exc, file=sys.stderr)

    # BLACKOUT (--mime-confusion)
    if getattr(args, "mime_confusion", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.mimeconfusion").fn(state)
            print("mime-confusion: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.mimeconfusion",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "BLACKOFF wave"})
        except Exception as exc:
            print("mime-confusion failed: %s" % exc, file=sys.stderr)

    # BLACKOUT (--blind-relay)
    if getattr(args, "blind_relay", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.blindrelay").fn(state)
            print("blind-relay: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.blindrelay",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "BLACKOFF wave"})
        except Exception as exc:
            print("blind-relay failed: %s" % exc, file=sys.stderr)

    # BLACKOUT (--h2-probe)
    if getattr(args, "h2_probe", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.h2probe").fn(state)
            print("h2-probe: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.h2probe",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "BLACKOFF wave"})
        except Exception as exc:
            print("h2-probe failed: %s" % exc, file=sys.stderr)

    # MELTDOWN (--deser-probe)
    if getattr(args, "deser_probe", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.deserprobe").fn(state)
            print("deser-probe: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.deserprobe",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "MELTDOWN wave"})
        except Exception as exc:
            print("deser-probe failed: %s" % exc, file=sys.stderr)

    # MELTDOWN (--meta-ssrf)
    if getattr(args, "meta_ssrf", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.metassrf").fn(state)
            print("meta-ssrf: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.metassrf",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "MELTDOWN wave"})
        except Exception as exc:
            print("meta-ssrf failed: %s" % exc, file=sys.stderr)

    # MELTDOWN (--authz-matrix)
    if getattr(args, "authz_matrix", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.authzmatrix").fn(state)
            print("authz-matrix: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.authzmatrix",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "MELTDOWN wave"})
        except Exception as exc:
            print("authz-matrix failed: %s" % exc, file=sys.stderr)

    # MELTDOWN (--ci-sweep)
    if getattr(args, "ci_sweep", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.cisweep").fn(state)
            print("ci-sweep: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.cisweep",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "MELTDOWN wave"})
        except Exception as exc:
            print("ci-sweep failed: %s" % exc, file=sys.stderr)

    # MELTDOWN (--cors-probe)
    if getattr(args, "cors_probe", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.corsprobe").fn(state)
            print("cors-probe: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.corsprobe",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "MELTDOWN wave"})
        except Exception as exc:
            print("cors-probe failed: %s" % exc, file=sys.stderr)

    # MELTDOWN (--adaptive)
    if getattr(args, "adaptive", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.adaptive").fn(state)
            print("adaptive: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.adaptive",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "MELTDOWN wave"})
        except Exception as exc:
            print("adaptive failed: %s" % exc, file=sys.stderr)

    # NIGHTFALL (--poc-gen)
    if getattr(args, "poc_gen", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.pocgen").fn(state)
            print("poc-gen: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.pocgen",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "NIGHTFALL wave"})
        except Exception as exc:
            print("poc-gen failed: %s" % exc, file=sys.stderr)

    # NIGHTFALL (--chain-compose)
    if getattr(args, "chain_compose", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.chaincomposer").fn(state)
            print("chain-compose: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.chaincomposer",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "NIGHTFALL wave"})
        except Exception as exc:
            print("chain-compose failed: %s" % exc, file=sys.stderr)

    # NIGHTFALL (--impact-score)
    if getattr(args, "impact_score", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.impactscorer").fn(state)
            print("impact-score: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.impactscorer",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "NIGHTFALL wave"})
        except Exception as exc:
            print("impact-score failed: %s" % exc, file=sys.stderr)

    # NIGHTFALL (--jwt-deep)
    if getattr(args, "jwt_deep", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("auth.jwtdeep").fn(state)
            print("jwt-deep: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "auth.jwtdeep",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "NIGHTFALL wave"})
        except Exception as exc:
            print("jwt-deep failed: %s" % exc, file=sys.stderr)

    # NIGHTFALL (--fp-exploit)
    if getattr(args, "fp_exploit", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.fpexploit").fn(state)
            print("fp-exploit: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.fpexploit",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "NIGHTFALL wave"})
        except Exception as exc:
            print("fp-exploit failed: %s" % exc, file=sys.stderr)

    # NIGHTFALL (--report-diff)
    if getattr(args, "report_diff", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.reportdiff").fn(state)
            print("report-diff: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.reportdiff",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "NIGHTFALL wave"})
        except Exception as exc:
            print("report-diff failed: %s" % exc, file=sys.stderr)

    # NIGHTFALL (--wordlist-gen)
    if getattr(args, "wordlist_gen", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.wordlistgen").fn(state)
            print("wordlist-gen: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.wordlistgen",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "NIGHTFALL wave"})
        except Exception as exc:
            print("wordlist-gen failed: %s" % exc, file=sys.stderr)

    # NIGHTFALL (--rate-fprint)
    if getattr(args, "rate_fprint", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.ratefprint").fn(state)
            print("rate-fprint: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.ratefprint",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "NIGHTFALL wave"})
        except Exception as exc:
            print("rate-fprint failed: %s" % exc, file=sys.stderr)

    # NIGHTFALL (--dos-expose)
    if getattr(args, "dos_expose", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.dosexpose").fn(state)
            print("dos-expose: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.dosexpose",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "NIGHTFALL wave"})
        except Exception as exc:
            print("dos-expose failed: %s" % exc, file=sys.stderr)

    # NIGHTFALL (--destruct-shape)
    if getattr(args, "destruct_shape", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.destrshape").fn(state)
            print("destruct-shape: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.destrshape",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "NIGHTFALL wave"})
        except Exception as exc:
            print("destruct-shape failed: %s" % exc, file=sys.stderr)

    # NIGHTFALL (--pwd-audit)
    if getattr(args, "pwd_audit", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.pwdaudit").fn(state)
            print("pwd-audit: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.pwdaudit",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "NIGHTFALL wave"})
        except Exception as exc:
            print("pwd-audit failed: %s" % exc, file=sys.stderr)

    # PHANTOM (--verb-tamper)
    if getattr(args, "verb_tamper", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.verbtamper").fn(state)
            print("verb-tamper: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.verbtamper",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "PHANTOM wave"})
        except Exception as exc:
            print("verb-tamper failed: %s" % exc, file=sys.stderr)

    # PHANTOM (--js-mine)
    if getattr(args, "js_mine", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.jsmine").fn(state)
            print("js-mine: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.jsmine",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "PHANTOM wave"})
        except Exception as exc:
            print("js-mine failed: %s" % exc, file=sys.stderr)

    # PHANTOM (--shadow-disc)
    if getattr(args, "shadow_disc", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.shadowdisc").fn(state)
            print("shadow-disc: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.shadowdisc",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "PHANTOM wave"})
        except Exception as exc:
            print("shadow-disc failed: %s" % exc, file=sys.stderr)

    # PHANTOM (--crlf-probe)
    if getattr(args, "crlf_probe", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.crlfprobe").fn(state)
            print("crlf-probe: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.crlfprobe",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "PHANTOM wave"})
        except Exception as exc:
            print("crlf-probe failed: %s" % exc, file=sys.stderr)

    # PHANTOM (--subd-graph)
    if getattr(args, "subd_graph", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.subdgraph").fn(state)
            print("subd-graph: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.subdgraph",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "PHANTOM wave"})
        except Exception as exc:
            print("subd-graph failed: %s" % exc, file=sys.stderr)

    # PHANTOM (--idor-oracle)
    if getattr(args, "idor_oracle", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.idororacle").fn(state)
            print("idor-oracle: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.idororacle",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "PHANTOM wave"})
        except Exception as exc:
            print("idor-oracle failed: %s" % exc, file=sys.stderr)

    # PHANTOM (--narrative)
    if getattr(args, "narrative", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.narrgen").fn(state)
            print("narrative: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.narrgen",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "PHANTOM wave"})
        except Exception as exc:
            print("narrative failed: %s" % exc, file=sys.stderr)

    # PHANTOM (--noise-audit)
    if getattr(args, "noise_audit", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.noiseaudit").fn(state)
            print("noise-audit: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.noiseaudit",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "PHANTOM wave"})
        except Exception as exc:
            print("noise-audit failed: %s" % exc, file=sys.stderr)

    # DEEPFROST (--auto-deep)
    if getattr(args, "auto_deep", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.autodeep").fn(state)
            print("auto-deep: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.autodeep",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "DEEPFROST wave"})
        except Exception as exc:
            print("auto-deep failed: %s" % exc, file=sys.stderr)

    # DEEPFROST (--fp-killer)
    if getattr(args, "fp_killer", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.fpkiller").fn(state)
            print("fp-killer: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.fpkiller",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "DEEPFROST wave"})
        except Exception as exc:
            print("fp-killer failed: %s" % exc, file=sys.stderr)

    # DEEPFROST (--session-life)
    if getattr(args, "session_life", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("offense.sessionlife").fn(state)
            print("session-life: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "offense.sessionlife",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "DEEPFROST wave"})
        except Exception as exc:
            print("session-life failed: %s" % exc, file=sys.stderr)

    # DEEPFROST (--smart-pace)
    if getattr(args, "smart_pace", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.smartpace").fn(state)
            print("smart-pace: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.smartpace",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "DEEPFROST wave"})
        except Exception as exc:
            print("smart-pace failed: %s" % exc, file=sys.stderr)

    # DEEPFROST (--evidence-pack)
    if getattr(args, "evidence_pack", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.evidencepack").fn(state)
            print("evidence-pack: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.evidencepack",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "DEEPFROST wave"})
        except Exception as exc:
            print("evidence-pack failed: %s" % exc, file=sys.stderr)

    # DEEPFROST (--portfolio)
    if getattr(args, "portfolio", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.multiorch").fn(state)
            print("portfolio: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.multiorch",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "DEEPFROST wave"})
        except Exception as exc:
            print("portfolio failed: %s" % exc, file=sys.stderr)

    # DEEPFROST (--self-test)
    if getattr(args, "self_test", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.selftest").fn(state)
            print("self-test: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.selftest",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "DEEPFROST wave"})
        except Exception as exc:
            print("self-test failed: %s" % exc, file=sys.stderr)

    # DEEPFROST (--html-report)
    if getattr(args, "html_report", False):
        try:
            from omega.core.brain import DEFAULT_REGISTRY as _reg
            doc = _reg.get("core.reporthtml").fn(state)
            print("html-report: %s" % (doc.get("note") or
                               "%d finding(s)" % len(doc.get("findings") or [])))
            state.findings.extend(doc.get("findings") or [])
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "core.reporthtml",
                                  "result": "ok",
                                  "new_facts": len(doc.get("findings") or []),
                                  "reasoning": "DEEPFROST wave"})
        except Exception as exc:
            print("html-report failed: %s" % exc, file=sys.stderr)

    # attack graph (--attack-graph)
    if getattr(args, "attack_graph", False):
        try:
            from omega.core.attackgraph import build_attack_graph
            doc = build_attack_graph(state.findings,
                                     log=getattr(state, "log", None))
            print("attack-graph: %d chain(s), %d node(s)"
                  % (len(doc.get("chains") or []), doc.get("nodes") or 0))
            state.attack_graph = doc
            state.history.append({"step": len(state.history) + 1,
                                  "capability": "attackgraph",
                                  "result": "ok",
                                  "new_facts": len(doc.get("chains") or []),
                                  "reasoning": "kill-chain assembly"})
        except Exception as exc:
            print("attack-graph failed: %s" % exc, file=sys.stderr)
            print("outcomes failed: %s" % exc, file=sys.stderr)


class _EngineStateShim:
    """Minimal state-like adapter over the engine engagement dict so
    the shared post-scan extras can run on the engage path."""

    def __init__(self, args, result):
        self.target = getattr(args, "target", None) or             result.get("target")
        self.mode = result.get("mode")
        self.findings = list(result.get("findings") or [])
        self.history = [{"capability": s,
                         "result": "ok"}
                        for s in result.get("stages_run") or []]
        self.surface = {"hosts":
                        sorted({str(f.get("location") or "")
                                for f in self.findings if
                                f.get("location")}) or [self.target],
                        "notes": [], "techs":
                        list(result.get("techs") or [])}
        self.chains_planned = result.get("chains_planned") or []
        self.budget_remaining = (result.get("budget") or {}).get(
            "max_requests", 0)
        self.fetch = None  # _run_post_scan_extras sets default_fetch
        self.log = lambda *a, **k: None


def _run_brain(args):
    """Run the autonomous decision-engine loop (omega.brain)."""
    from omega import brain as brain_mod

    state, report = brain_mod.Brain().run(
        args.target, mode=args.mode, scope_ack=True,
        max_steps=args.max_steps)
    exploit_result = _run_exploit_layer(args, state)
    # auto-chain: multi-stage recon -> harvest -> auth -> poc, gated by
    # OMEGA_AUTOCHAIN=1 (--autochain) or OMEGA_NO_LIMITS=1.
    if os.environ.get("OMEGA_AUTOCHAIN") == "1":
        try:
            from omega.core.autochain import run_autochain, narrate
            from omega.deepchecks import default_fetch
            chain_res = run_autochain(
                state.target, default_fetch, chain="full",
                findings=state.findings,
                creds=os.environ.get("OMEGA_CREDS"))
            state.history.append({
                "step": len(state.history) + 1,
                "capability": "autochain",
                "result": "ok" if chain_res.get("ok") else "error",
                "new_facts": len(chain_res.get("findings") or []),
                "detail": chain_res.get("stop_reason") or
                          " -> ".join(s.get("stage") for s in
                                      chain_res.get("stages") or []),
                "reasoning": "auto-chain executed: %s" % (
                    chain_res.get("stop_reason")
                    or "all stages produced evidence"),
                "sources": sorted({str(f.get("source")) for f in
                                   chain_res.get("findings") or []}),
            })
            state.findings.extend(chain_res.get("findings") or [])
            print(narrate({"target": state.target,
                           "history": state.history,
                           "findings": state.findings}))
        except Exception as exc:
            print("autochain failed: %s" % exc, file=sys.stderr)
    _run_post_scan_extras(args, state)
    if args.json:
        import json
        print(json.dumps({
            "target": state.target,
            "mode": state.mode,
            "steps": len(state.history),
            "surface": state.surface,
            "findings": len(state.findings),
            "chains_planned": len(state.chains_planned),
            "budget_remaining": state.budget_remaining,
        }, indent=2, default=str))
    else:
        print(report)
    if exploit_result:
        _print_findings(exploit_result,
                        "\n== EXPLOIT layer (PTK_EXPLOIT) ==")
    return 0


def _run_exploit_layer(args, state):
    """Run the PoC exploit layer when the PTK_EXPLOIT gate is open
    (--exploit / --aggressive). Returns None when skipped."""
    import os
    if os.environ.get("PTK_EXPLOIT") != "1":
        return None
    from omega.deepchecks import default_fetch
    from omega.exploit import run_exploit
    result = run_exploit(args.target, default_fetch,
                         findings=list(state.findings or []))
    if result.get("findings"):
        state.findings.extend(result["findings"])
    return result


def start_oob_server(args):
    """Pre-start the OOB callback server when --oob was passed.

    Binds 127.0.0.1 on an ephemeral port and exports
    OMEGA_OOB_BASE_URL so child suites can plant canary URLs against
    it. Returns the running server (caller must stop() it, ideally in
    a finally) or None when --oob was not given.
    """
    if not getattr(args, "oob", False):
        return None
    from omega.oob import OOBCallbackServer
    server = OOBCallbackServer()
    server.start()
    os.environ["OMEGA_OOB_BASE_URL"] = server.base_url()
    return server


def _stop_oob_server(server):
    if server is not None:
        server.stop()
        os.environ.pop("OMEGA_OOB_BASE_URL", None)


def main(argv=None):
    """CLI entry point. Returns process exit code."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="omega",
        description="OMEGA v1.0.0 — autonomous pentest engagement "
                    "operator powered by the engine.")
    parser.add_argument("--version", action="store_true",
                        help="print the OMEGA version and exit")
    sub = parser.add_subparsers(dest="command")
    eng = sub.add_parser(
        "engage", help="run a bounded, planning-only engagement")
    eng.add_argument("target", help="target host / URL / apk to engage")
    eng.add_argument("--mode", default="auto",
                     help="engagement mode (default: auto)")
    eng.add_argument("--scope-ack", action="store_true",
                     help="acknowledge you are authorized to test the "
                          "target (REQUIRED)")
    eng.add_argument("--polyglot", action="store_true",
                     help="enable the polyglot adapter gates "
                          "(sets PTK_POLYGLOT=1: native Go/Node adapters "
                          "and read-only system-binary tools)")
    eng.add_argument("--with-tools", action="store_true",
                     help="enable the read-only external tool bridge "
                          "(sets PTK_TOOLS=1)")
    eng.add_argument("--oob", action="store_true",
                     help="pre-start the local out-of-band callback server "
                          "(127.0.0.1, ephemeral port) and export "
                          "OMEGA_OOB_BASE_URL for child suites")
    eng.add_argument("--offense", action="store_true",
                     help="ENABLE THE OFFENSE LAYER (sets PTK_OFFENSE=1: "
                          "brute force + injection payload runner — "
                          "authorized targets only)")
    eng.add_argument("--aggressive", action="store_true",
                     help="MAXIMUM POWER: enables polyglot + offense + "
                          "exploit layers and lifts budget caps "
                          "(OMEGA_MAX_REQUESTS/OMEGA_FUSION_BUDGET). "
                          "Authorized targets only.")
    eng.add_argument("--risky-ok", dest="risky_ok", action="store_true",
                     help="MIDDLE TIER: PoC exploitation of confirmed "
                          "findings without full no-limits (sets "
                          "OMEGA_RISKY_OK=1; read-only PoCs only)")
    eng.add_argument("--autochain", action="store_true",
                     help="AUTO-CHAIN: run the multi-stage chain "
                          "(recon -> harvest -> auth -> poc), each stage "
                          "evidence-gated (sets OMEGA_AUTOCHAIN=1)")
    eng.add_argument("--authscan", action="store_true",
                     help="AUTH DEEP-SCAN: login (OMEGA_CREDS, single "
                          "attempt) + session fixation + logout "
                          "invalidation checks")
    eng.add_argument("--critique", action="store_true",
                     help="SELF-CRITIQUE: post-scan review of the "
                          "findings (FP smells, dead stages) + a "
                          "planner followup list")
    eng.add_argument("--brutal", action="store_true",
                     help="maximum power from the first request "
                     "(aggressive + no-limits + autochain in one "
                     "flag; --scope-ack still required)")
    eng.add_argument("--hypothesize", action="store_true",
                     help="hypothesis-driven verification loop "
                     "(observations -> scored hypotheses -> probes)")
    eng.add_argument("--logic", action="store_true",
                     help="business-logic templates: IDOR/price/"
                     "redeem/step-skip/role checklists")
    eng.add_argument("--kb", action="store_true",
                     help="expert-methodology suggestions from the "
                     "offline attack knowledge base")
    eng.add_argument("--waf-profile", action="store_true",
                     help="benign WAF/rate-limit probe ladder before "
                     "the main scan")
    eng.add_argument("--cvesuggest", action="store_true",
                     help="version-matched CVE suggestions from the "
                     "offline NVD feed")
    eng.add_argument("--multihypo", action="store_true",
                     help="multi-hypothesis engine: N competing hypotheses per signal, Bayes-ranked probes")
    eng.add_argument("--cwe-chain", action="store_true",
                     help="CWE-aware attack chain proposals over findings (plan only, gates explicit, never executed)")
    eng.add_argument("--spa-map", action="store_true",
                     help="static JS/SPA endpoint mapper (fetch/XHR/axios surface from bundles, no headless browser)")
    eng.add_argument("--waf-adapt", action="store_true",
                     help="fingerprint the protection layer and print the adaptive pacing/cookie strategy")
    eng.add_argument("--outcomes", action="store_true",
                     help="rank techniques by lessonsv2 win-rate (try what worked first)")
    eng.add_argument("--privesc", action="store_true",
                     help="post-exploit enumeration through CONFIRMED RCE only (EXPLOIT-GATED)")
    eng.add_argument("--authblast", action="store_true",
                     help="concurrent default-credential stuffing per tech fingerprint (OFFENSE-GATED)")
    eng.add_argument("--jwt-attack", action="store_true",
                     help="active JWT attacks: alg:none + weak HS256 re-sign (OFFENSE-GATED)")
    eng.add_argument("--attack-graph", action="store_true",
                     help="evidence-validated kill-chain attack graph over findings")
    eng.add_argument("--race-hunt", action="store_true",
                     help="race-condition hunter: N simultaneous requests, TOCTOU candidate (OFFENSE-GATED)")
    eng.add_argument("--second-order", action="store_true",
                     help="second-order injection: plant markers, re-crawl, cross-page replay (OFFENSE-GATED)")
    eng.add_argument("--biz-fuzz", action="store_true",
                     help="business-logic fuzzer: invalid values + action permutations (OFFENSE-GATED)")
    eng.add_argument("--exploit-loop", action="store_true",
                     help="closed-loop Bayesian exploit reasoning over hypotheses")
    eng.add_argument("--pivot-plan", action="store_true",
                     help="PLAN-ONLY post-exploit pivot plan from host state")
    eng.add_argument("--stack-route", action="store_true",
                     help="fingerprint-to-module routing for this stack")
    eng.add_argument("--crawl-state", action="store_true",
                     help="stateful session crawler: endpoints behind actions join the scan")
    eng.add_argument("--profiles", action="store_true",
                     help="adversary emulation profile (ATT&CK-tagged campaign)")
    eng.add_argument("--horizontal", action="store_true",
                     help="horizontal expansion: IDOR sweep + spray (OFFENSE-GATED)")
    eng.add_argument("--chain-run", action="store_true",
                     help="validated attack-chain execution with edge fallback (OFFENSE-GATED)")
    eng.add_argument("--evade-chain", action="store_true",
                     help="structured evasion ladder vs block detection (OFFENSE-GATED)")
    eng.add_argument("--api-special", action="store_true",
                     help="GraphQL/REST abuse: introspection, mass assignment, BOLA (OFFENSE-GATED)")
    eng.add_argument("--upload-fuzz", action="store_true",
                     help="upload bypass: extension tricks + inert execution markers (OFFENSE-GATED)")

    eng.add_argument("--smuggle", action="store_true",
                       help="BLACKOUT batch-13: smuggle (OFFENSE-GATED)")
    eng.add_argument("--cache-poison", action="store_true",
                       help="BLACKOUT batch-13: cache-poison (OFFENSE-GATED)")
    eng.add_argument("--ws-probe", action="store_true",
                       help="BLACKOUT batch-13: ws-probe (OFFENSE-GATED)")
    eng.add_argument("--proto-pollute", action="store_true",
                       help="BLACKOUT batch-13: proto-pollute (OFFENSE-GATED)")
    eng.add_argument("--session-matrix", action="store_true",
                       help="BLACKOUT batch-13: session-matrix (OFFENSE-GATED)")
    eng.add_argument("--mime-confusion", action="store_true",
                       help="BLACKOUT batch-13: mime-confusion (OFFENSE-GATED)")
    eng.add_argument("--blind-relay", action="store_true",
                       help="BLACKOUT batch-13: blind-relay (OFFENSE-GATED)")
    eng.add_argument("--h2-probe", action="store_true",
                       help="BLACKOUT batch-13: h2-probe (OFFENSE-GATED)")
    eng.add_argument("--deser-probe", action="store_true",
                       help="MELTDOWN batch-14: deser-probe (OFFENSE-GATED)")
    eng.add_argument("--meta-ssrf", action="store_true",
                       help="MELTDOWN batch-14: meta-ssrf (OFFENSE-GATED)")
    eng.add_argument("--authz-matrix", action="store_true",
                       help="MELTDOWN batch-14: authz-matrix (OFFENSE-GATED)")
    eng.add_argument("--ci-sweep", action="store_true",
                       help="MELTDOWN batch-14: ci-sweep (OFFENSE-GATED)")
    eng.add_argument("--cors-probe", action="store_true",
                       help="MELTDOWN batch-14: cors-probe (OFFENSE-GATED)")
    eng.add_argument("--adaptive", action="store_true",
                       help="MELTDOWN batch-14: adaptive (OFFENSE-GATED)")
    eng.add_argument("--poc-gen", action="store_true",
                       help="NIGHTFALL batch-15: poc-gen")
    eng.add_argument("--chain-compose", action="store_true",
                       help="NIGHTFALL batch-15: chain-compose")
    eng.add_argument("--impact-score", action="store_true",
                       help="NIGHTFALL batch-15: impact-score")
    eng.add_argument("--jwt-deep", action="store_true",
                       help="NIGHTFALL batch-15: jwt-deep")
    eng.add_argument("--fp-exploit", action="store_true",
                       help="NIGHTFALL batch-15: fp-exploit")
    eng.add_argument("--report-diff", action="store_true",
                       help="NIGHTFALL batch-15: report-diff")
    eng.add_argument("--wordlist-gen", action="store_true",
                       help="NIGHTFALL batch-15: wordlist-gen")
    eng.add_argument("--rate-fprint", action="store_true",
                       help="NIGHTFALL batch-15: rate-fprint")
    eng.add_argument("--dos-expose", action="store_true",
                       help="NIGHTFALL batch-15: dos-expose")
    eng.add_argument("--destruct-shape", action="store_true",
                       help="NIGHTFALL batch-15: destruct-shape")
    eng.add_argument("--pwd-audit", action="store_true",
                       help="NIGHTFALL batch-15: pwd-audit")
    eng.add_argument("--verb-tamper", action="store_true",
                       help="PHANTOM batch-16: verb-tamper")
    eng.add_argument("--js-mine", action="store_true",
                       help="PHANTOM batch-16: js-mine")
    eng.add_argument("--shadow-disc", action="store_true",
                       help="PHANTOM batch-16: shadow-disc")
    eng.add_argument("--crlf-probe", action="store_true",
                       help="PHANTOM batch-16: crlf-probe")
    eng.add_argument("--subd-graph", action="store_true",
                       help="PHANTOM batch-16: subd-graph")
    eng.add_argument("--idor-oracle", action="store_true",
                       help="PHANTOM batch-16: idor-oracle")
    eng.add_argument("--narrative", action="store_true",
                       help="PHANTOM batch-16: narrative")
    eng.add_argument("--noise-audit", action="store_true",
                       help="PHANTOM batch-16: noise-audit")
    eng.add_argument("--auto-deep", action="store_true",
                       help="DEEPFROST batch-17: auto-deep")
    eng.add_argument("--fp-killer", action="store_true",
                       help="DEEPFROST batch-17: fp-killer")
    eng.add_argument("--session-life", action="store_true",
                       help="DEEPFROST batch-17: session-life")
    eng.add_argument("--smart-pace", action="store_true",
                       help="DEEPFROST batch-17: smart-pace")
    eng.add_argument("--evidence-pack", action="store_true",
                       help="DEEPFROST batch-17: evidence-pack")
    eng.add_argument("--portfolio", action="store_true",
                       help="DEEPFROST batch-17: portfolio")
    eng.add_argument("--self-test", action="store_true",
                       help="DEEPFROST batch-17: self-test")
    eng.add_argument("--html-report", action="store_true",
                       help="DEEPFROST batch-17: html-report")
    eng.add_argument("--rank-targets", action="store_true",
                     help="impact-ranked attack queue for this surface")
    eng.add_argument("--chain-proposals", action="store_true",
                     help="CHAIN GRAPH: pairwise-match findings into "
                          "exploit-chain PROPOSALS (never executed)")
    eng.add_argument("--json", action="store_true",
                     help="print the full engagement dict as JSON "
                          "instead of the markdown report")
    brain = sub.add_parser(
        "brain", help="run the autonomous decision-engine loop "
                      "(chooses its own capabilities per stage)")
    brain.add_argument("target", help="target host / URL to engage")
    brain.add_argument("--mode", default="auto",
                       help="engagement mode (default: auto)")
    brain.add_argument("--scope-ack", action="store_true",
                       help="acknowledge you are authorized to test the "
                            "target (REQUIRED)")
    brain.add_argument("--polyglot", action="store_true",
                       help="enable the polyglot adapter gates "
                            "(sets PTK_POLYGLOT=1: native adapters and "
                            "read-only system-binary tools)")
    brain.add_argument("--max-steps", type=int, default=25,
                       help="hard step limit for the loop (default: 25)")
    brain.add_argument("--oob", action="store_true",
                       help="pre-start the local out-of-band callback "
                            "server (127.0.0.1, ephemeral port) and "
                            "export OMEGA_OOB_BASE_URL for child suites")
    brain.add_argument("--offense", action="store_true",
                       help="ENABLE THE OFFENSE LAYER (sets PTK_OFFENSE=1)")
    brain.add_argument("--aggressive", action="store_true",
                       help="MAXIMUM POWER: enables polyglot + offense + "
                            "exploit layers, lifts budget caps and steps "
                            "to 100. Authorized targets only.")
    brain.add_argument("--exploit", action="store_true",
                       help="ENABLE THE EXPLOIT LAYER (sets PTK_EXPLOIT=1: "
                            "PoC exploitation of confirmed findings)")
    brain.add_argument("--risky-ok", dest="risky_ok", action="store_true",
                       help="MIDDLE TIER: PoC exploitation of confirmed "
                            "findings without full no-limits (sets "
                            "OMEGA_RISKY_OK=1; read-only PoCs only)")
    brain.add_argument("--autochain", action="store_true",
                       help="AUTO-CHAIN: multi-stage recon -> harvest -> "
                            "auth -> poc, evidence-gated (sets "
                            "OMEGA_AUTOCHAIN=1)")
    brain.add_argument("--authscan", action="store_true",
                       help="auth deep-scan: single login from "
                       "OMEGA_CREDS + session-fixation and "
                       "logout-invalidation checks")
    brain.add_argument("--critique", action="store_true",
                       help="post-scan self-critique (FP smells, "
                       "dead stages, followups)")
    brain.add_argument("--chain-proposals", action="store_true",
                       help="pairwise exploit-chain PROPOSALS "
                       "(never executed)")
    brain.add_argument("--hypothesize", action="store_true",
                       help="hypothesis-driven verification loop")
    brain.add_argument("--logic", action="store_true",
                       help="business-logic templates (dry-run by "
                       "default)")
    brain.add_argument("--kb", action="store_true",
                       help="expert-methodology suggestions from "
                       "the offline attack knowledge base")
    brain.add_argument("--waf-profile", action="store_true",
                       help="benign WAF/rate-limit probe ladder")
    brain.add_argument("--cvesuggest", action="store_true",
                       help="version-matched CVE leads from the "
                       "offline NVD feed")
    brain.add_argument("--multihypo", action="store_true",
                       help="multi-hypothesis engine: N competing hypotheses per signal, Bayes-ranked probes")
    brain.add_argument("--cwe-chain", action="store_true",
                       help="CWE-aware attack chain proposals over findings (plan only, gates explicit, never executed)")
    brain.add_argument("--spa-map", action="store_true",
                       help="static JS/SPA endpoint mapper (fetch/XHR/axios surface from bundles, no headless browser)")
    brain.add_argument("--waf-adapt", action="store_true",
                       help="fingerprint the protection layer and print the adaptive pacing/cookie strategy")
    brain.add_argument("--outcomes", action="store_true",
                       help="rank techniques by lessonsv2 win-rate (try what worked first)")

    brain.add_argument("--privesc", action="store_true",
                       help="post-exploit enumeration through CONFIRMED RCE only (EXPLOIT-GATED)")
    brain.add_argument("--authblast", action="store_true",
                       help="concurrent default-credential stuffing per tech fingerprint (OFFENSE-GATED)")
    brain.add_argument("--jwt-attack", action="store_true",
                       help="active JWT attacks: alg:none + weak HS256 re-sign (OFFENSE-GATED)")
    brain.add_argument("--attack-graph", action="store_true",
                       help="evidence-validated kill-chain attack graph over findings")
    brain.add_argument("--race-hunt", action="store_true",
                       help="race-condition hunter: N simultaneous requests, TOCTOU candidate (OFFENSE-GATED)")
    brain.add_argument("--second-order", action="store_true",
                       help="second-order injection: plant markers, re-crawl, cross-page replay (OFFENSE-GATED)")
    brain.add_argument("--biz-fuzz", action="store_true",
                       help="business-logic fuzzer: invalid values + action permutations (OFFENSE-GATED)")
    brain.add_argument("--exploit-loop", action="store_true",
                       help="closed-loop Bayesian exploit reasoning over hypotheses")
    brain.add_argument("--pivot-plan", action="store_true",
                       help="PLAN-ONLY post-exploit pivot plan from host state")
    brain.add_argument("--stack-route", action="store_true",
                       help="fingerprint-to-module routing for this stack")
    brain.add_argument("--crawl-state", action="store_true",
                       help="stateful session crawler: endpoints behind actions join the scan")
    brain.add_argument("--profiles", action="store_true",
                       help="adversary emulation profile (ATT&CK-tagged campaign)")
    brain.add_argument("--horizontal", action="store_true",
                       help="horizontal expansion: IDOR sweep + spray (OFFENSE-GATED)")
    brain.add_argument("--chain-run", action="store_true",
                       help="validated attack-chain execution with edge fallback (OFFENSE-GATED)")
    brain.add_argument("--evade-chain", action="store_true",
                       help="structured evasion ladder vs block detection (OFFENSE-GATED)")
    brain.add_argument("--api-special", action="store_true",
                       help="GraphQL/REST abuse: introspection, mass assignment, BOLA (OFFENSE-GATED)")
    brain.add_argument("--upload-fuzz", action="store_true",
                       help="upload bypass: extension tricks + inert execution markers (OFFENSE-GATED)")

    brain.add_argument("--smuggle", action="store_true",
                       help="BLACKOUT batch-13: smuggle (OFFENSE-GATED)")
    brain.add_argument("--cache-poison", action="store_true",
                       help="BLACKOUT batch-13: cache-poison (OFFENSE-GATED)")
    brain.add_argument("--ws-probe", action="store_true",
                       help="BLACKOUT batch-13: ws-probe (OFFENSE-GATED)")
    brain.add_argument("--proto-pollute", action="store_true",
                       help="BLACKOUT batch-13: proto-pollute (OFFENSE-GATED)")
    brain.add_argument("--session-matrix", action="store_true",
                       help="BLACKOUT batch-13: session-matrix (OFFENSE-GATED)")
    brain.add_argument("--mime-confusion", action="store_true",
                       help="BLACKOUT batch-13: mime-confusion (OFFENSE-GATED)")
    brain.add_argument("--blind-relay", action="store_true",
                       help="BLACKOUT batch-13: blind-relay (OFFENSE-GATED)")
    brain.add_argument("--h2-probe", action="store_true",
                       help="BLACKOUT batch-13: h2-probe (OFFENSE-GATED)")
    brain.add_argument("--deser-probe", action="store_true",
                       help="MELTDOWN batch-14: deser-probe (OFFENSE-GATED)")
    brain.add_argument("--meta-ssrf", action="store_true",
                       help="MELTDOWN batch-14: meta-ssrf (OFFENSE-GATED)")
    brain.add_argument("--authz-matrix", action="store_true",
                       help="MELTDOWN batch-14: authz-matrix (OFFENSE-GATED)")
    brain.add_argument("--ci-sweep", action="store_true",
                       help="MELTDOWN batch-14: ci-sweep (OFFENSE-GATED)")
    brain.add_argument("--cors-probe", action="store_true",
                       help="MELTDOWN batch-14: cors-probe (OFFENSE-GATED)")
    brain.add_argument("--adaptive", action="store_true",
                       help="MELTDOWN batch-14: adaptive (OFFENSE-GATED)")
    brain.add_argument("--poc-gen", action="store_true",
                       help="NIGHTFALL batch-15: poc-gen")
    brain.add_argument("--chain-compose", action="store_true",
                       help="NIGHTFALL batch-15: chain-compose")
    brain.add_argument("--impact-score", action="store_true",
                       help="NIGHTFALL batch-15: impact-score")
    brain.add_argument("--jwt-deep", action="store_true",
                       help="NIGHTFALL batch-15: jwt-deep")
    brain.add_argument("--fp-exploit", action="store_true",
                       help="NIGHTFALL batch-15: fp-exploit")
    brain.add_argument("--report-diff", action="store_true",
                       help="NIGHTFALL batch-15: report-diff")
    brain.add_argument("--wordlist-gen", action="store_true",
                       help="NIGHTFALL batch-15: wordlist-gen")
    brain.add_argument("--rate-fprint", action="store_true",
                       help="NIGHTFALL batch-15: rate-fprint")
    brain.add_argument("--dos-expose", action="store_true",
                       help="NIGHTFALL batch-15: dos-expose")
    brain.add_argument("--destruct-shape", action="store_true",
                       help="NIGHTFALL batch-15: destruct-shape")
    brain.add_argument("--pwd-audit", action="store_true",
                       help="NIGHTFALL batch-15: pwd-audit")
    brain.add_argument("--verb-tamper", action="store_true",
                       help="PHANTOM batch-16: verb-tamper")
    brain.add_argument("--js-mine", action="store_true",
                       help="PHANTOM batch-16: js-mine")
    brain.add_argument("--shadow-disc", action="store_true",
                       help="PHANTOM batch-16: shadow-disc")
    brain.add_argument("--crlf-probe", action="store_true",
                       help="PHANTOM batch-16: crlf-probe")
    brain.add_argument("--subd-graph", action="store_true",
                       help="PHANTOM batch-16: subd-graph")
    brain.add_argument("--idor-oracle", action="store_true",
                       help="PHANTOM batch-16: idor-oracle")
    brain.add_argument("--narrative", action="store_true",
                       help="PHANTOM batch-16: narrative")
    brain.add_argument("--noise-audit", action="store_true",
                       help="PHANTOM batch-16: noise-audit")
    brain.add_argument("--auto-deep", action="store_true",
                       help="DEEPFROST batch-17: auto-deep")
    brain.add_argument("--fp-killer", action="store_true",
                       help="DEEPFROST batch-17: fp-killer")
    brain.add_argument("--session-life", action="store_true",
                       help="DEEPFROST batch-17: session-life")
    brain.add_argument("--smart-pace", action="store_true",
                       help="DEEPFROST batch-17: smart-pace")
    brain.add_argument("--evidence-pack", action="store_true",
                       help="DEEPFROST batch-17: evidence-pack")
    brain.add_argument("--portfolio", action="store_true",
                       help="DEEPFROST batch-17: portfolio")
    brain.add_argument("--self-test", action="store_true",
                       help="DEEPFROST batch-17: self-test")
    brain.add_argument("--html-report", action="store_true",
                       help="DEEPFROST batch-17: html-report")
    brain.add_argument("--rank-targets", action="store_true",
                       help="impact-ranked attack queue for this surface")
    brain.add_argument("--brutal", action="store_true",
                       help="maximum power from the first request "
                       "(aggressive + no-limits + autochain in one "
                       "flag; --scope-ack still required)")
    brain.add_argument("--no-limits", action="store_true",
                       help="NO-LIMITS EXPLOIT LAYER (sets OMEGA_NO_LIMITS=1 "
                            "and implies --exploit): enables the maximum-"
                            "power drivers (traversal_deep, cmd_write, "
                            "privesc, shell_poc, persist_poc, chain). "
                            "Authorized targets only.")
    brain.add_argument("--json", action="store_true",
                       help="print the final BrainState summary as JSON")

    run = sub.add_parser(
        "run", help="run an engagement from a free-form prompt "
                    "(Indonesian or English)")
    run.add_argument("prompt", help="free-form prompt, e.g. "
                    '\"bug bounty scan ke example.com, lengkap, saya '
                    'berhak\"')
    run.add_argument("--polyglot", action="store_true",
                     help="force the polyglot adapter gates ON (explicit "
                          "override of the parsed flags)")
    run.add_argument("--followup", action="store_true",
                     help="enable the adaptive follow-up loop: run a "
                          "second-depth probe per finding, gated by the "
                          "claimcheck validation gate")
    run.add_argument("--with-tools", action="store_true",
                     help="force the read-only tool bridge ON (explicit "
                          "override of the parsed flags)")
    run.add_argument("--json", action="store_true",
                     help="print the final BrainState summary as JSON")

    sess = sub.add_parser(
        "sessions", help="list / show / diff saved sessions")
    sess.add_argument("action", choices=["list", "show", "diff"])
    sess.add_argument("names", nargs="*",
                      help="session name (show) or two names (diff)")

    watch_p = sub.add_parser(
        "watch", help="run one monitoring pass and diff against the "
                      "previous session for the same target")
    watch_p.add_argument("target", help="target host / URL to watch")
    watch_p.add_argument("--mode", default="auto",
                         help="engagement mode (default: auto)")
    watch_p.add_argument("--scope-ack", action="store_true",
                         help="acknowledge you are authorized to test the "
                              "target (REQUIRED)")
    watch_p.add_argument("--label", default=None,
                         help="session label (default: UTC timestamp)")
    watch_p.add_argument("--json", action="store_true",
                         help="print the watch result as JSON")

    sub.add_parser(
        "stats", help="print the OMEGA arsenal size: registry stats + "
                      "pytools/probes/deepchecks/fusion capability counts")

    dsl_p = sub.add_parser(
        "dsl", help="run user-writable YAML DSL checks against a target "
                    "(omega/dsl.py; read-only methods only)")
    dsl_p.add_argument("target", help="target base URL to check")
    dsl_p.add_argument("yamlfile", help="path to the YAML checks file")
    dsl_p.add_argument("--scope-ack", action="store_true",
                       help="acknowledge you are authorized to test the "
                            "target (REQUIRED)")
    dsl_p.add_argument("--budget", type=int, default=None,
                       help="max requests (rate cap)")
    dsl_p.add_argument("--json", action="store_true",
                       help="print the result as JSON")

    matrix_p = sub.add_parser(
        "matrix", help="run the WAF-evasion encoding matrix over a "
                       "harmless marker (omega/payloadmatrix.py)")
    matrix_p.add_argument("target", help="target base URL to probe")
    matrix_p.add_argument("--scope-ack", action="store_true",
                          help="acknowledge you are authorized to test "
                               "the target (REQUIRED)")
    matrix_p.add_argument("--budget", type=int, default=None,
                          help="max probe requests (rate cap, "
                               "default 96)")
    matrix_p.add_argument("--marker", default="omega-reflect-marker",
                          help="harmless reflection marker to encode")
    matrix_p.add_argument("--json", action="store_true",
                          help="print the result as JSON")

    brute_p = sub.add_parser(
        "brute", help="OFFENSE: brute-force a login form / HTTP basic "
                      "auth with an OPERATOR-SUPPLIED wordlist "
                      "(--offense required, hard rate caps)")
    brute_p.add_argument("target", help="target base URL")
    brute_p.add_argument("--scope-ack", action="store_true",
                         help="acknowledge you are authorized (REQUIRED)")
    brute_p.add_argument("--offense", action="store_true",
                         help="enable the offense layer (REQUIRED)")
    brute_p.add_argument("--wordlist", default=None,
                         help="path to user:pass wordlist file")
    brute_p.add_argument("--login-path", default="/login",
                         help="login form path (default /login)")
    brute_p.add_argument("--fields", default="username,password",
                         help="field names user,password")
    brute_p.add_argument("--max-attempts", type=int, default=50,
                         help="hard attempt cap (default 50)")
    brute_p.add_argument("--json", action="store_true",
                         help="print the result as JSON")

    inject_p = sub.add_parser(
        "inject", help="OFFENSE: run the injection payload runner "
                       "(SQLi/CMDi/SSTI/XSS/traversal classes, "
                       "differential confirm) (--offense required)")
    inject_p.add_argument("target", help="target base URL")
    inject_p.add_argument("--scope-ack", action="store_true",
                          help="acknowledge you are authorized (REQUIRED)")
    inject_p.add_argument("--offense", action="store_true",
                          help="enable the offense layer (REQUIRED)")
    inject_p.add_argument("--param", default="q",
                          help="parameter to inject (default q)")
    inject_p.add_argument("--budget", type=int, default=100,
                          help="max requests (default 100)")
    inject_p.add_argument("--json", action="store_true",
                          help="print the result as JSON")

    report_p = sub.add_parser(
        "report", help="generate a report from stored session findings "
                       "(markdown/html/json/docx/pdf)")
    report_p.add_argument("session", help="session name (from "
                        "`omega sessions list`) or '-' for the latest")
    report_p.add_argument("--format", default=None,
                          choices=["markdown", "html", "json", "docx",
                                   "pdf", "dojo-csv", "dojo-json"],
                          help="report format (default markdown; "
                               "dojo-csv/dojo-json export DefectDojo-"
                               "compatible files)")
    report_p.add_argument("--out", default=None,
                          help="output file path (extension picks the "
                               "format when --format is omitted)")
    report_p.add_argument("--lang", default=None,
                          help="report label language (e.g. en, es, "
                               "fr, de, pt, zh, ja, ar, ru, hi)")

    validate_p = sub.add_parser(
        "validate", help="validate AI-proposed findings against the live "
                         "target (refute hallucinated claims before "
                         "reporting)")
    validate_p.add_argument("claims", help="path to a JSON file containing "
                          "a list of findings proposed by an assistant")
    validate_p.add_argument("--base", default=None,
                            help="base URL used when claim locations are "
                                 "relative paths")
    validate_p.add_argument("--json", action="store_true",
                            help="print validated claims as JSON")
    validate_p.add_argument("--drop-refuted", action="store_true",
                            help="omit refuted/unverifiable claims from "
                                 "the JSON output")

    followup_p = sub.add_parser(
        "followup", help="run the adaptive follow-up loop over a findings "
                         "JSON file: second-depth probes per finding type, "
                         "gated by the claimcheck validation gate")
    followup_p.add_argument("findings", help="path to a JSON file containing"
                          " a list of scanner findings")
    followup_p.add_argument("--base", default=None,
                            help="base URL used when finding locations are "
                                 "relative paths")
    followup_p.add_argument("--json", action="store_true",
                            help="print the full followup result as JSON")
    followup_p.add_argument("--budget", type=int, default=None,
                            help="max probes (default: OMEGA_FOLLOWUP_MAX "
                                 "or 12)")

    report_p.add_argument("--summary", action="store_true",
                          help="print a token-efficient summary (counts "
                               "per severity + top findings) instead of "
                               "the full report")

    campaign_p = sub.add_parser(
        "campaign", help="multi-target campaign: scan a list of targets "
                         "with a scan profile pack and produce one "
                         "combined report")
    campaign_p.add_argument(
        "targets",
        help="comma-separated targets (hosts/URLs) or a path to a text "
             "file with one target per line")
    campaign_p.add_argument(
        "--profile", default="web",
        help="scan profile pack: %s (default: web)"
             % ", ".join(["quick", "web", "full", "cloud", "mobile",
                          "api", "llm"]))
    campaign_p.add_argument("--scope-ack", action="store_true",
                            help="REQUIRED: acknowledge you are "
                                 "authorized to test these targets")
    campaign_p.add_argument("--aggressive", action="store_true",
                            help="open the offense/exploit gates "
                                 "(off by default)")
    campaign_p.add_argument("--out", default=None,
                            help="combined report path (.md or .pdf)")
    campaign_p.add_argument("--json", action="store_true",
                            help="print the campaign result as JSON")

    cf_p = sub.add_parser(
        "cvefeed", help="OFFLINE: build/refresh the compact CVE index "
                        "from a LOCALLY downloaded NVD JSON feed "
                        "(1.1 or 2.0 single file) and print counts. "
                        "Never fetches the network. CVE lookups are NOT "
                        "done here — the libcve scanning suite matches "
                        "fingerprinted JS libraries against this index "
                        "automatically during scans.")
    cf_p.add_argument("--feed", default=None,
                      help="path to the local NVD feed JSON "
                           "(default: OMEGA_CVE_FEED)")
    cf_p.add_argument("--index", default=None,
                      help="index output path (default: OMEGA_CVE_INDEX "
                           "or ~/.cache/omega/cve_index.json)")
    cf_p.add_argument("--status", action="store_true",
                      help="print index status (counts, staleness) "
                           "without refreshing")
    chains_p = sub.add_parser(
        "chains", help="recommend exploit chains from stored session "
                       "findings (deterministic, evidence-grounded, "
                       "planning only — never executed)")
    chains_p.add_argument("session",
                          help="session name (from `omega sessions "
                               "list`), a findings JSON path, or '-' "
                               "to read findings JSON from stdin",
                          default=None, nargs="?")
    chains_p.add_argument("--json", action="store_true",
                          help="print the plan as JSON instead of the "
                               "readable report")
    evade_p = sub.add_parser(
        "evade", help="probe the target's defenses (WAF / rate limiting) "
                      "and report which adaptive evasion tactics would "
                      "be used — PLANNING ONLY, no attack is executed")
    evade_p.add_argument("target", help="target base URL to probe")
    evade_p.add_argument("--scope-ack", action="store_true",
                         help="acknowledge you are authorized (REQUIRED)")
    evade_p.add_argument("--path", default="/",
                         help="path to probe (default /)")
    evade_p.add_argument("--json", action="store_true",
                         help="print the defense result as JSON")
    pb_p = sub.add_parser(
        "playbook", help="multi-stage attack playbooks: `omega playbook "
                         "list` shows them; `omega playbook NAME SESSION "
                         "--stage N --scope-ack` runs ONE gated, "
                         "evidence-checked stage")
    pb_p.add_argument("name",
                      help="playbook name (e.g. auth-takeover) or 'list'")
    pb_p.add_argument("session", nargs="?",
                      help="session name (from `omega sessions list`), "
                           "'-' for the latest, or a path to a raw "
                           "findings JSON file (required when running a "
                           "stage)")
    pb_p.add_argument("--stage", type=int, default=None,
                      help="stage index to execute (omit to print the "
                           "plan only)")
    pb_p.add_argument("--scope-ack", action="store_true",
                      help="acknowledge you are authorized (REQUIRED to "
                           "run a stage)")
    pb_p.add_argument("--json", action="store_true",
                      help="print machine-readable JSON")
    assets_p = sub.add_parser(
        "assets", help="show the persistent asset graph accumulated "
                       "across all runs (hosts, urls, techs, findings "
                       "with first/last-seen)")
    assets_p.add_argument("host", nargs="?",
                          help="show detail for one host (omit for a "
                               "summary of every host)")
    assets_p.add_argument("--json", action="store_true",
                          help="print the graph (or host detail) as JSON")
    args = parser.parse_args(argv)

    if args.command == "assets":
        return _run_assets(args)

    if args.command == "playbook":
        return _run_playbook(args)

    if args.command == "evade":
        return _run_evade(args)
    if args.command == "report":
        return _run_report(args)
    if args.command == "chains":
        return _run_chains(args)
    if args.command == "campaign":
        return _run_campaign(args)
    if args.command == "cvefeed":
        return _run_cvefeed(args)
    if args.command == "validate":
        return _run_validate(args)
    if args.command == "followup":
        return _run_followup(args)
    if getattr(args, "version", False):
        from omega import __version__
        print("OMEGA v%s" % __version__)
        return 0

    if args.command == "brute":
        return _run_brute(args)
    if args.command == "inject":
        return _run_inject(args)
    if args.command == "dsl":
        return _run_dsl(args)
    if args.command == "matrix":
        return _run_matrix(args)

    if args.command == "watch":
        return _run_watch(args)
    if args.command == "stats":
        return _run_stats(args)
    if args.command == "run":
        return _run_prompt(args)
    if args.command == "sessions":
        return _run_sessions(args)

    if args.command not in ("engage", "brain"):
        parser.print_help()
        return 0

    # SAFETY GATE: scope acknowledgment is mandatory.
    if not args.scope_ack:
        print("ERROR: --scope-ack is required. OMEGA will not run an "
              "engagement without explicit operator acknowledgment that "
              "you are authorized to test this target.", file=sys.stderr)
        return 2

    # BRUTAL MODE: OMEGA_BRUTAL_DEFAULT=1 (env, set in .zshrc) makes
    # every scan start at maximum power WITHOUT extra flags. --brutal
    # does the same explicitly. --scope-ack stays mandatory — that is
    # the one line that keeps accidental-target scans impossible.
    brutal_default = os.environ.get("OMEGA_BRUTAL_DEFAULT") == "1"
    if getattr(args, "brutal", False) or brutal_default:
        args.aggressive = True
        args.no_limits = True
        args.autochain = True
        os.environ["OMEGA_NO_LIMITS"] = "1"

    # MAXIMUM POWER: --aggressive turns on every layer and lifts the
    # budget caps. Individual flags still take precedence when set.
    if getattr(args, "aggressive", False):
        os.environ["PTK_POLYGLOT"] = "1"
        os.environ["PTK_OFFENSE"] = "1"
        os.environ["PTK_EXPLOIT"] = "1"
        os.environ.setdefault("OMEGA_AGGRESSIVE", "1")
        os.environ.setdefault("OMEGA_MAX_REQUESTS", "100000")
        os.environ.setdefault("OMEGA_FUSION_BUDGET", "500")
        if args.command == "brain":
            args.max_steps = max(getattr(args, "max_steps", 25) or 25, 100)

    # Polyglot gate: system-binary + native adapters stay disabled
    # unless explicitly enabled per invocation.
    if getattr(args, "polyglot", False):
        os.environ["PTK_POLYGLOT"] = "1"
    elif not getattr(args, "aggressive", False):
        os.environ.pop("PTK_POLYGLOT", None)

    # Offense gate (separate from polyglot; explicit opt-in only).
    if getattr(args, "offense", False) or getattr(args, "aggressive", False):
        os.environ["PTK_OFFENSE"] = "1"
    else:
        os.environ.pop("PTK_OFFENSE", None)

    # Exploit gate: PoC exploitation of confirmed findings.
    if getattr(args, "exploit", False) or getattr(args, "aggressive", False):
        os.environ["PTK_EXPLOIT"] = "1"
    else:
        os.environ.pop("PTK_EXPLOIT", None)

    # No-limits gate: maximum-power exploit drivers, layered ON TOP of
    # the exploit gate (--no-limits implies --exploit).
    if getattr(args, "no_limits", False):
        os.environ["OMEGA_NO_LIMITS"] = "1"
        os.environ["PTK_EXPLOIT"] = "1"

    # Risky-ok middle tier: PoC exploitation of confirmed findings
    # WITHOUT the full no-limits driver set. Read-only PoCs only —
    # destructive / data-mutating drivers stay gated behind
    # OMEGA_NO_LIMITS.
    if getattr(args, "risky_ok", False):
        os.environ["OMEGA_RISKY_OK"] = "1"

    # Auto-chain: multi-stage execution (recon -> harvest -> auth ->
    # poc). Explicit operator opt-in only, like every other offense
    # tier.
    if getattr(args, "autochain", False):
        os.environ["OMEGA_AUTOCHAIN"] = "1"

    oob_server = start_oob_server(args)
    try:
        if args.command == "brain":
            return _run_brain(args)

        # Engine resolution (clean degradation if missing).
        try:
            engagement, _toolbridge = load_engine()
        except EngineHomeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 3

        if args.mode not in engagement.MODES:
            print(f"ERROR: unknown mode {args.mode!r}; choices: "
                  f"{', '.join(sorted(engagement.MODES))}", file=sys.stderr)
            return 2

        if args.with_tools:
            os.environ["PTK_TOOLS"] = "1"
        else:
            os.environ.pop("PTK_TOOLS", None)

        try:
            result = engagement.run_engagement(
                args.target, mode=args.mode, scope_ack=True)
        except (PermissionError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

        # run the shared post-scan extras on an engine-result shim
        # so --authscan/--critique/--chain-proposals/--hypothesize/
        # --logic/--kb/--waf-profile/--cvesuggest actually execute
        # on the engage path too (QA HIGH #1 fix)
        shim = _EngineStateShim(args, result)
        _run_post_scan_extras(args, shim)

        if args.json:
            import json
            print(json.dumps(result, indent=2, default=str))
        else:
            print(engagement.render_report(result))
        return 0
    finally:
        _stop_oob_server(oob_server)


def _parse_campaign_targets(raw):
    """Comma-separated targets string OR path to a file with one
    target per line. Returns a list; empty when nothing usable."""
    raw = str(raw or "").strip()
    if not raw:
        return []
    if os.path.isfile(raw):
        try:
            with open(raw, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return []
        return [ln.strip() for ln in lines
                if ln.strip() and not ln.strip().startswith("#")]
    return [p.strip() for p in raw.split(",") if p.strip()]


def _run_campaign(args):
    """Multi-target campaign via omega.core.campaign. Exit 2 without
    --scope-ack (same convention as brain/dsl/matrix)."""
    gated = _scope_gate(args)
    if gated is not None:
        return gated
    targets = _parse_campaign_targets(getattr(args, "targets", ""))
    if not targets:
        print("ERROR: no usable targets supplied (comma-separated "
              "targets or a file path).", file=sys.stderr)
        return 1
    from omega.core.campaign import run_campaign
    result = run_campaign(targets, profile=getattr(args, "profile", "web"),
                          scope_ack=True,
                          aggressive=bool(getattr(args, "aggressive",
                                                  False)),
                          out=getattr(args, "out", None))
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, default=str))
        return 0
    per = result.get("per_target") or {}
    print("campaign: profile=%s targets=%d ok=%s"
          % (result.get("profile"), len(per), result.get("ok")))
    for tgt, info in per.items():
        if info.get("status") == "skipped":
            print("  [skipped] %s — %s" % (tgt, info.get("reason", "")))
        else:
            print("  [%s] %s (%d finding(s), %d corroborated)"
                  % (info.get("status"), tgt, info.get("count", 0),
                     info.get("corroborated", 0)))
    if result.get("report_path"):
        print("report written: %s" % result["report_path"])
    if result.get("truncated"):
        print("NOTE: target list was truncated to the campaign cap "
              "(OMEGA_CAMPAIGN_MAX).")
    if result.get("error"):
        print("note: %s" % result["error"])
    return 0


def _scope_gate(args):
    """Shared scope-ack gate for the dsl/matrix subcommands: returns an
    exit code (2) when --scope-ack is missing, else None."""
    if not getattr(args, "scope_ack", False):
        print("ERROR: --scope-ack is required. OMEGA will not run "
              "'%s' without explicit operator acknowledgment that you "
              "are authorized to test this target."
              % getattr(args, "command", "?"), file=sys.stderr)
        return 2
    return None


def _offense_env(args):
    """Enable PTK_OFFENSE when --offense passed; return True if enabled."""
    if getattr(args, "offense", False):
        os.environ["PTK_OFFENSE"] = "1"
        return True
    os.environ.pop("PTK_OFFENSE", None)
    print("ERROR: --offense is required for this command. The offense "
          "layer stays disabled unless explicitly enabled.",
          file=sys.stderr)
    return False


def _print_findings(result, header):
    findings = result.get("findings") or []
    print(header)
    for k, v in (result.get("skipped") or {}).items():
        print("  skipped : %s — %s" % (k, v))
    for f in findings:
        print("  [%s/%s] %s" % (f.get("severity"),
                                f.get("verification"),
                                f.get("title")))
    print("  findings: %d" % len(findings))


def _run_cvefeed(args):
    """OFFLINE: refresh the compact CVE index from a local NVD feed."""
    from omega.cvefeed import refresh, status
    if getattr(args, "status", False):
        st = status(path=args.index)
        print(json.dumps(st, indent=2, default=str))
        return 0
    result = refresh(args.feed, index_out=args.index) or {}
    if not result.get("ok"):
        print("ERROR: %s" % result.get("error", "refresh failed"),
              file=sys.stderr)
        return 1
    print("cvefeed index refreshed: %s" % result.get("index"))
    print("  feed     : %s" % result.get("feed"))
    print("  entries  : %s" % result.get("entries"))
    print("  cves     : %s" % result.get("cves"))
    print("  products : %s" % result.get("products"))
    if result.get("errors"):
        print("  errors   : %d item(s) skipped" % len(result["errors"]))
    return 0


def _run_validate(args):
    """VALIDATION GATE: re-check AI-proposed findings against the live
    target; refuted/unverifiable claims are flagged (or dropped) so a
    hallucinated finding can never reach the report."""
    import json as _json
    try:
        with open(args.claims, "r", encoding="utf-8") as fh:
            claims = _json.load(fh)
    except (OSError, ValueError) as exc:
        print("ERROR: cannot read claims %r: %s" % (args.claims, exc),
              file=sys.stderr)
        return 1
    if isinstance(claims, dict):
        claims = [claims]
    if not isinstance(claims, list):
        print("ERROR: claims file must contain a JSON list of findings",
              file=sys.stderr)
        return 1
    from omega.scanning.claimcheck import validate_claims
    results, stats = validate_claims(claims, base_url=args.base)
    dropped_kinds = ("refuted", "unverifiable", "unreachable")
    kept = [r for r in results
            if not (args.drop_refuted
                    and r.get("validation") in dropped_kinds)]
    kept_stats = {"refuted": sum(
        1 for r in kept if r.get("validation") == "refuted")}
    if args.json:
        print(_json.dumps(kept, indent=2))
    else:
        for r in results:
            print("[%s] %s @ %s — %s" % (
                r.get("validation", "?").upper(),
                str(r.get("title", r.get("raw", "?")))[:60],
                r.get("location") or r.get("url") or "-",
                r.get("validation_note", "")))
        print("\nstats: %s" % stats)
    return 0 if kept_stats["refuted"] == 0 else 2


def _run_followup(args):
    """ADAPTIVE FOLLOW-UP LOOP: run a second-depth probe per finding from
    a findings JSON file; every probe claim passes the claimcheck gate so
    nothing unverified is reported."""
    import json as _json
    try:
        with open(args.findings, "r", encoding="utf-8") as fh:
            findings = _json.load(fh)
    except (OSError, ValueError) as exc:
        print("ERROR: cannot read findings %r: %s" % (args.findings, exc),
              file=sys.stderr)
        return 1
    if isinstance(findings, dict):
        findings = [findings]
    if not isinstance(findings, list):
        print("ERROR: findings file must contain a JSON list of findings",
              file=sys.stderr)
        return 1
    from omega.scanning.followup import run_followups
    res = run_followups(findings, base_url=args.base, budget=args.budget)
    if args.json:
        print(_json.dumps(res, indent=2, default=str))
    else:
        for f in res["findings"]:
            fu = f.get("followup") or {}
            print("[followup:%s] %s" % (
                fu.get("status", "unprobed"),
                str(f.get("title", "?"))[:70]))
        for r in res["refuted"]:
            print("[refuted] %s — %s" % (
                str(r.get("title", "?"))[:60],
                r.get("validation_note", "")))
        for s in res["skipped"]:
            print("[skipped] %s — %s" % (s.get("title", "?"),
                                         s.get("reason", "")))
        print("\nprobes: %d | refuted: %d | skipped: %d" % (
            res["probes"], len(res["refuted"]), len(res["skipped"])))
    return 0


def _run_evade(args):
    """EVADE: probe the target's defenses and report the tactic plan.

    PLANNING ONLY — no attack is executed here; the AI/operator loop
    uses the plan with run_adaptive() when explicitly instructed."""
    gated = _scope_gate(args)
    if gated is not None:
        return gated
    from omega.offensive.evasion import (
        jsonify, plan_tactics, probe_defense, render_report)

    from omega.deepchecks import default_fetch
    defense = probe_defense(default_fetch, args.target,
                            path=getattr(args, "path", "/") or "/")
    plan = plan_tactics(defense)
    if getattr(args, "json", False):
        print(jsonify({"target": args.target, "defense": defense,
                       "tactics": plan}))
    else:
        print("omega evade: %s%s" % (args.target,
                                     getattr(args, "path", "/") or "/"))
        print(render_report(defense, plan))
        print("  note       : planning only — no attack executed")
    return 0


def _print_findings_summary(target, findings):
    """Token-efficient report summary: severity counts + top findings."""
    import collections as _cl
    counts = _cl.Counter(
        str(f.get("severity", "INFO")).upper() for f in findings)
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    print("SUMMARY %s — %d finding(s)" % (target, len(findings)))
    for sev in order:
        if counts.get(sev):
            print("  %s: %d" % (sev, counts[sev]))
    rank = {s: i for i, s in enumerate(order)}
    top = sorted(findings,
                 key=lambda f: rank.get(
                     str(f.get("severity", "INFO")).upper(), 9))[:5]
    print("\ntop findings:")
    for f in top:
        print("  [%s/%s] %s @ %s" % (
            str(f.get("severity", "?")).upper(),
            f.get("verification", "?"),
            str(f.get("title", "?"))[:70],
            str(f.get("location", "-"))[:60]))
    print("\n(full report: omega report - --out report.md)")


def _run_report(args):
    """Generate a report from a stored session (markdown/html/json/
    docx/pdf). '-' selects the most recently modified session."""
    from omega import session as session_mod
    from omega.report import generate_report, write_report

    name = args.session
    if name == "-":
        sessions = session_mod.list_sessions() or []
        if not sessions:
            print("ERROR: no stored sessions found. Run a scan first "
                  "(e.g. `omega brain <target> --scope-ack`).",
                  file=sys.stderr)
            return 1
        directory = session_mod.sessions_dir()
        name = max(sessions, key=lambda s: os.path.getmtime(
            os.path.join(directory, "%s.json" % s)))
    try:
        doc = session_mod.load_session(name)
    except (OSError, ValueError, KeyError) as exc:
        print("ERROR: cannot load session %r: %s" % (name, exc),
              file=sys.stderr)
        return 1
    state = doc.get("state") or doc
    findings = state.get("findings") or []
    target = doc.get("target") or state.get("target") or "unknown"
    meta = {"session": name, "timestamp": doc.get("timestamp")}
    if getattr(args, "summary", False):
        _print_findings_summary(target, findings)
        return 0
    fmt = args.format
    if fmt in ("dojo-csv", "dojo-json"):
        from omega.reporting.dojo import export_dojo
        out = export_dojo(findings, fmt=fmt.split("-")[1], path=args.out)
        if isinstance(out, dict) and out.get("error"):
            print("ERROR: %s" % out["error"], file=sys.stderr)
            return 1
        print("dojo report written: %s (%d findings)" % (out,
                                                         len(findings)))
        return 0
    if args.out:
        path = write_report(target, findings, args.out, fmt=fmt,
                            meta=meta, lang=args.lang)
        print("report written: %s (%d findings)" % (path, len(findings)))
        return 0
    if fmt in ("docx", "pdf"):
        print("ERROR: --format %s requires --out <file>" % fmt,
              file=sys.stderr)
        return 1
    print(generate_report(target, findings, meta=meta,
                          fmt=fmt or "markdown", lang=args.lang))
    return 0


def _load_findings_arg(name):
    """Load (findings, target) from a raw JSON file or a stored session.

    Shared by the playbook CLI; returns (findings, target, error). Never
    raises: error is a non-None message on failure.
    """
    if os.path.isfile(name) or name.endswith(".json"):
        try:
            with open(name, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as exc:
            return None, None, ("cannot read findings file %r: %s"
                                % (name, exc))
        if isinstance(doc, dict):
            state = doc.get("state") or doc
            findings = state.get("findings")
            target = doc.get("target") or state.get("target")
            if target == "unknown":
                target = None
        else:
            findings, target = doc, None
        if not isinstance(findings, list):
            return None, None, "%r does not contain a findings list" % name
        return findings, target, None
    from omega import session as session_mod
    if name == "-":
        sessions = session_mod.list_sessions() or []
        if not sessions:
            return None, None, ("no stored sessions found. Run a scan "
                                "first (e.g. `omega brain <target> "
                                "--scope-ack`).")
        directory = session_mod.sessions_dir()
        name = max(sessions, key=lambda s: os.path.getmtime(
            os.path.join(directory, "%s.json" % s)))
    try:
        doc = session_mod.load_session(name)
    except (OSError, ValueError, KeyError) as exc:
        return None, None, "cannot load session %r: %s" % (name, exc)
    state = doc.get("state") or doc
    findings = state.get("findings") or []
    target = doc.get("target") or state.get("target") or None
    return findings, target, None


def _run_playbook(args):
    """Attack playbooks CLI: `list`, plan (no --stage) or run ONE gated,
    evidence-checked stage (--stage N, requires --scope-ack). Never
    raises; a closed gate refuses the stage and is never auto-opened.
    """
    from omega.offensive.playbook import (
        PLAYBOOKS, format_plan, get_playbook, list_playbooks, run_stage)

    name = str(args.name or "list").strip().lower()
    if name == "list" or get_playbook(name) is None:
        if name != "list":
            print("ERROR: unknown playbook %r. Known: %s"
                  % (name, ", ".join(list_playbooks())), file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps({"playbooks": [
                {"name": n, "requires": PLAYBOOKS[n]["requires"],
                 "requires_no_limits": PLAYBOOKS[n]["requires_no_limits"],
                 "stages": [{"stage": s["stage"], "gate": s["gate"],
                             "probe": s["probe"]}
                            for s in PLAYBOOKS[n]["stages"]]}
                for n in list_playbooks()]}, indent=2))
        else:
            print("attack playbooks (multi-stage, gated, evidence-checked):")
            for n in list_playbooks():
                pb = PLAYBOOKS[n]
                gates = "/".join(sorted({s["gate"] for s in pb["stages"]}))
                print("  %-18s %d stage(s); gates: %s" %
                      (n, len(pb["stages"]), gates))
                print("      run: omega playbook %s SESSION --stage N "
                      "--scope-ack" % n)
        return 0

    if args.stage is not None and not args.scope_ack:
        print("ERROR: running a playbook stage requires --scope-ack "
              "(authorization acknowledgement).", file=sys.stderr)
        return 1
    if args.stage is not None and not args.session:
        print("ERROR: a SESSION (session name, '-' for latest, or a "
              "findings JSON file) is required to run a stage.",
              file=sys.stderr)
        return 1
    findings, target, err = _load_findings_arg(args.session)
    if err:
        print("ERROR: %s" % err, file=sys.stderr)
        return 1

    pb = get_playbook(name)
    if args.stage is None:
        # planning only: print the plan (stages, gates, abort conditions)
        if args.json:
            from omega.offensive.playbook import plan
            print(json.dumps(plan(name, findings, target), indent=2,
                             default=str))
        else:
            print(format_plan(pb, findings, target))
        return 0

    from omega.scanning.deepchecks import default_fetch
    res = run_stage(name, args.stage, default_fetch, target, findings)
    if args.json:
        print(json.dumps(res, indent=2, default=str))
    else:
        print("playbook   : %s (stage %s: %s)"
              % (name, res.get("stage_idx"), res.get("stage")))
        print("gate       : %s" % res.get("gate_required"))
        print("executed   : %s" % res.get("executed"))
        print("verified   : %s" % res.get("verified"))
        print("refuted    : %s" % res.get("refuted"))
        if res.get("stop_reason"):
            print("stop reason: %s" % res["stop_reason"])
        if res.get("detail"):
            print("detail     : %s" % res["detail"])
        f = res.get("finding")
        if isinstance(f, dict):
            print("finding    : %s (%s, %s)" % (
                f.get("title"), f.get("severity"),
                f.get("validation") or f.get("verification")))
            print("location   : %s" % f.get("location"))
    if res.get("refuted"):
        print("NOTE: stage REFUTED — the playbook stops here; record "
              "this reason and do not continue.", file=sys.stderr)
    return 0


def _run_chains(args):
    """PLANNING: recommend exploit chains from session findings.

    Loads a stored session exactly like `_run_report` does, or a raw
    findings JSON file (a list of finding dicts or a {"findings": [...]}
    / {"state": {"findings": [...]}} object). Prints a readable plan or
    --json. Chains are recommendations only — never executed here.
    """
    from omega import session as session_mod
    from omega.core.chainreco import format_plan, recommend

    name = args.session
    if not name:
        print("ERROR: a session name, findings JSON path, or '-' "
              "(stdin) is required. Run `omega sessions list` for "
              "available sessions.", file=sys.stderr)
        return 1
    target = None
    findings = None
    if name == "-":
        # stdin mode: raw findings JSON piped from another command.
        try:
            doc = json.load(sys.stdin)
        except ValueError as exc:
            print("ERROR: invalid findings JSON on stdin: %s" % exc,
                  file=sys.stderr)
            return 1
        if isinstance(doc, dict):
            state = doc.get("state") or doc
            findings = state.get("findings")
            target = doc.get("target") or state.get("target")
            if target == "unknown":
                target = None
        else:
            findings = doc
        if not isinstance(findings, list):
            print("ERROR: stdin JSON does not contain a findings list",
                  file=sys.stderr)
            return 1
    elif os.path.isfile(name) or name.endswith(".json"):
        try:
            with open(name, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as exc:
            print("ERROR: cannot read findings file %r: %s"
                  % (name, exc), file=sys.stderr)
            return 1
        if isinstance(doc, dict):
            state = doc.get("state") or doc
            findings = state.get("findings")
            target = doc.get("target") or state.get("target")
            if target == "unknown":
                target = None
        else:
            findings = doc
        if not isinstance(findings, list):
            print("ERROR: %r does not contain a findings list"
                  % name, file=sys.stderr)
            return 1
    else:
        try:
            doc = session_mod.load_session(name)
        except (OSError, ValueError, KeyError) as exc:
            print("ERROR: cannot load session %r: %s" % (name, exc),
                  file=sys.stderr)
            return 1
        state = doc.get("state") or doc
        findings = state.get("findings") or []
        target = doc.get("target") or state.get("target") or None

    plan = recommend(findings, target=target)
    if args.json:
        print(json.dumps(plan, indent=2, default=str))
    else:
        print(format_plan(plan, target=target))
    return 0


def _run_brute(args):
    """OFFENSE: brute-force a login form with operator wordlist."""
    if not _offense_env(args):
        return 2
    gated = _scope_gate(args)
    if gated is not None:
        return gated
    from omega.deepchecks import default_fetch
    from omega.offense.brute import brute_form

    fields = tuple(args.fields.split(","))
    result = brute_form(default_fetch, args.login_path, fields,
                        wordlist_path=args.wordlist,
                        base_url=args.target,
                        max_attempts=args.max_attempts) or {}
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print("omega brute: %s%s" % (args.target, args.login_path))
        print("  found   : %s" % (result.get("found") or "None"))
        print("  attempts: %s (%s)" % (result.get("attempts"),
                                       result.get("stop_reason")))
    return 0


def _run_inject(args):
    """OFFENSE: run the injection payload runner."""
    if not _offense_env(args):
        return 2
    gated = _scope_gate(args)
    if gated is not None:
        return gated
    from omega.deepchecks import default_fetch
    from omega.offense.injection import run_injections

    result = run_injections(args.target, args.param, default_fetch,
                            budget=args.budget) or {}
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_findings(result, "omega inject: %s (param %r)"
                        % (args.target, args.param))
    return 0


def _run_dsl(args):
    """Run omega.dsl.run_dsl_checks from the CLI (scope-gated)."""
    gated = _scope_gate(args)
    if gated is not None:
        return gated
    from omega.dsl import run_dsl_checks

    result = run_dsl_checks(args.target, args.yamlfile,
                            budget=args.budget) or {}
    findings = result.get("findings") or []
    if args.json:
        print(json.dumps({
            "target": args.target, "yaml": args.yamlfile,
            "ran": result.get("ran") or [],
            "skipped": result.get("skipped") or {},
            "findings": [dict(f) for f in findings],
        }, indent=2, default=str))
    else:
        print("omega dsl: %s (%s)" % (args.target, args.yamlfile))
        print("  ran     : %s" % (result.get("ran") or []))
        for k, v in (result.get("skipped") or {}).items():
            print("  skipped : %s — %s" % (k, v))
        for f in findings:
            print("  [%s/%s] %s" % (f.get("severity"),
                                    f.get("verification"),
                                    f.get("title")))
        print("  findings: %d" % len(findings))
    return 0


def _run_matrix(args):
    """Run omega.payloadmatrix.matrix_runner from the CLI
    (scope-gated)."""
    gated = _scope_gate(args)
    if gated is not None:
        return gated
    from omega.deepchecks import default_fetch
    from omega.payloadmatrix import matrix_runner

    result = matrix_runner(args.target, args.marker, default_fetch,
                           budget=args.budget) or {}
    findings = result.get("findings") or []
    if args.json:
        print(json.dumps({
            "target": args.target, "marker": args.marker,
            "requests_sent": result.get("requests_sent"),
            "skipped": result.get("skipped") or {},
            "findings": [dict(f) for f in findings],
        }, indent=2, default=str))
    else:
        print("omega matrix: %s (marker %r)" % (args.target, args.marker))
        print("  requests: %s" % result.get("requests_sent"))
        for k, v in (result.get("skipped") or {}).items():
            print("  skipped : %s — %s" % (k, v))
        for f in findings:
            print("  [%s/%s] %s" % (f.get("severity"),
                                    f.get("verification"),
                                    f.get("title")))
        print("  findings: %d" % len(findings))
        if findings:
            print("  note    : WAF-weakness signal — REQUIRES MANUAL "
                  "WAF ANALYSIS")
    return 0


def _run_watch(args):
    """Run one watch pass; exit code = alert_exit_code (cron-friendly)."""
    from omega import watch as watch_mod

    if not args.scope_ack:
        print("ERROR: --scope-ack is required. OMEGA will not run a "
              "watch engagement without explicit operator acknowledgment "
              "that you are authorized to test this target.", file=sys.stderr)
        return 2
    try:
        result = watch_mod.watch(
            args.target, mode=args.mode, scope_ack=True,
            max_steps=12, session_label=args.label)
    except (PermissionError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(result["report_markdown"])
    return watch_mod.alert_exit_code(result["baseline_or_delta"])


def _run_prompt(args):
    """Parse a free-form prompt and run the matching engagement."""
    from omega import intent as intent_mod
    from omega import session as session_mod

    parsed = intent_mod.parse_prompt(args.prompt)
    problems = intent_mod.validate_intent(parsed)
    if problems:
        print("ERROR: cannot build a plan from this prompt:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 2

    if not parsed["ack_claimed"]:
        print("ERROR: the prompt contains no authorization statement. "
              "Add e.g. 'saya berhak menguji target ini' or run with "
              "explicit approval. OMEGA will not engage without it.",
              file=sys.stderr)
        return 2

    if args.polyglot:
        parsed["polyglot"] = True
    if args.with_tools:
        parsed["with_tools"] = True
    if parsed["polyglot"]:
        parsed["with_tools"] = True

    if args.followup:
        os.environ["OMEGA_FOLLOWUP"] = "1"
    else:
        os.environ.pop("OMEGA_FOLLOWUP", None)

    plan = (
        f"OMEGA plan preview\n"
        f"  target     : {parsed['target']}\n"
        f"  mode       : {parsed['mode']}\n"
        f"  depth      : {parsed['depth']} "
        f"(max steps: {parsed['max_steps']})\n"
        f"  with_tools : {parsed['with_tools']}\n"
        f"  polyglot   : {parsed['polyglot']}\n"
        f"  safety     : chains are PLANNED only, never auto-executed\n")
    print(plan)

    if parsed["with_tools"]:
        os.environ["PTK_TOOLS"] = "1"
    else:
        os.environ.pop("PTK_TOOLS", None)
    if parsed["polyglot"]:
        os.environ["PTK_POLYGLOT"] = "1"
    else:
        os.environ.pop("PTK_POLYGLOT", None)

    try:
        state, report = _brain_instance().run(
            parsed["target"], mode=parsed["mode"], scope_ack=True,
            max_steps=parsed["max_steps"])
    except (PermissionError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    import datetime
    name = "{}-{}".format(
        re.sub(r"[^A-Za-z0-9._-]+", "_", str(parsed["target"]))[:60],
        datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%dT%H%M%S"))
    try:
        saved = session_mod.save_session(name, {
            "target": parsed["target"],
            "mode": parsed["mode"],
            "prompt": parsed["raw"],
            "surface": state.surface,
            "findings": state.findings,
            "chains_planned": state.chains_planned,
            "history": state.history,
        })
        print(f"session saved: {saved}")
        # asset graph: accumulate target knowledge across runs
        try:
            from omega.core.assetgraph import update_from_state
            _, delta = update_from_state({
                "target": parsed["target"],
                "surface": state.surface,
                "findings": state.findings,
            })
            known = sum(len(v) for k, v in delta.items()
                        if k != "hosts" and isinstance(v, list))
            print(f"asset graph updated: +{len(delta['hosts'])} hosts, "
                  f"+{known} entities new")
        except OSError as exc:
            print(f"warning: asset graph save failed: {exc}")
    except OSError as exc:
        print(f"warning: session save failed: {exc}")

    if args.json:
        import json
        print(json.dumps({
            "target": parsed["target"],
            "mode": parsed["mode"],
            "steps": len(state.history),
            "findings": len(state.findings),
            "session": name,
        }, indent=2, default=str))
    else:
        print(report)
    return 0


def _run_stats(args):
    """Print the arsenal size summary (no engine, no network, no gate)."""
    from omega.adapters.system_tools import registry_stats

    def _count_module(mod_name, attr=None, prefix=None):
        try:
            mod = importlib.import_module(f"omega.{mod_name}")
        except Exception:
            return 0
        if attr is not None:
            return len(getattr(mod, attr, []) or [])
        return len([n for n in dir(mod) if n.startswith(prefix or "")])

    import importlib  # noqa: F401  (local import kept near use)

    stats = registry_stats()
    pytools = _count_module("pytools", prefix="fn_")
    probes = _count_module("probes", attr="registry")
    deepchecks = _count_module("deepchecks", attr="registry")
    fusion = _count_module("fusion", prefix="_suite_")
    brain_total = 0
    try:
        from omega.brain import DEFAULT_REGISTRY
        brain_total = len(DEFAULT_REGISTRY.all())
    except Exception:
        brain_total = 0
    toolbridge = _count_module_offensive()

    print("OMEGA arsenal stats")
    print(f"  system registry : {stats['total']} tools")
    for k, v in stats["by_stage"].items():
        print(f"    stage {k:<7}: {v}")
    for k, v in stats["by_safety"].items():
        print(f"    safety {k:<12}: {v}")
    print(f"  pytools         : {pytools}")
    print(f"  probes          : {probes}")
    print(f"  deepchecks      : {deepchecks}")
    print(f"  fusion scanners : {fusion}")
    print(f"  brain caps      : {brain_total}")
    print(f"  toolbridge      : {toolbridge}")
    total = (stats["total"] + pytools + probes + deepchecks + fusion
             + toolbridge)
    print(f"  TOTAL (native)  : {total} tools "
          "(external toolbridge adds 12 when present)")
    return 0


def _count_module_offensive():
    """Best-effort count of external toolbridge tools (read-only)."""
    try:
        _engagement, toolbridge = load_engine()
        tools = getattr(toolbridge, "TOOL_REGISTRY", None) or \
            getattr(toolbridge, "TOOLS", None)
        try:
            return len(tools)
        except TypeError:
            return 0
    except Exception:
        return 0


def _run_sessions(args):
    """List / show / diff saved engagement sessions."""
    from omega import session as session_mod

    action = args.action
    if action == "list":
        docs = session_mod.list_sessions()
        if not docs:
            print("no sessions saved yet")
            return 0
        for d in docs:
            s = d.get("summary") or {}
            print("{ts}  {name}  target={t} findings={f}".format(
                ts=d.get("timestamp", "?"), name=d.get("name", "?"),
                t=d.get("target", "?"), f=s.get("findings", 0)))
        return 0
    if action == "show":
        if not args.names:
            print("ERROR: session name required", file=sys.stderr)
            return 2
        try:
            doc = session_mod.load_session(args.names[0])
        except KeyError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(doc.get("summary", doc), indent=2, default=str))
        return 0
    if action == "diff":
        if len(args.names) != 2:
            print("ERROR: diff needs exactly two session names",
                  file=sys.stderr)
            return 2
        try:
            a = session_mod.load_session(args.names[0])
            b = session_mod.load_session(args.names[1])
        except KeyError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        d = session_mod.diff_sessions(a, b)
        print(json.dumps(d, indent=2, default=str))
        return 0
    print("ERROR: unknown action", file=sys.stderr)
    return 2


def _brain_instance():
    from omega.brain import Brain
    return Brain()


if __name__ == "__main__":
    sys.exit(main())
