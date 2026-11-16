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


def _run_brain(args):
    """Run the autonomous decision-engine loop (omega.brain)."""
    from omega import brain as brain_mod

    state, report = brain_mod.Brain().run(
        args.target, mode=args.mode, scope_ack=True,
        max_steps=args.max_steps)
    exploit_result = _run_exploit_layer(args, state)
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
                          help="report label language (e.g. en, id, es, "
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
    args = parser.parse_args(argv)

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

    # MAXIMUM POWER: --aggressive turns on every layer and lifts the
    # budget caps. Individual flags still take precedence when set.
    if getattr(args, "aggressive", False):
        os.environ["PTK_POLYGLOT"] = "1"
        os.environ["PTK_OFFENSE"] = "1"
        os.environ["PTK_EXPLOIT"] = "1"
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
