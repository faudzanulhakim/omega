"""omega/core/pivot — post-exploit pivot planner (PLAN-ONLY).

Turns privesc/probe results into an ordered pivot plan: credentials
found -> try them against services seen in recon; SSH keys -> list
what they could reach; docker.sock -> container escape vector note.
Every plan step is PLAN-ONLY (executed=False) with the evidence that
motivated it; the operator executes. Never runs a single network call
by itself.
"""
__all__ = ["build_pivot_plan"]

# privesc check -> pivot plan generation rules
_PIVOT_RULES = [
    ("env-secrets", "credentials in environment variables",
     "Try the exposed variables against every service found in recon "
     "(databases, admin panels, cloud APIs). Validate each manually."),
    ("ssh-keys", "SSH private keys present",
     "Identify the key's account, list hosts with authorized_keys "
     "accepting it, then attempt keyed login to recon-discovered "
     "hosts on port 22."),
    ("sudo", "sudo NOPASSWD rights",
     "Map the allowed commands to known GTFOBins escalation paths."),
    ("docker", "docker group or docker.sock access",
     "Test container breakout via privileged mount (read-only probe "
     "plan) or enumerate sibling containers' networks."),
    ("cron", "cron jobs readable",
     "Check each job's script for writable paths; a writable job "
     "script is a scheduled-execution vector."),
    ("suid", "unusual SUID binaries",
     "Cross-reference each SUID binary against GTFOBins."),
    ("writable-sensitive", "writable sensitive file",
     "A writable /etc/passwd, /etc/shadow or sudoers is direct "
     "root — plan the exact minimal edit."),
]


def build_pivot_plan(privesc_results, surface=None, log=None):
    """Plan-only pivot steps from enumerated host state.

    privesc_results: [{'check','output','flag'}] from gotools_offense
    run_privesc surface, or [] .
    surface: {'hosts','urls','ports','techs'} for service targeting.
    """
    plan = []
    notable = {r.get("check"): str(r.get("output") or "")[:200]
               for r in (privesc_results or []) if r.get("flag")}
    services = list((surface or {}).get("urls") or [])[:10]
    for i, (check, motive, action) in enumerate(_PIVOT_RULES, 1):
        evidence = notable.get(check)
        plan.append({
            "step": i,
            "motive": motive,
            "action": action,
            "evidence": evidence,
            "triggered": evidence is not None,
            "executed": False,
            "targets": services if evidence is not None else [],
        })
    triggered = [p for p in plan if p["triggered"]]
    if log:
        log(f"pivot: {len(triggered)}/{len(plan)} steps triggered")
    return {"plan": plan, "triggered": len(triggered),
            "note": "PLAN-ONLY: every step needs operator execution; "
                    "nothing here ran against the target"}
