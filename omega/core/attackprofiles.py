"""omega/core/attackprofiles — adversary emulation profiles (ATT&CK).

Pre-planned campaigns per adversary persona. Each profile is an
ordered TTP list mapped to OMEGA capabilities; running a profile
drives the brain through the same move sequence that class of
attacker would use. Attack graph + kill-chain report tag each step
with its ATT&CK technique ID.

PLAN-DRIVEN, gate-respecting: offense steps only run when the PTK
gates are open (the no-limit doctrine exports them automatically).
"""
__all__ = ["PROFILES", "run_profile", "ATTACK_IDS"]

ATTACK_IDS = {
    "recon": "T1595", "recon_passive": "T1593",
    "initial_access": "T1190", "valid_accounts": "T1078",
    "exploit_public": "T1190", "command_exec": "T1059",
    "priv_esc": "T1068", "credential_access": "T1555",
    "discovery": "T1087", "lateral": "T1021", "exfil": "T1041",
}

PROFILES = {
    "external": {
        "desc": "External internet attacker, no prior access",
        "steps": [
            {"ttp": "recon", "caps": ["recon", "scanning.deepchecks",
                                      "core.stackroute"]},
            {"ttp": "initial_access", "caps": ["offense.hackwave",
                                               "offense.takeover"]},
            {"ttp": "valid_accounts", "caps": ["offense.authblast",
                                               "auth.jwtattack"]},
            {"ttp": "exploit_public", "caps": ["offense.racehunt",
                                               "offense.bizfuzz"]},
            {"ttp": "command_exec", "caps": ["offense.privesc"]},
            {"ttp": "discovery", "caps": ["core.pivot"]},
        ],
    },
    "insider": {
        "desc": "Authenticated low-privilege user (creds provided)",
        "steps": [
            {"ttp": "recon", "caps": ["recon", "scanning.deepchecks"]},
            {"ttp": "credential_access", "caps": ["core.authchecks",
                                                  "auth.jwtattack"]},
            {"ttp": "priv_esc", "caps": ["core.authchecks",
                                         "offense.bizfuzz"]},
            {"ttp": "lateral", "caps": ["core.attackgraph",
                                        "core.pivot"]},
        ],
    },
    "compromised-laptop": {
        "desc": "Attacker already holds one endpoint/account",
        "steps": [
            {"ttp": "valid_accounts", "caps": ["offense.authblast"]},
            {"ttp": "discovery", "caps": ["scanning.spamap",
                                          "scanning.crawlstate"]},
            {"ttp": "lateral", "caps": ["offense.horizontal",
                                        "core.attackgraph"]},
            {"ttp": "priv_esc", "caps": ["offense.privesc"]},
        ],
    },
}


def run_profile(name, state, execute_fn=None, log=None):
    """Build (and optionally execute) a campaign plan.

    execute_fn(step_dict) -> result dict; when None the plan is
    PLAN-ONLY. Returns {"profile", "steps": [{ttp, attack_id, caps,
    executed, result}], "gates_open": bool}.
    """
    import os
    prof = PROFILES.get(name)
    if prof is None:
        return {"note": f"unknown profile {name!r}; "
                        f"one of {sorted(PROFILES)}"}
    gates_open = os.environ.get("PTK_OFFENSE") == "1"
    steps = []
    for st in prof["steps"]:
        entry = {"ttp": st["ttp"],
                 "attack_id": ATTACK_IDS.get(st["ttp"], "Txxxx"),
                 "caps": st["caps"], "executed": False, "result": None}
        if execute_fn is not None and gates_open:
            try:
                entry["result"] = execute_fn(st)
                entry["executed"] = True
            except Exception as exc:
                entry["result"] = {"error": str(exc)}
        steps.append(entry)
    if log:
        log(f"profile {name}: {len(steps)} TTP steps, "
            f"executed={sum(1 for x in steps if x['executed'])}")
    return {"profile": name, "desc": prof["desc"], "steps": steps,
            "gates_open": gates_open,
            "note": None if gates_open else
                    "offense gates closed — plan returned unexecuted"}
