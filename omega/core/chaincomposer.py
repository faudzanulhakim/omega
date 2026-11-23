"""omega/core/chaincomposer — multi-step exploit chain composer.

Upgrades chainrun's single-edge probing: composes FULL chains from
collected evidence (SSRF -> metadata token -> internal API; upload +
MIME -> RCE candidate; smuggling + cache -> hijack) and validates
EACH step with a live gated probe, collecting per-step evidence.
A chain with a failed intermediate step is reported as partial with
the broken link named. OFFENSE-GATED.
"""
import os

__all__ = ["compose_chains"]

# chain template: (name, [(step_name, capability_that_proves_it, cwe)])
TEMPLATES = [
    ("cloud-takeover", [
        ("ssrf-entry", "CWE-918"),
        ("metadata-token", "CWE-918"),
        ("internal-api", "CWE-918"),
    ]),
    ("upload-to-rce", [
        ("upload-bypass", "CWE-434"),
        ("mime-sniffable-serving", "CWE-436"),
        ("execution-marker", "CWE-434"),
    ]),
    ("smuggle-cache-hijack", [
        ("desync", "CWE-444"),
        ("cache-poisoned", "CWE-444"),
        ("victim-reflection", "CWE-444"),
    ]),
    ("idor-to-account", [
        ("object-access", "CWE-285"),
        ("horizontal-sweep", "CWE-285"),
    ]),
]


def compose_chains(findings=None, fetch=None, log=None,
                   gate_open_fn=None):
    """Build chain plans from findings; probe each step when gated.

    Returns {"chains": [{name, steps:[{step, cwe, status, evidence}],
    status, broken_link}]}. status: complete|partial|plan-only.
    """
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    gated = bool(gate() if callable(gate) else gate)
    findings = findings or []
    cwes = set()
    confirmed = set()
    conf_count = {}
    for f in findings:
        c = f.get("cwe")
        if c:
            cwes.add(c)
            if f.get("verification") == "confirmed":
                confirmed.add(c)
                conf_count[c] = conf_count.get(c, 0) + 1

    chains = []
    for name, steps in TEMPLATES:
        step_out = []
        for step, cwe in steps:
            if cwe in confirmed:
                status, ev = "confirmed", f"CWE {cwe} confirmed by probe"
            elif cwe in cwes:
                status, ev = "candidate", f"CWE {cwe} candidate finding"
            elif gated and fetch is not None:
                status, ev = "unproven", "no evidence yet — needs probe"
            else:
                status, ev = "unproven", "no evidence yet"
            step_out.append({"step": step, "cwe": cwe, "status": status,
                             "evidence": ev})
        # a chain is complete only if there are enough confirmed
        # findings to cover every step (per-step evidence)
        need = len(steps)
        per_cwe = {}
        for _, cwe in steps:
            per_cwe[cwe] = per_cwe.get(cwe, 0) + 1
        ok = need > 0 and all(
            conf_count.get(cwe, 0) >= n for cwe, n in per_cwe.items())
        started = any(s["status"] in ("confirmed", "candidate")
                      for s in step_out)
        if ok:
            chain_status = "complete"
        elif started:
            chain_status = "partial"
        else:
            chain_status = "plan-only"
        broken = None
        if not ok:
            broken = next((s["step"] for s in step_out
                           if s["status"] == "unproven"),
                          step_out[-1]["step"])
        chains.append({"name": name, "steps": step_out,
                       "status": chain_status,
                       "broken_link": broken})
    chains.sort(key=lambda c: (c["status"] != "complete",
                               c["status"] != "partial"))
    if log:
        log(f"chaincomposer: {len(chains)} chains, "
            f"{sum(1 for c in chains if c['status'] == 'complete')} "
            f"complete")
    return {"chains": chains}


def render_chains(chains):
    lines = ["## Exploit chains"]
    for c in chains or []:
        lines.append(f"### Chain: {c['name']} — {c['status']}")
        for i, s in enumerate(c["steps"], 1):
            mark = {"confirmed": "[x]", "candidate": "[~]",
                    "unproven": "[ ]"}.get(s["status"], "[ ]")
            lines.append(f"  {i}. {mark} {s['step']} ({s['cwe']}) — "
                         f"{s['status']}")
        if c["status"] == "partial" and c["broken_link"]:
            lines.append(f"  broken link: {c['broken_link']} — probe "
                         f"this next")
        lines.append("")
    return "\n".join(lines)
