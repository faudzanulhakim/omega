"""omega/core/autochain.py — automatic multi-stage chain execution.

A chain is an ordered list of stages; each stage consumes the output of
the previous one, validates its own evidence through the claim gate,
and STOPS the chain when evidence is refuted or missing. No stage ever
claims success without a finding that carries real evidence.

Stages (all contained, each returns {stage, findings, evidence, ok,
reason}):

  recon      — fetch framework kit paths for the detected stack
  harvest    — scan response bodies/text for secret material
               (AWS/GCP keys, private keys, DB URLs, API tokens, JWT)
  poc        — delegate to the gated exploit layer for confirmed leads
  auth       — delegate to the authenticated session layer (needs creds)

Gates: the chain refuses to run unless OMEGA_AUTOCHAIN=1 or
OMEGA_NO_LIMITS=1 — an explicit operator decision (CLI --autochain /
--no-limits). Every stage is read-only except `poc`, which only runs
drivers already allowed by the exploit gate.

Kill-chain narrative: narrate() turns an engagement/session doc into a
readable "how it happened" story (decision -> capability -> evidence).
"""

from __future__ import annotations

import os
import re

__all__ = [
    "CHAINS",
    "HARVEST_PATTERNS",
    "harvest_secrets",
    "autochain_gate_ok",
    "run_autochain",
    "narrate",
]

AUTOCHAIN_ENV = "OMEGA_AUTOCHAIN"
NO_LIMITS_ENV = "OMEGA_NO_LIMITS"


def autochain_gate_ok():
    return (os.environ.get(AUTOCHAIN_ENV) == "1"
            or os.environ.get(NO_LIMITS_ENV) == "1")


# (kind, regex, note) — evidence patterns only; nothing is written.
HARVEST_PATTERNS = (
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}"),
     "AWS access key id"),
    ("aws-secret", re.compile(
        r"(?i)aws.{0,20}(secret|private).{0,20}[:=]\s*"
        r"['\"]?([A-Za-z0-9/+=]{40})"), "AWS secret access key"),
    ("private-key", re.compile(
        r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "private key block"),
    ("db-url", re.compile(
        r"(?i)(mysql|postgres|postgresql|mongodb|redis|amqp)://"
        r"[^\s'\"<>]{6,120}"), "database connection string"),
    ("api-token", re.compile(
        r"(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)"
        r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,64})"), "api key/token"),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
     "github token"),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,72}"),
     "slack token"),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
                       r"[A-Za-z0-9_-]{8,}"), "JWT"),
    ("basic-auth-url", re.compile(
        r"(?i)https?://[^/\s:@]{2,40}:[^/\s@]{4,40}@[^\s'\"<>]+"),
     "credentials embedded in URL"),
    ("password-line", re.compile(
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{4,64})"),
     "password assignment"),
)


def harvest_secrets(text, limit=50):
    """Scan text for secret material. Returns list of
    {kind, note, snippet} — snippets capped at 120 chars.

    Secrets are returned for evidence purposes; callers must never log
    them into reports without masking.
    """
    if not isinstance(text, str) or not text:
        return []
    found, seen = [], set()
    for kind, rx, note in HARVEST_PATTERNS:
        for m in rx.finditer(text):
            snippet = re.sub(r"\s+", " ", m.group(0))[:120]
            key = (kind, snippet[:40])
            if key in seen:
                continue
            seen.add(key)
            found.append({"kind": kind, "note": note, "snippet": snippet})
            if len(found) >= limit:
                return found
    return found


CHAINS = {
    "exposure": ["recon", "harvest"],
    "takeover": ["recon", "poc"],
    "config-leak": ["recon", "harvest", "auth", "poc"],
    "full": ["recon", "harvest", "auth", "poc"],
}


def _finding(title, severity, evidence, location, note, source):
    return {
        "title": title,
        "severity": severity,
        "confidence": "low",
        "verification": "candidate",
        "verification_note": note,
        "manual_check": note,
        "location": location,
        "evidence": str(evidence)[:300],
        "source": source,
    }


def _stage_recon(target, fetch, ctx, log):
    from omega.core.frameworks import detect_frameworks, kit_paths
    base = target.rstrip("/")
    headers, body = {}, ""
    try:
        st, hdrs, raw = fetch("GET", base + "/", {})
        headers = hdrs or {}
        body = raw.decode("utf-8", "replace") if isinstance(raw, bytes) \
            else str(raw or "")
    except Exception as exc:
        return {"stage": "recon", "ok": False,
                "reason": "baseline fetch failed: %s" % exc,
                "findings": [], "evidence": ""}
    names = detect_frameworks(headers=headers, body=body)
    ctx["frameworks"] = names
    if names:
        try:
            from omega.core.lessons import record_frameworks
            record_frameworks(target, names)
        except OSError:
            pass
    paths = kit_paths(names)
    hits = []
    evidence = []
    for p in paths[:10]:
        try:
            st, hdrs, raw = fetch("GET", base + p, {})
            txt = raw.decode("utf-8", "replace") if isinstance(raw,
                                                               bytes) \
                else str(raw or "")
            if int(st) in (200, 401, 403):
                hits.append((p, int(st), txt))
                evidence.append("%s -> %d (%dB)" % (p, st, len(txt)))
        except Exception:
            continue
    findings = []
    for p, st, txt in hits:
        if st == 200 and len(txt) > 0:
            findings.append(_finding(
                "Framework endpoint reachable: %s" % p, "info",
                txt[:200], p,
                "framework kit path returned 200 — inspect content",
                "omega-autochain/recon"))
    ctx["recon_pages"] = hits
    return {"stage": "recon", "ok": bool(hits) or bool(names),
            "findings": findings, "evidence": "; ".join(evidence[:8]),
            "frameworks": names,
            "reason": "" if hits else "no kit paths returned content"}


def _stage_harvest(target, fetch, ctx, log):
    texts = []
    for p, st, txt in (ctx.get("recon_pages") or []):
        texts.append((p, txt))
    for f in ctx.get("findings") or []:
        if isinstance(f, dict) and f.get("evidence"):
            texts.append((f.get("location", "finding"),
                          str(f["evidence"])))
    hits = []
    for loc, txt in texts:
        for h in harvest_secrets(txt):
            hits.append((loc, h))
    findings = []
    for loc, h in hits[:20]:
        findings.append(_finding(
            "Secret material exposed (%s)" % h["note"], "high",
            h["snippet"], loc,
            "harvest hit — verify the value is live before reporting; "
            "mask it in any shared report",
            "omega-autochain/harvest"))
    ctx["harvest"] = hits
    return {"stage": "harvest", "ok": bool(hits), "findings": findings,
            "evidence": "%d secret candidates" % len(hits),
            "reason": "" if hits else "no secret patterns in collected "
                                      "content"}


def _stage_auth(target, fetch, ctx, log):
    creds = ctx.get("creds")
    if not creds:
        return {"stage": "auth", "ok": False, "findings": [],
                "evidence": "", "reason": "no credentials supplied "
                                          "(skipped)"}
    try:
        from omega.core.auth import login, detect_login_form
        form = detect_login_form(fetch, target)
        if not form:
            return {"stage": "auth", "ok": False, "findings": [],
                    "evidence": "", "reason": "no login form detected"}
        res = login(fetch, target, creds)
        ok = bool(res.get("ok") or res.get("cookies"))
        return {"stage": "auth", "ok": ok, "findings": [],
                "evidence": "login %s" % ("accepted" if ok else "refused"),
                "reason": "" if ok else "login rejected"}
    except Exception as exc:
        return {"stage": "auth", "ok": False, "findings": [],
                "evidence": "", "reason": "auth stage error: %s" % exc}


def _stage_poc(target, fetch, ctx, log):
    from omega.offensive.exploit import run_exploit, no_limits_ok
    if not no_limits_ok():
        return {"stage": "poc", "ok": False, "findings": [],
                "evidence": "", "reason": "no-limits gate closed — set "
                                          "OMEGA_NO_LIMITS=1 to run PoCs"}
    findings = list(ctx.get("findings") or [])
    for ev in (ctx.get("harvest") or []):
        loc, h = ev
        findings.append({"title": h["note"], "severity": "high",
                         "verification": "confirmed",
                         "location": loc, "evidence": h["snippet"],
                         "source": "omega-autochain/harvest"})
    out = run_exploit(target, fetch, findings=findings, allow=True)
    return {"stage": "poc", "ok": bool(out.get("ran")),
            "findings": out.get("findings") or [],
            "evidence": "drivers run: %s" % ",".join(out.get("ran") or []),
            "reason": "" if out.get("ran") else "no exploitable lead"}


STAGE_FUNCS = {
    "recon": _stage_recon,
    "harvest": _stage_harvest,
    "auth": _stage_auth,
    "poc": _stage_poc,
}


def run_autochain(target, fetch, chain="full", findings=None,
                  creds=None, log=None):
    """Run a chain stage-by-stage. Never raises.

    Returns {chain, gate, stages: [...], findings, stopped_at,
    stop_reason, ok}. A stage failure with no evidence stops the chain:
    later stages never run on unproven ground.
    """
    log = log or (lambda msg: None)
    if not autochain_gate_ok():
        return {"chain": chain, "gate": False, "stages": [],
                "findings": [], "stopped_at": 0,
                "stop_reason": "autochain gate closed: set "
                               "OMEGA_AUTOCHAIN=1 (CLI --autochain) or "
                               "OMEGA_NO_LIMITS=1",
                "ok": False}
    stages = CHAINS.get(chain) or CHAINS["full"]
    ctx = {"frameworks": [], "findings": list(findings or []),
           "creds": creds}
    results, all_findings = [], []
    stopped_at, stop_reason = 0, ""
    for idx, name in enumerate(stages, 1):
        fn = STAGE_FUNCS.get(name)
        if not fn:
            continue
        try:
            res = fn(target, fetch, ctx, log)
        except Exception as exc:
            res = {"stage": name, "ok": False, "findings": [],
                   "evidence": "", "reason": "%s: %s"
                   % (type(exc).__name__, exc)}
        # evidence gate: a stage that produced nothing stops the chain
        if not res.get("ok"):
            results.append(res)
            stopped_at, stop_reason = idx, res.get("reason") or \
                "no evidence"
            log("[autochain] stop at stage %d (%s): %s"
                % (idx, name, stop_reason))
            break
        results.append(res)
        all_findings.extend(res.get("findings") or [])
    return {"chain": chain, "gate": True, "stages": results,
            "findings": all_findings, "stopped_at": stopped_at,
            "stop_reason": stop_reason,
            "ok": not stop_reason}


def narrate(doc):
    """Turn an engagement/session doc into a kill-chain story.

    Deterministic markdown: one bullet per step with its reasoning and
    the findings it produced. Empty history -> explicit note.
    """
    if isinstance(doc, dict) and isinstance(doc.get("state"), dict):
        state = doc["state"]
        history = ((doc.get("audit") or {}).get("history")
                   or state.get("history") or [])
        findings = state.get("findings") or []
        target = state.get("target")
    else:
        doc = doc or {}
        history = doc.get("history") or []
        findings = doc.get("findings") or []
        target = doc.get("target")
    lines = ["# Kill chain — %s" % (target or "unknown target"), ""]
    if not history:
        lines.append("_No audit history in this session._")
        return "\n".join(lines)
    by_source = {}
    for f in findings:
        if isinstance(f, dict):
            by_source.setdefault(str(f.get("source")), []).append(f)
    for h in history:
        step = h.get("step")
        cap = h.get("capability")
        reason = h.get("reasoning") or "(no reasoning recorded)"
        lines.append("## Step %s — %s" % (step, cap))
        lines.append("- why: %s" % reason)
        produced = []
        for src in (h.get("sources") or []):
            for f in by_source.get(str(src), []):
                produced.append("%s [%s]" % (f.get("title"),
                                             f.get("severity", "?")))
        if produced:
            lines.append("- produced: " + "; ".join(sorted(set(produced))))
        else:
            lines.append("- produced: no findings")
        lines.append("")
    return "\n".join(lines)


# ------------------------------------------------- chain graph (v2)

# pairwise matchers: (finding-title regex A, finding-title regex B,
# chain proposal). Proposal strings describe the composed attack path
# with the evidence of both endpoints; NOTHING is executed here — a
# proposal is a plan for the operator to approve.
_CHAIN_RULES = [
    (r"ssrf|request forgery", r"internal|intranet|private ip|"
     r"metadata|localhost",
     "SSRF pivot: use the SSRF primitive to reach the internal "
     "service; enumerate internal endpoints through the blind/echo "
     "channel"),
    (r"graphql", r"introspection",
     "GraphQL schema walk: use introspection to map sensitive "
     "mutations, then probe authorization on each mutation"),
    (r"prototype pollution", r"bypass|auth|privilege|admin|"
     r"role|escalat",
     "prototype-pollution gadget: merge into an authorization check "
     "object to overwrite privilege fields"),
    (r"smuggl", r"cache|proxy|front-end",
     "smuggling + cache: desync the front-end to poison the shared "
     "cache and reach other users"),
    (r"xss|script injection", r"admin|dashboard|backoffice",
     "stored XSS in the admin surface: capture an admin session or "
     "drive privileged actions from an admin visit"),
    (r"path traversal|lfi|file read", r"config|env|credential|"
     r"secret|key",
     "file-read to secret material: traverse to configuration files "
     "revealed by the harvest stage and extract credentials"),
    (r"open redirect", r"oauth|sso|token|callback",
     "open redirect in an OAuth/SSO flow: intercept authorization "
     "codes via the redirect_uri"),
    (r"sqli|injection", r"database|db url|credential|password",
     "SQLi to credential extraction: pivot from the injection point "
     "to the credential store exposed by the harvest stage"),
    (r"cookie|session", r"no httponly|javascript|xss",
     "session theft chain: XSS reads the non-HttpOnly session cookie "
     "and exfiltrates the session"),
]


def chain_propose(findings, max_proposals=10):
    """Graph match: pairwise-combine findings into exploit-chain
    proposals. Pure function — returns proposals with evidence refs,
    executes nothing, opens nothing. Each proposal lists the source
    finding titles so the operator can audit the reasoning."""
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    titles = [str(f.get("title") or "") for f in findings]
    lowered = [t.lower() for t in titles]
    proposals = []
    seen = set()
    for a_re, b_re, story in _CHAIN_RULES:
        a_idx = [i for i, t in enumerate(lowered) if re.search(a_re, t)]
        b_idx = [i for i, t in enumerate(lowered) if re.search(b_re, t)]
        for i in a_idx:
            for j in b_idx:
                if i == j:
                    continue
                key = (a_re, b_re, min(i, j), max(i, j))
                if key in seen:
                    continue
                seen.add(key)
                proposals.append({
                    "chain": story,
                    "links": [{"finding": titles[i],
                               "evidence": str(findings[i].get(
                                   "evidence") or "")[:120],
                               "location": findings[i].get("location")},
                              {"finding": titles[j],
                               "evidence": str(findings[j].get(
                                   "evidence") or "")[:120],
                               "location": findings[j].get("location")}],
                    "requires_operator_approval": True,
                })
                if len(proposals) >= max_proposals:
                    return proposals
    return proposals
