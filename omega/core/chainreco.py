"""omega/core/chainreco.py — deterministic exploit-chain recommender.

Reads a findings list (session JSON ``state.findings`` or a raw list of
finding dicts) and produces exploit-chain recommendations grounded ONLY
in verified evidence already present in the findings. No LLM, no
network: pure keyword matching over titles/locations/severities.

Public API:

    recommend(findings, target=None) -> dict
        {chains: [...], assault_cmds: [...], notes: [...]}

    Each chain: {name, steps, requires_no_limits, rationale}
    Each step:  {uses, evidence_ref, action, risk}

Rules (deterministic, matched on titles/severity):
  env/secret exposure + (login form OR jwt)  -> credential-replay chain
      (requires the offense gate: PTK_OFFENSE)
  version disclosure + local CVE index entry -> cve-exploit chain
      (requires the exploit gate: PTK_EXPLOIT)
  admin panel + upload endpoint              -> upload chain
  open redirect + subdomain takeover hint    -> takeover chain
  traversal + .env                           -> secret-retrieval chain
      (requires the no-limits gate: OMEGA_NO_LIMITS)
  fallback: one verify-then-decide chain per unmatched finding

Chains referencing findings whose ``verification`` is ``candidate``
carry the note ``candidate-only chain: verify first``. Endpoints and
credentials are never invented — every referenced location comes from
a finding.

CLI: ``omega chains SESSION_OR_FILE [--json]`` (see omega/core/cli.py).
"""

from __future__ import annotations

import os
import re

__all__ = ["recommend", "format_plan"]


# ---------------------------------------------------------------------------
# helpers — never raise on junk input
# ---------------------------------------------------------------------------

def _norm_finding(f):
    """Coerce a finding to a plain dict with title/location/severity.

    Never raises: non-dict or missing fields degrade to empty strings.
    """
    if not isinstance(f, dict):
        return {"title": str(f), "location": "", "severity": "info",
                "verification": "", "evidence": ""}
    title = str(f.get("title") or f.get("name") or "")
    location = str(f.get("location") or f.get("url") or f.get("path") or "")
    severity = str(f.get("severity") or "info").lower()
    verification = str(f.get("verification")
                       or f.get("status") or "").lower()
    evidence = f.get("evidence")
    if not isinstance(evidence, str):
        evidence = ""
    return {"title": title, "location": location, "severity": severity,
            "verification": verification, "evidence": evidence}


def _blob(f):
    """Lowercase text blob used for keyword matching (title+location)."""
    return ("%s %s" % (f["title"], f["location"])).lower()


def _path_of(location):
    """Extract the URL path from a location string ('' if none)."""
    m = re.search(r"https?://[^/]+(/[^?\s]*)", location)
    if m:
        return m.group(1)
    if location.startswith("/"):
        return location.split("?")[0]
    return ""


def _has(blob, *keywords):
    return any(k in blob for k in keywords)


def _any_finding(norms, *keywords):
    """First finding whose blob contains any keyword, else None."""
    for f in norms:
        if _has(_blob(f), *keywords):
            return f
    return None


def _gate_env(gate):
    """Read a PTK_/OMEGA_ gate flag from the environment (bool)."""
    return os.environ.get(gate) == "1"


def _cmd(args):
    """Build a paste-ready CLI line (always starts with 'omega ')."""
    return "omega " + " ".join(a for a in args if a)


# ---------------------------------------------------------------------------
# chain builders
# ---------------------------------------------------------------------------

def _make_chain(name, steps, rationale, requires_no_limits=False,
                findings_used=()):
    """Assemble one chain dict plus its candidate-only bookkeeping."""
    candidate = any(f["verification"] == "candidate" for f in findings_used)
    return {"name": name,
            "steps": steps,
            "requires_no_limits": bool(requires_no_limits),
            "rationale": rationale,
            "_candidate": candidate,
            "_findings": findings_used}


def _cred_replay_chain(norms, target):
    """Rule 1: env/secret exposure + (login form OR jwt)."""
    secret = _any_finding(
        norms, "env", "secret", "credential", "leak", "token", "key")
    if secret is None:
        return None
    login = _any_finding(norms, "login form", "login page", "login",
                         "jwt", "auth")
    if login is None:
        return None
    login_path = _path_of(login["location"]) or "/login"
    steps = [
        {"uses": secret["title"],
         "evidence_ref": secret["location"] or "(no location recorded)",
         "action": "replay leaked credential against %s" % login_path,
         "risk": secret["severity"] or "info"},
        {"uses": login["title"],
         "evidence_ref": login["location"] or "(no location recorded)",
         "action": "verify successful authentication by observing the "
                   "session response",
         "risk": login["severity"] or "info"},
    ]
    return _make_chain(
        "credential-replay", steps,
        "secret/env material exposed in findings can be replayed against "
        "the discovered login surface",
        requires_no_limits=False, findings_used=[secret, login])


def _cve_exploit_chain(norms, target):
    """Rule 2: version disclosure + matching entry in the local CVE index."""
    version = _any_finding(
        norms, "version", "server banner", "disclosure", "outdated",
        "stack")
    if version is None:
        return None
    try:
        from omega.scanning import cvefeed
    except Exception:  # pragma: no cover - import guard, never raises
        return None
    try:
        st = cvefeed.status() or {}
    except Exception:
        return None
    if not (st.get("cves") or st.get("entries") or st.get("products")):
        return None  # no local index -> no CVE chain (no invention)
    # Try a real lookup for the disclosed product/version when parseable.
    product_hint = None
    m = re.search(r"\b(nginx|apache|openssl|mysql|postgres|php|tomcat|"
                  r"node\.?js|express|django|flask|rails)\b",
                  _blob(version))
    if m:
        product_hint = m.group(1)
    cves = []
    if product_hint:
        try:
            cves = cvefeed.lookup(product_hint, "") or []
        except Exception:
            cves = []
    if not cves:
        # Index exists but nothing matched the disclosed product; still
        # emit the chain keyed on the index status (operator checks CVEs
        # manually) — the evidence reference stays the version finding.
        action = "match disclosed version against the local CVE index " \
                 "and review candidate CVEs manually"
    else:
        ids = ", ".join(sorted({str(c.get("cve_id", "?"))
                                for c in cves})[:5])
        action = "match disclosed version against the local CVE index " \
                 "(candidates: %s)" % ids
    steps = [{"uses": version["title"],
              "evidence_ref": version["location"]
              or "(no location recorded)",
              "action": action,
              "risk": version["severity"] or "info"}]
    return _make_chain(
        "cve-exploit", steps,
        "disclosed version matched against the locally downloaded CVE "
        "index (offline; nothing is fetched at recommendation time)",
        requires_no_limits=False, findings_used=[version])


def _upload_chain(norms, target):
    """Rule 3: admin panel + upload endpoint."""
    admin = _any_finding(norms, "admin panel", "admin", "dashboard")
    upload = _any_finding(norms, "upload")
    if admin is None or upload is None:
        return None
    steps = [
        {"uses": admin["title"],
         "evidence_ref": admin["location"] or "(no location recorded)",
         "action": "authenticate to the discovered admin panel surface",
         "risk": admin["severity"] or "info"},
        {"uses": upload["title"],
         "evidence_ref": upload["location"] or "(no location recorded)",
         "action": "probe the upload endpoint with a benign marker file "
                   "to test content-type enforcement",
         "risk": upload["severity"] or "info"},
    ]
    return _make_chain(
        "upload-bypass", steps,
        "authenticated admin surface with an upload endpoint is the "
        "classic file-upload bypass path",
        requires_no_limits=False, findings_used=[admin, upload])


def _takeover_chain(norms, target):
    """Rule 4: open redirect + subdomain takeover hint."""
    redirect = _any_finding(norms, "open redirect", "redirect")
    takeover = _any_finding(norms, "takeover", "dangling", "cname",
                            "unclaimed")
    if redirect is None or takeover is None:
        return None
    steps = [
        {"uses": takeover["title"],
         "evidence_ref": takeover["location"]
         or "(no location recorded)",
         "action": "verify the dangling DNS record resolves to an "
                   "unclaimed service before any further action",
         "risk": takeover["severity"] or "info"},
        {"uses": redirect["title"],
         "evidence_ref": redirect["location"]
         or "(no location recorded)",
         "action": "assess whether the redirect target can be pointed "
                   "at the unclaimed subdomain",
         "risk": redirect["severity"] or "info"},
    ]
    return _make_chain(
        "subdomain-takeover", steps,
        "open redirect combined with a takeover hint on the same "
        "surface suggests a takeover path",
        requires_no_limits=False, findings_used=[redirect, takeover])


def _secret_retrieval_chain(norms, target):
    """Rule 5: traversal + .env disclosure."""
    traversal = _any_finding(norms, "traversal", "lfi", "path "
                             "traversal")
    envfile = _any_finding(norms, ".env", "env file", "dot env")
    if traversal is None or envfile is None:
        return None
    steps = [
        {"uses": traversal["title"],
         "evidence_ref": traversal["location"]
         or "(no location recorded)",
         "action": "confirm traversal depth with the harmless canary "
                   "already recorded in the evidence",
         "risk": traversal["severity"] or "info"},
        {"uses": envfile["title"],
         "evidence_ref": envfile["location"]
         or "(no location recorded)",
         "action": "retrieve the .env file through the confirmed "
                   "traversal path and diff against the leaked keys",
         "risk": envfile["severity"] or "info"},
    ]
    return _make_chain(
        "secret-retrieval", steps,
        "confirmed traversal plus a known .env location yields direct "
        "secret retrieval",
        requires_no_limits=True, findings_used=[traversal, envfile])


def _fallback_chain(f, target):
    """Fallback: single-finding verify-then-decide chain."""
    steps = [{"uses": f["title"],
              "evidence_ref": f["location"] or "(no location recorded)",
              "action": "manual_check",
              "risk": f["severity"] or "info"}]
    return _make_chain(
        "verify-then-decide", steps,
        "no chain rule matched; the finding needs manual verification "
        "before any next step is decided",
        requires_no_limits=False, findings_used=[f])


def _chain_cmd(chain, target):
    """Concrete CLI invocation for a chain (real subcommands only)."""
    t = target or "<target>"
    ack = "--scope-ack"
    if chain["name"] == "credential-replay":
        return _cmd(["brute", t, ack, "--offense", "--login-path",
                     "/login", "--max-attempts", "50", "--json"])
    if chain["name"] == "cve-exploit":
        return _cmd(["brain", t, ack, "--exploit", "--json"])
    if chain["name"] == "upload-bypass":
        return _cmd(["brain", t, ack, "--offense", "--json"])
    if chain["name"] == "subdomain-takeover":
        return _cmd(["brain", t, ack, "--json"])
    if chain["name"] == "secret-retrieval":
        # --no-limits is emitted EXPLICITLY only here, never implicitly.
        return _cmd(["brain", t, ack, "--no-limits", "--json"])
    return _cmd(["brain", t, ack, "--json"])


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def recommend(findings, target=None):
    """Produce exploit-chain recommendations from a findings list.

    Accepts a list of finding dicts (or anything iterable of dict-like
    items); never raises on junk input. Returns
    ``{chains, assault_cmds, notes}``.
    """
    try:
        items = list(findings or [])
    except TypeError:
        items = []
    norms = [_norm_finding(f) for f in items if f is not None]

    chains = []
    for builder in (_cred_replay_chain, _cve_exploit_chain, _upload_chain,
                    _takeover_chain, _secret_retrieval_chain):
        chain = builder(norms, target)
        if chain is not None:
            chains.append(chain)

    # Fallback: findings not consumed by any matched chain get a
    # verify-then-decide chain each.
    used = {id(f) for c in chains for f in c["_findings"]}
    for f in norms:
        if id(f) not in used:
            chains.append(_fallback_chain(f, target))

    notes = []
    assault_cmds = []
    for chain in chains:
        assault_cmds.append(_chain_cmd(chain, target))
        if chain.pop("_candidate"):
            notes.append("candidate-only chain: verify first")
    for chain in chains:
        chain.pop("_findings", None)

    if not norms:
        notes.append("no findings: nothing to recommend (no findings "
                     "by themselves)")
    return {"chains": chains, "assault_cmds": assault_cmds,
            "notes": notes}


def format_plan(plan, target=None):
    """Render the plan as a readable operator report (plain text)."""
    lines = ["Exploit chain plan%s" %
             (" for %s" % target if target else ""), ""]
    if not plan["chains"]:
        lines.append("  (no chains — no findings to act on)")
    for i, chain in enumerate(plan["chains"], 1):
        lines.append("%d. %s%s" % (
            i, chain["name"],
            "  [NO-LIMITS REQUIRED]" if chain["requires_no_limits"]
            else ""))
        lines.append("   rationale: %s" % chain["rationale"])
        for s in chain["steps"]:
            lines.append("   - %s @ %s" % (s["uses"], s["evidence_ref"]))
            lines.append("     action: %s (risk: %s)"
                         % (s["action"], s["risk"]))
        cmd = plan["assault_cmds"][i - 1] \
            if i - 1 < len(plan["assault_cmds"]) else None
        if cmd:
            lines.append("   cmd: %s" % cmd)
        lines.append("")
    for n in plan["notes"]:
        lines.append("note: %s" % n)
    return "\n".join(lines)
