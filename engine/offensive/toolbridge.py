"""
offensive/toolbridge.py — external-tool bridge for ENGINE.

ENGINE-native connectivity to well-known third-party recon/enum tools:
detect installed binaries with shutil.which, run READ-ONLY invocations
only, and ingest their output as normalized ENGINE findings (vulnscan2
shape). Missing binaries are skipped, never an error.

SAFETY CONTRACT:
  * every registry entry declares safety: passive | active-recon.
  * arg_builder produces READ-ONLY invocations only: no exploitation
    tools, no flags that modify the target (no nmap -A / --script, no
    brute-force, no intrusive scanners).
  * every finding is confidence=candidate, verification='signature' —
    external tool output is a SIGNATURE, not a proof; the operator must
    verify manually (manual_check=True).
  * gated behind env PTK_TOOLS=1 (or an explicit allow=True param).
"""
import json
import os
import shutil
import subprocess

# output size cap: first 1 MB of a tool's stdout is kept
MAX_CAPTURE_BYTES = 1024 * 1024

DEFAULT_TIMEOUT_S = 30
FINDING_EVIDENCE_CAP = 300


# ----------------------------------------------------------------- helpers

def _finding(tool, title, severity, evidence, location="", param="",
             note=None):
    ev = str(evidence or "")
    if len(ev) > FINDING_EVIDENCE_CAP:
        ev = ev[:FINDING_EVIDENCE_CAP] + "…"
    return {
        "title": title,
        "severity": severity,          # INFO / LOW by class
        "confidence": "candidate",
        "verification": "signature",   # external output = signature, not proof
        "verification_note": note or
            f"external-tool signature from '{tool}'; requires manual "
            "verification before acting on it",
        "manual_check": True,
        "location": location or "",
        "param": param or "",
        "evidence": ev,
        "source": tool,
    }


def _lines(stdout):
    for ln in (stdout or "").splitlines():
        ln = ln.strip()
        if ln:
            yield ln


# ------------------------------------------------------------------ parsers
# each parser(c_stdout, c_stderr, tool) -> (findings, surface_updates)

def _p_jsonl_subdomains(tool):
    def parser(out, err):
        findings, hosts = [], []
        for ln in _lines(out):
            try:
                rec = json.loads(ln)
                host = (rec.get("host") or rec.get("name") or
                        rec.get("name_value") or "").strip()
            except Exception:
                host = ln.strip()
            if not host:
                continue
            hosts.append(host)
            findings.append(_finding(tool, f"subdomain discovered: {host}",
                                     "INFO", ln, location=host))
        return findings, {"hosts": hosts}
    return parser


def _p_text_lines(tool, label, severity="INFO", surface_key="hosts"):
    def parser(out, err):
        findings, vals = [], []
        for ln in _lines(out):
            vals.append(ln)
            findings.append(_finding(tool, f"{label}: {ln}", severity, ln))
        return findings, {surface_key: vals}
    return parser


def _p_httpx(tool):
    def parser(out, err):
        findings, urls = [], []
        for ln in _lines(out):
            try:
                rec = json.loads(ln)
            except Exception:
                rec = {"url": ln}
            url = rec.get("url") or rec.get("input") or ""
            if not url:
                continue
            urls.append(url)
            bits = []
            if rec.get("status_code"):
                bits.append(f"HTTP {rec['status_code']}")
            if rec.get("title"):
                bits.append(f"title={rec['title']}")
            if rec.get("tech"):
                tech = rec["tech"]
                bits.append("tech=" + (",".join(tech)
                                       if isinstance(tech, list) else str(tech)))
            summary = ", ".join(bits) or "live host"
            findings.append(_finding(
                tool, f"live web service: {url} ({summary})", "INFO", ln,
                location=url))
        return findings, {"urls": urls}
    return parser


def _p_dnsx(tool):
    def parser(out, err):
        findings, hosts = [], []
        for ln in _lines(out):
            try:
                rec = json.loads(ln)
            except Exception:
                rec = {"host": ln}
            host = rec.get("host") or ""
            if not host:
                continue
            hosts.append(host)
            a = rec.get("a") or rec.get("records") or []
            findings.append(_finding(
                tool, f"DNS resolution for {host}: {a}", "INFO", ln,
                location=host))
        return findings, {"hosts": hosts}
    return parser


def _p_crtsh(tool):
    def parser(out, err):
        findings, hosts = [], []
        try:
            recs = json.loads(out or "[]")
        except Exception:
            recs = []
        if isinstance(recs, dict):
            recs = [recs]
        seen = set()
        for rec in recs[:500]:  # cap ingestion
            name = str(rec.get("name_value") or "").strip()
            for h in name.split("\n"):
                h = h.strip().lstrip("*.")
                if h and h not in seen:
                    seen.add(h)
                    hosts.append(h)
                    findings.append(_finding(
                        tool, f"certificate-transparency subdomain: {h}",
                        "INFO", h, location=h))
        return findings, {"hosts": hosts}
    return parser


def _p_whois(tool):
    def parser(out, err):
        picked = {}
        for ln in _lines(out):
            if ":" in ln:
                k, v = ln.split(":", 1)
                k = k.strip().lower()
                if k in ("domain name", "registrar", "creation date",
                         "expiry date", "registry expiry date"):
                    picked.setdefault(k, v.strip())
        if not picked:
            return [], {}
        summary = "; ".join(f"{k}={v}" for k, v in sorted(picked.items()))
        return [_finding(tool, "WHOIS registration record", "INFO", summary)],
        {"whois": picked}
    return parser


def _p_dig(tool):
    def parser(out, err):
        findings, recs = [], []
        for ln in _lines(out):
            if ln.startswith((";;", ";")) or ln.startswith("<<"):
                continue
            recs.append(ln)
        if recs:
            block = "\n".join(recs[:50])
            findings.append(_finding(tool, "DNS records (dig)", "INFO", block))
        return findings, {"dns": recs}
    return parser


def _p_naabu(tool):
    def parser(out, err):
        findings, ports = [], []
        for ln in _lines(out):
            # naive output "host:port" or plain port lines
            ports.append(ln)
            findings.append(_finding(
                tool, f"open TCP port reported: {ln}", "LOW", ln))
        return findings, {"ports": ports}
    return parser


def _p_nmap_greppable(tool):
    def parser(out, err):
        findings, ports = [], []
        for ln in _lines(out):
            if not ln.startswith("Host:"):
                continue
            try:
                hostpart, portpart = ln.split("Ports:", 1)
            except ValueError:
                continue
            for entry in portpart.split(","):
                entry = entry.strip()
                parts = entry.split("/")
                if len(parts) < 5 or parts[1] != "open":
                    continue
                port, proto, svc, ver = (parts[0], parts[2], parts[4],
                                         parts[4])
                detail = f"{port}/{proto} {svc}"
                if len(parts) > 5 and parts[5]:
                    detail += f" ({parts[5]})"
                ports.append(detail)
                findings.append(_finding(
                    tool, f"open service on {hostpart.split()[1]}: {detail}",
                    "LOW", entry, location=f":{port}"))
        return findings, {"ports": ports}
    return parser


def _p_whatweb(tool):
    def parser(out, err):
        findings = []
        for ln in _lines(out):
            findings.append(_finding(
                tool, f"web technology fingerprint: {ln}", "INFO", ln))
        return findings, {"fingerprints": list(_lines(out))}
    return parser


def _p_waybackurls(tool):
    return _p_text_lines(tool, "historical URL (wayback)", "INFO", "urls")


# ------------------------------------------------------------- arg builders

def _ab(target):
    return [target]


ARG_BUILDERS = {
    "subfinder": lambda t: ["-d", t, "-silent"],
    "amass": lambda t: ["enum", "-passive", "-d", t],
    "assetfinder": _ab,
    "waybackurls": _ab,
    "crtsh": lambda t: ["-s", "--max-time", "20",
                        f"https://crt.sh/?q=%.{t}&output=json"],
    "whois": _ab,
    "dig": lambda t: ["+short", t, "ANY"],
    "dnsx": lambda t: ["-d", t, "-silent", "-json"],
    "httpx": lambda t: ["-u", t, "-json", "-silent"],
    "naabu": lambda t: ["-host", t, "-top-ports", "100", "-silent"],
    "nmap": lambda t: ["-sV", "--top-ports", "100", "-oG", "-", t],
    "whatweb": lambda t: ["-q", "--no-errors", t],
}

PARSERS = {
    "subfinder": _p_jsonl_subdomains("subfinder"),
    "amass": _p_text_lines("amass", "passive subdomain (amass)"),
    "assetfinder": _p_text_lines("assetfinder", "subdomain (assetfinder)"),
    "waybackurls": _p_waybackurls("waybackurls"),
    "crtsh": _p_crtsh("crtsh"),
    "whois": _p_whois("whois"),
    "dig": _p_dig("dig"),
    "dnsx": _p_dnsx("dnsx"),
    "httpx": _p_httpx("httpx"),
    "naabu": _p_naabu("naabu"),
    "nmap": _p_nmap_greppable("nmap"),
    "whatweb": _p_whatweb("whatweb"),
}


# ---------------------------------------------------------------- registry

TOOL_REGISTRY = {
    # -------- passive recon --------
    "subfinder": {
        "binary": "subfinder", "stage": "recon", "output": "json",
        "arg_builder": ARG_BUILDERS["subfinder"],
        "parser": PARSERS["subfinder"], "timeout_s": 30,
        "safety": "passive",
        "desc": "passive subdomain enumeration from public data sources",
    },
    "amass-passive": {
        "binary": "amass", "stage": "recon", "output": "text",
        "arg_builder": ARG_BUILDERS["amass"],
        "parser": PARSERS["amass"], "timeout_s": 60,
        "safety": "passive",
        "desc": "OWASP Amass in passive mode only (no active probes)",
    },
    "assetfinder": {
        "binary": "assetfinder", "stage": "recon", "output": "text",
        "arg_builder": ARG_BUILDERS["assetfinder"],
        "parser": PARSERS["assetfinder"], "timeout_s": 30,
        "safety": "passive",
        "desc": "subdomains from public certificate/CT archives",
    },
    "crtsh": {
        "binary": "curl", "stage": "recon", "output": "json",
        "arg_builder": ARG_BUILDERS["crtsh"],
        "parser": PARSERS["crtsh"], "timeout_s": 30,
        "safety": "passive",
        "desc": "certificate-transparency log lookup (read-only GET)",
    },
    "whois": {
        "binary": "whois", "stage": "recon", "output": "text",
        "arg_builder": ARG_BUILDERS["whois"],
        "parser": PARSERS["whois"], "timeout_s": 20,
        "safety": "passive",
        "desc": "domain registration record lookup",
    },
    "dig": {
        "binary": "dig", "stage": "recon", "output": "text",
        "arg_builder": ARG_BUILDERS["dig"],
        "parser": PARSERS["dig"], "timeout_s": 15,
        "safety": "passive",
        "desc": "DNS record resolution (short output, read-only query)",
    },
    # -------- enum / active-recon (read-only) --------
    "dnsx": {
        "binary": "dnsx", "stage": "enum", "output": "json",
        "arg_builder": ARG_BUILDERS["dnsx"],
        "parser": PARSERS["dnsx"], "timeout_s": 30,
        "safety": "active-recon",
        "desc": "DNS resolution/records against the target domain",
    },
    "httpx": {
        "binary": "httpx", "stage": "enum", "output": "json",
        "arg_builder": ARG_BUILDERS["httpx"],
        "parser": PARSERS["httpx"], "timeout_s": 30,
        "safety": "active-recon",
        "desc": "live web service probe (HTTP GET, read-only)",
    },
    "naabu": {
        "binary": "naabu", "stage": "enum", "output": "text",
        "arg_builder": ARG_BUILDERS["naabu"],
        "parser": PARSERS["naabu"], "timeout_s": 60,
        "safety": "active-recon",
        "desc": "top-100 TCP port list scan (read-only connect scan)",
    },
    "nmap-sv": {
        "binary": "nmap", "stage": "enum", "output": "text",
        "arg_builder": ARG_BUILDERS["nmap"],
        "parser": PARSERS["nmap"], "timeout_s": 120,
        "safety": "active-recon",
        "desc": ("nmap READ-ONLY service detection: -sV --top-ports only "
                 "(no -A, no scripts, no intrusive probes)"),
    },
    "whatweb": {
        "binary": "whatweb", "stage": "enum", "output": "text",
        "arg_builder": ARG_BUILDERS["whatweb"],
        "parser": PARSERS["whatweb"], "timeout_s": 30,
        "safety": "active-recon",
        "desc": "web technology fingerprinting (stealth, read-only GET)",
    },
    "waybackurls": {
        "binary": "waybackurls", "stage": "enum", "output": "text",
        "arg_builder": ARG_BUILDERS["waybackurls"],
        "parser": PARSERS["waybackurls"], "timeout_s": 30,
        "safety": "passive",
        "desc": "historical URLs from public archives (read-only fetch)",
    },
}


# ------------------------------------------------------------------ public

def available_tools(which_fn=shutil.which):
    """{tool name: binary_path or None} for every registry entry."""
    return {name: which_fn(spec["binary"])
            for name, spec in TOOL_REGISTRY.items()}


def run_tool(name, target, timeout_s=None, which_fn=shutil.which):
    """Run ONE registry tool against target (READ-ONLY invocation).

    Never raises. Returns {findings, surface, cmd, exit, truncated}.
    """
    empty = {"findings": [], "surface": {}, "cmd": None, "exit": None,
             "truncated": False}
    spec = TOOL_REGISTRY.get(name)
    if spec is None:
        return empty
    try:
        binary = which_fn(spec["binary"])
    except Exception:
        binary = None
    if not binary:
        return empty
    try:
        args = [binary] + list(spec["arg_builder"](str(target)))
    except Exception as e:
        f = _finding(name, f"tool '{name}' arg_builder failed: "
                     f"{type(e).__name__}: {e}", "LOW", "")
        return dict(empty, findings=[f], cmd=None, exit=None)

    timeout = float(timeout_s if timeout_s is not None
                    else spec.get("timeout_s") or DEFAULT_TIMEOUT_S)
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout)
        c_out = proc.stdout or b""
        c_err = proc.stderr or b""
        exit_code = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as e:
        c_out = (e.stdout or b"") if isinstance(e.stdout, bytes) else b""
        c_err = (e.stderr or b"") if isinstance(e.stderr, bytes) else b""
        exit_code = None
        timed_out = True
    except Exception as e:  # any other spawn failure is contained
        f = _finding(name, f"tool '{name}' failed to run: "
                     f"{type(e).__name__}: {e}", "LOW", "")
        return dict(empty, findings=[f], cmd=args, exit=None)

    truncated = len(c_out) > MAX_CAPTURE_BYTES
    c_out = c_out[:MAX_CAPTURE_BYTES]
    out_s = c_out.decode("utf-8", "replace")
    err_s = c_err[:MAX_CAPTURE_BYTES].decode("utf-8", "replace")

    if timed_out:
        warn = _finding(name, f"tool '{name}' timed out after {timeout}s "
                        "— partial output only", "LOW", err_s or out_s,
                        note=f"timeout contained; exit status unknown")
        warn["confidence"] = "candidate"
        findings, surface = [warn], {}
    else:
        try:
            findings, surface = spec["parser"](out_s, err_s)
            if not isinstance(findings, list):
                findings = []
            if not isinstance(surface, dict):
                surface = {}
        except Exception as e:
            findings = [_finding(name, f"tool '{name}' output parsing "
                                 f"failed: {type(e).__name__}: {e}",
                                 "LOW", out_s)]
            surface = {}

    return {"findings": findings, "surface": surface, "cmd": args,
            "exit": exit_code, "truncated": truncated}


def run_bridge(target, stage, which_fn=shutil.which, budget_requests=None,
               log=None, allow=None, allowlist=None):
    """Run every registry tool matching `stage` whose binary exists.

    Gate: env PTK_TOOLS=1, or explicit allow=True — else PermissionError.
    budget_requests: shared cap; each tool run counts 1 (None = unlimited).
    allowlist: optional iterable restricting which tools may run.
    Returns {findings, surface, ran, skipped}.
    """
    log = log or (lambda m: None)
    if allow is not True and os.environ.get("PTK_TOOLS") != "1":
        raise PermissionError(
            "external tools are gated: set env PTK_TOOLS=1 (or pass "
            "allow=True) to permit third-party tool execution")
    avail = available_tools(which_fn=which_fn)
    allowed = set(allowlist) if allowlist else None

    findings, surface = [], {}
    ran, skipped = [], []
    used = 0
    for name, spec in TOOL_REGISTRY.items():
        if spec["stage"] != stage:
            continue
        if allowed is not None and name not in allowed:
            skipped.append(name)
            continue
        if not avail.get(name):
            log(f"[toolbridge] skip '{name}': binary "
                f"'{spec['binary']}' not installed")
            skipped.append(name)
            continue
        if budget_requests is not None and used >= budget_requests:
            log(f"[toolbridge] request budget exhausted after {used} "
                "tool run(s) — stopping")
            skipped.append(name)
            continue
        log(f"[toolbridge] running '{name}' ({spec['safety']}, "
            f"read-only) against {target}")
        res = run_tool(name, target, which_fn=which_fn)
        used += 1
        ran.append(name)
        findings.extend(res.get("findings") or [])
        for k, v in (res.get("surface") or {}).items():
            if isinstance(v, list):
                surface.setdefault(k, []).extend(v)
            else:
                surface[k] = v
        log(f"[toolbridge] '{name}' finished: "
            f"{len(res.get('findings') or [])} findings, "
            f"exit={res.get('exit')}")
    # dedupe surface lists, keep order
    for k, v in list(surface.items()):
        if isinstance(v, list):
            seen, out = set(), []
            for x in v:
                if x not in seen:
                    seen.add(x)
                    out.append(x)
            surface[k] = out
    return {"findings": findings, "surface": surface, "ran": ran,
            "skipped": skipped}
