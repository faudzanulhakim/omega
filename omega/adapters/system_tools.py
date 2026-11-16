"""omega/adapters/system_tools.py — read-only system-binary tool suite.

Wraps installed recon binaries (nmap, ffuf, nuclei, subfinder, amass,
httpx, openssl, jq) behind a engine-shaped registry. Every tool is
READ-ONLY: version/top-port scans, GET-only content discovery with rate
limits, passive OSINT, passive CT/TLS chain inspection. No scripting
engines, no exploit flags, no brute force.

SAFETY CONTRACT
  * GATE: run_system_suite refuses to execute anything unless the
    environment has PTK_POLYGLOT=1 (mirrors omega.adapters.native).
  * every arg_builder emits read-only flags only; tests audit the whole
    registry for dangerous tokens (-A, --script, exploit-ish words).
  * subprocess timeouts are contained: a hanging binary becomes a
    per-tool skip entry, never an exception escaping the suite.
  * findings are engine-shaped (confidence=candidate,
    verification=signature, manual_check=True with a concrete
    curl/nmap reproduction command, source='omega-sys/<name>') and
    evidence is truncated to 300 chars.
"""
import json
import os
import re
import shutil
import subprocess
from functools import partial as _partial

GATE_ENV = "PTK_POLYGLOT"
EVIDENCE_CAP = 300
DEFAULT_STAGES = ("recon", "enum", "verify")

# candidate wordlists for ffuf (first existing wins; else tool skipped)
FFUF_WORDLIST_CANDIDATES = (
    os.environ.get("OMEGA_FFUF_WORDLIST") or "",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/wfuzz/general/common.txt",
)


# ---------------------------------------------------------------- helpers

def _norm_host(target):
    """Extract bare hostname (no scheme/port) from a target string."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        t = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", t)
    t = t.split("/")[0].strip().rstrip(".")
    return t.lower()


def _norm_base_url(target):
    """Normalize a target into a scheme-qualified base URL."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "http://" + t
    netloc = t.split("://", 1)[1].split("/")[0]
    scheme = t.split("://", 1)[0]
    return f"{scheme}://{netloc}" if netloc else ""


def _host_port(target, default_port=443):
    """host:port pair for TLS probing from a URL or host target."""
    t = (target or "").strip()
    netloc = _norm_base_url(t).split("://", 1)[-1] or _norm_host(t)
    if ":" in netloc:
        host, port = netloc.rsplit(":", 1)
        if port.isdigit():
            return host, port
    host = _norm_host(t)
    return host, str(default_port)


def _finding(tool, title, severity, evidence, location="", note=None,
             manual_cmd=""):
    """engine-shaped finding produced by an omega-sys binary tool."""
    ev = str(evidence or "")
    if len(ev) > EVIDENCE_CAP:
        ev = ev[:EVIDENCE_CAP] + "…"
    vnote = (f"signature from system binary '{tool}'; requires manual "
             "verification before acting on it")
    if manual_cmd:
        vnote += f". Reproduce manually: {manual_cmd}"
    return {
        "title": title,
        "severity": severity,
        "confidence": "candidate",
        "verification": "signature",
        "verification_note": note or vnote,
        "manual_check": True,
        "location": location or "",
        "param": "",
        "evidence": ev,
        "source": f"omega-sys/{tool}",
    }


def _run_x509(pem_text):
    """Inspect one PEM cert with `openssl x509 -noout`; best effort."""
    binary = _X509_BIN
    try:
        proc = subprocess.run(
            [binary, "x509", "-noout", "-subject", "-issuer",
             "-startdate", "-enddate"],
            input=pem_text, capture_output=True, text=True, timeout=30)
        return proc.stdout.strip()
    except Exception:
        return ""


# ---------------------------------------------------------------- parsers

def _parse_nmap(stdout, stderr):
    """Parse nmap grepable output (-oG -) into findings + surface."""
    findings = []
    surface = {"hosts": [], "ports": []}
    for line in (stdout or "").splitlines():
        if not line.startswith("Host: "):
            continue
        body = line[len("Host: "):]
        m = re.match(r"\s*(\S+)\s*\(\)\s*(.*)$", body)
        if not m:
            continue
        host, rest = m.group(1), m.group(2)
        ports_part = rest
        if "Ports: " in rest:
            ports_part = rest.split("Ports: ", 1)[1]
        for entry in ports_part.split(", "):
            fields = entry.strip().split("/")
            if len(fields) >= 4 and fields[1] == "open":
                port, proto, service = fields[0], fields[2], fields[3]
                surface["hosts"].append(host)
                surface["ports"].append(f"{port}")
                findings.append(_finding(
                    "nmap_sv", f"open {service or proto} port on {host}: "
                    f"{port}/{proto}", "INFO",
                    f"{host} {port}/open/{proto}//{service}///",
                    location=f"{host}:{port}",
                    manual_cmd=f"nmap -sV --top-ports 100 {host}"))
    surface["hosts"] = sorted(set(surface["hosts"]))
    surface["ports"] = sorted(set(surface["ports"]))
    return findings, surface


def _parse_ffuf(stdout, stderr):
    """Parse ffuf JSON (-of json) or tolerant text output."""
    findings = []
    urls = []
    text = stdout or ""
    results = []
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            results = data.get("results") or []
        except Exception:
            results = []
    if not results:
        # tolerant text mode: lines containing Status=...
        for m in re.finditer(r"(\S+)\s*\[Status=(\d+)", text):
            results.append({"url": m.group(1), "status": int(m.group(2))})
    for r in results:
        url = str(r.get("url") or r.get("input", {}).get("FUZZ") or "")
        status = r.get("status") or r.get("status_code")
        if not url:
            continue
        urls.append(url)
        findings.append(_finding(
            "ffuf_light", f"path discovered: {url} (HTTP {status})",
            "INFO", f"{url} -> HTTP {status}", location=url,
            manual_cmd=f"curl -sI {url}"))
    return findings, {"urls": sorted(set(urls))}


def _parse_nuclei(stdout, stderr):
    """Parse nuclei -jsonl output."""
    findings = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        info = rec.get("info") or {}
        title = info.get("name") or rec.get("template-id") or "nuclei hit"
        sev = str(info.get("severity") or "info").upper()
        matched = rec.get("matched-at") or rec.get("host") or ""
        findings.append(_finding(
            "nuclei_scan", f"nuclei template hit: {title}", sev,
            line, location=str(matched),
            manual_cmd=f"curl -sI {matched}" if matched else
            "re-run the nuclei template manually against the target"))
    return findings, {}


def _parse_lines(tool, title_fmt, stdout, stderr, surface_key="hosts"):
    """Passive line-per-item parsers (subfinder, amass)."""
    findings = []
    items = []
    for raw in (stdout or "").splitlines():
        item = raw.strip().lstrip("*.").lower()
        if item and re.match(r"^[A-Za-z0-9_.:\-]+$", item):
            items.append(item)
    uniq = sorted(set(items))
    for item in uniq:
        findings.append(_finding(
            tool, title_fmt.format(item=item), "INFO", item,
            location=item,
            manual_cmd=f"curl -sI http://{item}/ ; "
                       f"nmap -sV --top-ports 100 {item}"))
    return findings, {surface_key: uniq}


def _parse_subfinder(stdout, stderr):
    return _parse_lines("subfinder_passive", "passive subdomain: {item}",
                        stdout, stderr)


def _parse_amass(stdout, stderr):
    return _parse_lines("amass_passive", "passive OSINT host: {item}",
                        stdout, stderr)


def _parse_httpx(stdout, stderr):
    """Parse httpx -json output (one JSON object per line)."""
    findings = []
    urls = []
    techs = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        url = str(rec.get("url") or rec.get("input") or "")
        if not url:
            continue
        status = rec.get("status_code")
        title = str(rec.get("title") or "")
        urls.append(url)
        for t in rec.get("tech") or []:
            techs.add(str(t))
        desc = f"{url} -> HTTP {status}"
        if title:
            desc += f" title: {title!r}"
        findings.append(_finding(
            "httpx_json", f"live URL: {url} (HTTP {status})", "INFO",
            desc, location=url,
            manual_cmd=f"curl -sI {url}"))
    surface = {"urls": sorted(set(urls))}
    if techs:
        surface["techs"] = sorted(techs)
    return findings, surface


def _parse_ssl_chain(stdout, stderr):
    """Parse `openssl s_client -showcerts` output: extract PEM chain."""
    findings = []
    certs = []
    pem_blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        stdout or "", re.DOTALL)
    for pem in pem_blocks[:10]:
        details = _run_x509(pem)
        certs.append({"subject": details, "bytes": len(pem)})
        subject = ""
        issuer = ""
        for ln in details.splitlines():
            ln = ln.strip()
            if ln.startswith("subject="):
                subject = ln[len("subject="):].strip()
            elif ln.startswith("issuer="):
                issuer = ln[len("issuer="):].strip()
        if subject:
            findings.append(_finding(
                "ssl_chain", f"TLS certificate in chain: {subject}",
                "INFO", f"{subject} | issued by {issuer}",
                location=subject,
                manual_cmd="openssl s_client -showcerts -connect "
                           "<host>:443 | openssl x509 -noout -subject -issuer"))
    if not pem_blocks and (stdout or stderr):
        findings.append(_finding(
            "ssl_chain", "no TLS certificate chain retrievable", "INFO",
            f"s_client produced no certificates: "
            f"{(stderr or stdout or '')[:120]}",
            manual_cmd="openssl s_client -showcerts -connect <host>:443"))
    return findings, {"certs": certs}


# arg builders: READ-ONLY flags only (audited in tests). Returning None
# means "not applicable for this target/environment" -> contained skip.

def _args_nmap_sv(target):
    host = _norm_host(target)
    if not host:
        return None
    # grepable stdout for the parser; read-only service scan only
    return ["-sV", "--top-ports", "100", "-T3", "-Pn", "-oG", "-", host]


def _args_ffuf_light(target):
    base = _norm_base_url(target)
    if not base:
        return None
    # env var checked at call time so tests can point it at a fixture
    wordlist = os.environ.get("OMEGA_FFUF_WORDLIST") or ""
    for cand in (wordlist,) + FFUF_WORDLIST_CANDIDATES:
        if cand and os.path.isfile(cand):
            wordlist = cand
            break
    if not wordlist:
        return None  # no wordlist available -> contained skip
    return ["-u", base + "/FUZZ", "-w", wordlist, "-X", "GET",
            "-mc", "200,204,301,302,307,401,403",
            "-t", "2", "-rate-limit", "20", "-timeout", "10",
            "-of", "json", "-s"]


def _args_nuclei_scan(target):
    base = _norm_base_url(target) or target
    if not base:
        return None
    return [base, "-jsonl", "-severity", "low,medium,high",
            "-rl", "20", "-c", "10", "-timeout", "10",
            "-silent", "-nc"]


def _args_subfinder_passive(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return ["-d", domain, "-passive", "-silent"]


def _args_amass_passive(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return ["enum", "-passive", "-d", domain, "-timeout", "5"]


def _args_httpx_json(target):
    if not _norm_host(target):
        return None
    return ["-json", "-no-color", "-silent", "-timeout", "10", "-threads", "5"]


def _args_ssl_chain(target):
    host, port = _host_port(target)
    if not host:
        return None
    return ["s_client", "-showcerts", "-connect", f"{host}:{port}",
            "-servername", host]


def _args_jq_probe(target):
    # reserved helper: never auto-run against a target
    return None


# ------------------------------------------------- extended-tool helpers

# hard caps for the extended (15+) system toolset
WHATWEB_MAX_URLS = 25        # whatweb: at most 25 URLs per invocation
BIG_OUTPUT_FINDING_CAP = 50  # URL-emitting tools: max findings per run
DNS_FINDING_CAP = 32         # dnsx / massdns / mapcidr finding caps

MASSDNS_RESOLVER_CANDIDATES = (
    os.environ.get("OMEGA_MASSDNS_RESOLVERS") or "",
    "/etc/massdns/resolvers.txt",
    "/usr/share/massdns/lists/resolvers.txt",
    "/opt/massdns/lists/resolvers.txt",
)

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _cap(items, cap=BIG_OUTPUT_FINDING_CAP):
    return list(items[:cap])


def _is_single_url(target):
    """True when the target is exactly one URL/host (no lists)."""
    t = (target or "").strip()
    return bool(t) and not re.search(r"[\s,]", t)


def _whatweb_urls(target):
    """Split a target into at most WHATWEB_MAX_URLS URLs."""
    parts = [p.strip() for p in re.split(r"[\s,]+", target or "") if p.strip()]
    urls = []
    for p in parts[:WHATWEB_MAX_URLS]:
        urls.append(p if "://" in p else "http://" + p)
    return urls


def _resolver_file():
    """First existing massdns resolver list containing plain-IP lines."""
    candidates = ((os.environ.get("OMEGA_MASSDNS_RESOLVERS") or ""),) + \
        MASSDNS_RESOLVER_CANDIDATES
    for cand in candidates:
        if cand and os.path.isfile(cand):
            try:
                with open(cand, "r", encoding="utf-8", errors="replace") as fh:
                    first = fh.readline().strip().split()[0]
            except OSError:
                continue
            if first and _IPV4_RE.match(first):
                return cand
    return None


def _cidr_from_env():
    cidr = os.environ.get("OMEGA_CIDR") or ""
    return cidr if _CIDR_RE.match(cidr) else None


def _jwt_from_env():
    token = os.environ.get("OMEGA_JWT") or ""
    return token if re.match(r"^[\w\-]+(\.[\w\-]+)*=*$", token) else None


def _js_file_from_env():
    """Operator-fetched local JavaScript file(s) for jsluice (read-only)."""
    for env in ("OMEGA_JS_FILE", "OMEGA_JS_PATHS"):
        val = os.environ.get(env) or ""
        for part in val.split(","):
            part = part.strip()
            if part and os.path.isfile(part):
                return part
    return None


def _gitleaks_source(target):
    """Local scan source for gitleaks: target dir if local, else env."""
    t = (target or "").strip()
    if t and os.path.isdir(t):
        return t
    env = os.environ.get("OMEGA_GITLEAKS_SOURCE") or ""
    if env and os.path.isdir(env):
        return env
    return None


def _looks_like_git_target(target):
    t = (target or "").strip().lower()
    return (t.startswith(("http://", "https://", "git@", "git://", "ssh://"))
            or t.endswith(".git"))


def _trufflehog_source(target):
    """git URL for remote repos, local dir for filesystem mode, else None."""
    t = (target or "").strip()
    if t and os.path.isdir(t):
        return ("filesystem", t)
    if _looks_like_git_target(t):
        return ("git", t)
    return None


def _domain_list_file(domain):
    """Write a one-domain list file for massdns (temp, read-only usage)."""
    import tempfile
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    fh.write(domain + "\n")
    fh.close()
    return fh.name


_CIDR_RE = re.compile(
    r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$|^[0-9a-fA-F:]+/\d{1,3}$")


# ------------------------------------------------------- extended parsers

def _parse_whatweb(stdout, stderr):
    """Parse whatweb --log-json array output or default human text."""
    findings = []
    urls, techs = [], set()
    text = (stdout or "").strip()
    if text.startswith(("[", "{")):
        try:
            data = json.loads(text)
        except Exception:
            data = None
        if isinstance(data, dict):
            data = [data]
        if isinstance(data, list):
            for rec in data:
                if not isinstance(rec, dict):
                    continue
                url = str(rec.get("target") or "")
                if url:
                    urls.append(url)
                plugins = rec.get("plugins") or {}
                for pname, pdata in list(plugins.items())[:15]:
                    techs.add(pname)
                    detail = ""
                    if isinstance(pdata, dict):
                        detail = str(pdata.get("string") or "")
                    findings.append(_finding(
                        "whatweb_fp", f"whatweb plugin: {pname}" +
                        (f" ({detail})" if detail else ""),
                        "INFO", json.dumps({pname: pdata})[:200],
                        location=url,
                        manual_cmd=f"curl -sI {url or '<target>'}"))
            return findings, {"urls": sorted(set(urls)),
                              "techs": sorted(techs)}
    # human text mode: "http://host/ [200 OK] Plugin[...], ..."
    for line in text.splitlines():
        m = re.match(r"^(https?://\S+)\s+\[(\d+)\s*\w*\]\s*(.*)$", line.strip())
        if not m:
            continue
        url, status, rest = m.groups()
        urls.append(url)
        for pm in list(re.finditer(r"([A-Za-z0-9_+.\-]+)\[([^\]]*)\]",
                                   rest))[:15]:
            pname = pm.group(1)
            techs.add(pname)
            findings.append(_finding(
                "whatweb_fp", f"whatweb plugin: {pname}", "INFO",
                line.strip()[:200], location=url,
                manual_cmd=f"curl -sI {url}"))
    return findings, {"urls": sorted(set(urls)), "techs": sorted(techs)}


def _parse_arjun(stdout, stderr):
    """Parse arjun parameter-discovery output (header + '- name' lines)."""
    findings, params = [], []
    in_section = False
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if re.search(r"parameters?\s+found", line, re.IGNORECASE):
            in_section = True
            continue
        m = re.match(r"^[-*+]\s+([A-Za-z_][\w\[\]\-]*)$", line)
        if m and in_section:
            params.append(m.group(1))
        for um in re.finditer(r"[?&]([A-Za-z_][\w-]*)=", line):
            params.append(um.group(1))
    for p in sorted(set(params)):
        findings.append(_finding(
            "arjun_get", f"GET parameter discovered: {p}", "INFO", p,
            location=f"?{p}=",
            manual_cmd=f"curl -s '<target>?{p}=1'  # vary the {p} value "
                       "and diff responses"))
    return findings, {"params": sorted(set(params))}


def _parse_katana(stdout, stderr):
    """Parse katana -jsonl crawl output (or bare URL lines)."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            if re.match(r"^(https?://|/)\S+$", line) and line.startswith("http"):
                url, status, method = line, "", "GET"
            else:
                continue
        else:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            url = str(rec.get("url") or "")
            status = rec.get("status") or ""
            method = str(rec.get("method") or "GET")
        if not url:
            continue
        urls.append(url)
        findings.append(_finding(
            "katana_crawl", f"crawler endpoint: {url}", "INFO",
            f"{method} {url} -> HTTP {status}".strip(), location=url,
            manual_cmd=f"curl -sI {url}"))
    return _cap(findings), {"urls": sorted(set(urls))}


def _parse_gau(stdout, stderr):
    """Parse gau archived-URL lines (--providers wayback,commoncrawl)."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("http"):
            if line.startswith("{"):
                try:
                    line = str(json.loads(line).get("url") or "")
                except Exception:
                    continue
            else:
                continue
        if not line.startswith("http"):
            continue
        urls.append(line)
        findings.append(_finding(
            "gau_urls", f"archived URL: {line}", "INFO", line,
            location=line, manual_cmd=f"curl -sI '{line}'"))
    return _cap(findings), {"urls": sorted(set(urls))}


def _parse_dnsx(stdout, stderr):
    """Parse dnsx -ro response lines: 'name [TYPE] [value ...]'."""
    findings, hosts, dns = [], [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*\[([A-Z]{1,5})\]\s*\[([^\]]+)\]$",
                     line)
        if not m:
            if _IPV4_RE.match(line.split()[0] if line.split() else ""):
                name, rtype, value = "", "A", line
            else:
                continue
        else:
            name, rtype, value = m.groups()
        if name:
            hosts.append(name.rstrip("."))
        dns.append(f"{rtype} {value}" + (f" ({name})" if name else ""))
        findings.append(_finding(
            "dnsx_resolve", f"DNS {rtype} record: {value}", "INFO",
            line[:200], location=name or value,
            manual_cmd=f"dig {rtype} {name or value} +short"))
    return _cap(findings, DNS_FINDING_CAP), {
        "hosts": sorted(set(hosts)), "dns": _cap(dns, 64)}


def _parse_massdns(stdout, stderr):
    """Parse massdns -o S output: 'name. TYPE value'."""
    findings, hosts = [], []
    for line in (stdout or "").splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)\.\s+([A-Z]{1,5})\s+(\S+)$",
                     line.strip())
        if not m:
            continue
        name, rtype, value = m.group(1), m.group(2), m.group(3)
        hosts.append(name)
        findings.append(_finding(
            "massdns_resolve", f"DNS resolution: {name} {rtype} {value}",
            "INFO", line.strip()[:200], location=name,
            manual_cmd=f"dig {rtype} {name} +short"))
    return _cap(findings, DNS_FINDING_CAP), {"hosts": sorted(set(hosts))}


def _parse_mapcidr(stdout, stderr):
    """Parse mapcidr expansion output (bare IP/CIDR lines)."""
    findings, ips = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if _IPV4_RE.match(line) or _CIDR_RE.match(line):
            ips.append(line)
    for ip in ips[:DNS_FINDING_CAP]:
        findings.append(_finding(
            "mapcidr_expand", f"expanded IP from operator CIDR: {ip}",
            "INFO", ip, location=ip,
            manual_cmd=f"nmap -sV --top-ports 100 {ip}"))
    return findings, {"ips": ips}


def _parse_naabu(stdout, stderr):
    """Parse naabu -j JSON lines or 'host:port' text output."""
    findings, hosts, ports = [], [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        host, port = "", ""
        if line.startswith("{"):
            try:
                rec = json.loads(line)
            except Exception:
                continue
            host = str(rec.get("host") or rec.get("ip") or "")
            port = str(rec.get("port") or "")
        else:
            m = re.match(r"^([A-Za-z0-9_.\-]+):(\d{1,5})$", line)
            if m:
                host, port = m.groups()
        if not (host and port.isdigit()):
            continue
        hosts.append(host)
        ports.append(port)
        findings.append(_finding(
            "naabu_top100", f"open port on {host}: {port}", "INFO",
            f"{host}:{port} (naabu top-ports 100)", location=f"{host}:{port}",
            manual_cmd=f"nmap -sV -p {port} {host}"))
    return _cap(findings), {"hosts": sorted(set(hosts)),
                            "ports": sorted(set(ports), key=lambda p: int(p))}


def _parse_dirsearch(stdout, stderr):
    """Parse dirsearch default-text output: '200  1KB  http://.../path'."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        m = re.match(r"^(\d{3})\s+\S+\s+(https?://\S+)", line.strip())
        if not m:
            continue
        status, url = m.groups()
        urls.append(url)
        findings.append(_finding(
            "dirsearch_paths", f"path discovered: {url} (HTTP {status})",
            "INFO", line.strip()[:200], location=url,
            manual_cmd=f"curl -sI {url}"))
    return _cap(findings), {"urls": sorted(set(urls))}


def _parse_feroxbuster(stdout, stderr):
    """Parse feroxbuster --json lines or default text output."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        url, status = "", ""
        if line.startswith("{"):
            try:
                rec = json.loads(line)
            except Exception:
                continue
            url = str(rec.get("url") or rec.get("original_url") or "")
            status = str(rec.get("status") or "")
        else:
            m = re.match(r"^(\d{3})\s+\S+\s+(https?://\S+)", line)
            if m:
                status, url = m.groups()
        if not url:
            continue
        urls.append(url)
        findings.append(_finding(
            "feroxbuster_light", f"path discovered: {url} "
            + (f"(HTTP {status})" if status else ""), "INFO",
            line[:200], location=url, manual_cmd=f"curl -sI {url}"))
    return _cap(findings), {"urls": sorted(set(urls))}


def _parse_crlfuzz(stdout, stderr):
    """Parse crlfuzz output: vulnerable URLs, one per line (GET-only)."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("http"):
            continue
        urls.append(line)
        findings.append(_finding(
            "crlfuzz_scan", f"possible CRLF injection: {line}", "MEDIUM",
            line[:200], location=line,
            manual_cmd=f"curl -sI --get '{line}'  # inspect injected headers"))
    return _cap(findings, 20), {"urls": sorted(set(urls))}


def _parse_graphw00f(stdout, stderr):
    """Parse graphw00f fingerprint output."""
    findings, hits = [], []
    for line in (stdout or "").splitlines():
        if re.search(r"may be running|Detected|fingerprint|engine",
                     line, re.IGNORECASE):
            hits.append(line.strip())
            findings.append(_finding(
                "graphw00f_fp", f"GraphQL fingerprint: {line.strip()}",
                "INFO", line.strip()[:200],
                manual_cmd="graphw00f -f -t <target> -T 10"))
    if findings:
        return findings, {"graphql": hits}
    return [], {"graphql": []}


def _parse_dalfox(stdout, stderr):
    """Parse dalfox --silence POC output (XSS candidates)."""
    findings = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not (line.startswith("[") or "POC" in line):
            continue
        triggered = "Triggered" in line
        findings.append(_finding(
            "dalfox_scan",
            f"XSS candidate{' (triggered)' if triggered else ''}: "
            f"{line[:120]}", "HIGH" if triggered else "MEDIUM",
            line[:300],
            manual_cmd="dalfox scan <url> --no-color --silence  # "
                       "verify the payload manually in a browser"))
    return _cap(findings, 20), {}


def _parse_kxss(stdout, stderr):
    """Parse kxss reflection output: URL lines with reflected param values."""
    findings, params = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("http"):
            continue
        for pm in re.finditer(r"([A-Za-z_][\w-]*)=([^&\s]*)", line):
            param, value = pm.group(1), pm.group(2)
            if not value:
                continue
            unquoted = value.replace("%3C", "<").replace("%3E", ">")
            if ("<" in unquoted) or (">" in unquoted):
                params.append(param)
                findings.append(_finding(
                    "kxss_reflect", f"reflected parameter: {param}", "MEDIUM",
                    line[:300], location=line[:120],
                    manual_cmd=f"curl -s --get '{line.split('?')[0]}' "
                               f"--data-urlencode '{param}=<b>x</b>' "
                               "-G  # confirm reflection then escape context"))
    return _cap(findings, 20), {"params": sorted(set(params))}


def _parse_nikto(stdout, stderr):
    """Parse nikto informational findings (Tuning 123 classes only)."""
    findings = []
    for line in (stdout or "").splitlines():
        m = re.match(r"^\+\s+([^:]+):\s*(.+)$", line.strip())
        if not m:
            continue
        item, desc = m.group(1).strip(), m.group(2).strip()
        if item.startswith(("OSVDB", "Nikto", "Target ")) or \
                item in ("Start Time", "End Time"):
            continue
        findings.append(_finding(
            "nikto_info", f"nikto informational finding: {item}", "INFO",
            line.strip()[:300], location=item if item.startswith("/") else "",
            manual_cmd=f"curl -sI '{item}'  # inspect manually"))
    return _cap(findings), {}


def _parse_jwt_tool(stdout, stderr):
    """Parse jwt_tool decode-only output ([+] key = \"value\" lines)."""
    findings = []
    section = ""
    header, payload = {}, {}
    for line in (stdout or "").splitlines():
        line = line.strip()
        low = line.lower()
        if low.startswith("token header"):
            section = "header"
            continue
        if low.startswith("token payload"):
            section = "payload"
            continue
        m = re.match(r"^\[\+\]\s*([\w\-]+)\s*=\s*(.+)$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip().strip('"')
        if section == "header":
            header[key] = val
        elif section == "payload":
            payload[key] = val
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        findings.append(_finding(
            "jwt_decode", "JWT uses alg=none (unsigned token accepted?)",
            "HIGH", f"alg = none | payload keys: {sorted(payload)}",
            location="operator-supplied JWT",
            manual_cmd="jwt_tool <token>  # confirm unsigned acceptance "
                       "manually; never run tamper/crack modes"))
    for k, v in list(payload.items())[:25]:
        findings.append(_finding(
            "jwt_decode", f"JWT payload claim: {k}", "INFO", f"{k} = {v}",
            location="operator-supplied JWT",
            manual_cmd="jwt_tool <token>  # decode only, no tamper modes"))
    return findings, {"jwt_header": header, "jwt_claims": sorted(payload)}


def _mask_secret(raw):
    raw = str(raw or "")
    if len(raw) <= 10:
        return raw[:2] + "…" if raw else ""
    return raw[:8] + "…(redacted)"


def _parse_trufflehog(stdout, stderr):
    """Parse trufflehog --json secret findings (no live verification)."""
    findings = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        detector = str(rec.get("DetectorName") or "unknown")
        where = ""
        try:
            where = str(rec["SourceMetadata"]["Data"]["Git"]["file"] or "")
        except (KeyError, TypeError):
            where = str(rec.get("Path") or "")
        findings.append(_finding(
            "trufflehog_fs", f"credential detected ({detector})", "HIGH",
            f"detector={detector} file={where} "
            f"raw={_mask_secret(rec.get('Raw'))}",
            location=where or "repository",
            manual_cmd="trufflehog git <repo-url> --json --no-update "
                       "--no-verification  # review the file manually"))
    return _cap(findings), {}


def _parse_gitleaks(stdout, stderr):
    """Parse gitleaks detect --report-format json --report-path - output."""
    findings = []
    text = (stdout or "").strip()
    data = None
    if text.startswith(("[", "{")):
        try:
            data = json.loads(text)
        except Exception:
            data = None
    if isinstance(data, dict):
        data = [data]
    if isinstance(data, list):
        for rec in data[:50]:
            if not isinstance(rec, dict):
                continue
            findings.append(_finding(
                "gitleaks_scan",
                f"leak detected: {rec.get('RuleID') or 'unknown'}", "HIGH",
                f"file={rec.get('File')} line={rec.get('StartLine')} "
                f"secret={_mask_secret(rec.get('Secret'))}",
                location=str(rec.get("File") or "repository"),
                manual_cmd="gitleaks detect --no-banner --source <dir> "
                           "--report-format json --report-path -  # review"))
    return findings, {}


def _parse_jsluice(stdout, stderr):
    """Parse jsluice urls output (JSON lines)."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        url = str(rec.get("url") or "")
        if not url:
            continue
        urls.append(url)
        findings.append(_finding(
            "jsluice_urls", f"JS-referenced URL: {url}", "INFO",
            line[:200], location=url,
            manual_cmd=f"curl -sI '{url}'"))
    return _cap(findings), {"urls": sorted(set(urls))}


def _parse_interactsh(stdout, stderr):
    # reserved: never auto-run
    return [], {"note": "interactsh reserved"}


# ------------------------------------------------- extended arg builders
# All READ-ONLY: explicit rate/thread caps, GET-only where applicable.
# Returning None means "not applicable for this target/environment".

def _args_whatweb_fp(target):
    urls = _whatweb_urls(target)
    if not urls:
        return None
    # aggression 0 = stealthy, max 25 URLs, no extra requests
    return (["--no-color", "--aggression", "0", "--no-errors"]
            + urls[:WHATWEB_MAX_URLS])


def _args_arjun_get(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["-u", base, "-m", "GET", "-t", "5", "-T", "10",
            "--rate-limit", "20", "--stable"]


def _args_nikto_info(target):
    base = _norm_base_url(target)
    if not base:
        return None
    # Tuning 1,2,3 = interesting files / misconfig / information disclosure
    # only — never injection, execution, upload or DoS classes.
    return ["-h", base, "-Tuning", "123", "-timeout", "10",
            "-maxtime", "120s", "-ask", "no", "-nointeract"]


def _args_dalfox_scan(target):
    base = _norm_base_url(target)
    if not base or not _is_single_url(target):
        return None
    return ["scan", base, "--no-color", "--silence", "--worker", "5",
            "--timeout", "10", "--delay", "100"]


def _args_katana_crawl(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["-u", base, "-d", "2", "-c", "10", "-rl", "20", "-timeout", "10",
            "-silent", "-no-color", "-jsonl"]


def _args_gau_urls(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return [domain, "--threads", "4", "--providers", "wayback,commoncrawl",
            "--timeout", "10"]


def _args_dnsx_resolve(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return ["-d", domain, "-a", "-aaaa", "-mx", "-ns", "-txt",
            "-ro", "-t", "10", "-rl", "20", "-silent"]


def _args_massdns_resolve(target):
    domain = _norm_host(target)
    resolvers = _resolver_file()
    if not domain or not resolvers:
        return None
    return ["-r", resolvers, "-t", "A", "-o", "S", "-s", "10", "-q",
            _domain_list_file(domain)]


def _args_mapcidr_expand(target):
    cidr = _cidr_from_env()
    if not cidr:
        return None
    return ["-cl", cidr, "-skip-base", "-skip-broadcast"]


def _args_naabu_top100(target):
    host = _norm_host(target)
    if not host:
        return None
    return ["-host", host, "-top-ports", "100", "-rate", "500",
            "-c", "10", "-j", "-silent", "-duc"]


def _args_dirsearch_paths(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["-u", base + "/", "-t", "10", "--random-agent", "-x", "404",
            "--timeout", "10"]


def _args_feroxbuster_light(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["-u", base, "-t", "5", "--rate-limit", "20", "--no-state",
            "--json", "--quiet", "--timeout", "10"]


def _args_crlfuzz_scan(target):
    base = _norm_base_url(target)
    if not base:
        return None
    # GET-only (no -X flag), capped concurrency, results to stdout
    return ["-u", base, "-c", "10", "-s", "-o", "-"]


def _args_graphw00f_fp(target):
    base = _norm_base_url(target)
    if not base or not _is_single_url(target):
        return None
    return ["-f", "-t", base, "-T", "10"]


def _args_kxss_reflect(target):
    base = _norm_base_url(target)
    if not base or not _is_single_url(target):
        return None
    return [base]  # kxss reads URLs from stdin; URL kept for audit trail


def _args_jwt_decode(target):
    token = _jwt_from_env()
    if not token:
        return None
    # decode-only: token argument, NO tamper (-t) / crack (-C/-d) modes
    return [token]


def _args_trufflehog_fs(target):
    src = _trufflehog_source(target)
    if not src:
        return None
    mode, source = src
    return [mode, source, "--json", "--no-update", "--no-verification",
            "--concurrency", "2"]


def _args_gitleaks_scan(target):
    src = _gitleaks_source(target)
    if not src:
        return None
    return ["detect", "--no-banner", "--source", src,
            "--report-format", "json", "--report-path", "-", "--redact"]


def _args_jsluice_urls(target):
    js = _js_file_from_env()
    if not js:
        return None
    return ["urls", js, "-c", "2", "-u"]


def _args_interactsh_reserved(target):
    return None


# ------------------------------------------------- arsenal-2 helpers
# Extended arsenal (append-only batch #3): web fuzzing/recon, TLS,
# DNS/OSINT, crawl/JS, vuln scanners, API/GraphQL, read-only auth
# fingerprinting, cloud/bucket, curl-based probes. All READ-ONLY,
# rate/thread-capped, skip-contained when binaries/env are absent.

# wordlist candidates shared by gobuster/wfuzz/dirb/gobuster-vhost
_ARSENAL_WORDLIST_CANDIDATES = (
    os.environ.get("OMEGA_FFUF_WORDLIST") or "",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/wfuzz/general/common.txt",
)

# read-only TLS port sweep candidate set (openssl s_client, one call per
# operator-driven port; top TLS ports only)
TOP_TLS_PORTS = (443, 465, 563, 587, 636, 853, 990, 992, 993, 995,
                 1443, 2443, 4443, 5443, 8443, 8883, 8888, 9443, 10443, 18443)

_CURL_URL_CAP = 12  # max URLs per curl-based probe invocation


def _wordlist_file():
    """First existing content-discovery wordlist, else None (skip).

    Candidates are evaluated at call time so tests/env can point
    OMEGA_FFUF_WORDLIST at a fixture after import.
    """
    candidates = ((os.environ.get("OMEGA_FFUF_WORDLIST") or ""),) + \
        _ARSENAL_WORDLIST_CANDIDATES[1:]
    for cand in candidates:
        if cand and os.path.isfile(cand):
            return cand
    return None


def _env_file(env):
    """Env-provided file path that exists, else None (skip)."""
    val = os.environ.get(env) or ""
    return val if val and os.path.isfile(val) else None


def _env_val(env):
    """Non-empty env string, else None (skip)."""
    val = os.environ.get(env) or ""
    return val if val.strip() else None


def _cms_urls(target, cap=_CURL_URL_CAP):
    """Absolute URLs from a target for curl-based path probes."""
    base = _norm_base_url(target)
    if not base:
        return []
    return [base]


def _parse_url_lines(tool, title_fmt, stdout, stderr, cap=BIG_OUTPUT_FINDING_CAP):
    """Parse tools that emit one URL per line (hakrawler, photon, ...)."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith(("http://", "https://")):
            continue
        urls.append(line)
        findings.append(_finding(
            tool, title_fmt.format(url=line), "INFO", line[:200],
            location=line, manual_cmd=f"curl -sI '{line}'"))
    return _cap(findings, cap), {"urls": sorted(set(urls))}


def _parse_json_records(tool, title_key, stdout, stderr,
                        sev="INFO", cap=BIG_OUTPUT_FINDING_CAP):
    """Parse JSON / JSONL output tolerantly (skip bad lines)."""
    findings, records = [], []
    text = (stdout or "").strip()
    data = None
    if text.startswith((("[", "{"))):
        try:
            data = json.loads(text)
        except Exception:
            data = None
    if isinstance(data, dict):
        data = [data]
    lines = data if isinstance(data, list) else []
    if not lines:
        for line in (stdout or "").splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    lines.append(json.loads(line))
                except Exception:
                    continue
    for rec in lines[:cap]:
        if not isinstance(rec, dict):
            continue
        records.append(rec)
        title = str(rec.get(title_key) or rec.get("name") or "hit")
        findings.append(_finding(
            tool, f"{title}", sev, json.dumps(rec, default=str)[:250],
            manual_cmd=f"review {tool} output manually"))
    return findings, {"records": records}


def _parse_marked_curl(tool, title, severity, stdout, stderr):
    """Parse curl -w 'URL=%{url_effective} CODE=%{http_code}' probes.

    The body precedes each marker line; a marker CODE=200 with a
    meaningful body produces one candidate finding.
    """
    findings, hits = [], []
    body_lines, marker = [], None

    def _flush():
        if marker is None:
            return
        url = marker.get("url", "")
        code = marker.get("code", "")
        body = "\n".join(body_lines).strip()
        if code in ("200", "403", "401") and body:
            findings.append(_finding(
                tool, f"{title}: {url} (HTTP {code})",
                severity if code == "200" else "INFO",
                body[:250], location=url,
                manual_cmd=f"curl -s '{url}'  # inspect manually"))

    for line in (stdout or "").splitlines():
        m = re.match(r"^URL=(\S+)\s+CODE=(\d{3})\s*$", line.strip())
        if m:
            _flush()
            marker = {"url": m.group(1), "code": m.group(2)}
            body_lines = []
        else:
            if marker is not None:
                body_lines.append(line)
    _flush()
    for f in findings:
        hits.append(f["location"])
    return _cap(findings), {"hits": hits}


# ------------------------------------------------------- arsenal-2 parsers

def _parse_testssl(stdout, stderr):
    """Parse testssl.sh plain output: '<SEVERITY> <description>' lines."""
    findings, sevlines = [], []
    for line in (stdout or "").splitlines():
        m = re.match(r"^(CRITICAL|HIGH|MEDIUM|LOW|WARN|INFO)\s+(.{4,})$",
                     line.strip())
        if not m:
            continue
        sevmap = {"WARN": "LOW", "INFO": "INFO"}
        sev = sevmap.get(m.group(1), m.group(1))
        desc = m.group(2).strip()[:200]
        sevlines.append(line.strip())
        findings.append(_finding(
            "testssl_sev", f"TLS finding ({m.group(1)}): {desc}", sev,
            line.strip()[:250],
            manual_cmd="testssl.sh --severity LOW <host:port>  # review"))
    return _cap(findings), {"tls_findings": sevlines[:64]}


def _parse_sslscan(stdout, stderr):
    """Parse sslscan --no-colours output (cipher/protocol lines)."""
    findings, ciphers = [], []
    for line in (stdout or "").splitlines():
        m = re.match(r"^\s*(Accepted|Preferred)\s+(\S+)\s+(\d+)\s+bits?\s+"
                     r"(\S+)", line)
        if m:
            state, proto, bits, cipher = m.groups()
            ciphers.append(line.strip())
            findings.append(_finding(
                "sslscan_quiet", f"accepted cipher: {cipher} ({proto}, "
                f"{bits} bits)", "INFO", line.strip()[:200],
                manual_cmd="sslscan --no-colours <host:port>  # review"))
            continue
        if re.match(r"^\s*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)\s+(enabled|"
                    r"disabled)", line):
            proto, state = line.split()[0], line.split()[1]
            if state == "enabled":
                findings.append(_finding(
                    "sslscan_quiet", f"deprecated protocol enabled: {proto}",
                    "LOW", line.strip()[:200],
                    manual_cmd="sslscan --no-colours <host:port>"))
    return _cap(findings), {"ciphers": ciphers[:64]}


def _parse_sslyze(stdout, stderr):
    """Parse sslyze --regular text output (plugin result lines)."""
    findings, notes = [], []
    for line in (stdout or "").splitlines():
        if re.search(r"(UNSUPPORTED|DEPRECATED|INSECURE|FAILED|disabled|"
                     r"not supported)", line, re.IGNORECASE):
            notes.append(line.strip())
            findings.append(_finding(
                "sslyze_regular", f"TLS config note: {line.strip()[:120]}",
                "INFO", line.strip()[:200],
                manual_cmd="sslyze --regular <host:port>  # review"))
    return _cap(findings), {"notes": notes[:64]}


def _parse_ssl_brief(tool, stdout, stderr):
    """Parse `openssl s_client -brief` verify/protocol output."""
    findings, lines = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if line.startswith(("Protocol version", "Ciphersuite",
                            "Verification", "Peer signing digest")):
            lines.append(line)
            if "Verification" in line and "OK" not in line:
                findings.append(_finding(
                    tool, f"TLS verification problem: {line}", "LOW",
                    line[:200],
                    manual_cmd="openssl s_client -brief -connect "
                               "<host>:443  # inspect the chain manually"))
    if lines:
        findings.append(_finding(
            tool, "TLS session details captured", "INFO",
            " | ".join(lines)[:250],
            manual_cmd="openssl s_client -brief -connect <host>:443"))
    return findings, {"tls": lines}


def _parse_dnsrecon(stdout, stderr):
    """Parse dnsrecon -t std text/JSON output ([*]/[+] record lines)."""
    findings, dns = [], []
    text = (stdout or "").strip()
    if text.startswith("["):
        recs = _parse_json_records("dnsrecon_std", "name", stdout, stderr)[1]
        for rec in recs.get("records", [])[:DNS_FINDING_CAP]:
            dns.append(json.dumps(rec, default=str)[:120])
        return ([_finding(
            "dnsrecon_std", "DNS zone record (JSON)", "INFO", d,
            manual_cmd="dig <record> <domain> +short") for d in dns],
            {"dns": dns})
    for line in (stdout or "").splitlines():
        m = re.match(r"^[\*\+\-\[\]]*\s*\[?([A-Z]{1,5})\]?\s+(\S+)"
                     r"(\s+\S.*)?$", line.strip())
        if not m:
            continue
        rtype, value = m.group(1), m.group(2)
        if rtype not in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME",
                         "SRV", "PTR"):
            continue
        dns.append(f"{rtype} {value}")
        findings.append(_finding(
            "dnsrecon_std", f"DNS {rtype} record: {value}", "INFO",
            line.strip()[:200], location=value,
            manual_cmd=f"dig {rtype} {value} +short"))
    return _cap(findings, DNS_FINDING_CAP), {"dns": dns[:64]}


def _parse_dnsenum(stdout, stderr):
    """Parse dnsenum output (Host's addresses / name server lines)."""
    findings, dns = [], []
    section = ""
    for line in (stdout or "").splitlines():
        line = line.strip()
        low = line.lower()
        if "name server" in low or "mailserver" in low or \
                "host's addresses" in low or "wildcard" in low:
            section = low
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s+(\d{1,3}(?:\.\d{1,3}){3})$",
                     line)
        if m:
            dns.append(f"A {m.group(1)} -> {m.group(2)}")
            findings.append(_finding(
                "dnsenum_std", f"DNS enumeration: {m.group(1)}",
                "INFO", line[:200], location=m.group(1),
                manual_cmd=f"dig A {m.group(1)} +short"))
    return _cap(findings, DNS_FINDING_CAP), {"dns": dns[:64]}


def _parse_github_dorks_unused(stdout, stderr):
    return _parse_json_records("github_dorks", "name", stdout, stderr)


def _parse_osint_lines(tool, stdout, stderr):
    """Parse OSINT line-per-hit tools (sublist3r -v, knockpy, ...)."""
    return _parse_lines(tool, "OSINT hit: {item}", stdout, stderr)


def _parse_theharvester(stdout, stderr):
    """Parse theHarvester output (hosts/emails sections)."""
    findings, hosts = [], []
    section = ""
    for line in (stdout or "").splitlines():
        line = line.strip()
        low = line.lower().rstrip(":")
        if low in ("hosts", "emails", "ips", "domain", "shutdown"):
            section = low
            continue
        if section in ("hosts", "ips") and re.match(
                r"^[A-Za-z0-9_.:\-]+$", line) and len(line) > 3:
            hosts.append(line.lower())
            findings.append(_finding(
                "theharvester_osint", f"OSINT host: {line}", "INFO", line,
                location=line,
                manual_cmd=f"curl -sI http://{line}/"))
    return _cap(findings), {"hosts": sorted(set(hosts))}


def _parse_sherlock(stdout, stderr):
    """Parse sherlock --print-found output ('[+] ... URL')."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        m = re.match(r"^\[\+\]\s*([\w.\-]+):\s*(https?://\S+)$", line.strip())
        if not m:
            continue
        user, url = m.groups()
        urls.append(url)
        findings.append(_finding(
            "sherlock_user", f"profile found for '{user}': {url}", "INFO",
            line.strip()[:200], location=url,
            manual_cmd=f"curl -sI '{url}'"))
    return _cap(findings), {"urls": sorted(set(urls))}


def _parse_maigret(stdout, stderr):
    """Parse maigret --print-found output."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        m = re.search(r"(https?://\S+)", line)
        if not m or not re.search(r"\[\+\]|found", line, re.IGNORECASE):
            continue
        url = m.group(1).rstrip(")….")
        urls.append(url)
        findings.append(_finding(
            "maigret_user", f"account hint: {url}", "INFO", line[:200],
            location=url, manual_cmd=f"curl -sI '{url}'"))
    return _cap(findings), {"urls": sorted(set(urls))}


def _parse_hakrawler(stdout, stderr):
    return _parse_url_lines("hakrawler_crawl", "crawled endpoint: {url}",
                            stdout, stderr)


def _parse_photon(stdout, stderr):
    return _parse_url_lines("photon_crawl", "photon URL: {url}",
                            stdout, stderr)


def _parse_linkfinder(stdout, stderr):
    """Parse LinkFinder CLI output (regex-extracted absolute/relative URLs)."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        for m in re.finditer(r"(https?://[^\s\"'<>)]+|/(?:[A-Za-z0-9_\-./]"
                             r"{2,}))", line):
            url = m.group(1)
            urls.append(url)
            findings.append(_finding(
                "linkfinder_js", f"JS-referenced endpoint: {url}", "INFO",
                line.strip()[:200], location=url,
                manual_cmd=f"curl -sI '{url}'"))
    return _cap(findings), {"urls": sorted(set(urls))[:64]}


def _parse_relative_urls(stdout, stderr):
    """curl+grep relative-URL extractor output (one match per line)."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if re.match(r"^/[A-Za-z0-9_\-./]{2,}$", line) or \
                line.startswith(("http://", "https://")):
            urls.append(line)
            findings.append(_finding(
                "relative_url_extract", f"relative endpoint: {line}", "INFO",
                line[:200], location=line,
                manual_cmd=f"curl -sI '{line}'"))
    return _cap(findings), {"urls": sorted(set(urls))[:64]}


def _parse_wpscan(stdout, stderr):
    """Parse wpscan --no-update output ([+] finding lines)."""
    findings, hits = [], []
    for line in (stdout or "").splitlines():
        m = re.match(r"^\[\+\]\s*(.+)$", line.strip())
        if not m:
            continue
        desc = m.group(1).strip()
        sev = "LOW" if re.search(r"outdated|vulnerable|warning|error",
                                 desc, re.IGNORECASE) else "INFO"
        hits.append(desc)
        findings.append(_finding(
            "wpscan_enum", f"WordPress finding: {desc[:120]}", sev,
            line.strip()[:250],
            manual_cmd="wpscan --no-update --random-user-agent -u <url>"))
    return _cap(findings), {"hits": hits[:64]}


def _parse_cms_text(tool, stdout, stderr):
    """Generic CMS-detector text parser (droopescan/joomscan/drupwn/cmseek)."""
    findings, hits = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if re.search(r"(cms|wordpress|drupal|joomla|moodle|silverstripe|"
                     r"version|panel|plugin|theme|found|detected)",
                     line, re.IGNORECASE) and len(line) > 4 and \
                not line.startswith(("[i]", "[?]", "#")):
            hits.append(line[:150])
            findings.append(_finding(
                tool, f"CMS detail: {line[:120]}", "INFO", line[:250],
                manual_cmd=f"review '{tool}' output manually"))
    return _cap(findings), {"hits": hits[:64]}


def _parse_scorecard(stdout, stderr):
    """Parse OSSF Scorecard API JSON response (repo checks summary)."""
    findings, scores = [], []
    text = (stdout or "").strip()
    try:
        data = json.loads(text) if text.startswith("{") else None
    except Exception:
        data = None
    if isinstance(data, dict):
        score = data.get("score")
        for chk in (data.get("checks") or [])[:40]:
            if not isinstance(chk, dict):
                continue
            name, cscore = chk.get("name"), chk.get("score")
            if name is None:
                continue
            scores.append(f"{name}: {cscore}")
            if isinstance(cscore, (int, float)) and cscore <= 4:
                findings.append(_finding(
                    "scorecard_ossf",
                    f"OSSF check '{name}' scored {cscore}/10", "LOW",
                    f"{name}: {cscore} (repo score {score})",
                    manual_cmd="https://api.securityscorecards.dev/ "
                               "# review the check detail"))
        if score is not None:
            findings.append(_finding(
                "scorecard_ossf", f"OSSF Scorecard overall: {score}/10",
                "INFO", f"overall score {score}", location=str(score),
                manual_cmd="review scorecard.dev report"))
    return findings, {"scores": scores}


def _parse_graphql_introspect(stdout, stderr):
    """Parse GET-based curl introspection response (schema type names)."""
    findings, types = [], []
    try:
        data = json.loads((stdout or "").strip() or "{}")
    except Exception:
        data = None
    body = stdout or ""
    if isinstance(data, dict):
        for t in (((data.get("data") or {}).get("__schema") or {})
                  .get("types") or [])[:60]:
            if isinstance(t, dict) and t.get("name"):
                types.append(t["name"])
    elif "__schema" in body:
        types = re.findall(r'"name"\s*:\s*"([\w]+)"', body)[:60]
    if types:
        findings.append(_finding(
            "graphql_introspect",
            f"GraphQL schema introspectable ({len(types)} types)", "MEDIUM",
            f"types: {types[:25]}", location="<graphql-endpoint>",
            manual_cmd="curl -sG <endpoint> --data-urlencode "
                       "'query={__schema{types{name}}}'  # confirm manually"))
    elif "error" in body.lower() and body.strip():
        findings.append(_finding(
            "graphql_introspect", "GraphQL endpoint responded (errors)",
            "INFO", body.strip()[:200],
            manual_cmd="curl -sG <endpoint> --data-urlencode "
                       "'query={__typename}'  # confirm manually"))
    return findings, {"graphql_types": types}


def _parse_params(stdout, stderr):
    return _parse_url_lines("paramspider_disc",
                            "parameterised URL: {url}", stdout, stderr)


def _parse_arjun2(stdout, stderr):
    return _parse_arjun(stdout, stderr)


def _parse_auth_hints(stdout, stderr):
    """Fingerprint login-page markers — READ-ONLY, never submits creds."""
    findings, markers = [], []
    body = (stdout or "").lower()
    checks = [
        ("login form", r"<form[^>]*>(?:.|\n){0,400}?(password|passwd)"
         r"[\s\S]{0,200}?input|input[^>]*type=[\"']?password"),
        ("http auth", r"^www-authenticate:\s*(basic|digest|ntlm)",
         True),
        ("default-cred marker", r"(admin\s*/\s*admin|default credentials|"
         r"password\s*:\s*admin|demo\s*/\s*demo)"),
        ("auth bypass marker", r"(?<![\w])username[\"']?\s*[:=]\s*[\"']?"
         r"admin(?![\w])"),
    ]
    for name, pat, *flags in checks:
        reflags = re.MULTILINE if flags else 0
        if re.search(pat, body if not flags else stdout or "",
                     reflags | re.IGNORECASE):
            markers.append(name)
            findings.append(_finding(
                "auth_hints_fp", f"auth surface hint: {name}", "INFO",
                f"marker '{name}' observed on login/auth page (GET only; "
                "no credentials were submitted)",
                manual_cmd="curl -sS <target> | grep -i password  # "
                           "review the form manually"))
    return findings, {"auth_markers": markers}


def _parse_s3scanner(stdout, stderr):
    """Parse s3scanner output (JSON or CSV 'provider,bucket,...' lines)."""
    findings, buckets = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            recs = _parse_json_records("s3scanner_scan", "bucket",
                                       line, stderr)[1].get("records", [])
            for rec in recs:
                buckets.append(str(rec.get("bucket", "")))
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 3 and parts[1]:
            buckets.append(parts[1])
            public = any(p.lower() in ("public", "true") for p in parts[3:])
            findings.append(_finding(
                "s3scanner_scan",
                f"cloud bucket: {parts[1]} "
                f"({'public listing' if public else 'exists'})",
                "LOW" if public else "INFO", line[:200],
                location=parts[1],
                manual_cmd=f"curl -sI https://{parts[1]}.s3.amazonaws.com/ "
                           "# confirm manually (read-only)"))
    return _cap(findings), {"buckets": sorted(set(buckets))}


def _parse_cloud_enum(stdout, stderr):
    """Parse cloud_enum stdout (public asset URL lines)."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        m = re.match(r"^(\[([^\]]+)\]\s*)?(https?://\S+)", line)
        if not m:
            continue
        url = m.group(3)
        if not re.search(r"(open|public|\[\+\])", line, re.IGNORECASE):
            continue
        urls.append(url)
        findings.append(_finding(
            "cloud_enum_scan", f"public cloud asset: {url}", "LOW",
            line[:200], location=url, manual_cmd=f"curl -sI '{url}'"))
    return _cap(findings), {"urls": sorted(set(urls))}


def _parse_wafw00f(stdout, stderr):
    """Parse wafw00f output ('is behind ...' lines)."""
    findings, wafs = [], []
    for line in (stdout or "").splitlines():
        if re.search(r"is behind|No WAF detected|Generic detection",
                     line, re.IGNORECASE):
            wafs.append(line.strip()[:150])
            if "is behind" in line.lower():
                findings.append(_finding(
                    "wafw00f_fp", f"WAF detected: {line.strip()[:120]}",
                    "INFO", line.strip()[:200],
                    manual_cmd="wafw00f -v <url>  # confirm manually"))
    return findings, {"wafs": wafs}


def _parse_open_probe(tool, title, severity, marker_re, stdout, stderr):
    """Parse curl probes for readable sensitive files (.git/HEAD, ...)."""
    findings, hits = [], []
    for line in (stdout or "").splitlines():
        m = re.match(r"^URL=(\S+)\s+CODE=(\d{3})\s*$", line.strip())
        if not m:
            continue
        url, code = m.group(1), m.group(2)
        hits.append(url)
        findings.append(_finding(
            tool, f"{title}: {url} (HTTP {code})", severity,
            f"{url} returned HTTP {code}", location=url,
            manual_cmd=f"curl -s '{url}'  # inspect manually (read-only)"))
    return _cap(findings), {"hits": hits}


def _parse_git_open(stdout, stderr):
    """curl probe with body: /.git/HEAD readable = exposed repo candidate."""
    findings, hits = [], []
    body, marker = [], None

    def _flush():
        if not marker:
            return
        url, code = marker
        text = "\n".join(body).strip()
        if code == "200" and re.search(r"ref:\s*refs/", text):
            findings.append(_finding(
                "git_open_probe", "exposed .git/HEAD (repo index readable)",
                "LOW", f"{url} -> {text[:120]}", location=url,
                manual_cmd=f"curl -s '{url}'  # candidate only; review "
                           "manually before any deeper inspection"))

    for line in (stdout or "").splitlines():
        m = re.match(r"^URL=(\S+)\s+CODE=(\d{3})\s*$", line.strip())
        if m:
            _flush()
            marker = (m.group(1), m.group(2))
            body = []
        elif marker:
            body.append(line)
    _flush()
    return findings, {"hits": [f["location"] for f in findings]}


def _parse_backup_probe(stdout, stderr):
    """Parse the multi-URL backup-file probe (URL=/CODE= markers)."""
    findings, hits = [], []
    for line in (stdout or "").splitlines():
        m = re.match(r"^URL=(\S+)\s+CODE=(200)\s*$", line.strip())
        if m:
            url = m.group(1)
            hits.append(url)
            findings.append(_finding(
                "backup_file_probe", f"possible backup file exposed: {url}",
                "LOW", f"{url} returned HTTP 200", location=url,
                manual_cmd=f"curl -sI '{url}'  # confirm size/content "
                           "manually (read-only)"))
    return _cap(findings), {"hits": hits}


def _parse_headers_probe(stdout, stderr):
    """Parse curl -sSI response headers of interest (server/security)."""
    findings, headers = [], []
    for line in (stdout or "").splitlines():
        m = re.match(r"^([Ss]erver|[Xx]-[Pp]owered-[Bb]y):\s*(.+)$",
                     line.strip())
        if m:
            headers.append(line.strip())
            findings.append(_finding(
                "headers_probe", f"banner header: {line.strip()[:100]}",
                "INFO", line.strip()[:200],
                manual_cmd=f"curl -sSI <target>  # review manually"))
    return findings, {"headers": headers}


def _parse_open_probe_svn(stdout, stderr):
    return _parse_open_probe("svn_open_probe", "readable SVN metadata",
                             "LOW", r"ref:", stdout, stderr)


def _parse_open_probe_ds(stdout, stderr):
    return _parse_open_probe("ds_store_probe", "readable .DS_Store",
                             "LOW", r"Bud1", stdout, stderr)


def _parse_open_probe_sec(stdout, stderr):
    return _parse_open_probe("securitytxt_probe",
                             "security.txt present", "INFO", r"Contact:",
                             stdout, stderr)



def _parse_gobuster(stdout, stderr):
    """Parse gobuster dir/vhost output: '/path (Status: 200)' or
    'Found: host (Status: 200)' lines."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        m = re.match(r"^(?:Found:\s*)?(/[\w./-]+|https?://\S+)\s+"
                     r"\(Status:\s*(\d{3})\)", line)
        if not m:
            continue
        path, status = m.groups()
        url = path if path.startswith("http") else f"<target>{path}"
        urls.append(url)
        findings.append(_finding(
            "gobuster_dir" if "(Status:" in line else "gobuster_vhost",
            f"gobuster hit: {path} (HTTP {status})", "INFO", line[:200],
            location=url, manual_cmd=f"curl -sI '{url}'"))
    return _cap(findings), {"urls": sorted(set(urls))}


def _parse_dirb(stdout, stderr):
    """Parse dirb output: '+ http://host/path (CODE:200|SIZE:123)'."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        m = re.match(r"^\+\s*(https?://\S+)\s*\(CODE:(\d{3})", line.strip())
        if not m:
            continue
        url, code = m.groups()
        urls.append(url)
        findings.append(_finding(
            "dirb_slow", f"dirb hit: {url} (HTTP {code})", "INFO",
            line.strip()[:200], location=url, manual_cmd=f"curl -sI '{url}'"))
    return _cap(findings), {"urls": sorted(set(urls))}


# ------------------------------------------------- arsenal-2 arg builders

def _args_gobuster_dir(target):
    base = _norm_base_url(target)
    wl = _wordlist_file()
    if not base or not wl:
        return None
    return ["dir", "-u", base + "/", "-w", wl, "-t", "5",
            "--no-progress", "-q", "--timeout", "10s", "-b",
            "404,400"]


def _args_wfuzz_get(target):
    base = _norm_base_url(target)
    wl = _wordlist_file()
    if not base or not wl:
        return None
    return ["-c", "-z", "file", wl, "-t", "5",
            "--sc", "200,204,301,302,307,401,403",
            base + "/FUZZ"]


def _args_dirb_slow(target):
    base = _norm_base_url(target)
    wl = _wordlist_file()
    if not base or not wl:
        return None
    return ["-S", "-t", "10", "-w", base + "/", wl]


def _args_halberd_scan(target):
    base = _norm_base_url(target)
    if not base:
        return None
    # scan-mode only; no fuzzing payloads, single URL
    return ["-u", base, "--no-check", "--timeout", "10", "-s"]


def _args_wapiti_crawl(target):
    base = _norm_base_url(target)
    if not base:
        return None
    # level 1 = passive-ish crawl only; no injection modules, no report dir
    return ["-u", base, "--level", "1", "--back-root", "none",
            "--scope", "folder", "--no-color", "--flush",
            "--max-links-per-page", "20", "--max-scan-time", "120"]


def _args_arachni_checks(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return [base, "--checks", "xss_frame*", "--timeout", "300",
            "--http-request-concurrency-limit", "5",
            "--http-request-timeout", "10000", "--quiet"]


def _args_skipfish_scan(target):
    base = _norm_base_url(target)
    outdir = _env_val("OMEGA_SKIPFISH_OUT")
    if outdir and not os.path.exists(outdir):
        outdir = None
    if not base or not outdir:
        return None
    return ["-o", outdir, "-t", "10", "-q", "-u", "5", "-L", "5", base]


def _args_testssl_sev(target):
    host, port = _host_port(target)
    if not host:
        return None
    return ["--severity", "LOW", "--quiet", "--color", "0",
            f"{host}:{port}"]


def _args_sslscan_quiet(target):
    host, port = _host_port(target)
    if not host:
        return None
    return ["--no-colours", f"{host}:{port}"]


def _args_sslyze_regular(target):
    host, port = _host_port(target)
    if not host:
        return None
    return ["--regular", f"{host}:{port}"]


def _args_openssl_sclient(target):
    host, port = _host_port(target)
    if not host:
        return None
    return ["s_client", "-brief", "-connect", f"{host}:{port}",
            "-servername", host]


def _args_openssl_tls_sweep(target):
    host, port = _host_port(target)
    port_env = _env_val("OMEGA_TLS_PORT")
    if not host or not port_env:
        return None
    if not port_env.isdigit() or int(port_env) not in TOP_TLS_PORTS:
        return None
    return ["s_client", "-brief", "-connect", f"{host}:{port_env}",
            "-servername", host]


def _args_dnsrecon_std(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return ["-d", domain, "-t", "std", "-n", "1.1.1.1"]


def _args_dnsenum_std(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return ["--threads", "5", "--timeout", "10", "--dnsserver",
            "1.1.1.1", domain]


def _args_sublist3r_enum(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return ["-d", domain, "-v", "-t", "5"]


def _args_knockpy_enum(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return ["--no-header", "--json", domain]


def _args_theharvester_osint(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return ["-d", domain, "-b", "baidu,crtsh", "-l", "50", "-f", "-"]


def _args_sherlock_user(target):
    user = _env_val("OMEGA_USERNAME")
    if not user:
        return None
    return ["--timeout", "10", "--print-found", user]


def _args_maigret_user(target):
    user = _env_val("OMEGA_USERNAME")
    if not user:
        return None
    return ["--timeout", "10", "--print-found", user]


def _args_photon_crawl(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["-u", base, "-l", "2", "--only-urls", "--timeout", "10",
            "--threads", "2"]


def _args_spiderfoot_cli(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return ["-s", domain, "-q"]


def _args_github_dorks(target):
    token = _env_val("OMEGA_GITHUB_TOKEN")
    domain = _norm_host(target)
    if not token or not domain:
        return None
    q = f"\"{domain}\" filename:.env OR filename:config.php.password"
    return ["-sS", "--max-time", "20", "-H",
            "Accept: application/vnd.github+json", "-H",
            f"Authorization: Bearer {token}",
            "https://api.github.com/search/code", "-G",
            "--data-urlencode", f"q={q}", "--data-urlencode", "per_page=10"]


def _args_intelx_probe(target):
    key = _env_val("OMEGA_INTELX_KEY")
    domain = _norm_host(target)
    if not key or not domain:
        return None
    return ["-sS", "--max-time", "20", "-H", f"x-key: {key}",
            f"https://2.intelx.io/phonebook/search?term={domain}"
            "&bu=0&pb=0&termtype=1&limit=10"]


def _args_hakrawler_crawl(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["-u", base, "-depth", "2", "-plain", "-t", "5",
            "-timeout", "10"]


def _args_linkfinder_js(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["-i", base + "/", "-o", "cli"]


def _args_relative_url_extract(target):
    js_url = _env_val("OMEGA_JS_URL")
    if not js_url or not js_url.startswith(("http://", "https://")):
        return None
    return ["-sS", "--max-time", "15", "-o", "-", "-w",
            "\n", js_url]


def _args_jsanalyze_urls(target):
    js = _js_file_from_env()
    if not js:
        return None
    return ["urls", js, "--max-depth", "2"]


def _args_wpscan_enum(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["--no-update", "--random-user-agent", "--url", base,
            "--plugins-detection", "passive", "--request-timeout", "10",
            "--max-requests-when-caching-vulnerabilities", "10",
            "--throttle", "5"]


def _args_droopescan_scan(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["scan", "drupal", "-u", base, "-t", "4",
            "--threads", "2"]


def _args_joomscan_scan(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["-u", base, "--no-cookie", "-ec", "-eh"]


def _args_drupwn_enum(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["--mode", "enum", "--target", base, "--range", "1",
            "--threads", "2"]


def _args_cmseek_fp(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["-u", base, "--batch", "-i"]


def _args_scorecard_ossf(target):
    repo = _env_val("OMEGA_OSSF_REPO")
    if not repo or not re.match(r"^[\w.\-/]+$", repo):
        return None
    return ["-sS", "--max-time", "25",
            f"https://api.securityscorecards.dev/projects/{repo}"]


def _args_graphql_introspect(target):
    base = _norm_base_url(target)
    if not base:
        return None
    # GET-based introspection (-G): read-only, no POST body mutation
    return ["-sS", "--max-time", "20", "-G", base,
            "--data-urlencode",
            "query={__schema{types{name}}}"]


def _args_paramspider_disc(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return ["--domain", domain, "--level", "1", "--exclude", "404,301",
            "--quiet"]


def _args_kiterunner_scan(target):
    base = _norm_base_url(target)
    wl = _env_file("OMEGA_KR_WORDLIST")
    if not base or not wl:
        return None
    return ["scan", base, "-w", wl, "-t", "5", "--delay", "0.2",
            "--timeout", "10s"]


def _args_auth_hints_fp(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["-sS", "--max-time", "15", "-L", "-o", "-", "-w",
            "\n", base]


def _args_s3scanner_scan(target):
    bucket_file = _env_file("OMEGA_BUCKET_FILE")
    if not bucket_file:
        return None
    return ["--bucket-file", bucket_file, "--skip-existing", "--dump",
            "--provider", "aws", "--quiet"]


def _args_cloud_enum_scan(target):
    name = _env_val("OMEGA_CLOUD_NAME") or _norm_host(target)
    if not name:
        return None
    return ["-k", name, "-qs"]


def _args_gobuster_vhost(target):
    base = _norm_base_url(target)
    wl = _wordlist_file()
    if not base or not wl:
        return None
    return ["vhost", "-u", base, "-w", wl, "-t", "5", "--no-progress",
            "-q", "--timeout", "10s"]


def _args_curl_probe(target, paths, extra_w="\n"):
    """Shared curl builder for file-exposure probes (read-only GET)."""
    base = _norm_base_url(target)
    if not base or not paths:
        return None
    args = ["-sS", "--max-time", "20", "-o", "-",
            "-w", "\nURL=%{url_effective} CODE=%{http_code}\n"]
    for p in paths[:_CURL_URL_CAP]:
        args.append(base + p)
    return args


def _args_git_open_probe(target):
    return _args_curl_probe(target, ["/.git/HEAD"])


def _args_svn_open_probe(target):
    return _args_curl_probe(target, ["/.svn/entries", "/.svn/wc.db"])


def _args_ds_store_probe(target):
    return _args_curl_probe(target, ["/.DS_Store"])


def _args_backup_file_probe(target):
    return _args_curl_probe(target, ["/backup.bak", "/backup.sql",
                                     "/backup.zip", "/db.sql",
                                     "/site.bak", "/dump.sql"])


def _args_securitytxt_probe(target):
    return _args_curl_probe(target, ["/.well-known/security.txt"])


def _args_headers_probe(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["-sS", "-I", "--max-time", "15", "-o", "-", "-w",
            "\n", base]


def _args_waybackurls_passive(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return [domain, "-no-subs"]


def _args_whois_lookup(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return ["-H", domain]


def _args_dig_query(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return ["+time=5", "+tries=1", domain, "A"]


def _args_crtsh_passive(target):
    domain = _norm_host(target)
    if not domain:
        return None
    return ["-sS", "--max-time", "25",
            f"https://crt.sh/?q=%25.{domain}&output=json"]


# ---------------------------------------------------------------- registry


def _parse_wfuzz(stdout, stderr):
    """Parse wfuzz plain output: '000012:  C=200  ... 'word'."""
    findings, urls = [], []
    for line in (stdout or "").splitlines():
        m = re.match(r"^\d{6}:\s+C=(\d{3})", line.strip())
        if not m:
            continue
        status = m.group(1)
        tail = line.strip().split("C=" + status, 1)[1].strip()
        last = tail.split()[-1].strip("'\"") if tail.split() else "fuzz"
        findings.append(_finding(
            "wfuzz_get", f"path fuzz hit: {last} (HTTP {status})", "INFO",
            line.strip()[:200],
            manual_cmd="curl -sI <target>/<path>  # confirm manually"))
    return _cap(findings), {"hits": [f["evidence"] for f in findings]}


def _parse_generic_lines(tool, stdout, stderr):
    """Tolerant parser for descriptive line-output tools (whois, halberd,
    spiderfoot, wapiti, arachni): keep meaningful non-noise lines."""
    findings, lines = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if len(line) < 8 or line.startswith(("#", "==", "--", "Using")):
            continue
        if not re.search(r"[A-Za-z]", line):
            continue
        lines.append(line[:150])
        findings.append(_finding(
            tool, f"{tool} note: {line[:110]}", "INFO", line[:250],
            manual_cmd=f"review '{tool}' output manually"))
    return _cap(findings), {"lines": lines[:64]}


def _parse_lines_passive(stdout, stderr):
    return _parse_lines("sublist3r_enum", "passive subdomain: {item}",
                        stdout, stderr)


def _parse_knockpy(stdout, stderr):
    """knockpy: JSON (--json) or 'domain -> ip' text."""
    findings, hosts = [], []
    for line in (stdout or "").splitlines():
        line = line.strip()
        m = re.match(r"^([\w*.\-]+\.[A-Za-z]{2,})\s*(->|:)\s*"
                     r"(\d{1,3}(?:\.\d{1,3}){3})?", line)
        if m:
            hosts.append(m.group(1).lstrip("*."))
    for h in sorted(set(hosts))[:DNS_FINDING_CAP]:
        findings.append(_finding(
            "knockpy_enum", f"knock subdomain: {h}", "INFO", h,
            location=h, manual_cmd=f"dig A {h} +short"))
    return findings, {"hosts": sorted(set(hosts))}


def _parse_json_records_tool(stdout, stderr):
    """JSON-array API responses (github code search, intelx)."""
    return _parse_json_records("api_osint", "name", stdout, stderr)


def _parse_crtsh(stdout, stderr):
    """Parse crt.sh ?output=json array of CT log entries."""
    try:
        data = json.loads((stdout or "").strip() or "[]")
    except Exception:
        data = []
    names = set()
    if isinstance(data, list):
        for rec in data:
            if isinstance(rec, dict):
                for nv in str(rec.get("name_value", "")).split("\n"):
                    nv = nv.strip().lstrip("*.").lower()
                    if nv and re.match(r"^[A-Za-z0-9_.\-]+$", nv):
                        names.add(nv)
    findings = [_finding(
        "crtsh_passive", f"CT-log name: {n}", "INFO", n, location=n,
        manual_cmd=f"dig A {n} +short") for n in sorted(names)[:32]]
    return findings, {"hosts": sorted(names)}


def _parse_url_lines_kr(stdout, stderr):
    """kiterunner output: '[300] [GET] /api/v1/users' style lines."""
    findings, routes = [], []
    for line in (stdout or "").splitlines():
        m = re.match(r"^\[\d{3}\]\s*\[([A-Z]+)\]\s*(\S+)", line.strip())
        if not m:
            continue
        status, method, path = "kr", m.group(1), m.group(2)
        routes.append(f"{method} {path}")
        findings.append(_finding(
            "kiterunner_scan", f"API route: {method} {path} ({status})",
            "INFO", line.strip()[:200], location=path,
            manual_cmd=f"curl -sI <target>{path}  # confirm manually"))
    return _cap(findings), {"routes": routes[:64]}


def _args_wafw00f_single(target):
    base = _norm_base_url(target)
    if not base:
        return None
    return ["-v", base]


# ---------------------------------------------------------------- registry

# openssl binary used by the ssl_chain parser (monkeypatchable in tests)
_X509_BIN = "openssl"

SYS_REGISTRY = {
    "nmap_sv": {
        "name": "nmap_sv", "binary": "nmap", "stage": "recon",
        "safety": "active-recon", "arg_builder": _args_nmap_sv,
        "parser": _parse_nmap, "timeout_s": 300, "stdin_target": False,
        "description": "read-only service/version scan, top-100 ports",
    },
    "ffuf_light": {
        "name": "ffuf_light", "binary": "ffuf", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_ffuf_light,
        "parser": _parse_ffuf, "timeout_s": 300, "stdin_target": False,
        "description": "GET-only content discovery, rate-limited, "
                       "small wordlist",
    },
    "nuclei_scan": {
        "name": "nuclei_scan", "binary": "nuclei", "stage": "verify",
        "safety": "active-recon", "arg_builder": _args_nuclei_scan,
        "parser": _parse_nuclei, "timeout_s": 600, "stdin_target": False,
        "description": "read-only template scan, rate-limited, "
                       "low/medium/high severity",
    },
    "subfinder_passive": {
        "name": "subfinder_passive", "binary": "subfinder", "stage": "recon",
        "safety": "passive", "arg_builder": _args_subfinder_passive,
        "parser": _parse_subfinder, "timeout_s": 300, "stdin_target": False,
        "description": "passive subdomain enumeration (-passive only)",
    },
    "amass_passive": {
        "name": "amass_passive", "binary": "amass", "stage": "recon",
        "safety": "passive", "arg_builder": _args_amass_passive,
        "parser": _parse_amass, "timeout_s": 600, "stdin_target": False,
        "description": "passive OSINT enumeration (amass enum -passive)",
    },
    "httpx_json": {
        "name": "httpx_json", "binary": "httpx", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_httpx_json,
        "parser": _parse_httpx, "timeout_s": 300, "stdin_target": True,
        "description": "batch URL liveness probe, JSON output, no color",
    },
    "ssl_chain": {
        "name": "ssl_chain", "binary": "openssl", "stage": "recon",
        "safety": "passive", "arg_builder": _args_ssl_chain,
        "parser": _parse_ssl_chain, "timeout_s": 120, "stdin_target": False,
        "description": "fetch and inspect the TLS certificate chain "
                       "(s_client -showcerts + x509)",
    },
    "jq_probe": {
        "name": "jq_probe", "binary": "jq", "stage": "report",
        "safety": "passive", "arg_builder": _args_jq_probe,
        "parser": lambda stdout, stderr: ([], {"note": "jq reserved"}),
        "timeout_s": 120, "stdin_target": False, "reserved": True,
        "description": "RESERVED: pretty-filters other tools' JSON "
                       "(see jq_filter); never auto-run",
    },
    # ---------------- extended registry (append-only) ----------------
    "gau_urls": {
        "name": "gau_urls", "binary": "gau", "stage": "recon",
        "safety": "passive", "arg_builder": _args_gau_urls,
        "parser": _parse_gau, "timeout_s": 300, "stdin_target": False,
        "description": "passive archived URLs from wayback/commoncrawl "
                       "(--threads 4)",
    },
    "dnsx_resolve": {
        "name": "dnsx_resolve", "binary": "dnsx", "stage": "recon",
        "safety": "passive", "arg_builder": _args_dnsx_resolve,
        "parser": _parse_dnsx, "timeout_s": 120, "stdin_target": False,
        "description": "read-only DNS A/AAAA/MX/NS/TXT queries, "
                       "rate-limited, -resp-only",
    },
    "massdns_resolve": {
        "name": "massdns_resolve", "binary": "massdns", "stage": "recon",
        "safety": "passive", "arg_builder": _args_massdns_resolve,
        "parser": _parse_massdns, "timeout_s": 120, "stdin_target": False,
        "description": "rate-capped A-record resolution via resolver "
                       "list (skipped when none exists)",
    },
    "mapcidr_expand": {
        "name": "mapcidr_expand", "binary": "mapcidr", "stage": "recon",
        "safety": "passive", "arg_builder": _args_mapcidr_expand,
        "parser": _parse_mapcidr, "timeout_s": 120, "stdin_target": False,
        "description": "expand operator-provided CIDR (OMEGA_CIDR) "
                       "into IPs; no scanning",
    },
    "naabu_top100": {
        "name": "naabu_top100", "binary": "naabu", "stage": "recon",
        "safety": "active-recon", "arg_builder": _args_naabu_top100,
        "parser": _parse_naabu, "timeout_s": 300, "stdin_target": False,
        "description": "top-100 port scan, rate capped at 500 pps",
    },
    "whatweb_fp": {
        "name": "whatweb_fp", "binary": "whatweb", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_whatweb_fp,
        "parser": _parse_whatweb, "timeout_s": 300, "stdin_target": False,
        "description": "passive-ish web fingerprinting, aggression 0, "
                       "25 URLs max",
    },
    "arjun_get": {
        "name": "arjun_get", "binary": "arjun", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_arjun_get,
        "parser": _parse_arjun, "timeout_s": 300, "stdin_target": False,
        "description": "GET-only hidden parameter discovery, "
                       "rate-limited, capped timeout",
    },
    "katana_crawl": {
        "name": "katana_crawl", "binary": "katana", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_katana_crawl,
        "parser": _parse_katana, "timeout_s": 300, "stdin_target": False,
        "description": "non-headless crawler, depth 2, 10 workers, "
                       "rate-limited, jsonl output",
    },
    "dirsearch_paths": {
        "name": "dirsearch_paths", "binary": "dirsearch", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_dirsearch_paths,
        "parser": _parse_dirsearch, "timeout_s": 600, "stdin_target": False,
        "description": "default-wordlist content discovery, 10 threads, "
                       "random agent, 404 excluded",
    },
    "feroxbuster_light": {
        "name": "feroxbuster_light", "binary": "feroxbuster", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_feroxbuster_light,
        "parser": _parse_feroxbuster, "timeout_s": 300, "stdin_target": False,
        "description": "content discovery, 5 threads, rate limit 20, "
                       "no state file, default wordlist",
    },
    "crlfuzz_scan": {
        "name": "crlfuzz_scan", "binary": "crlfuzz", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_crlfuzz_scan,
        "parser": _parse_crlfuzz, "timeout_s": 300, "stdin_target": False,
        "description": "GET-only CRLF injection fuzzing, 10 concurrent, "
                       "results to stdout",
    },
    "graphw00f_fp": {
        "name": "graphw00f_fp", "binary": "graphw00f", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_graphw00f_fp,
        "parser": _parse_graphw00f, "timeout_s": 120, "stdin_target": False,
        "description": "single-URL GraphQL engine fingerprint",
    },
    "dalfox_scan": {
        "name": "dalfox_scan", "binary": "dalfox", "stage": "verify",
        "safety": "active-recon", "arg_builder": _args_dalfox_scan,
        "parser": _parse_dalfox, "timeout_s": 300, "stdin_target": False,
        "description": "XSS scan mode, single URL, --no-color --silence, "
                       "capped workers",
    },
    "kxss_reflect": {
        "name": "kxss_reflect", "binary": "kxss", "stage": "verify",
        "safety": "active-recon", "arg_builder": _args_kxss_reflect,
        "parser": _parse_kxss, "timeout_s": 120, "stdin_target": True,
        "description": "single-URL GET reflection check (stdin-driven)",
    },
    "nikto_info": {
        "name": "nikto_info", "binary": "nikto", "stage": "verify",
        "safety": "active-recon", "arg_builder": _args_nikto_info,
        "parser": _parse_nikto, "timeout_s": 600, "stdin_target": False,
        "description": "informational nikto classes only (Tuning 123), "
                       "no exploit/mutating tuning codes",
    },
    "jwt_decode": {
        "name": "jwt_decode", "binary": "jwt_tool", "stage": "verify",
        "safety": "passive", "arg_builder": _args_jwt_decode,
        "parser": _parse_jwt_tool, "timeout_s": 120, "stdin_target": False,
        "description": "decode-only JWT inspection of OMEGA_JWT "
                       "(no tamper/crack modes)",
    },
    "trufflehog_fs": {
        "name": "trufflehog_fs", "binary": "trufflehog", "stage": "verify",
        "safety": "passive", "arg_builder": _args_trufflehog_fs,
        "parser": _parse_trufflehog, "timeout_s": 600, "stdin_target": False,
        "description": "filesystem/git secret scan, --json --no-update "
                       "--no-verification",
    },
    "gitleaks_scan": {
        "name": "gitleaks_scan", "binary": "gitleaks", "stage": "verify",
        "safety": "passive", "arg_builder": _args_gitleaks_scan,
        "parser": _parse_gitleaks, "timeout_s": 600, "stdin_target": False,
        "description": "detect --no-banner secret scan on a local "
                       "repo/source, redacted JSON report",
    },
    "jsluice_urls": {
        "name": "jsluice_urls", "binary": "jsluice", "stage": "verify",
        "safety": "passive", "arg_builder": _args_jsluice_urls,
        "parser": _parse_jsluice, "timeout_s": 120, "stdin_target": False,
        "description": "urls mode over operator-fetched local JS "
                       "(OMEGA_JS_FILE/OMEGA_JS_PATHS)",
    },
    "interactsh_client": {
        "name": "interactsh_client", "binary": "interactsh-client",
        "stage": "report", "safety": "passive",
        "arg_builder": _args_interactsh_reserved,
        "parser": _parse_interactsh, "timeout_s": 120,
        "stdin_target": False, "reserved": True,
        "description": "RESERVED: OOB interaction client; never auto-run, "
                       "operator starts it manually when needed",
    },
    # ---------------- arsenal-2 (append-only batch: +51) -------------
    # WEB FUZZING / RECON
    "gobuster_dir": {
        "name": "gobuster_dir", "binary": "gobuster", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_gobuster_dir,
        "parser": _parse_gobuster, "timeout_s": 300,
        "stdin_target": False,
        "description": "dir mode content discovery, -t 5, --no-progress",
    },
    "wfuzz_get": {
        "name": "wfuzz_get", "binary": "wfuzz", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_wfuzz_get,
        "parser": _parse_wfuzz, "timeout_s": 300, "stdin_target": False,
        "description": "GET-only fuzzing, -t 5, wordlist-driven",
    },
    "dirb_slow": {
        "name": "dirb_slow", "binary": "dirb", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_dirb_slow,
        "parser": _parse_dirb, "timeout_s": 600,
        "stdin_target": False,
        "description": "dirb slow (-S) scan with default wordlist",
    },
    "halberd_scan": {
        "name": "halberd_scan", "binary": "halberd", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_halberd_scan,
        "parser": _partial(_parse_generic_lines, "halberd_scan"), "timeout_s": 300,
        "stdin_target": False,
        "description": "single-URL scan mode (skipped when absent)",
    },
    "wapiti_crawl": {
        "name": "wapiti_crawl", "binary": "wapiti", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_wapiti_crawl,
        "parser": _partial(_parse_generic_lines, "wapiti_crawl"), "timeout_s": 600,
        "stdin_target": False,
        "description": "--level 1 --back-root none read-only crawl",
    },
    "arachni_checks": {
        "name": "arachni_checks", "binary": "arachni", "stage": "verify",
        "safety": "active-recon", "arg_builder": _args_arachni_checks,
        "parser": _partial(_parse_generic_lines, "arachni_checks"), "timeout_s": 600,
        "stdin_target": False,
        "description": "--checks xss_frame* only, capped concurrency",
    },
    "skipfish_scan": {
        "name": "skipfish_scan", "binary": "skipfish", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_skipfish_scan,
        "parser": _partial(_parse_generic_lines, "skipfish_scan"), "timeout_s": 600,
        "stdin_target": False, "env_gated": True,
        "description": "requires operator-provided output dir "
                       "(OMEGA_SKIPFISH_OUT); skipped otherwise",
    },
    # TLS
    "testssl_sev": {
        "name": "testssl_sev", "binary": "testssl.sh", "stage": "recon",
        "safety": "passive", "arg_builder": _args_testssl_sev,
        "parser": _parse_testssl, "timeout_s": 600, "stdin_target": False,
        "description": "--severity LOW --quiet TLS config inspection",
    },
    "sslscan_quiet": {
        "name": "sslscan_quiet", "binary": "sslscan", "stage": "recon",
        "safety": "passive", "arg_builder": _args_sslscan_quiet,
        "parser": _parse_sslscan, "timeout_s": 300, "stdin_target": False,
        "description": "--no-colours cipher/protocol listing",
    },
    "sslyze_regular": {
        "name": "sslyze_regular", "binary": "sslyze", "stage": "recon",
        "safety": "passive", "arg_builder": _args_sslyze_regular,
        "parser": _parse_sslyze, "timeout_s": 600, "stdin_target": False,
        "description": "--regular TLS plugin scan (text output)",
    },
    "openssl_sclient": {
        "name": "openssl_sclient", "binary": "openssl", "stage": "recon",
        "safety": "passive", "arg_builder": _args_openssl_sclient,
        "parser": _partial(_parse_ssl_brief, "openssl_sclient"), "timeout_s": 120,
        "stdin_target": False,
        "description": "s_client -brief session inspection (default 443)",
    },
    "openssl_tls_sweep": {
        "name": "openssl_tls_sweep", "binary": "openssl", "stage": "recon",
        "safety": "passive", "arg_builder": _args_openssl_tls_sweep,
        "parser": _partial(_parse_ssl_brief, "openssl_tls_sweep"), "timeout_s": 120,
        "stdin_target": False, "env_gated": True,
        "description": "one top-20 TLS port via OMEGA_TLS_PORT "
                       "(operator-driven sweep, read-only)",
    },
    # DNS / OSINT
    "dnsrecon_std": {
        "name": "dnsrecon_std", "binary": "dnsrecon", "stage": "recon",
        "safety": "passive", "arg_builder": _args_dnsrecon_std,
        "parser": _parse_dnsrecon, "timeout_s": 300,
        "stdin_target": False,
        "description": "-t std standard zone enumeration",
    },
    "dnsenum_std": {
        "name": "dnsenum_std", "binary": "dnsenum", "stage": "recon",
        "safety": "passive", "arg_builder": _args_dnsenum_std,
        "parser": _parse_dnsenum, "timeout_s": 300,
        "stdin_target": False,
        "description": "thread-capped DNS enumeration, no brute wordlist",
    },
    "sublist3r_enum": {
        "name": "sublist3r_enum", "binary": "sublist3r", "stage": "recon",
        "safety": "passive", "arg_builder": _args_sublist3r_enum,
        "parser": _parse_lines_passive, "timeout_s": 300,
        "stdin_target": False,
        "description": "passive subdomain enumeration (-v, 5 threads)",
    },
    "knockpy_enum": {
        "name": "knockpy_enum", "binary": "knockpy", "stage": "recon",
        "safety": "passive", "arg_builder": _args_knockpy_enum,
        "parser": _parse_knockpy, "timeout_s": 300,
        "stdin_target": False,
        "description": "subdomain knock enumeration (JSON/text)",
    },
    "theharvester_osint": {
        "name": "theharvester_osint", "binary": "theHarvester",
        "stage": "recon", "safety": "passive",
        "arg_builder": _args_theharvester_osint,
        "parser": _parse_theharvester, "timeout_s": 300,
        "stdin_target": False,
        "description": "-b baidu,crtsh -l 50 passive OSINT",
    },
    "sherlock_user": {
        "name": "sherlock_user", "binary": "sherlock", "stage": "recon",
        "safety": "passive", "arg_builder": _args_sherlock_user,
        "parser": _parse_sherlock, "timeout_s": 300,
        "stdin_target": False, "env_gated": True,
        "description": "single username (OMEGA_USERNAME), --timeout 10",
    },
    "maigret_user": {
        "name": "maigret_user", "binary": "maigret", "stage": "recon",
        "safety": "passive", "arg_builder": _args_maigret_user,
        "parser": _parse_maigret, "timeout_s": 300,
        "stdin_target": False, "env_gated": True,
        "description": "single username (OMEGA_USERNAME), --timeout 10",
    },
    "photon_crawl": {
        "name": "photon_crawl", "binary": "photon", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_photon_crawl,
        "parser": _parse_photon, "timeout_s": 300,
        "stdin_target": False,
        "description": "-l 2 --only-urls level-2 crawl",
    },
    "spiderfoot_cli": {
        "name": "spiderfoot_cli", "binary": "spiderfoot", "stage": "recon",
        "safety": "passive", "arg_builder": _args_spiderfoot_cli,
        "parser": _partial(_parse_generic_lines, "spiderfoot_cli"), "timeout_s": 600,
        "stdin_target": False,
        "description": "-s CLI mode passive OSINT (skipped when absent)",
    },
    "github_dorks": {
        "name": "github_dorks", "binary": "curl", "stage": "recon",
        "safety": "passive", "arg_builder": _args_github_dorks,
        "parser": _parse_json_records_tool, "timeout_s": 120,
        "stdin_target": False, "env_gated": True,
        "description": "code-search dorks via GitHub API (OMEGA_GITHUB_TOKEN)",
    },
    "intelx_probe": {
        "name": "intelx_probe", "binary": "curl", "stage": "recon",
        "safety": "passive", "arg_builder": _args_intelx_probe,
        "parser": _parse_json_records_tool, "timeout_s": 120,
        "stdin_target": False, "env_gated": True,
        "description": "IntelX phonebook lookup (OMEGA_INTELX_KEY)",
    },
    "crtsh_passive": {
        "name": "crtsh_passive", "binary": "curl", "stage": "recon",
        "safety": "passive", "arg_builder": _args_crtsh_passive,
        "parser": _parse_crtsh, "timeout_s": 120, "stdin_target": False,
        "description": "public crt.sh CT-log subdomain lookup (no key)",
    },
    "whois_lookup": {
        "name": "whois_lookup", "binary": "whois", "stage": "recon",
        "safety": "passive", "arg_builder": _args_whois_lookup,
        "parser": _partial(_parse_generic_lines, "whois_lookup"), "timeout_s": 120,
        "stdin_target": False,
        "description": "passive WHOIS registration record",
    },
    "dig_query": {
        "name": "dig_query", "binary": "dig", "stage": "recon",
        "safety": "passive", "arg_builder": _args_dig_query,
        "parser": _parse_dnsenum, "timeout_s": 120,
        "stdin_target": False,
        "description": "single A query, 5s timeout, 1 try",
    },
    "waybackurls_passive": {
        "name": "waybackurls_passive", "binary": "waybackurls",
        "stage": "recon", "safety": "passive",
        "arg_builder": _args_waybackurls_passive,
        "parser": _parse_gau, "timeout_s": 300, "stdin_target": False,
        "description": "archived URLs for one host (-no-subs)",
    },
    # CRAWL / JS
    "hakrawler_crawl": {
        "name": "hakrawler_crawl", "binary": "hakrawler", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_hakrawler_crawl,
        "parser": _parse_hakrawler, "timeout_s": 300,
        "stdin_target": False,
        "description": "-depth 2 -plain crawler, 5 threads",
    },
    "linkfinder_js": {
        "name": "linkfinder_js", "binary": "linkfinder", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_linkfinder_js,
        "parser": _parse_linkfinder, "timeout_s": 300,
        "stdin_target": False,
        "description": "JS endpoint extraction (skipped when absent)",
    },
    "relative_url_extract": {
        "name": "relative_url_extract", "binary": "curl", "stage": "enum",
        "safety": "passive", "arg_builder": _args_relative_url_extract,
        "parser": _parse_relative_urls, "timeout_s": 120,
        "stdin_target": False, "env_gated": True,
        "description": "curl+grep relative-URL extraction from "
                       "operator-fetched JS (OMEGA_JS_URL)",
    },
    "jsanalyze_urls": {
        "name": "jsanalyze_urls", "binary": "jsanalyze", "stage": "enum",
        "safety": "passive", "arg_builder": _args_jsanalyze_urls,
        "parser": _parse_jsluice, "timeout_s": 120,
        "stdin_target": False, "env_gated": True,
        "description": "node-based JS URL analysis of local files "
                       "(OMEGA_JS_FILE/OMEGA_JS_PATHS)",
    },
    # VULN SCANNERS (informational classes only)
    "wpscan_enum": {
        "name": "wpscan_enum", "binary": "wpscan", "stage": "verify",
        "safety": "active-recon", "arg_builder": _args_wpscan_enum,
        "parser": _parse_wpscan, "timeout_s": 600, "stdin_target": False,
        "description": "--no-update --random-user-agent passive plugin "
                       "detection (no api-token)",
    },
    "droopescan_scan": {
        "name": "droopescan_scan", "binary": "droopescan", "stage": "verify",
        "safety": "active-recon", "arg_builder": _args_droopescan_scan,
        "parser": _partial(_parse_cms_text, "droopescan_scan"), "timeout_s": 600,
        "stdin_target": False,
        "description": "drupal enumeration scan, 2 threads",
    },
    "joomscan_scan": {
        "name": "joomscan_scan", "binary": "joomscan", "stage": "verify",
        "safety": "active-recon", "arg_builder": _args_joomscan_scan,
        "parser": _partial(_parse_cms_text, "joomscan_scan"), "timeout_s": 600,
        "stdin_target": False,
        "description": "joomla enumeration (no cookie/exploit modes)",
    },
    "drupwn_enum": {
        "name": "drupwn_enum", "binary": "drupwn", "stage": "verify",
        "safety": "active-recon", "arg_builder": _args_drupwn_enum,
        "parser": _partial(_parse_cms_text, "drupwn_enum"), "timeout_s": 600,
        "stdin_target": False,
        "description": "drupal --mode enum, 2 threads",
    },
    "cmseek_fp": {
        "name": "cmseek_fp", "binary": "cmseek", "stage": "verify",
        "safety": "active-recon", "arg_builder": _args_cmseek_fp,
        "parser": _partial(_parse_cms_text, "cmseek_fp"), "timeout_s": 300,
        "stdin_target": False,
        "description": "CMS fingerprint detection only",
    },
    "scorecard_ossf": {
        "name": "scorecard_ossf", "binary": "curl", "stage": "recon",
        "safety": "passive", "arg_builder": _args_scorecard_ossf,
        "parser": _parse_scorecard, "timeout_s": 120,
        "stdin_target": False, "env_gated": True,
        "description": "OSSF Scorecard API for a repo (OMEGA_OSSF_REPO)",
    },
    # API / GRAPHQL
    "graphql_introspect": {
        "name": "graphql_introspect", "binary": "curl", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_graphql_introspect,
        "parser": _parse_graphql_introspect, "timeout_s": 120,
        "stdin_target": False,
        "description": "GET-based (-G) schema introspection via curl",
    },
    "paramspider_disc": {
        "name": "paramspider_disc", "binary": "paramspider",
        "stage": "enum", "safety": "passive",
        "arg_builder": _args_paramspider_disc,
        "parser": _parse_params, "timeout_s": 300,
        "stdin_target": False,
        "description": "--level 1 archived-parameter discovery, 404 excluded",
    },
    "kiterunner_scan": {
        "name": "kiterunner_scan", "binary": "kiterunner", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_kiterunner_scan,
        "parser": _parse_url_lines_kr, "timeout_s": 300,
        "stdin_target": False, "env_gated": True,
        "description": "API route scan with operator wordlist "
                       "(OMEGA_KR_WORDLIST), skipped otherwise",
    },
    # AUTH SURFACE (READ-ONLY fingerprinting; NO credential submission)
    "auth_hints_fp": {
        "name": "auth_hints_fp", "binary": "curl", "stage": "verify",
        "safety": "passive", "arg_builder": _args_auth_hints_fp,
        "parser": _parse_auth_hints, "timeout_s": 120,
        "stdin_target": False,
        "description": "login-form/auth-marker fingerprint via GET; "
                       "never submits credentials",
    },
    # CLOUD / BUCKET
    "s3scanner_scan": {
        "name": "s3scanner_scan", "binary": "s3scanner", "stage": "enum",
        "safety": "passive", "arg_builder": _args_s3scanner_scan,
        "parser": _parse_s3scanner, "timeout_s": 300,
        "stdin_target": False, "env_gated": True,
        "description": "--skip-existing --dump over operator bucket list "
                       "(OMEGA_BUCKET_FILE)",
    },
    "cloud_enum_scan": {
        "name": "cloud_enum_scan", "binary": "cloud_enum", "stage": "enum",
        "safety": "passive", "arg_builder": _args_cloud_enum_scan,
        "parser": _parse_cloud_enum, "timeout_s": 600,
        "stdin_target": False,
        "description": "public cloud asset keyword search (-qs, no keyfile)",
    },
    "gobuster_vhost": {
        "name": "gobuster_vhost", "binary": "gobuster", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_gobuster_vhost,
        "parser": _parse_gobuster, "timeout_s": 300,
        "stdin_target": False,
        "description": "vhost mode, -t 5, --no-progress",
    },
    # MISC PROBES (curl-based, read-only GET)
    "wafw00f_fp": {
        "name": "wafw00f_fp", "binary": "wafw00f", "stage": "enum",
        "safety": "active-recon", "arg_builder": _args_wafw00f_single,
        "parser": _parse_wafw00f, "timeout_s": 300,
        "stdin_target": False,
        "description": "single-host WAF detection (-v)",
    },
    "git_open_probe": {
        "name": "git_open_probe", "binary": "curl", "stage": "verify",
        "safety": "passive", "arg_builder": _args_git_open_probe,
        "parser": _parse_git_open, "timeout_s": 120,
        "stdin_target": False,
        "description": "/.git/HEAD readability probe (candidate LOW)",
    },
    "svn_open_probe": {
        "name": "svn_open_probe", "binary": "curl", "stage": "verify",
        "safety": "passive", "arg_builder": _args_svn_open_probe,
        "parser": _parse_open_probe_svn, "timeout_s": 120,
        "stdin_target": False,
        "description": "/.svn/entries + /.svn/wc.db readability probe",
    },
    "ds_store_probe": {
        "name": "ds_store_probe", "binary": "curl", "stage": "verify",
        "safety": "passive", "arg_builder": _args_ds_store_probe,
        "parser": _parse_open_probe_ds, "timeout_s": 120,
        "stdin_target": False,
        "description": "/.DS_Store readability probe",
    },
    "backup_file_probe": {
        "name": "backup_file_probe", "binary": "curl", "stage": "verify",
        "safety": "passive", "arg_builder": _args_backup_file_probe,
        "parser": _parse_backup_probe, "timeout_s": 120,
        "stdin_target": False,
        "description": "common backup paths (.bak/.sql/.zip), GET only",
    },
    "securitytxt_probe": {
        "name": "securitytxt_probe", "binary": "curl", "stage": "recon",
        "safety": "passive", "arg_builder": _args_securitytxt_probe,
        "parser": _parse_open_probe_sec, "timeout_s": 120,
        "stdin_target": False,
        "description": "/.well-known/security.txt presence probe",
    },
    "headers_probe": {
        "name": "headers_probe", "binary": "curl", "stage": "recon",
        "safety": "passive", "arg_builder": _args_headers_probe,
        "parser": _parse_headers_probe, "timeout_s": 120,
        "stdin_target": False,
        "description": "banner header capture (Server / X-Powered-By)",
    },
}

# Tools whose *binary names* are refused outright (credential-cracking /
# credentialed-access class). The registry must never contain them; the
# audit test enforces this blocklist.
REFUSED_BINARY_BLOCKLIST = (
    "hydra", "medusa", "mimikatz", "hashcat", "john", "patator",
    "ncrack", "brutespray", "crowbar", "secretsdump",
)


def registry_stats():
    """Summary export for the arsenal: totals and per-bucket counts."""
    by_stage = {}
    by_safety = {}
    for spec in SYS_REGISTRY.values():
        by_stage[spec["stage"]] = by_stage.get(spec["stage"], 0) + 1
        by_safety[spec["safety"]] = by_safety.get(spec["safety"], 0) + 1
    return {
        "total": len(SYS_REGISTRY),
        "by_stage": dict(sorted(by_stage.items())),
        "by_safety": dict(sorted(by_safety.items())),
    }


# ---------------------------------------------------------------- jq helper

def jq_filter(json_text, filter=".", which_fn=None):
    """Pretty-filter another tool's JSON through jq (read-only).

    Returns the parsed jq output (list/dict/str) or an error string —
    never raises. Reserved helper for post-processing SYS_REGISTRY /
    PY_REGISTRY JSON blobs.
    """
    which = which_fn or shutil.which
    if which("jq") is None:
        return "error: jq binary not found"
    try:
        proc = subprocess.run(["jq", "-c", filter],
                              input=json_text, capture_output=True,
                              text=True, timeout=30)
        if proc.returncode != 0:
            return f"error: jq failed: {proc.stderr.strip()[:200]}"
        out = proc.stdout.strip()
        if not out:
            return "error: jq produced no output"
        parsed = [json.loads(ln) for ln in out.splitlines() if ln.strip()]
        return parsed[0] if len(parsed) == 1 else parsed
    except Exception as exc:
        return f"error: {exc}"


# ---------------------------------------------------------------- suite

def run_system_suite(target, stages=None, budget=None, log=None,
                     allowlist=None, which_fn=None):
    """Run read-only system-binary tools against `target`.

    stages: iterable of stage names (recon/enum/verify/report);
            None = DEFAULT_STAGES. allowlist: optional tool-name filter.
    budget: max number of tools executed (each costs 1).
    which_fn: binary-locator override for hermetic tests.
    Returns {'findings', 'surface', 'ran', 'skipped'} and NEVER raises.
    GATE: without PTK_POLYGLOT=1 in the environment every tool is
    recorded as a contained skip and nothing executes.
    """
    log = log or (lambda msg: None)
    stage_set = set(stages) if stages else set(DEFAULT_STAGES)
    allowed = set(allowlist) if allowlist else None
    which = which_fn or shutil.which
    gate_open = os.environ.get(GATE_ENV) == "1"

    findings, surface = [], {}
    ran, skipped = [], []

    candidates = [spec for spec in SYS_REGISTRY.values()
                  if spec["stage"] in stage_set and
                  (allowed is None or spec["name"] in allowed)]

    for spec in candidates:
        name = spec["name"]
        if budget is not None and len(ran) >= int(budget):
            skipped.append({"tool": name, "reason": "budget exhausted"})
            log(f"[system] skipped '{name}': budget exhausted")
            continue
        if not gate_open:
            reason = f"gate closed: {GATE_ENV}=1 required for system tools"
            skipped.append({"tool": name, "reason": reason})
            log(f"[system] skipped '{name}': {reason}")
            continue
        binary_path = which(spec["binary"])
        if binary_path is None:
            reason = f"binary not found: {spec['binary']}"
            skipped.append({"tool": name, "reason": reason})
            log(f"[system] skipped '{name}': {reason}")
            continue
        args = spec["arg_builder"](target)
        if args is None:
            skipped.append({"tool": name,
                            "reason": "not applicable for this target/"
                                      "environment"})
            log(f"[system] skipped '{name}': not applicable")
            continue

        cmd = [binary_path] + args
        stdin_data = (target.strip() + "\n") if spec.get("stdin_target") \
            else ""
        log(f"[system] running '{name}' ({spec['safety']}, "
            f"stage={spec['stage']}, timeout={spec['timeout_s']}s)")
        try:
            proc = subprocess.run(
                cmd, input=stdin_data, capture_output=True, text=True,
                timeout=spec["timeout_s"])
        except subprocess.TimeoutExpired:
            skipped.append({"tool": name,
                            "reason": f"timeout contained after "
                                      f"{spec['timeout_s']}s"})
            log(f"[system] '{name}' timed out (contained)")
            continue
        except Exception as exc:
            skipped.append({"tool": name, "reason": f"error: {exc}"})
            log(f"[system] '{name}' failed (tolerated): {exc}")
            continue

        try:
            f, s = spec["parser"](proc.stdout or "", proc.stderr or "")
        except Exception as exc:
            skipped.append({"tool": name, "reason": f"parser error: {exc}"})
            log(f"[system] '{name}' parser failed (tolerated): {exc}")
            continue

        findings.extend(f)
        if isinstance(s, dict):
            for k, v in s.items():
                if k in surface and isinstance(surface[k], list) \
                        and isinstance(v, list):
                    surface[k].extend(v)
                else:
                    surface[k] = v
        ran.append(name)
        log(f"[system] '{name}' done: {len(f)} findings")

    # dedupe surface lists
    for k, v in surface.items():
        if isinstance(v, list):
            seen, uniq = set(), []
            for item in v:
                key = json.dumps(item, sort_keys=True, default=str) \
                    if isinstance(item, dict) else str(item)
                if key not in seen:
                    seen.add(key)
                    uniq.append(item)
            surface[k] = uniq
    return {"findings": findings, "surface": surface,
            "ran": ran, "skipped": skipped}
