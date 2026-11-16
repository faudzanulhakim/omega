"""
omega/pytools.py — pure-Python recon tool suite for OMEGA.

Zero external binaries: every tool is plain Python (urllib.request for
HTTP, socket for DNS) with short timeouts, so the suite works anywhere
and is hermetically testable against a local HTTP server / stubs.

Registry shape mirrors engine offensive.toolbridge TOOL_REGISTRY entries
({name, stage, output, parser, safety, ...}) so engine run_bridge-style
allowlists can filter these tools the same way.  Additionally every entry
carries `fn(target, log)` which returns (findings, surface) — engine
finding shape (confidence=candidate, verification='signature',
manual_check=True, source='omega-py/<name>').

SAFETY CONTRACT (mirrors the engine bridge):
  * every entry declares safety: passive | active-recon.
  * READ-ONLY operations only: GET/HEAD requests, DNS resolution,
    public archive/CT-log queries.  No brute force, no exploitation.
  * small, bounded wordlists; short timeouts; never raises outward —
    callers get findings plus (possibly empty) surfaces.
"""
import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# --------------------------------------------------------------- constants
HTTP_TIMEOUT_S = 6
DNS_TIMEOUT_S = 3
FINDING_EVIDENCE_CAP = 300
UA = "omega-pytools/1.0 (pure-python recon; read-only)"

COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
    "ns", "ww1", "mx", "mx1", "mx2", "cdn", "mysql", "git", "api", "app",
    "dev", "staging", "stg", "qa", "uat", "demo", "beta", "alpha", "aws",
    "cloud", "admin", "administrator", "dashboard", "cpanel", "whm",
    "webdisk", "autodiscover", "autoconfig", "imap", "pop", "pop3",
    "relay", "gateway", "gw", "router", "firewall", "proxy", "cache",
    "lb", "loadbalancer", "db", "database", "sql", "postgres", "redis",
    "mongo", "es", "elastic", "kibana", "grafana", "prometheus", "jenkins",
    "ci", "cd", "build", "nexus", "artifactory", "sso", "auth", "login",
    "oauth", "id", "identity", "accounts", "account", "my", "help",
    "support", "docs", "doc", "wiki", "status", "monitor", "nagios",
    "zabbix", "backup", "backups", "old", "new", "www2", "www3", "static",
    "assets", "img", "images", "media", "video", "videos", "download",
    "downloads", "files", "file", "share", "cloud2", "s3", "storage",
    "office", "owa", "exchange", "lync", "skype", "teams", "zoom", "meet",
    "chat", "jabber", "ldap", "directory", "ad", "adfs", "radius",
    "vpn2", "ssl", "tls", "cert", "certs", "pki", "ca", "ocsp", "crl",
    "svn", "hg", "gitlab", "bitbucket", "jira", "confluence", "redmine",
    "bugzilla", "phabricator", "sonar", "sonarqube", "checkmarx",
    "sendy", "newsletter", "lists", "list", "mailman", "crm", "erp",
    "sap", "oracle", "intranet", "portal2", "partner", "partners",
    "vendor", "vendors", "supplier", "client", "clients", "customer",
    "customers", "shop2", "store", "cart", "checkout", "pay", "payment",
    "billing", "invoice", "invoices", "finance", "hr", "people",
    "recruit", "jobs", "career", "careers", "learn", "training",
    "lms", "academy", "school", "university", "lab", "labs", "sandbox",
    "preprod", "pre", "int", "integration", "internal", "ext", "external",
    "corp", "corporate", "hq", "ny", "london", "paris", "tokyo", "berlin",
    "edge", "node", "node1", "node2", "host", "host1", "host2", "vps",
    "vm", "docker", "k8s", "kubernetes", "rancher", "swarm", "registry",
    "npm", "pypi", "apt", "yum", "repo", "repos", "mirror", "mirrors",
    "time", "ntp", "log", "logs", "syslog", "metrics", "trace", "tracing",
    "jaeger", "zipkin", "sentry", "bug", "bugs", "error", "errors",
    "wap", "mobile", "ios", "android", "m2", "amp", "go", "link", "links",
    "short", "shortener", "url", "urls", "redirect", "r", "s", "t",
]

DIR_WORDLIST_TOP100 = [
    "admin", "login", "wp-admin", "wp-login.php", "administrator",
    "dashboard", "config", "configuration", "setup", "install",
    "phpmyadmin", "pma", "mysql", "sql", "db", "backup", "backups",
    "bak", "old", "test", "tmp", "temp", "dev", "development",
    "api", "api/v1", "api/v2", "v1", "v2", "rest", "graphql",
    "swagger", "openapi.json", "docs", "documentation", "help",
    "status", "health", "healthz", "ping", "info", "server-info",
    "server-status", ".git", ".git/config", ".env", ".htaccess",
    ".svn", ".DS_Store", "web.config", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "clientaccesspolicy.xml", "security.txt",
    "favicon.ico", "index.php", "index.html", "index.bak",
    "login.html", "signin", "signout", "logout", "register",
    "signup", "user", "users", "account", "accounts", "profile",
    "admin.php", "admin panel", "cpanel", "shell", "upload",
    "uploads", "files", "download", "downloads", "media", "images",
    "img", "css", "js", "static", "assets", "assets/js", "assets/css",
    "public", "private", "secret", "secrets", "keys", "cert", "certs",
    "cgi-bin", "bin", "scripts", "include", "includes", "lib",
    "library", "vendor", "node_modules", "app", "application",
    "src", "core", "system", "modules", "plugins", "themes",
    "content", "data", "dump", "export", "report", "reports",
    "log", "logs", "error", "errors", "email", "contact", "about",
    "blog", "news", "forum", "shop", "store", "search",
]

TECH_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/favicon.ico", "/humans.txt", "/crossdomain.xml",
]

SECRET_KEY_HINTS = [
    "api_key", "apikey", "api-key", "access_token", "auth_token",
    "client_secret", "private_key", "secret", "password", "passwd",
    "aws_access_key_id", "aws_secret_access_key", "firebase",
    "bearer", "authorization", "token",
]

# top-1000-ish default port list for the async scanner lives in
# pytools_scan; imported lazily to keep this module dependency-light.


# ---------------------------------------------------------------- helpers

def _finding(tool, title, severity, evidence, location="", param="",
             note=None, tags=None, flaky=None):
    """engine-shaped finding produced by an omega-py tool."""
    ev = str(evidence or "")
    if len(ev) > FINDING_EVIDENCE_CAP:
        ev = ev[:FINDING_EVIDENCE_CAP] + "…"
    out = {
        "title": title,
        "severity": severity,               # INFO / LOW by class
        "confidence": "candidate",
        "verification": "signature",        # tool output = signature, not proof
        "verification_note": note or (
            f"signature from pure-python tool '{tool}'; requires manual "
            "verification before acting on it"),
        "manual_check": True,
        "location": location or "",
        "param": param or "",
        "evidence": ev,
        "source": f"omega-py/{tool}",
    }
    if tags:
        out["tags"] = list(tags)
    if flaky is not None:
        out["flaky"] = bool(flaky)
    return out


def _norm_base_url(target):
    """Normalize a target into a scheme-qualified base URL."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "http://" + t
    p = urllib.parse.urlparse(t)
    if not p.netloc:
        return ""
    return f"{p.scheme or 'http'}://{p.netloc}"


def _norm_domain(target):
    """Extract a bare hostname (no scheme/port) from a target string."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        t = urllib.parse.urlparse(t).netloc or t
    t = t.split("/")[0].split(":")[0].strip().rstrip(".")
    return t.lower()


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _http_get(url, timeout=HTTP_TIMEOUT_S, method="GET", headers=None):
    """Read-only HTTP fetch via stdlib. Returns dict, never raises."""
    req = urllib.request.Request(
        url, method=method,
        headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(512 * 1024)
            return {"status": resp.status, "headers": dict(resp.headers),
                    "set_cookie_list":
                        resp.headers.get_all("Set-Cookie") or [],
                    "body": body, "final_url": resp.geturl(), "error": None}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(64 * 1024)
        except Exception:
            body = b""
        return {"status": e.code, "headers": dict(e.headers or {}),
                "set_cookie_list": (e.headers or {}).get_all("Set-Cookie")
                or [],
                "body": body, "final_url": url, "error": f"HTTP {e.code}"}
    except Exception as e:  # URLError, socket.timeout, ValueError, ...
        return {"status": None, "headers": {}, "body": b"",
                "set_cookie_list": [], "final_url": url, "error": str(e)}


def _entropy(s):
    """Shannon entropy (bits/char) of a string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _looks_like_token(s):
    """Differential care for JS secrets: long + high-entropy only."""
    return len(s) >= 20 and _entropy(s) >= 3.5


def _resolve_host(host, timeout=DNS_TIMEOUT_S):
    """Best-effort IPv4 resolution; returns IP or None."""
    if _is_ip(host):
        return host
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(host)
    except Exception:
        return None


def _page_title(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "",
                  re.IGNORECASE | re.DOTALL)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    return ""


def _meta_generator(html):
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]*'
                  r'content=["\']([^"\']+)', html or "", re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _same_netloc(url, base):
    try:
        return urllib.parse.urlparse(url).netloc.lower() == \
            urllib.parse.urlparse(base).netloc.lower()
    except Exception:
        return False


def _in_scope(url, base):
    """Scope check: only same-host links/pages are followed."""
    try:
        u, b = urllib.parse.urlparse(url), urllib.parse.urlparse(base)
        return u.netloc.lower() == b.netloc.lower() and \
            u.scheme in ("http", "https")
    except Exception:
        return False


# ------------------------------------------------------------ tool fns

def fn_subdomain_sweep(target, log=None):
    """Resolve a common-wordlist of subdomains under the target domain."""
    domain = _norm_domain(target)
    findings, hosts = [], []
    if not domain or _is_ip(domain):
        return findings, {"hosts": []}
    candidates = [f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS]
    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(_resolve_host, candidates))
    for host, ip in zip(candidates, results):
        if ip:
            hosts.append(host)
            findings.append(_finding(
                "subdomain_sweep", f"subdomain resolves: {host}", "INFO",
                f"{host} -> {ip}", location=host))
    return findings, {"hosts": hosts, "resolved": len(hosts)}


def fn_dns_records(target, log=None):
    """Best-effort A/AAAA/MX/NS/TXT/CNAME via socket only.

    Full RR fetching needs a DNS wire client; this implementation does a
    plain A lookup plus a heuristic TXT-less check and is declared
    best-effort — records beyond A/AAAA are reported only if resolvable
    through the system resolver's canonical-name behaviour (CNAME via
    getaddrinfo aliases).
    """
    domain = _norm_domain(target)
    findings, records = [], []
    if not domain:
        return findings, {"records": records}
    # A record
    ip = _resolve_host(domain)
    if ip:
        records.append({"type": "A", "value": ip})
        findings.append(_finding("dns_records", f"A record: {domain} -> {ip}",
                                 "INFO", f"{domain} A {ip}", location=domain))
    # AAAA record (socket.getaddrinfo, AF_INET6 only)
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET6,
                                   socket.SOCK_STREAM)
        v6 = sorted({i[4][0] for i in infos})
        for v in v6[:5]:
            records.append({"type": "AAAA", "value": v})
        if v6:
            findings.append(_finding(
                "dns_records", f"AAAA record: {domain} -> {v6[0]}", "INFO",
                f"{domain} AAAA {', '.join(v6[:5])}", location=domain))
    except Exception:
        pass
    # CNAME-like alias via getaddrinfo canonical name
    try:
        canon = socket.gethostbyname_ex(domain)[0]
        if canon and canon.lower() != domain:
            records.append({"type": "CNAME-candidate", "value": canon})
            findings.append(_finding(
                "dns_records", f"canonical name: {domain} -> {canon}",
                "INFO", f"{domain} CNAME-candidate {canon}", location=domain))
    except Exception:
        pass
    if not records:
        findings.append(_finding(
            "dns_records", f"no DNS records resolvable for {domain}",
            "INFO", f"{domain}: resolution failed (NXDOMAIN or no network)",
            location=domain,
            note="domain did not resolve; signature from resolver failure"))
    return findings, {"records": records}


def fn_http_fingerprint(target, log=None):
    """Fetch / and parse Server / X-Powered-By / title / generator."""
    base = _norm_base_url(target)
    findings, surface = [], {}
    if not base:
        return findings, surface
    resp = _http_get(base + "/")
    surface["http_status"] = resp["status"]
    if resp["status"] is None:
        findings.append(_finding(
            "http_fingerprint", f"HTTP unreachable: {base}", "INFO",
            f"GET {base}/ failed: {resp['error']}", location=base))
        return findings, surface
    hdrs = {k.lower(): v for k, v in resp["headers"].items()}
    body = resp["body"].decode("utf-8", "replace")
    server = hdrs.get("server", "")
    powered = hdrs.get("x-powered-by", "")
    title = _page_title(body)
    gen = _meta_generator(body)
    surface.update({"server": server, "x_powered_by": powered,
                    "title": title, "generator": gen})
    if server:
        findings.append(_finding("http_fingerprint",
                                 f"server header on {base}", "INFO",
                                 f"Server: {server}", location=base))
    if powered:
        findings.append(_finding("http_fingerprint",
                                 f"X-Powered-By disclosed on {base}", "LOW",
                                 f"X-Powered-By: {powered}", location=base))
    if title:
        surface["title"] = title
    if gen:
        findings.append(_finding("http_fingerprint",
                                 f"meta generator on {base}", "LOW",
                                 f"generator: {gen}", location=base))
    return findings, surface


def fn_tech_probe(target, log=None):
    """Probe common metadata paths; hash bodies to flag presence."""
    base = _norm_base_url(target)
    findings, present = [], []
    if not base:
        return findings, present

    def probe(path):
        r = _http_get(base + path, method="GET")
        digest = hashlib.sha256(r["body"]).hexdigest()[:16] if r["body"] \
            else ""
        return path, r, digest

    with ThreadPoolExecutor(max_workers=len(TECH_PATHS)) as pool:
        results = list(pool.map(probe, TECH_PATHS))
    for path, r, digest in results:
        if r["status"] == 200 and r["body"]:
            present.append({"path": path, "sha256_16": digest,
                            "bytes": len(r["body"])})
            findings.append(_finding(
                "tech_probe", f"metadata file present: {path}", "INFO",
                f"GET {base}{path} -> 200 ({len(r['body'])} bytes, "
                f"sha256:{digest})", location=base + path))
    return findings, {"present": present}


def _extract_from_js(js_text, page_url):
    """Regex-mine endpoints and high-entropy secret candidates from JS."""
    endpoints, tokens = set(), set()
    for m in re.finditer(
            r'["\'](/[A-Za-z0-9_\-./]{3,80})["\']', js_text or ""):
        ep = m.group(1)
        if re.match(r"^/[\w.\-]+(/[\w.\-]+)*$", ep) and \
                not ep.startswith("//"):
            endpoints.add(ep)
    # key=value secret shapes
    for m in re.finditer(
            r'(?i)["\']?([A-Za-z0-9_\-]{4,40})["\']?\s*[:=]\s*'
            r'["\']([A-Za-z0-9+/_=\-]{20,})["\']', js_text or ""):
        key, val = m.group(1), m.group(2)
        if any(h in key.lower() for h in SECRET_KEY_HINTS) and \
                _looks_like_token(val):
            tokens.add(f"{key}={val[:24]}…")
    # bare high-entropy long strings (differential care: >= 20 chars)
    for m in re.finditer(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']',
                         js_text or ""):
        tok = m.group(1)
        if _looks_like_token(tok):
            tokens.add(tok[:24] + "…")
    return endpoints, tokens


def fn_js_endpoint_miner(target, log=None):
    """Fetch page + same-origin JS files; regex endpoints / high-entropy
    secret candidates.  Differential care: only tokens >= 20 chars with
    high entropy are reported."""
    base = _norm_base_url(target)
    findings, surface = [], {"endpoints": [], "secret_candidates": []}
    if not base:
        return findings, surface
    page = _http_get(base + "/")
    if page["status"] is None:
        return findings, surface
    html = page["body"].decode("utf-8", "replace")
    endpoints, tokens = set(), set()
    ep, tk = _extract_from_js(html, base + "/")
    endpoints |= ep
    tokens |= tk
    # find same-origin script srcs
    scripts = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html,
                         re.IGNORECASE):
        src = urllib.parse.urljoin(base + "/", m.group(1))
        if _in_scope(src, base):
            scripts.add(src)
    for src in list(scripts)[:10]:
        r = _http_get(src)
        if r["status"] == 200 and r["body"]:
            ep, tk = _extract_from_js(r["body"].decode("utf-8", "replace"),
                                      src)
            endpoints |= ep
            tokens |= tk
    surface["endpoints"] = sorted(endpoints)[:200]
    surface["secret_candidates"] = sorted(tokens)[:50]
    for ep in surface["endpoints"]:
        findings.append(_finding("js_endpoint_miner",
                                 f"endpoint found in JS: {ep}", "INFO",
                                 f"endpoint {ep}", location=base))
    for tok in surface["secret_candidates"]:
        findings.append(_finding(
            "js_endpoint_miner",
            "possible secret candidate in JS (high-entropy, >=20 chars)",
            "LOW", f"token candidate: {tok}", location=base,
            note="high-entropy string candidate only; differential care "
                 "applied (length >= 20 and entropy >= 3.5); manual "
                 "verification required"))
    return findings, surface


# External-OSINT handling: results are tagged osint-external and cached
# with a TTL so repeat scans stay consistent; a failed/timeout query is
# flagged flaky instead of being treated as a negative result.
_OSINT_CACHE = {}
_OSINT_TTL_S = 900  # 15 minutes


def _osint_cached(key, fn, *args):
    """Return (findings, surface) for an external OSINT query with TTL cache."""
    ent = _OSINT_CACHE.get(key)
    now = time.monotonic()
    if ent and (now - ent[0]) < _OSINT_TTL_S:
        f, s = ent[1]
        return [dict(x) for x in f], dict(s)
    f, s = fn(*args)
    # only cache successful queries — a failed/tolerated lookup is flaky
    # and must be retried on the next scan, never treated as a result
    if not any(x.get("flaky") for x in f):
        _OSINT_CACHE[key] = (now, ([dict(x) for x in f], dict(s)))
    return f, s


def fn_wayback_client(target, log=None):
    """Query web.archive.org CDX API for archived URLs (passive)."""
    domain = _norm_domain(target)
    if not domain:
        return [], {}
    return _osint_cached("wayback:" + domain, _wayback_query, domain)


def _wayback_query(domain):
    findings, urls = [], []
    api = ("https://web.archive.org/cdx/search/cdx?output=json&"
           f"url={urllib.parse.quote(domain)}/*&limit=500&collapse=urlkey")
    req = urllib.request.Request(api, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            data = json.loads(resp.read(2 * 1024 * 1024).decode("utf-8",
                                                                "replace"))
        # tolerant of shape: rows may include a header row
        for row in data if isinstance(data, list) else []:
            if isinstance(row, list) and len(row) >= 3 and \
                    row[0] != "urlkey":
                u = row[2] if len(row) > 2 else (row[-1] or "")
                if u:
                    urls.append(u)
    except Exception as e:
        findings.append(_finding(
            "wayback_client", "archive CDX query unavailable", "INFO",
            f"web.archive.org query failed (tolerated): {e}",
            location=domain,
            note="network failure tolerated; no archive data collected",
            tags=["osint-external"], flaky=True))
        return findings, {"urls": []}
    seen = []
    for u in urls:
        if u not in seen:
            seen.append(u)
    for u in seen[:100]:
        findings.append(_finding("wayback_client",
                                 f"archived URL: {u}", "INFO", u,
                                 location=u,
                                 tags=["osint-external"], flaky=False))
    return findings, {"urls": seen[:200]}


def fn_crtsh_client(target, log=None):
    """Query crt.sh JSON for certificate-transparency subdomains."""
    domain = _norm_domain(target)
    if not domain:
        return [], {}
    return _osint_cached("crtsh:" + domain, _crtsh_query, domain)


def _crtsh_query(domain):
    findings, names = [], []
    api = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    req = urllib.request.Request(api, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            data = json.loads(resp.read(2 * 1024 * 1024).decode("utf-8",
                                                                "replace"))
        for rec in data if isinstance(data, list) else []:
            raw = rec.get("name_value", "") if isinstance(rec, dict) else ""
            for n in str(raw).splitlines():
                n = n.strip().lstrip("*.").lower()
                if n.endswith("." + domain) and n not in names:
                    names.append(n)
    except Exception as e:
        findings.append(_finding(
            "crtsh_client", "crt.sh query unavailable", "INFO",
            f"crt.sh query failed (tolerated): {e}", location=domain,
            note="network failure tolerated; no CT data collected",
            tags=["osint-external"], flaky=True))
        return findings, {"names": []}
    for n in sorted(names)[:100]:
        findings.append(_finding("crtsh_client",
                                 f"CT-log name: {n}", "INFO", n, location=n,
                                 tags=["osint-external"], flaky=False))
    return findings, {"names": sorted(names)[:200]}


def fn_httpx_py(target, log=None):
    """Batch URL liveness probe: status + title via thread pool.

    `target` may be a single host or a list/iterable of hosts/URLs.
    """
    if isinstance(target, (list, tuple, set)):
        items = list(target)
    else:
        items = [target]
    bases = []
    for t in items:
        b = _norm_base_url(t)
        if b and b not in bases:
            bases.append(b)
    findings, live = [], []

    def probe(base):
        r = _http_get(base + "/", timeout=HTTP_TIMEOUT_S)
        title = _page_title(r["body"].decode("utf-8", "replace")) \
            if r["body"] else ""
        return base, r, title

    with ThreadPoolExecutor(max_workers=min(16, max(1, len(bases)))) as pool:
        results = list(pool.map(probe, bases))
    for base, r, title in results:
        if r["status"] is not None:
            live.append({"url": base, "status": r["status"],
                         "title": title})
            findings.append(_finding(
                "httpx_py", f"live URL: {base} ({r['status']})", "INFO",
                f"{base} -> HTTP {r['status']}"
                + (f" title: {title!r}" if title else ""),
                location=base))
        else:
            findings.append(_finding(
                "httpx_py", f"URL unreachable: {base}", "INFO",
                f"{base} probe failed: {r['error']}", location=base))
    return findings, {"live": live}


def fn_dirfind_py(target, log=None):
    """Top-100 path discovery with differential baseline.

    A random-ish baseline path (404-base) is requested first; only
    paths whose status differs from the baseline (and from the noise
    pattern of two further random probes) are reported.
    """
    base = _norm_base_url(target)
    findings, hits = [], []
    if not base:
        return findings, hits
    noise_paths = ["/%s" % hashlib.md5(os.urandom(8)).hexdigest(),
                   "/%s" % hashlib.md5(os.urandom(8)).hexdigest()]
    statuses = {}
    for np in noise_paths:
        r = _http_get(base + np, method="HEAD")
        statuses[np] = r["status"]
    baseline = statuses.get(noise_paths[0])
    # baseline is trustworthy only if both random paths behave the same
    baseline_ok = baseline is not None and \
        statuses.get(noise_paths[1]) == baseline

    def probe(path):
        r = _http_get(base + "/" + path.lstrip("/"), method="HEAD")
        if r["status"] in (405, 501) or r["status"] is None:
            # HEAD refused — fall back to GET
            r = _http_get(base + "/" + path.lstrip("/"), method="GET")
        return path, r

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(probe, DIR_WORDLIST_TOP100))
    for path, r in results:
        st = r["status"]
        if st is None:
            continue
        if baseline_ok and st == baseline:
            continue  # matches 404/403-noise pattern — not interesting
        if baseline_ok and st == 404 and baseline == 404:
            continue
        if not baseline_ok and st == 404:
            continue
        hits.append({"path": "/" + path.lstrip("/"), "status": st})
        findings.append(_finding(
            "dirfind_py", f"path responds differently: /{path.lstrip('/')} "
            f"({st})", "INFO", f"GET {base}/{path.lstrip('/')} -> {st}",
            location=f"{base}/{path.lstrip('/')}",
            note="status differs from random-path baseline; may still be "
                 "noise (custom 404 handlers vary)"))
    return findings, {"hits": hits, "baseline_status": baseline}


def fn_cookie_flag_audit(target, log=None):
    """Audit Set-Cookie flags on / (Secure, HttpOnly, SameSite)."""
    base = _norm_base_url(target)
    findings, cookies = [], []
    if not base:
        return findings, cookies
    resp = _http_get(base + "/")
    raw = resp["set_cookie_list"]
    if resp["status"] is None:
        findings.append(_finding(
            "cookie_flag_audit", f"HTTP unreachable: {base}", "INFO",
            f"GET {base}/ failed: {resp['error']}", location=base))
        return findings, cookies
    if not raw:
        findings.append(_finding(
            "cookie_flag_audit", "no Set-Cookie observed on /", "INFO",
            f"no Set-Cookie header on GET {base}/", location=base))
        return findings, cookies
    for raw_cookie in raw:
        first = raw_cookie.split(";", 1)[0].strip()
        name = first.split("=", 1)[0].strip()
        low = raw_cookie.lower()
        flags = {"secure": "secure" in low,
                 "httponly": "httponly" in low,
                 "samesite": "samesite" in low}
        cookies.append({"name": name, **flags, "raw": raw_cookie[:120]})
        missing = [f for f in ("secure", "httponly", "samesite")
                   if not flags[f]]
        if missing:
            findings.append(_finding(
                "cookie_flag_audit",
                f"cookie '{name}' missing flags: {', '.join(missing)}",
                "LOW", f"Set-Cookie: {raw_cookie[:160]}", location=base,
                param=name))
        else:
            findings.append(_finding(
                "cookie_flag_audit",
                f"cookie '{name}' carries all recommended flags", "INFO",
                f"Set-Cookie: {raw_cookie[:160]}", location=base,
                param=name))
    return findings, {"cookies": cookies}


# ------------------------------------------------------------ registry

# parser field mirrors toolbridge (a callable normalizing output);
# for pure-python tools the fn already returns normalized findings, so
# parser is a pass-through identity for compatibility with allowlist
# logic that only checks presence/fields.
def _identity_parser(value):
    return value


PY_REGISTRY = {
    "subdomain_sweep": {
        "name": "subdomain_sweep", "stage": "recon", "output": "json",
        "parser": _identity_parser, "safety": "passive",
        "fn": fn_subdomain_sweep,
        "description": "resolve common-wordlist subdomains (socket DNS)",
    },
    "dns_records": {
        "name": "dns_records", "stage": "recon", "output": "json",
        "parser": _identity_parser, "safety": "passive",
        "fn": fn_dns_records,
        "description": "best-effort A/AAAA/CNAME via socket",
    },
    "http_fingerprint": {
        "name": "http_fingerprint", "stage": "enum", "output": "json",
        "parser": _identity_parser, "safety": "active-recon",
        "fn": fn_http_fingerprint,
        "description": "server/x-powered-by/title/generator from /",
    },
    "tech_probe": {
        "name": "tech_probe", "stage": "enum", "output": "json",
        "parser": _identity_parser, "safety": "active-recon",
        "fn": fn_tech_probe,
        "description": "probe robots/sitemap/security.txt/favicon paths",
    },
    "js_endpoint_miner": {
        "name": "js_endpoint_miner", "stage": "enum", "output": "json",
        "parser": _identity_parser, "safety": "active-recon",
        "fn": fn_js_endpoint_miner,
        "description": "regex-mine endpoints + high-entropy secrets in JS",
    },
    "wayback_client": {
        "name": "wayback_client", "stage": "recon", "output": "json",
        "parser": _identity_parser, "safety": "passive",
        "fn": fn_wayback_client,
        "description": "web.archive.org CDX API archived URLs",
    },
    "crtsh_client": {
        "name": "crtsh_client", "stage": "recon", "output": "json",
        "parser": _identity_parser, "safety": "passive",
        "fn": fn_crtsh_client,
        "description": "crt.sh certificate-transparency names",
    },
    "httpx_py": {
        "name": "httpx_py", "stage": "enum", "output": "json",
        "parser": _identity_parser, "safety": "active-recon",
        "fn": fn_httpx_py,
        "description": "batch URL liveness + title + status",
    },
    "dirfind_py": {
        "name": "dirfind_py", "stage": "enum", "output": "json",
        "parser": _identity_parser, "safety": "active-recon",
        "fn": fn_dirfind_py,
        "description": "top-100 path discovery vs random-path baseline",
    },
    "cookie_flag_audit": {
        "name": "cookie_flag_audit", "stage": "verify", "output": "json",
        "parser": _identity_parser, "safety": "active-recon",
        "fn": fn_cookie_flag_audit,
        "description": "Set-Cookie Secure/HttpOnly/SameSite audit on /",
    },
}
