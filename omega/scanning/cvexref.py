"""omega/cvexref.py — offline tech-to-CVE correlation (mini bundled DB).

Correlates technology fingerprints (from omega surface.techs, pytools
http_fingerprint, or a whatweb parser output shape) against a bundled
mini-DB of product / version-range -> known CVE ids. FULLY OFFLINE:
no network calls of any kind.

Rules:
- Never guesses without an exact version string: a banner without a
  parseable version is SKIPPED with reason 'no version'.
- A finding is emitted (verification='candidate', severity 'info' or
  'high' for flagged entries) only when the parsed version falls in an
  affected range; evidence carries parsed version + CVE id + why.
- source=omega-cve/xref.
"""

from __future__ import annotations

import re

__all__ = [
    "CVE_DB",
    "Finding",
    "parse_version",
    "correlate",
    "db_audit",
]

from omega.deepchecks import Finding

# ---------------------------------------------------------------------------
# Bundled mini-DB. One product entry per known banner family:
#   aliases      — lowercase substrings matched against the product string
#   cves         — list of {id, desc, min, max} (inclusive version range)
#   high_ids     — CVE ids considered HIGH severity when matched
# Entries cover common banners as required by the OMEGA contract.
# ---------------------------------------------------------------------------

CVE_DB = [
    {"product": "apache httpd", "aliases": ["apache", "httpd"], "cves": [
        {"id": "CVE-2021-41773", "desc": "path traversal + RCE via "
         "mapped-in .so handlers (2.4.49/2.4.50)",
         "min": "2.4.49", "max": "2.4.49"},
        {"id": "CVE-2021-42013", "desc": "path traversal / RCE, bypass of "
         "the 41773 fix (2.4.49/2.4.50)", "min": "2.4.49", "max": "2.4.50"},
        {"id": "CVE-2021-44790", "desc": "buffer overflow in mod_lua "
         "request parsing", "min": "2.4.48", "max": "2.4.51"},
        {"id": "CVE-2019-0211", "desc": "privilege escalation via "
         "scoreboard in Apache HTTP Server before 2.4.39",
         "min": "2.4.0", "max": "2.4.38"},
    ]},
    {"product": "nginx", "aliases": ["nginx"], "cves": [
        {"id": "CVE-2021-23017", "desc": "DNS resolver off-by-one "
         "heap corruption (1.20.0)", "min": "0.6.18", "max": "1.20.0"},
        {"id": "CVE-2019-9511", "desc": "HTTP/2 DATA-flood DoS",
         "min": "1.9.5", "max": "1.17.2"},
        {"id": "CVE-2017-7529", "desc": "integer overflow leaks "
         "upstream response memory", "min": "0.5.6", "max": "1.13.1"},
    ]},
    {"product": "tomcat", "aliases": ["tomcat", "coyote"], "cves": [
        {"id": "CVE-2017-12617", "desc": "JSP PUT upload RCE when "
         "write-enabled (examples/readonly default off)",
         "min": "7.0.0", "max": "7.0.81"},
        {"id": "CVE-2019-0232", "desc": "CGI servlet argument injection "
         "RCE on Windows", "min": "8.5.0", "max": "8.5.40"},
        {"id": "CVE-2020-1938", "desc": "Ghostcat AJP message "
         "file-read/inclusion", "min": "7.0.0", "max": "9.0.30"},
    ]},
    {"product": "php", "aliases": ["php"], "cves": [
        {"id": "CVE-2019-11043", "desc": "fpm main-process buffer "
         "overflow -> RCE via URL (nginx+fpm)", "min": "7.1.0",
         "max": "7.3.10"},
        {"id": "CVE-2012-1823", "desc": "cgi mode argument injection "
         "RCE (EOL 5.x branch)", "min": "5.2.0", "max": "5.4.37"},
        {"id": "CVE-2015-2348", "desc": "move_uploaded_file null-byte "
         "truncation (EOL 5.x branch)", "min": "5.0.0", "max": "5.6.99"},
    ]},
    {"product": "openssh", "aliases": ["openssh"], "cves": [
        {"id": "CVE-2018-15473", "desc": "username enumeration via "
         "malformed auth requests (pre-8.4 era still leaks via timing)",
         "min": "1.0.0", "max": "8.3"},
        {"id": "CVE-2016-10009", "desc": "sftp-server arbitrary library "
         "load via ssh-agent", "min": "5.0", "max": "7.3"},
    ]},
    {"product": "mysql", "aliases": ["mysql", "mariadb"], "cves": [
        {"id": "CVE-2017-3302", "desc": "auth-switch pre-auth "
         "use-after-free (5.7 line)", "min": "5.7.0", "max": "5.7.16"},
        {"id": "CVE-2016-6662", "desc": "root privilege escalation via "
         "config injection (5.7 branch)", "min": "5.7.0", "max": "5.7.13"},
    ]},
    {"product": "iis", "aliases": ["iis", "microsoft-iis"], "cves": [
        {"id": "CVE-2020-0646", "desc": ".NET crypto remote code "
         "execution exposed via IIS 10 sites", "min": "10.0", "max": "10.99"},
        {"id": "CVE-2017-7269", "desc": "WebDAV buffer overflow RCE "
         "(IIS 6, listed for completeness of legacy surfaces)",
         "min": "6.0", "max": "6.0"},
    ]},
    {"product": "jquery", "aliases": ["jquery"], "cves": [
        {"id": "CVE-2020-11022", "desc": "XSS via untrusted HTML with "
         "<option> (fixed 3.5.0)", "min": "1.2.0", "max": "3.4.9"},
        {"id": "CVE-2019-11358", "desc": "prototype pollution via "
         "$.extend (fixed 3.4.0)", "min": "1.0.0", "max": "3.3.9"},
    ]},
    {"product": "log4j", "aliases": ["log4j"], "cves": [
        {"id": "CVE-2021-44228", "desc": "Log4Shell JNDI lookup RCE "
         "(2.x below 2.15)", "min": "2.0", "max": "2.14.9"},
        {"id": "CVE-2021-45046", "desc": "incomplete fix follow-up "
         "JNDI RCE (2.x below 2.16)", "min": "2.0", "max": "2.15.9"},
    ]},
    {"product": "django", "aliases": ["django"], "cves": [
        {"id": "CVE-2021-31542", "desc": "multi-part filename "
         "path traversal in 3.x", "min": "3.0", "max": "3.1.11"},
        {"id": "CVE-2020-7471", "desc": "StringAgg SQL injection in "
         "3.x", "min": "3.0", "max": "3.0.3"},
    ]},
    {"product": "wordpress", "aliases": ["wordpress", "wp-"], "cves": [
        {"id": "CVE-2021-29450", "desc": "object injection via "
         "phpmailer (pre-5.8)", "min": "3.7", "max": "5.7.9"},
        {"id": "CVE-2019-8942", "desc": "stored XSS via crafted post "
         "slug (pre-5.8 era lines)", "min": "4.9", "max": "5.0.16"},
    ]},
    {"product": "drupal", "aliases": ["drupal"], "cves": [
        {"id": "CVE-2019-6340", "desc": "remote code execution via "
         "untrusted render arrays (7/8 EOL lines)", "min": "7.0",
         "max": "8.6.9"},
        {"id": "CVE-2018-7600", "desc": "Drupalgeddon2 pre-auth RCE "
         "(7/8)", "min": "7.0", "max": "8.5.0"},
    ]},
    {"product": "openssl", "aliases": ["openssl"], "cves": [
        {"id": "CVE-2014-0160", "desc": "Heartbleed heartbeat read "
         "overrun", "min": "1.0.1", "max": "1.0.1f"},
        {"id": "CVE-2021-3711", "desc": "SM2 buffer overflow in "
         "pre-3.0 lines", "min": "1.1.1", "max": "1.1.1k"},
    ]},
    {"product": "jetty", "aliases": ["jetty"], "cves": [
        {"id": "CVE-2021-28165", "desc": "SSL/TLS DoS via handshake "
         "loop", "min": "9.4.0", "max": "9.4.38"},
        {"id": "CVE-2017-7657", "desc": "double-beta HTTP smuggling "
         "chunk parse", "min": "9.2.0", "max": "9.2.27"},
    ]},
    {"product": "lighttpd", "aliases": ["lighttpd"], "cves": [
        {"id": "CVE-2019-11072", "desc": "connection state DoS in "
         "mod_extforward", "min": "1.4.0", "max": "1.4.53"},
    ]},
    {"product": "haproxy", "aliases": ["haproxy"], "cves": [
        {"id": "CVE-2021-40346", "desc": "integer overflow enables HTTP "
         "request smuggling", "min": "2.0", "max": "2.2.13"},
    ]},
    {"product": "exim", "aliases": ["exim"], "cves": [
        {"id": "CVE-2019-10149", "desc": "The Return of the WIZard: "
         "remote command exec via recipient", "min": "4.87",
         "max": "4.91"},
    ]},
    {"product": "dovecot", "aliases": ["dovecot"], "cves": [
        {"id": "CVE-2019-11500", "desc": "imap/metadata allocator "
         "overflow", "min": "2.1.0", "max": "2.3.7"},
    ]},
    {"product": "proftpd", "aliases": ["proftpd"], "cves": [
        {"id": "CVE-2019-12815", "desc": "mod_copy SITE CPFR/CPTO "
         "arbitrary copy", "min": "1.3.5", "max": "1.3.6"},
    ]},
    {"product": "vsftpd", "aliases": ["vsftpd"], "cves": [
        {"id": "CVE-2015-1419", "desc": "config denial / unverifiable "
         "upload overwrite in 3.0 line", "min": "3.0.0", "max": "3.0.2"},
    ]},
    {"product": "postfix", "aliases": ["postfix"], "cves": [
        {"id": "CVE-2021-33910", "desc": "systemd-journald adjacency: "
         "long-line SMTP DoS", "min": "3.0", "max": "3.5.9"},
    ]},
    {"product": "cups", "aliases": ["cups"], "cves": [
        {"id": "CVE-2018-4700", "desc": "cups-browsed SNMP cookie "
         "command injection", "min": "1.0", "max": "2.2.7"},
    ]},
    {"product": "samba", "aliases": ["samba"], "cves": [
        {"id": "CVE-2017-7494", "desc": "SambaCry: named-pipe module "
         "load RCE", "min": "3.5.0", "max": "4.6.3"},
    ]},
    {"product": "bind", "aliases": ["bind", "named"], "cves": [
        {"id": "CVE-2020-8616", "desc": "BIND_TSANG resolver assertion "
         "DoS", "min": "9.0", "max": "9.16.2"},
    ]},
    {"product": "krb5", "aliases": ["krb5", "kerberos"], "cves": [
        {"id": "CVE-2018-20217", "desc": "KDC double free via "
         "kadmin remotely", "min": "1.7", "max": "1.16.2"},
    ]},
    {"product": "gitlab", "aliases": ["gitlab"], "cves": [
        {"id": "CVE-2022-1162", "desc": "hardcoded 'miner' account "
         "allows arbitrary user email takeover", "min": "11.10",
         "max": "14.7.6"},
    ]},
    {"product": "jenkins", "aliases": ["jenkins"], "cves": [
        {"id": "CVE-2019-1003000", "desc": "sandbox bypass in script "
         "security plugin", "min": "2.0", "max": "2.181"},
        {"id": "CVE-2018-1000861", "desc": " Stapler request routing "
         "code execution (pre-2.150.1)", "min": "2.0", "max": "2.150"},
    ]},
    {"product": "jira", "aliases": ["jira"], "cves": [
        {"id": "CVE-2019-11581", "desc": "template injection RCE via "
         "contact-admin forms", "min": "7.0", "max": "8.2.3"},
    ]},
    {"product": "confluence", "aliases": ["confluence"], "cves": [
        {"id": "CVE-2022-26134", "desc": "unauthenticated OGNL "
         "injection RCE", "min": "7.0", "max": "7.19.1"},
    ]},
    {"product": "weblogic", "aliases": ["weblogic", "oracle http"], "cves": [
        {"id": "CVE-2020-14882", "desc": "unauthenticated console "
         "component RCE", "min": "10.3.6", "max": "14.1.1"},
        {"id": "CVE-2017-10271", "desc": "WLS-XML decoder deserialization "
         "RCE", "min": "10.3.6", "max": "12.2.1.2"},
    ]},
    {"product": "websphere", "aliases": ["websphere"], "cves": [
        {"id": "CVE-2015-7450", "desc": "Java deserialization RCE in "
         "admin console", "min": "8.0", "max": "8.5.5"},
    ]},
    {"product": "struts", "aliases": ["struts"], "cves": [
        {"id": "CVE-2017-5638", "desc": "Jakarta multipart parser OGNL "
         "RCE", "min": "2.3.5", "max": "2.3.31"},
        {"id": "CVE-2018-11776", "desc": "Semmelroth namespace OGNL "
         "RCE when alwaysSelectFullNamespace", "min": "2.3.0",
         "max": "2.3.34"},
    ]},
    {"product": "spring", "aliases": ["spring"], "cves": [
        {"id": "CVE-2022-22965", "desc": "Spring4Shell data-binding "
         "RCE on JDK9+ Tomcat", "min": "5.2.0", "max": "5.2.19"},
        {"id": "CVE-2018-1270", "desc": "spring-messaging STOMP "
         "SpEL RCE", "min": "4.3.0", "max": "4.3.14"},
    ]},
    {"product": "shiro", "aliases": ["shiro"], "cves": [
        {"id": "CVE-2016-4437", "desc": "rememberMe AES key "
         "deserialization RCE", "min": "1.0", "max": "1.2.4"},
    ]},
    {"product": "fastjson", "aliases": ["fastjson"], "cves": [
        {"id": "CVE-2022-25845", "desc": "autoType deserialization "
         "bypass RCE", "min": "1.2.0", "max": "1.2.82"},
    ]},
    {"product": "thinkphp", "aliases": ["thinkphp"], "cves": [
        {"id": "CVE-2018-20062", "desc": "core routing invokeFunction "
         "RCE", "min": "5.0.0", "max": "5.1.30"},
    ]},
    {"product": "elasticsearch", "aliases": ["elasticsearch"], "cves": [
        {"id": "CVE-2015-1427", "desc": "dynamic script Groovy sandbox "
         "escape RCE", "min": "1.3.0", "max": "1.3.7"},
    ]},
    {"product": "rabbitmq", "aliases": ["rabbitmq"], "cves": [
        {"id": "CVE-2019-11283", "desc": "management UI XSS via "
         "virtual host names", "min": "3.7.0", "max": "3.7.20"},
    ]},
    {"product": "redis", "aliases": ["redis"], "cves": [
        {"id": "CVE-2022-0543", "desc": "Debian-packaged Lua sandbox "
         "escape RCE", "min": "2.2", "max": "6.2.5"},
    ]},
    {"product": "memcached", "aliases": ["memcached"], "cves": [
        {"id": "CVE-2019-15096", "desc": "lru_maintainer thread DoS "
         "via crafted SASL packet", "min": "1.5.0", "max": "1.5.22"},
    ]},
    {"product": "grafana", "aliases": ["grafana"], "cves": [
        {"id": "CVE-2021-43798", "desc": "arbitrary file read via "
         "public plugins path traversal", "min": "7.5.0", "max": "8.3.0"},
    ]},
    {"product": "kibana", "aliases": ["kibana"], "cves": [
        {"id": "CVE-2019-7609", "desc": "Timelion visualization "
         "prototype-pollution RCE", "min": "5.6.0", "max": "6.6.0"},
    ]},
    {"product": "node", "aliases": ["node.js", "nodejs"], "cves": [
        {"id": "CVE-2019-9511", "desc": "HTTP/2 Data-flood DoS in "
         "nghttp2", "min": "8.0", "max": "12.11"},
    ]},
    {"product": "go", "aliases": ["golang", "go-http"], "cves": [
        {"id": "CVE-2019-16221", "desc": "net/http proxy 404 leak "
         "Denial of Service", "min": "1.12", "max": "1.12.9"},
    ]},
    {"product": "glassfish", "aliases": ["glassfish"], "cves": [
        {"id": "CVE-2017-1000028", "desc": "RestfulService unlabeled "
         "injection RCE", "min": "3.0", "max": "4.1"},
    ]},
    {"product": "wildfly", "aliases": ["wildfly", "jboss"], "cves": [
        {"id": "CVE-2017-12149", "desc": "JMX invoker servlet "
         "deserialization RCE", "min": "5.0", "max": "6.4.0"},
    ]},
    {"product": "solr", "aliases": ["solr"], "cves": [
        {"id": "CVE-2019-0193", "desc": "DataImportHandler XSLT "
         "deserialization RCE", "min": "5.0", "max": "8.1.0"},
    ]},
    {"product": "zabbix", "aliases": ["zabbix"], "cves": [
        {"id": "CVE-2022-23131", "desc": "unauthenticated setup.php "
         "SAML auth bypass", "min": "5.4.0", "max": "5.4.8"},
    ]},
    {"product": "phpmyadmin", "aliases": ["phpmyadmin"], "cves": [
        {"id": "CVE-2020-5504", "desc": "display page SQL injection to "
         "XSS/RCE path", "min": "5.0.0", "max": "5.0.0"},
    ]},
    {"product": "webmin", "aliases": ["webmin"], "cves": [
        {"id": "CVE-2019-15107", "desc": "unauthenticated password_chg "
         "backdoor RCE", "min": "1.890", "max": "1.920"},
    ]},
    {"product": "minio", "aliases": ["minio"], "cves": [
        {"id": "CVE-2021-21287", "desc": "SSRF in console / verifying "
         "external endpoint", "min": "0.1", "max": "2021.01.04"},
    ]},
    {"product": "harbor", "aliases": ["harbor"], "cves": [
        {"id": "CVE-2019-16097", "desc": "unauthenticated admin "
         "privilege escalation via /api/users", "min": "1.7.0",
         "max": "1.8.2"},
    ]},
    {"product": "kubernetes", "aliases": ["kubernetes", "kube"], "cves": [
        {"id": "CVE-2018-1002105", "desc": "aggregated API server "
         "backend TLS escalation", "min": "1.0", "max": "1.13.0"},
    ]},
    {"product": "docker", "aliases": ["docker"], "cves": [
        {"id": "CVE-2019-5736", "desc": "runc container escape via "
         "overwritten host binary", "min": "1.0", "max": "18.09.2"},
    ]},
    {"product": "nuxt", "aliases": ["nuxt"], "cves": [
        {"id": "CVE-2023-3224", "desc": "dev-mode route SSRF/file "
         "disclosure (dev servers)", "min": "2.0", "max": "2.16.0"},
    ]},
    {"product": "webpack", "aliases": ["webpack"], "cves": [
        {"id": "CVE-2020-7310", "desc": "dev-server source exposure "
         "misconfig (webpack-dev-server lines)", "min": "3.0",
         "max": "3.1.13"},
    ]},
    {"product": "goahead", "aliases": ["goahead"], "cves": [
        {"id": "CVE-2021-42342", "desc": "CGI env LD_PRELOAD RCE "
         "(pre-5.1.4)", "min": "5.0.0", "max": "5.1.3"},
    ]},
    {"product": "cherokee", "aliases": ["cherokee"], "cves": [
        {"id": "CVE-2020-12859", "desc": "handler error DoS in "
         "1.2 line", "min": "1.2", "max": "1.2.5"},
    ]},
    {"product": "nagios", "aliases": ["nagios"], "cves": [
        {"id": "CVE-2016-9565", "desc": "command injection via "
         "magpierss in Nagios Core web UI (fixed 4.2.2)",
         "min": "4.0", "max": "4.2.1"},
    ]},
    {"product": "supervisord", "aliases": ["supervisord", "supervisor"],
     "cves": [
        {"id": "CVE-2017-11610", "desc": "XML-RPC auth bypass -> "
         "arbitrary command execution (fixed 3.3.3/3.4.0)",
         "min": "3.0", "max": "3.3.2"},
    ]},
]

_HIGH_IDS = {"CVE-2021-41773", "CVE-2021-42013", "CVE-2021-44228",
             "CVE-2022-26134", "CVE-2019-6340", "CVE-2018-7600",
             "CVE-2019-0211", "CVE-2019-0193", "CVE-2017-5638",
             "CVE-2022-22965", "CVE-2019-15107", "CVE-2018-1002105"}


def parse_version(text):
    """Extract the first dotted version-looking string, or None."""
    if not text:
        return None
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){1,3}(?:[.\d]{0,10}))\b",
                  str(text))
    if not m:
        return None
    return m.group(1).rstrip(".")


def _vtup(v):
    return tuple(int(x) for x in re.findall(r"\d+", v))


def _version_in_range(v, lo, hi):
    t = _vtup(v)
    return _vtup(lo) <= t <= _vtup(hi)


def _product_for(tech_name):
    low = str(tech_name).lower()
    for entry in CVE_DB:
        for alias in entry["aliases"]:
            if alias in low:
                return entry
    return None


def db_audit():
    """Audit the bundled DB: returns (entries, cve_count, problems)."""
    problems = []
    ids = set()
    n_cves = 0
    for entry in CVE_DB:
        if not entry.get("aliases"):
            problems.append("entry %r has no aliases" % entry.get("product"))
        for c in entry.get("cves", []):
            n_cves += 1
            for key in ("id", "desc", "min", "max"):
                if not c.get(key):
                    problems.append("entry %s: CVE missing %s"
                                    % (entry["product"], key))
            if not re.match(r"^CVE-\d{4}-\d{4,}$", c.get("id", "")):
                problems.append("entry %s: bad CVE id %r"
                                % (entry["product"], c.get("id")))
            if c["id"] in ids:
                problems.append("duplicate CVE id %s" % c["id"])
            ids.add(c["id"])
            if not _version_in_range(c["min"], c["min"], c["max"]):
                problems.append("entry %s: min %s outside range"
                                % (entry["product"], c["min"]))
    return len(CVE_DB), n_cves, problems


def correlate(fingerprints):
    """Correlate fingerprints against the offline CVE mini-DB.

    ``fingerprints`` accepts:
      * list of strings ("Apache/2.4.49", "nginx/1.18.0")
      * list of dicts ({"product": ..., "version": ...}) — the
        surface.techs / http_fingerprint / whatweb shape.
    Returns {findings: [...], skipped: {tech: reason}}.
    """
    out = {"findings": [], "skipped": {}}
    for fp in fingerprints or []:
        if isinstance(fp, dict):
            product = str(fp.get("product") or fp.get("name") or
                          fp.get("tech") or "")
            version = fp.get("version") or fp.get("ver")
        else:
            product = str(fp)
            version = None
        if not product or product == "None":
            continue
        entry = _product_for(product)
        if entry is None:
            continue
        parsed = parse_version(version) if version else parse_version(product)
        if not parsed:
            out["skipped"][product] = "no version"
            continue
        for c in entry["cves"]:
            if _version_in_range(parsed, c["min"], c["max"]):
                high = c["id"] in _HIGH_IDS
                out["findings"].append(Finding(
                    title="%s %s matches %s (%s)" % (
                        entry["product"], parsed, c["id"],
                        "EOL/affected range" if not high
                        else "known-critical range"),
                    severity="high" if high else "info",
                    confidence="low",
                    verification="candidate",
                    verification_note=(
                        "OFFLINE correlation only: bundled mini-DB entry "
                        "%s covers %s %s..%s and the exact parsed version "
                        "%s falls inside it. Candidate: banner versions "
                        "can be spoofed; manual confirmation required. "
                        "No network call was made." % (
                            c["id"], entry["product"], c["min"], c["max"],
                            parsed)),
                    manual_check="verify live version: curl -sI "
                                 "<target> | grep -i server",
                    location=product,
                    evidence={"product": entry["product"],
                              "parsed_version": parsed,
                              "cve": c["id"],
                              "why": "%s affects %s..%s; %s in range"
                                     % (c["id"], c["min"], c["max"], parsed),
                              "description": c["desc"]},
                    source="omega-cve/xref"))
    return out
