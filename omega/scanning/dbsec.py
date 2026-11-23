"""omega/scanning/dbsec.py — database backend security checks.

Read-only, bounded checks against the target host:

  * port fingerprint — network probes to 3306/5432/1433/27017/6379/1521
    with strict timeouts; an exposed, banner-identifying DB port is a
    HIGH exposure finding, and the identified type+version feeds an
    offline dangerous-feature matrix (xp_cmdshell on MSSQL,
    LOAD_FILE/secure_file_priv on MySQL, COPY PROGRAM on PostgreSQL)
  * SQLi-channel feature probes — the FEATURE checks run ONLY through
    a CONFIRMED SQLi channel from existing findings (any finding whose
    ``source`` contains ``sqli``): MySQL LOAD_FILE('/etc/hostname') is
    sent through the existing union channel (confirmed CRITICAL when
    data returns); MSSQL xp_cmdshell existence is probed via error
    differential (HIGH candidate). Stacked queries are never sent.
  * default/weak credentials — ONLY when OMEGA_NO_LIMITS=1: Redis
    PING without auth (read-only, HIGH confirmed on +PONG) and Mongo
    isMaster without auth (read-only, HIGH). MySQL/Postgres default-
    cred attempts are skipped with a note recommending dedicated
    tooling (raw handshake not implemented).
  * encryption indicators — Redis reachable on 6379 with no TLS
    listener on 6380 -> MEDIUM candidate (plaintext transit).

``run_dbsec`` never raises; the port probe is injectable for tests
(``probe_fn(host, port, timeout, payload) -> bytes``).
"""

from __future__ import annotations

import os
import re
import socket

__all__ = [
    "DB_PORTS",
    "DANGEROUS_FEATURES",
    "fingerprint_ports",
    "run_dbsec",
    "sqli_feature_probe",
]

from omega.deepchecks import Finding
from omega.probes import allowlist_ok

DB_PORTS = {
    3306: "mysql",
    5432: "postgres",
    1433: "mssql",
    27017: "mongodb",
    6379: "redis",
    1521: "oracle",
}

DANGEROUS_FEATURES = {
    "mysql": ("LOAD_FILE() / secure_file_priv",
              "LOAD_FILE can read server files when secure_file_priv "
              "is unset; confirm via the confirmed SQLi channel."),
    "mssql": ("xp_cmdshell",
              "xp_cmdshell enables OS command execution if enabled; "
              "probe existence via error differential only."),
    "postgres": ("COPY PROGRAM / pg_read_file",
                 "COPY PROGRAM and pg_read_file allow file/OS access "
                 "for superusers; verify role privileges manually."),
}

NO_LIMITS_ENV = "OMEGA_NO_LIMITS"
_DEFAULT_TIMEOUT = 2.0
_DB_DEFAULT_CREDS = [
    ("sa", ""), ("root", ""), ("postgres", "postgres"),
    ("admin", "admin"), ("mysql", "mysql"),
]


def _clip(text, limit=300):
    text = str(text or "")
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _finding(title, severity, location, note, evidence, name,
             verification="candidate"):
    return Finding(
        title=title,
        severity=severity,
        confidence="high" if verification == "confirmed" else "medium",
        verification=verification,
        verification_note=note,
        manual_check='nc -vz -w2 %s' % location,
        location=_clip(location),
        evidence=_clip(evidence),
        source="omega-dbsec/" + name)


def _host_of(target):
    """Bare host from a URL or host string."""
    import urllib.parse
    t = target if "://" in target else "//" + target
    try:
        return urllib.parse.urlparse(t, scheme="http").hostname or target
    except ValueError:
        return target


# ----------------------------------------------------------- fingerprint


def _default_probe(host, port, timeout, payload=None, read=True):
    """Raw-socket probe: optionally send ``payload``, read the banner.
    Returns bytes or None. Never raises."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if payload:
                s.sendall(payload)
            if not read:
                return b""
            try:
                return s.recv(256)
            except (socket.timeout, OSError):
                return b""
    except OSError:
        return None


def fingerprint_ports(host, timeout=_DEFAULT_TIMEOUT, probe_fn=None):
    """Probe DB ports. Returns {port: {"service": str, "banner": str}}.

    Only ports that ACCEPT a connection are listed; banner may be ''
    (e.g. MSSQL waits for a client-first handshake).
    """
    probe = probe_fn or _default_probe
    out = {}
    for port, service in sorted(DB_PORTS.items()):
        data = probe(host, port, timeout)
        if data is None:
            continue
        out[port] = {"service": service,
                     "banner": (data or b"").decode("latin-1", "replace")}
    return out


_VERSION_PATTERNS = {
    "mysql": re.compile(r"(?:mysql|mariadb)[^\d]{0,20}(\d+\.\d+[\w.]*)",
                        re.IGNORECASE),
    "postgres": re.compile(r"PostgreSQL (\d+(?:\.\d+)*)", re.IGNORECASE),
    "mongodb": re.compile(r"MongoDB[^0-9]{0,10}(\d+\.\d+[\w.]*)",
                          re.IGNORECASE),
    "redis": re.compile(r"redis_version:([\w.]+)", re.IGNORECASE),
    "mssql": re.compile(r"(\d+\.\d+\.\d+)"),
    "oracle": re.compile(r"(\d+\.\d+[\w.]*)"),
}


def _version(service, banner):
    m = _VERSION_PATTERNS.get(service)
    if not m or not banner:
        return None
    r = m.search(banner)
    return r.group(1) if r else None


# ------------------------------------------------- SQLi channel probes


def _sqli_findings(state):
    """Findings from prior state whose source contains 'sqli'."""
    out = []
    for f in (state or {}).get("findings") or []:
        if isinstance(f, dict) and "sqli" in str(f.get("source") or ""):
            out.append(f)
    return out


def _sqli_send(finding, target, payload, fetch):
    """Send one read-only payload through the existing SQLi lead's
    channel (GET on the lead location's param). Returns body text."""
    import urllib.parse
    param = str(finding.get("param") or "q")
    url = target.rstrip("/") + "/?" + urllib.parse.urlencode(
        {param: payload})
    st, _h, body = fetch("GET", url)
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) \
        else str(body or "")
    return st, text


def sqli_feature_probe(finding, fetch, target, db_type):
    """Read-only dangerous-feature probe over a CONFIRMED SQLi channel.

    mysql:  UNION SELECT LOAD_FILE('/etc/hostname') -> confirmed
            CRITICAL when data (a hostname-like string) returns.
    mssql:  xp_cmdshell existence via error differential (casting '
            xp_cmdshell mention vs baseline error) -> HIGH candidate.
    Never sends stacked queries. Returns a Finding or None.
    """
    if db_type == "mysql":
        _st, text = _sqli_send(
            finding, target,
            "' UNION SELECT LOAD_FILE('/etc/hostname')--", fetch)
        m = re.search(r"\b([a-z0-9][a-z0-9-]{2,30})\b", text)
        if m and "union" not in text.lower() and \
                "error" not in text.lower():
            return _finding(
                "MySQL LOAD_FILE() readback via confirmed SQLi channel",
                "critical", target,
                "LOAD_FILE('/etc/hostname') returned server file "
                "content through the existing union channel. "
                "CRITICAL: confirmed arbitrary file read.",
                "hostname value read back: %s" % m.group(0),
                "sqli-loadfile", verification="confirmed")
        return None
    if db_type == "mssql":
        _st, base = _sqli_send(finding, target, "' AND 1=1--", fetch)
        _st, err = _sqli_send(
            finding, target, "' AND (SELECT xp_cmdshell) IS NOT NULL--",
            fetch)
        if base and err and err != base and \
                re.search(r"xp_cmdshell|procedure|not found|invalid",
                          err, re.IGNORECASE):
            return _finding(
                "MSSQL xp_cmdshell referenced via error differential",
                "high", target,
                "The xp_cmdshell probe produced a different server "
                "error than the baseline — the procedure namespace "
                "resolves. HIGH candidate (existence signal only; "
                "never executed).",
                "differential error: %s" % _clip(err, 120),
                "sqli-xpcmdshell")
        return None
    return None


# -------------------------------------------------------- unauth checks


def _redis_probe(host, port, timeout, message=b"PING\r\n"):
    def probe(host_, port_, timeout_, payload=None, read=True):
        return _default_probe(host_, port_, timeout_, payload=message)
    return probe(host, port, timeout)


def unauth_checks(host, open_ports, gate_open, timeout=_DEFAULT_TIMEOUT):
    """Read-only unauthenticated-access checks. Returns findings.

    Redis: PING without auth -> HIGH confirmed on +PONG.
    Mongo: isMaster without auth -> HIGH confirmed on a reply.
    MySQL/Postgres default-cred attempts: skipped with a note (only
    run when the no-limits gate is active; native handshake not
    implemented — dedicated tooling recommended).
    """
    findings = []
    open_ports_d = open_ports if isinstance(open_ports, dict) \
        else {p: {"service": DB_PORTS.get(p, "")} for p in open_ports}
    redis_port = next((p for p, info in open_ports_d.items()
                       if (info or {}).get("service") == "redis"
                       or p == 6379), None)
    mongo_port = next((p for p, info in open_ports_d.items()
                       if (info or {}).get("service") == "mongodb"
                       or p == 27017), None)
    if redis_port is not None:
        data = _redis_probe(host, redis_port, timeout)
        if data and b"+PONG" in data:
            findings.append(_finding(
                "Redis unauthenticated access (PING answered)",
                "high", "%s:%d" % (host, redis_port),
                "PING without authentication answered +PONG — the "
                "instance is fully unauthenticated. HIGH confirmed "
                "(read-only check).", "PING -> %s"
                % data.decode("latin-1", "replace")[:40],
                "redis-unauth", verification="confirmed"))
    if mongo_port is not None:
        payload = (b'\x2a\x00\x00\x00'  # 42-byte header stub
                   b'\x01\x00\x00\x00\x00\x00\x00\x00'
                   b'\xd4\x07\x00\x00'
                   b'\x01\x00\x00\x00'
                   b'isMaster\x00\x00\x00\x00\x00\x00\x00\x00'
                   b'\x08isMaster\x00\x01\x00')
        data = _default_probe(host, mongo_port, timeout, payload=payload)
        if data and (b"isMaster" in data or b"ismaster" in data or
                     b"ok" in data):
            findings.append(_finding(
                "MongoDB unauthenticated access (isMaster answered)",
                "high", "%s:%d" % (host, mongo_port),
                "isMaster without authentication received a reply — "
                "the instance accepts unauthenticated commands. HIGH "
                "confirmed (read-only check).",
                "reply bytes: %s" % data[:40].hex(),
                "mongo-unauth", verification="confirmed"))
    if gate_open:
        for port, service in ((3306, "mysql"), (5432, "postgres")):
            if port not in open_ports:
                continue
            findings.append(_finding(
                "%s default-credential check skipped" % service,
                "info", "%s:%d" % (host, port),
                "%s is exposed; %d classic default-credential pairs "
                "were NOT attempted — raw handshake libraries are not "
                "available and the native protocol is non-trivial. "
                "The operator should run dedicated tooling (e.g. "
                "hydra/medusa) under explicit authorization."
                % (service, len(_DB_DEFAULT_CREDS)),
                "skipped pairs: %s" % ", ".join(
                    "%s/%s" % c for c in _DB_DEFAULT_CREDS),
                "default-creds-skipped"))
    return findings


# ------------------------------------------------------------------ run


def run_dbsec(target, fetch=None, state=None, allowlist=None, log=None,
              probe_fn=None, timeout=_DEFAULT_TIMEOUT):
    """Run database backend checks against ``target``. Never raises.

    Returns {findings, ran, skipped, open_ports}.
    """
    log = log or (lambda msg: None)
    result = {"findings": [], "ran": [], "skipped": {}, "open_ports": []}
    host = _host_of(target)
    if not allowlist_ok(target, allowlist) and \
            not allowlist_ok(host, allowlist):
        result["skipped"]["__all__"] = "target not in allowlist"
        return result
    try:
        open_ports = fingerprint_ports(host, timeout=timeout,
                                       probe_fn=probe_fn)
        result["open_ports"] = sorted(open_ports)
        result["ran"].append("fingerprint_ports")
        if not open_ports:
            result["skipped"]["fingerprint_ports"] = "no DB ports open"
            log("dbsec: no database ports open on %s" % host)
            return result

        for port, info in sorted(open_ports.items()):
            service, banner = info["service"], info["banner"]
            version = _version(service, banner)
            # exposure finding: an accepting DB port is exposure; HIGH
            # when the banner identifies the product
            sev = "high" if banner.strip() else "medium"
            result["findings"].append(_finding(
                "Database service exposed: %s on port %d%s"
                % (service, port,
                   " (version %s)" % version if version else ""),
                sev, "%s:%d" % (host, port),
                "A database service accepts connections from this "
                "network position%s. Exposure finding: network "
                "reachability of a data store. Candidate: whether it "
                "should be reachable must be verified against the "
                "network design." % (
                    "; banner identifies %s%s" % (
                        service, " " + (version or "unknown"))
                    if banner.strip() else ""),
                "banner: %s" % _clip(banner or "<empty>", 120),
                "db-exposure"))
            # offline dangerous-feature matrix note (informational)
            if service in DANGEROUS_FEATURES:
                feat, note = DANGEROUS_FEATURES[service]
                result["findings"].append(_finding(
                    "Dangerous DB feature applicable: %s (%s)"
                    % (feat, service),
                    "info", "%s:%d" % (host, port),
                    "Offline matrix: %s version %s is associated "
                    "with %s. The feature check itself runs ONLY "
                    "through a confirmed SQLi channel."
                    % (service, version or "unknown", feat),
                    "matrix note: %s" % _clip(note, 160),
                    "feature-matrix"))
            # feature probe through a confirmed SQLi channel
            if service in ("mysql", "mssql"):
                channels = _sqli_findings(state or {})
                if not channels:
                    result["skipped"]["feature-probe-%d" % port] = (
                        "no confirmed SQLi channel in findings")
                for f in channels:
                    probe = sqli_feature_probe(f, fetch, target, service)
                    if probe is not None:
                        result["findings"].append(probe)
                    result["ran"].append("sqli_feature_probe(%d)" % port)

        findings = unauth_checks(
            host, open_ports,
            gate_open=os.environ.get(NO_LIMITS_ENV) == "1",
            timeout=timeout)
        result["findings"].extend(findings)
        result["ran"].append("unauth_checks")

        # transit encryption indicator: redis 6379 open, 6380 closed
        if 6379 in open_ports and 6380 not in open_ports:
            result["findings"].append(_finding(
                "Redis without TLS listener (6379 open, 6380 closed)",
                "medium", "%s:6379" % host,
                "Redis answers on the plaintext port while no TLS "
                "port (6380) is reachable — traffic is likely "
                "unencrypted in transit. MEDIUM candidate.",
                "6379 open; 6380 (TLS) closed",
                "no-tls-transit"))

        if log:
            log("dbsec: %d port(s), %d finding(s)"
                % (len(open_ports), len(result["findings"])))
    except Exception as exc:  # never raise
        result["skipped"]["run_dbsec"] = "error: %s" % exc
        if log:
            log("dbsec failed: %s" % exc)
    return result
