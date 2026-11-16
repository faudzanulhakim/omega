"""omega/subperm.py — DNS subdomain permutation & zone intelligence.

Pure-stdlib DNS reconnaissance, no external APIs:

  - Built-in wordlist (~80 common prefixes) permuted against the target
    domain; each candidate resolved with a bounded ThreadPoolExecutor
    (max 20 workers, 2s per-host timeout via socket.setdefaulttimeout
    save/restore, 0.05s sleep between batches, hard cap of 100 lookups
    per run).
  - Wildcard FP guard: a random high-entropy probe subdomain
    (``omega-<32hex>.target``) is resolved first; if IT resolves, every
    positive result is tagged ``wildcard_noise=True`` and kept at
    verification 'info' — no candidate LOW findings are derived from
    wildcard-noise hosts.
  - Private-range IPs (RFC1918/loopback/link-local/::1/fc00::/7) on
    resolvable subdomains -> candidate LOW "internal host resolvable
    from public DNS".
  - Zone-apex dump (A/AAAA via getaddrinfo; MX/NS/TXT via a minimal
    raw-UDP DNS client reading /etc/resolv.conf — stdlib only). TXT is
    parsed for SPF/DMARC/DKIM presence (INFO); missing DMARC -> LOW
    candidate.
  - Alive-subdomain inventory as an INFO finding.

The resolver is injectable (module-level ``_resolve``) so tests run
hermetically with an in-memory fake — no real DNS. run_subperm never
raises; resolver failures degrade into result['skipped'].
"""

from __future__ import annotations

import ipaddress
import os
import random
import socket
import struct
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

__all__ = [
    "WORDLIST",
    "PRIVATE_NETS",
    "run_subperm",
]

WORDLIST = [
    "www", "mail", "ftp", "admin", "dev", "staging", "test", "vpn", "api",
    "app", "portal", "intranet", "git", "jenkins", "ci", "cd", "db", "mysql",
    "postgres", "redis", "cache", "elastic", "kibana", "grafana",
    "prometheus", "monitor", "nagios", "zabbix", "backup", "old", "new",
    "beta", "alpha", "demo", "lab", "sandbox", "uat", "qa", "preprod",
    "prod", "internal", "corp", "sso", "auth", "oauth", "login", "id",
    "cdn", "static", "media", "img", "assets", "docs", "wiki", "help",
    "support", "status", "blog", "shop", "store", "pay", "billing", "api2",
    "gateway", "proxy", "ns1", "ns2", "mx", "smtp", "pop", "imap",
    "webmail", "remote", "citrix", "terminal", "rdp", "vnc", "cloud",
    "k8s", "docker", "registry",
]

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

MAX_WORKERS = 20
PER_HOST_TIMEOUT = 2.0
LOOKUP_CAP = 100
BATCH_SLEEP = 0.05
EVIDENCE_CAP = 300

_SRC = "omega-subperm"

_sleep = time.sleep
_resolve = None  # injectable; None -> default socket.gethostbyname wrapper
_dns_query = None  # injectable raw DNS query; None -> default UDP client


def _ev(text):
    text = str(text or "").strip().replace("\n", " | ")
    if len(text) > EVIDENCE_CAP:
        text = text[: EVIDENCE_CAP - 3] + "..."
    return text


def _finding(title, severity, note, manual_check, location, evidence,
             confidence="medium"):
    return {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "verification": "candidate",
        "verification_note": note,
        "manual_check": manual_check,
        "location": location,
        "evidence": _ev(evidence),
        "source": _SRC,
    }


def _info_finding(title, note, manual_check, location, evidence):
    f = _finding(title, "info", note, manual_check, location, evidence)
    f["verification"] = "info"
    return f


def _default_resolve(name):
    """Default per-host resolver with a 2s timeout (save/restore)."""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(PER_HOST_TIMEOUT)
        return socket.gethostbyname(name)
    finally:
        socket.setdefaulttimeout(old)


def _do_resolve(name):
    fn = _resolve if _resolve is not None else _default_resolve
    return fn(name)


def is_private_ip(ip_text):
    try:
        addr = ipaddress.ip_address(ip_text.strip())
    except ValueError:
        return False
    return any(addr in net for net in PRIVATE_NETS)


# ---------------------------------------------------------------------------
# Minimal raw-UDP DNS client (stdlib only) for MX/NS/TXT.
# ---------------------------------------------------------------------------

_QTYPES = {"A": 1, "NS": 2, "MX": 15, "TXT": 16}


def _nameservers():
    servers = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    if not servers:
        servers = ["8.8.8.8", "1.1.1.1"]
    return servers


def _read_name(data, off):
    """Parse a (possibly compressed) DNS name; returns (name, next_offset)."""
    labels = []
    end = None
    jumps = 0
    while True:
        if off >= len(data):
            break
        length = data[off]
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if end is None:
                end = off + 2
            off = ptr
            jumps += 1
            if jumps > 32:
                break
            continue
        off += 1
        if length == 0:
            if end is None:
                end = off
            break
        labels.append(data[off:off + length].decode("latin1"))
        off += length
    return ".".join(labels), (end if end is not None else off)


def _default_dns_query(name, qtype_str, timeout=2.0):
    """Send one raw UDP DNS query; returns list of answer strings."""
    qtype = _QTYPES[qtype_str]
    query = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii", "replace")[:63]
        query += bytes([len(raw)]) + raw
    query += b"\x00" + struct.pack(">HH", qtype, 1)
    for server in _nameservers():
        data = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(query, (server, 53))
            data, _ = sock.recvfrom(4096)
            sock.close()
        except OSError:
            continue
        if data is None or len(data) < 12:
            continue
        rcode = data[3] & 0x0F
        ancount = struct.unpack(">H", data[6:8])[0]
        if rcode != 0:
            return []
        off = 12
        _read_name(data, off)  # question name
        _qname, off = _read_name(data, off)
        off += 4
        answers = []
        for _ in range(ancount):
            if off >= len(data):
                break
            _aname, off = _read_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rd = data[off:off + rdlen]
            if rtype == 1 and rdlen == 4:
                answers.append(socket.inet_ntoa(rd))
            elif rtype == 2:
                answers.append(_read_name(data, off)[0])
            elif rtype == 15 and rdlen >= 3:
                pref = struct.unpack(">H", rd[:2])[0]
                answers.append("%d %s" % (pref, _read_name(data, off + 2)[0]))
            elif rtype == 16:
                parts = []
                i = 0
                while i < len(rd):
                    ln = rd[i]
                    parts.append(rd[i + 1:i + 1 + ln].decode("latin1"))
                    i += 1 + ln
                answers.append("".join(parts))
            off += rdlen
        return answers
    return []


def _do_dns_query(name, qtype_str):
    fn = _dns_query if _dns_query is not None else _default_dns_query
    return fn(name, qtype_str)


# ---------------------------------------------------------------------------
# Entry point — never raises.
# ---------------------------------------------------------------------------

def run_subperm(target, extra=None, log=None):
    """Subdomain permutation + zone intelligence. Never raises."""
    result = {
        "findings": [],
        "skipped": {},
        "requests_sent": 0,
        "ran": ["subperm"],
        "alive": [],
    }
    try:
        if not target:
            result["skipped"]["subperm"] = "no target"
            return result
        target = target.strip().rstrip(".")
        if "://" in target:
            target = urllib.parse.urlparse(target).netloc.split("@")[-1]
        if not target or "/" in target:
            result["skipped"]["subperm"] = "invalid target domain"
            return result

        words = list(WORDLIST)
        for w in extra or []:
            w = str(w).strip()
            if w and w not in words:
                words.append(w)

        # --- Wildcard FP guard: high-entropy probe first -------------------
        probe_label = "omega-%032x" % random.getrandbits(128)
        probe_name = "%s.%s" % (probe_label, target)
        wildcard = False
        try:
            probe_ip = _do_resolve(probe_name)
            result["requests_sent"] += 1
            wildcard = bool(probe_ip)
        except Exception as exc:
            result["requests_sent"] += 1
            if log:
                log("subperm: wildcard probe failed: %s" % exc)
            result["skipped"]["wildcard_probe"] = "resolver error: %s" % exc
        if wildcard and log:
            log("subperm: wildcard DNS detected on %s" % target)

        # --- Permuted candidate resolution ---------------------------------
        budget = LOOKUP_CAP - result["requests_sent"]
        budget = max(0, min(budget, len(words)))
        candidates = ["%s.%s" % (w, target) for w in words[:budget]]
        alive = []
        errors = 0
        batch = MAX_WORKERS
        for i in range(0, len(candidates), batch):
            chunk = candidates[i:i + batch]
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                futures = {pool.submit(_do_resolve, c): c for c in chunk}
                for fut, cand in futures.items():
                    result["requests_sent"] += 1
                    try:
                        ip = fut.result()
                    except Exception:
                        errors += 1
                        continue
                    if ip:
                        alive.append({"subdomain": cand, "ip": str(ip),
                                      "wildcard_noise": wildcard})
            if i + batch < len(candidates):
                _sleep(BATCH_SLEEP)
        if errors and errors == len(candidates) and not alive:
            result["skipped"]["subperm"] = (
                "all %d lookups failed with resolver errors" % errors)
        result["alive"] = alive

        # --- Findings -------------------------------------------------------
        if alive:
            shown = ["%s -> %s%s" % (
                a["subdomain"], a["ip"],
                " (wildcard noise)" if a["wildcard_noise"] else "")
                for a in alive[:30]]
            f = _info_finding(
                "Resolvable subdomains (%d found)" % len(alive),
                "DNS inventory of permuted common subdomains.",
                "dig +short %s   # spot-check each alive subdomain" % alive[0]["subdomain"],
                "DNS resolution",
                "; ".join(shown),
            )
            if wildcard:
                # Wildcard noise: everything "resolves" — do not score it.
                f["verification_note"] = (
                    "Wildcard DNS detected: every positive may be wildcard "
                    "synthesis; treat as unverified inventory only.")
            result["findings"].append(f)

        if wildcard:
            result["findings"].append(_finding(
                "Wildcard DNS detected on %s" % target,
                "low",
                "A high-entropy random subdomain resolved, so ANY name "
                "under this domain resolves; every positive subdomain "
                "result is likely wildcard synthesis (FP guard engaged).",
                "dig +short %s   # random name; resolves = wildcard" % probe_name,
                "DNS zone %s" % target,
                "probe %s resolved to %s" % (probe_name, probe_ip),
            ))
        else:
            # Private-range IPs are only meaningful when not wildcard noise.
            private_hosts = [
                a for a in alive
                if not a["wildcard_noise"] and is_private_ip(a["ip"])
            ]
            for host in private_hosts[:10]:
                result["findings"].append(_finding(
                    "Internal host resolvable from public DNS: %s" % host["subdomain"],
                    "low",
                    "Subdomain resolves to a private-range IP (%s); "
                    "internal naming/topology leaked via public DNS."
                    % host["ip"],
                    "dig +short %s && ip route get <ip>   # confirm "
                    "private range" % host["subdomain"],
                    "DNS zone %s" % target,
                    "%s -> %s" % (host["subdomain"], host["ip"]),
                ))

        # --- Zone-apex dump (stdlib only) -----------------------------------
        if LOOKUP_CAP - result["requests_sent"] >= 2:
            zone = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}
            try:
                infos = socket.getaddrinfo(target, None, socket.AF_INET)
                zone["A"] = sorted({i[4][0] for i in infos})
            except Exception:
                pass
            result["requests_sent"] += 1
            try:
                infos6 = socket.getaddrinfo(target, None, socket.AF_INET6)
                zone["AAAA"] = sorted({i[4][0] for i in infos6})
            except Exception:
                pass
            result["requests_sent"] += 1
            for qtype in ("MX", "NS", "TXT"):
                if result["requests_sent"] >= LOOKUP_CAP:
                    break
                try:
                    zone[qtype] = _do_dns_query(target, qtype)
                except Exception as exc:
                    result["skipped"]["zone_%s" % qtype] = "resolver error: %s" % exc
                result["requests_sent"] += 1

            txt_join = " | ".join(zone["TXT"])
            has_spf = any(r.lower().startswith("v=spf1") for r in zone["TXT"])
            # DMARC/DKIM live under dedicated labels (do not consume wordlist
            # budget; two extra lookups outside the per-run cap accounting).
            try:
                dmarc = _do_dns_query("_dmarc.%s" % target, "TXT")
            except Exception:
                dmarc = []
            try:
                dkim = _do_dns_query("default._domainkey.%s" % target, "TXT")
            except Exception:
                dkim = []
            has_dmarc = any("v=DMARC1" in r for r in dmarc)
            has_dkim = bool(dkim)

            zone_summary = []
            if zone["A"]:
                zone_summary.append("A: %s" % ", ".join(zone["A"][:5]))
            if zone["AAAA"]:
                zone_summary.append("AAAA: %s" % ", ".join(zone["AAAA"][:3]))
            if zone["MX"]:
                zone_summary.append("MX: %s" % "; ".join(zone["MX"][:5]))
            if zone["NS"]:
                zone_summary.append("NS: %s" % "; ".join(zone["NS"][:5]))
            if zone["TXT"]:
                zone_summary.append("TXT: %s" % _ev(txt_join))
            result["findings"].append(_info_finding(
                "Zone apex DNS dump for %s" % target,
                "A/AAAA/MX/NS/TXT inventory of the zone apex (stdlib DNS only).",
                "dig +short A %s ; dig +short MX %s ; dig +short NS %s ; "
                "dig +short TXT %s" % (target, target, target, target),
                "zone apex %s" % target,
                " ; ".join(zone_summary) or "no answers",
            ))
            result["findings"].append(_info_finding(
                "Email security records for %s" % target,
                "Presence of SPF/DMARC/DKIM in TXT records.",
                "dig +short TXT %s ; dig +short TXT _dmarc.%s ; "
                "dig +short TXT default._domainkey.%s" % (target, target, target),
                "zone apex %s" % target,
                "SPF: %s | DMARC: %s | DKIM: %s"
                % (has_spf, has_dmarc, has_dkim),
            ))
            if not has_dmarc:
                result["findings"].append(_finding(
                    "No DMARC record for %s" % target,
                    "low",
                    "_dmarc.%s has no v=DMARC1 TXT record; spoofed-mail "
                    "policy is unenforced." % target,
                    "dig +short TXT _dmarc.%s   # empty = no DMARC" % target,
                    "zone apex %s" % target,
                    "no v=DMARC1 record found at _dmarc.%s" % target,
                ))
            if not wildcard:
                private_apex = [a for a in zone["A"] if is_private_ip(a)]
                for ip in private_apex[:5]:
                    result["findings"].append(_finding(
                        "Zone apex %s resolves to a private IP" % target,
                        "low",
                        "Apex A record is private-range (%s): internal "
                        "host exposed via public DNS." % ip,
                        "dig +short A %s" % target,
                        "zone apex %s" % target,
                        "%s -> %s" % (target, ip),
                    ))
    except Exception as exc:  # containment: run_* never raises
        result["skipped"]["subperm"] = "error: %s" % exc
    return result
