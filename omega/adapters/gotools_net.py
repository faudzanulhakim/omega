"""omega/adapters/gotools_net — Python runners for the Go network
microtools (portsweep, subhunt, tlsprobe, smuggler, udpsweep, swarm,
sniffy, fuzzwave).

Pattern: identical to gotools.py — polyglot gate, compile-on-demand,
JSON stdin/stdout, candidate-grade findings with manual_check, never
raises. Pure-python fallbacks live in omega/adapters/pyfallback.py.
"""
import os

from omega.adapters.gotools import (
    GATE_KEY, _finding, _result, _slug, _run_tool_json, _gate_open,
    _build_tool,
)
from omega.adapters import native

NEW_TOOLS = ("portsweep", "subhunt", "tlsprobe", "smuggler", "udpsweep",
             "swarm", "sniffy", "fuzzwave", "techprof", "jsmine",
             "diffscan", "gqlprobe", "racewin", "spprobe")


def _prepare(tool, gate_open_fn=None, log=None):
    """Gate + build; returns (binary, None) or (None, skip_result)."""
    if not _gate_open(gate_open_fn):
        return None, _result(skipped={GATE_KEY:
                                      "polyglot gate closed (PTK_POLYGLOT)"})
    if not os.environ.get("_GOTL_SHUTTLE"):
        import shutil
        if not shutil.which("go"):
            return None, _result(skipped={GATE_KEY:
                                          "go toolchain unavailable"},
                                 requests_sent=0)
    try:
        native.ensure_native(native.DEFAULT_CACHE_DIR, log=log)
        binary = _build_tool(tool, native.DEFAULT_CACHE_DIR, log=log)
        return binary, None
    except Exception as e:
        return None, _result(skipped={GATE_KEY: f"{tool} build failed: {e}"})


def run_portsweep(host, ports=None, timeout_ms=1500, log=None,
                  gate_open_fn=None):
    """Concurrent TCP port sweep + service fingerprint (Go core)."""
    binary, skip = _prepare("portsweep", gate_open_fn, log)
    if skip:
        return skip
    data, err = _run_tool_json(
        binary, {"host": host, "ports": list(ports or []),
                 "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"portsweep: {err}"})
    findings = []
    open_ports = data.get("open") or []
    for r in open_ports:
        port, svc = r.get("port"), r.get("service")
        banner = (r.get("banner") or "")[:200]
        sev = "LOW" if port in (22, 53, 443) else "MEDIUM"
        findings.append(_finding(
            f"open port {port} ({svc})", sev,
            f"go-portsweep/{port}",
            f"TCP connect succeeded to {host}:{port} in {r.get('ms')}ms; "
            f"banner: {banner!r}",
            f"{host}:{port}",
            f"nmap -sV -p {port} {host}"))
    if log:
        log(f"gotools: portsweep {host} open={len(open_ports)}")
    return _result(findings=findings, requests_sent=len(open_ports),
                   ran=["portsweep"], surface={"portsweep": open_ports})


def run_subhunt(domain, words=None, target=None, do_ct=False, log=None,
                gate_open_fn=None):
    """Subdomain + vhost enumeration (Go core, wildcard-safe)."""
    binary, skip = _prepare("subhunt", gate_open_fn, log)
    if skip:
        return skip
    data, err = _run_tool_json(
        binary, {"domain": domain, "words": list(words or []),
                 "target": target or "", "do_ct": bool(do_ct)}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"subhunt: {err}"})
    findings = []
    for h in data.get("dns") or []:
        findings.append(_finding(
            f"subdomain resolves: {h.get('host')}", "LOW",
            f"go-subhunt/dns-{_slug(h.get('host') or '')}",
            f"DNS lookup {h.get('host')} -> {h.get('ip')}",
            h.get("host"),
            f"dig +short {h.get('host')}"))
    for h in data.get("vhost") or []:
        findings.append(_finding(
            f"virtual host responds: {h.get('host')}", "LOW",
            f"go-subhunt/vhost-{_slug(h.get('host') or '')}",
            f"Host-header probe {h.get('host')} -> HTTP "
            f"{h.get('status')}, {h.get('size')}B (differs from "
            f"wildcard baseline)",
            f"{target} (Host: {h.get('host')})",
            f"curl -s -H 'Host: {h.get('host')}' {target}/ -o /dev/null"
            f" -w '%{{http_code}}'"))
    n = len(data.get("dns") or []) + len(data.get("vhost") or [])
    if log:
        log(f"gotools: subhunt {domain} hits={n}")
    return _result(findings=findings, requests_sent=n, ran=["subhunt"],
                   surface={"subhunt": data})


def run_tlsprobe(host, port=443, timeout_ms=5000, log=None,
                 gate_open_fn=None):
    """TLS configuration audit (Go core): versions, ciphers, cert."""
    binary, skip = _prepare("tlsprobe", gate_open_fn, log)
    if skip:
        return skip
    data, err = _run_tool_json(
        binary, {"host": host, "port": port, "timeout_ms": timeout_ms},
        log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"tlsprobe: {err}"})
    findings = []
    weak = data.get("weak") or {}
    versions = data.get("versions") or {}
    legacy = [v for v in ("ssl3.0", "tls1.0", "tls1.1")
              if versions.get(v)]
    if legacy:
        findings.append(_finding(
            f"legacy TLS versions enabled: {', '.join(legacy)}", "MEDIUM",
            f"go-tlsprobe/legacy-version",
            f"Handshake succeeded with {', '.join(legacy)} on "
            f"{host}:{port}", f"{host}:{port}",
            f"openssl s_client -{legacy[0].replace('.', '')} -connect "
            f"{host}:{port}"))
    for cipher, why in weak.items():
        if why == "legacy-version-supported":
            continue
        findings.append(_finding(
            f"weak cipher suite accepted: {cipher}", "MEDIUM",
            f"go-tlsprobe/cipher",
            f"Handshake succeeded with {cipher} ({why}) on "
            f"{host}:{port}", f"{host}:{port}",
            f"openssl s_client -cipher {cipher} -connect {host}:{port}"))
    cert = data.get("cert") or {}
    if cert.get("expired"):
        findings.append(_finding(
            "TLS certificate expired", "MEDIUM", "go-tlsprobe/cert",
            f"not_after={cert.get('not_after')} on {host}:{port}",
            f"{host}:{port}", "openssl s_client -connect "
            f"{host}:{port} | openssl x509 -noout -dates"))
    elif isinstance(cert.get("days_left"), int) and cert["days_left"] < 30:
        findings.append(_finding(
            f"TLS certificate expiring soon "
            f"({cert['days_left']} days)", "LOW", "go-tlsprobe/cert",
            f"not_after={cert.get('not_after')}", f"{host}:{port}",
            "openssl x509 -noout -dates"))
    if cert and not cert.get("hostname_ok", True):
        findings.append(_finding(
            "TLS certificate hostname mismatch", "MEDIUM",
            "go-tlsprobe/cert",
            f"cert does not cover {host}; SAN={cert.get('san')}",
            f"{host}:{port}", "openssl x509 -noout -text"))
    if log:
        log(f"gotools: tlsprobe {host}:{port} "
            f"weak={len(weak)} findings={len(findings)}")
    return _result(findings=findings, requests_sent=len(versions) + 1,
                   ran=["tlsprobe"], surface={"tlsprobe": data})


def run_smuggler(target, timeout_ms=4000, log=None, gate_open_fn=None):
    """HTTP request smuggling detection (Go core, raw byte-level)."""
    binary, skip = _prepare("smuggler", gate_open_fn, log)
    if skip:
        return skip
    data, err = _run_tool_json(
        binary, {"target": target, "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"smuggler: {err}"})
    findings = []
    if not data.get("control_ok"):
        # control failed: the differential is meaningless — no finding
        if log:
            log("gotools: smuggler control failed — results suppressed")
        return _result(ran=["smuggler"],
                       surface={"smuggler": {"control_ok": False,
                                             "suppressed": True}})
    for s in data.get("smuggled") or []:
        findings.append(_finding(
            f"HTTP request smuggling differential: {s.get('technique')}",
            "HIGH", f"go-smuggler/{_slug(s.get('technique') or '')}",
            f"Poison probe ({s.get('technique')}) desynchronized the "
            f"front-end/back-end pair ({s.get('evidence')}) on "
            f"{target}; control pair healthy", target,
            "reproduce manually with a raw netcat pair; confirm with a "
            "second benign request AFTER the poison probe"))
    if log:
        log(f"gotools: smuggler {target} findings={len(findings)}")
    return _result(findings=findings, requests_sent=6, ran=["smuggler"],
                   surface={"smuggler": data})


def run_udpsweep(host, ports=None, timeout_ms=1500, log=None,
                 gate_open_fn=None):
    """UDP service discovery (Go core): DNS/SNMP/NTP/memcached/SSDP."""
    binary, skip = _prepare("udpsweep", gate_open_fn, log)
    if skip:
        return skip
    data, err = _run_tool_json(
        binary, {"host": host, "ports": list(ports or []),
                 "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"udpsweep: {err}"})
    findings = []
    for r in data.get("open") or []:
        sev = "LOW"
        if r.get("service") in ("snmp", "memcached"):
            sev = "MEDIUM"   # SNMP public / memcached = info-leak class
        findings.append(_finding(
            f"UDP service responds: {r.get('service')} on port "
            f"{r.get('port')}", sev, f"go-udpsweep/{r.get('service')}",
            f"Protocol-correct UDP probe to {host}:{r.get('port')} "
            f"got a {r.get('reply_len')}B reply matching the "
            f"{r.get('service')} signature; note={r.get('note')!r}",
            f"{host}:{r.get('port')}/udp",
            f"nmap -sU -p {r.get('port')} -sV {host}"))
    if log:
        log(f"gotools: udpsweep {host} open={len(data.get('open') or [])}")
    return _result(findings=findings,
                   requests_sent=len(data.get("open") or []),
                   ran=["udpsweep"], surface={"udpsweep": data})


def run_swarm(targets, workers=None, timeout_ms=3000, log=None,
              gate_open_fn=None):
    """Distributed scan coordinator (Go core): fan targets to workers."""
    binary, skip = _prepare("swarm", gate_open_fn, log)
    if skip:
        return skip
    data, err = _run_tool_json(
        binary, {"targets": [str(t) for t in targets],
                 "workers": [str(w) for w in (workers or [])],
                 "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"swarm: {err}"})
    rows = data.get("results") or []
    findings = []
    for r in rows:
        if r.get("status") == 200:
            findings.append(_finding(
                f"live web service: {r.get('target')}", "INFO",
                "go-swarm/liveness",
                f"GET {r.get('target')}/ -> 200; server="
                f"{r.get('server')!r}; title={r.get('title')!r}",
                r.get("target"), f"curl -sI {r.get('target')}"))
    if log:
        log(f"gotools: swarm targets={len(rows)} workers={len(workers or [])}")
    return _result(findings=findings, requests_sent=len(rows),
                   ran=["swarm"], surface={"swarm": rows})


def run_sniffy(iface="", seconds=10, listen_udp=0, log=None,
               gate_open_fn=None):
    """Passive traffic observation (Go core). No values stored."""
    binary, skip = _prepare("sniffy", gate_open_fn, log)
    if skip:
        return skip
    data, err = _run_tool_json(
        binary, {"iface": iface, "seconds": int(seconds),
                 "listen_udp": int(listen_udp)}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"sniffy: {err}"})
    findings = []
    if data.get("privileged"):
        n = data.get("cleartext_auth") or 0
        if n:
            findings.append(_finding(
                "cleartext credentials observed on the wire", "HIGH",
                "go-sniffy/cleartext-auth",
                f"{n} HTTP Authorization/password-pattern line(s) seen "
                f"in {data.get('packets')} packets (VALUES NOT STORED — "
                f"count only)", "passive observation",
                "switch the observed flow to TLS and re-check"))
    if log:
        log(f"gotools: sniffy packets={data.get('packets')}")
    return _result(findings=findings, requests_sent=0, ran=["sniffy"],
                   surface={"sniffy": data})


def run_fuzzwave(target, paths, cookie=None, concurrency=200,
                 timeout_ms=2500, log=None, gate_open_fn=None):
    """Content-discovery fuzzer (Go core, adaptive 3-baseline filter)."""
    binary, skip = _prepare("fuzzwave", gate_open_fn, log)
    if skip:
        return skip
    data, err = _run_tool_json(
        binary, {"target": target, "paths": [str(p) for p in paths],
                 "cookie": cookie or "", "concurrency": int(concurrency),
                 "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"fuzzwave: {err}"})
    findings = []
    for r in data.get("results") or []:
        klass = r.get("class")
        if klass in ("exists", "protected", "redirect"):
            url = target.rstrip("/") + r.get("path", "")
            sev = {"exists": "LOW", "protected": "INFO",
                   "redirect": "INFO"}[klass]
            if klass == "exists" and any(
                    k in r.get("path", "").lower()
                    for k in ("admin", "backup", "config", "secret",
                              "debug", "env", "git", "sql", "dump")):
                sev = "HIGH"
            findings.append(_finding(
                f"content discovered ({klass}): {r.get('path')} "
                f"(HTTP {r.get('status')})", sev,
                f"go-fuzzwave/{klass}-{_slug(r.get('path') or '')}",
                f"GET {url} -> {r.get('status')}, {r.get('size')}B, "
                f"{r.get('ctype') or 'n/a'} — differs from soft-404 and "
                f"random-probe baselines", url,
                f"curl -s -o /dev/null -w '%{{http_code}}' {url}"))
    if log:
        log(f"gotools: fuzzwave {target} paths={len(paths)} "
            f"findings={len(findings)}")
    return _result(findings=findings, requests_sent=len(paths) + 4,
                   ran=["fuzzwave"], surface={"fuzzwave":
                                              data.get("results") or []})


def run_techprof(target, timeout_ms=2500, log=None, gate_open_fn=None):
    """Technology stack profiler (Go core)."""
    binary, skip = _prepare("techprof", gate_open_fn, log)
    if skip:
        return skip
    data, err = _run_tool_json(binary, {"target": target,
        "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"techprof: {err}"})
    prof = data.get("profile") or {}
    findings = []
    sec = prof.get("security_headers") or {}
    missing = [h for h, v in sec.items() if not v]
    if missing:
        findings.append(_finding(
            f"security headers missing: {', '.join(missing[:4])}",
            "LOW" if len(missing) <= 2 else "MEDIUM",
            "go-techprof/headers",
            f"absent: {', '.join(missing)}; server="
            f"{prof.get('server') or 'n/a'}", target,
            "curl -sI %s | grep -iE 'csp|hsts|x-frame'" % target))
    stack = [f"{k}={v}" for k, v in prof.items()
             if k in ("generator", "bundler", "cdn", "wordpress_theme",
                      "service_worker") and v]
    if stack:
        findings.append(_finding(
            "technology stack identified: " + ", ".join(stack), "INFO",
            "go-techprof/stack", "; ".join(stack), target,
            "review the stack against known CVEs manually"))
    if prof.get("sourcemap"):
        findings.append(_finding(
            "source map exposed in shipped JS", "MEDIUM",
            "go-techprof/sourcemap",
            f"sourceMappingURL={prof.get('sourcemap')}", target,
            "fetch the .map file and review original sources"))
    if log:
        log(f"gotools: techprof {target} stack={stack}")
    return _result(findings=findings, requests_sent=3,
                   ran=["techprof"], surface={"techprof": prof})


def run_jsmine(target, js_urls=None, timeout_ms=3000, log=None,
               gate_open_fn=None):
    """JavaScript bundle miner (Go core). Secrets: hint-only."""
    binary, skip = _prepare("jsmine", gate_open_fn, log)
    if skip:
        return skip
    data, err = _run_tool_json(binary, {"target": target,
        "js_urls": [str(u) for u in (js_urls or [])],
        "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"jsmine: {err}"})
    findings = []
    for s in data.get("secrets") or []:
        sev = "HIGH" if s.get("kind") in (
            "aws-access-key", "github-token", "private-key-block",
            "db-url") else "MEDIUM"
        findings.append(_finding(
            f"secret material in client bundle: {s.get('kind')}", sev,
            f"go-jsmine/{s.get('kind')}",
            f"hint {s.get('hint')} in {s.get('file')} (value truncated, "
            f"full value NOT stored)", s.get("file") or target,
            "open the bundle, locate the value, rotate the credential"))
    dbg = data.get("debug") or {}
    if dbg.get("debug-flag"):
        findings.append(_finding(
            "debug flag enabled in shipped JS", "LOW",
            "go-jsmine/debug",
            f"{dbg.get('debug-flag')} debug-flag match(es); sourcemap "
            f"hits: {dbg.get('sourcemap') or 0}", target,
            "rebuild the bundle in production mode"))
    n_ep = len(data.get("endpoints") or [])
    if n_ep:
        findings.append(_finding(
            f"{n_ep} API endpoint(s) mined from client JS", "INFO",
            "go-jsmine/endpoints",
            "sample: %s" % sorted(data.get("endpoints") or [])[:5],
            target, "probe the discovered endpoints with the auth "
            "checks suite"))
    if log:
        log(f"gotools: jsmine {target} secrets={len(findings)} "
            f"endpoints={n_ep}")
    return _result(findings=findings, requests_sent=1 + int(
        data.get("files_scanned") or 0), ran=["jsmine"],
        surface={"jsmine": data})


def run_diffscan(target, paths=None, baseline=None, log=None,
                 gate_open_fn=None):
    """Snapshot/diff regression scanner (Go core)."""
    binary, skip = _prepare("diffscan", gate_open_fn, log)
    if skip:
        return skip
    mode = "diff" if baseline else "save"
    data, err = _run_tool_json(binary, {"target": target,
        "mode": mode, "paths": [str(p) for p in (paths or [])],
        "baseline": baseline or {}}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"diffscan: {err}"})
    findings = []
    if baseline:
        churn = data.get("churn") or {}
        for p in churn.get("new") or []:
            row = (data.get("snapshot") or {}).get(p) or {}
            findings.append(_finding(
                f"new endpoint since baseline: {p}", "LOW",
                "go-diffscan/churn",
                f"absent in baseline, now HTTP {row.get('status')}, "
                f"{row.get('size')}B", target + p,
                "review what shipped; run the auth checks suite on it"))
        for p in churn.get("changed") or []:
            row = (data.get("snapshot") or {}).get(p) or {}
            findings.append(_finding(
                f"endpoint changed since baseline: {p}", "INFO",
                "go-diffscan/churn",
                f"baseline {baseline.get(p)} -> now status={row.get('status')}, "
                f"size={row.get('size')}", target + p,
                "diff the responses manually"))
    if log:
        log(f"gotools: diffscan {target} mode={mode} "
            f"paths={len(paths or [])}")
    return _result(findings=findings, requests_sent=len(paths or ["/"]),
                   ran=["diffscan"], surface={"diffscan": data})


def run_gqlprobe(target, endpoints=None, timeout_ms=3000, log=None,
                 gate_open_fn=None):
    """GraphQL abuse prober (Go core)."""
    binary, skip = _prepare("gqlprobe", gate_open_fn, log)
    if skip:
        return skip
    data, err = _run_tool_json(binary, {"target": target,
        "endpoints": [str(e) for e in (endpoints or [])],
        "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"gqlprobe: {err}"})
    findings = []
    for e in data.get("endpoints") or []:
        path = e.get("path")
        if e.get("introspection"):
            findings.append(_finding(
                f"GraphQL introspection enabled: {path}", "MEDIUM",
                "go-gqlprobe/introspection",
                f"__schema query returned schema data at {path}",
                target + path,
                "disable introspection in production; review the "
                "schema for sensitive fields"))
        if e.get("suggestions"):
            findings.append(_finding(
                f"GraphQL field-suggestion leak: {path}", "LOW",
                "go-gqlprobe/suggestions",
                "'Did you mean' error path reveals valid field names",
                target + path,
                "set suggestion masking in the GraphQL server config"))
        if e.get("batch"):
            findings.append(_finding(
                f"GraphQL array batching accepted: {path}", "LOW",
                "go-gqlprobe/batch",
                "an array of 2 queries executed in one request — "
                "rate-limit/depth bypass enabler", target + path,
                "cap operations-per-request at 1"))
        if e.get("get_query"):
            findings.append(_finding(
                f"GraphQL accepts GET-query injection: {path}", "LOW",
                "go-gqlprobe/get",
                "query executed via the query-string", target + path,
                "enforce POST-only, check CSRF exposure"))
        if e.get("deep_ok"):
            findings.append(_finding(
                f"GraphQL depth limit absent: {path}", "LOW",
                "go-gqlprobe/depth",
                "60-alias query executed without a depth error",
                target + path,
                "add a depth/query-complexity limiter"))
    if log:
        log(f"gotools: gqlprobe {target} endpoints={len(data.get('endpoints') or [])}")
    return _result(findings=findings,
                   requests_sent=6 * len(data.get("endpoints") or []),
                   ran=["gqlprobe"], surface={"gqlprobe": data})


def run_racewin(target, method="POST", path="/", body=None,
                headers=None, n=20, timeout_ms=4000, log=None,
                gate_open_fn=None):
    """Race condition detector (Go core). Operator supplies request."""
    binary, skip = _prepare("racewin", gate_open_fn, log)
    if skip:
        return skip
    data, err = _run_tool_json(binary, {"target": target,
        "method": method, "path": path, "body": body or "",
        "headers": {str(k): str(v) for k, v in (headers or {}).items()},
        "n": int(n), "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"racewin: {err}"})
    findings = []
    if data.get("race_signal"):
        classes = data.get("classes") or {}
        findings.append(_finding(
            f"race condition differential on {path}", "HIGH",
            "go-racewin/race",
            f"{n} simultaneous requests produced mixed classes "
            f"{classes} — winners/losers split; confirm business "
            f"impact manually", target + path,
            "re-run with a state-changing request you OWN on a test "
            "account; confirm the double-apply impact"))
    if log:
        log(f"gotools: racewin {target}{path} n={n} "
            f"signal={data.get('race_signal')}")
    return _result(findings=findings, requests_sent=int(n),
                   ran=["racewin"], surface={"racewin": data})


def run_spprobe(target, endpoints=None, check=None, timeout_ms=3000,
                log=None, gate_open_fn=None):
    """Server-side prototype pollution prober (Go core)."""
    binary, skip = _prepare("spprobe", gate_open_fn, log)
    if skip:
        return skip
    data, err = _run_tool_json(binary, {"target": target,
        "endpoints": [str(e) for e in (endpoints or [])],
        "check": check or "", "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"spprobe: {err}"})
    findings = []
    for r in data.get("results") or []:
        if r.get("polluted"):
            findings.append(_finding(
                f"server-side prototype pollution: {r.get('endpoint')} "
                f"({r.get('channel')})", "HIGH",
                "go-spprobe/pollution",
                f"__proto__/constructor payload marker persisted across "
                f"requests ({r.get('evidence')})",
                target + str(r.get("endpoint") or ""),
                "confirm gadget impact manually; check which merged "
                "object the server feeds the payload into"))
    if log:
        log(f"gotools: spprobe {target} "
            f"polluted={len(findings)}")
    return _result(findings=findings,
                   requests_sent=8 * len(data.get("results") or []),
                   ran=["spprobe"], surface={"spprobe": data})
