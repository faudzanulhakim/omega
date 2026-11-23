"""
omega/pytools_scan.py — pure-Python async port scanner + suite runner.

AsyncPortScanner: asyncio + asyncio.open_connection, banner/protocol
probing (plain recv for banners, HTTP GET probe to detect web services).
Rate-safe (bounded semaphore concurrency) and cancellable.

run_py_suite: executes omega.pytools PY_REGISTRY tools matching the
requested stages with a counting budget (each tool consumes 1), an
optional allowlist of tool names, and never raises — failures become
per-tool error entries in `skipped`.
"""
import asyncio

import omega.pytools as pt

# default top-1000 port list (condensed nmap-top-1000 ordering)
TOP_PORTS_1000 = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306,
    8080, 1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465,
    548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 1027, 1028, 1029,
    1024, 161, 254, 515, 631, 9100, 49152, 49153, 49154, 49155, 49156,
    5432, 2222, 2525, 1433, 554, 563, 636, 994, 2121, 3128, 3268, 3307,
    3690, 4444, 5061, 5222, 5269, 5280, 5433, 5666, 5984, 6379, 6443,
    6666, 6667, 7000, 7001, 7002, 7443, 8000, 8001, 8002, 8008, 8009,
    8010, 8020, 8081, 8082, 8083, 8086, 8087, 8089, 8090, 8091, 8181,
    8443, 8444, 8500, 8649, 8686, 8834, 8880, 8983, 9000, 9001, 9002,
    9080, 9090, 9091, 9200, 9300, 9418, 9443, 9595, 9999, 10001,
    10002, 10003, 10443, 11211, 15672, 18080, 20000, 2082, 2083,
    2086, 2087, 2095, 2096, 27017, 27018, 27019, 28017, 30000,
    30001, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 50000,
    50001, 50002, 55555, 61000, 65000,
] + list(range(1, 100))


class AsyncPortScanner:
    """Cancellable, concurrency-bounded async TCP port scanner."""

    def __init__(self, concurrency=500, timeout=1.5):
        self.concurrency = max(1, int(concurrency))
        self.timeout = float(timeout)
        self._cancelled = False

    def cancel(self):
        """Request cancellation of an in-flight scan."""
        self._cancelled = True

    async def _probe_port(self, host, port):
        """Connect, optionally grab a banner, guess the service."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout)
        except Exception:
            return None
        banner = b""
        try:
            # give well-known talkative services a moment to speak first
            if port in (21, 22, 23, 25, 110, 143, 110, 995, 993, 587):
                try:
                    banner = await asyncio.wait_for(
                        reader.read(256), timeout=self.timeout)
                except Exception:
                    banner = b""
            if not banner:
                # protocol probe: try an HTTP GET (http/https handshake
                # detection) — a web server answers with a status line
                probe_req = b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % \
                    host.encode()[:255]
                try:
                    writer.write(probe_req)
                    await writer.drain()
                    banner = await asyncio.wait_for(
                        reader.read(256), timeout=self.timeout)
                except Exception:
                    banner = banner or b""
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        entry = {"port": port, "banner_guess": _guess_service(port, banner)}
        return entry

    async def scan_async(self, host, ports=None, concurrency=None,
                         timeout=None):
        """Scan `host`; returns {'open': [{port, banner_guess}, ...]}."""
        if ports is None:
            ports = TOP_PORTS_1000
        conc = concurrency or self.concurrency
        sem = asyncio.Semaphore(max(1, int(conc)))
        open_ports = []

        async def guarded(p):
            if self._cancelled:
                return
            async with sem:
                if self._cancelled:
                    return
                res = await self._probe_port(host, p)
                if res is not None:
                    open_ports.append(res)

        await asyncio.gather(*(guarded(p) for p in ports))
        open_ports.sort(key=lambda e: e["port"])
        return {"open": open_ports, "cancelled": self._cancelled}

    def scan(self, host, ports=None, concurrency=None, timeout=None):
        """Sync wrapper around scan_async."""
        if timeout is not None:
            self.timeout = float(timeout)
        return asyncio.run(self.scan_async(host, ports=ports,
                                           concurrency=concurrency))


def _guess_service(port, banner):
    """Service guess by port + observed banner / HTTP response."""
    text = ""
    if banner:
        text = banner.decode("utf-8", "replace").strip()
    lower = text.lower()
    if lower.startswith("http/") or "html" in lower[:256]:
        scheme = "https" if (port == 443 or port in (8443, 7443)) else "http"
        server = ""
        for ln in text.splitlines():
            if ln.lower().startswith("server:"):
                server = ln.split(":", 1)[1].strip()
                break
        guess = scheme
        if server:
            guess += f" ({server})"
        return guess
    static = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
        110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
        143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps",
        587: "smtp-submission", 993: "imaps", 995: "pop3s", 1433: "ms-sql",
        3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
        5900: "vnc", 6379: "redis", 8080: "http-alt", 9200: "elasticsearch",
        11211: "memcached", 27017: "mongod",
    }
    guess = static.get(port, f"tcp/{port}")
    if text and not text.startswith("HTTP/"):
        first = text.splitlines()[0][:80] if text.splitlines() else ""
        if first:
            guess += f' banner="{first}"'
    return guess


# ------------------------------------------------------------- suite

def run_py_suite(target, stages=None, budget=None, log=None, allowlist=None):
    """Run pure-python registry tools matching `stages` under a budget.

    stages: iterable of stage names (recon/enum/verify); None = all.
    budget: max number of tools to execute (each tool costs 1).
    allowlist: optional iterable of tool names to restrict to.
    Returns {'findings', 'surface', 'ran', 'skipped'} and NEVER raises.
    """
    log = log or (lambda msg: None)
    stage_set = set(stages) if stages else \
        {"recon", "enum", "verify"}
    allowed = set(allowlist) if allowlist else None

    findings, surface = [], {}
    ran, skipped = [], []

    candidates = [spec for spec in pt.PY_REGISTRY.values()
                  if spec["stage"] in stage_set and
                  (allowed is None or spec["name"] in allowed)]

    for spec in candidates:
        name = spec["name"]
        if budget is not None and len(ran) >= int(budget):
            skipped.append({"tool": name, "reason": "budget exhausted"})
            log(f"[pytools] skipped '{name}': budget exhausted")
            continue
        log(f"[pytools] running '{name}' ({spec['safety']}, "
            f"stage={spec['stage']})")
        try:
            f, s = spec["fn"](target, log=log)
            findings.extend(f)
            if isinstance(s, dict):
                for k, v in s.items():
                    if k in surface and isinstance(surface[k], list) \
                            and isinstance(v, list):
                        surface[k].extend(v)
                    else:
                        surface[k] = v
            ran.append(name)
            log(f"[pytools] '{name}' done: {len(f)} findings")
        except Exception as exc:  # never raises outward
            skipped.append({"tool": name, "reason": f"error: {exc}"})
            log(f"[pytools] '{name}' failed (tolerated): {exc}")
    return {"findings": findings, "surface": surface,
            "ran": ran, "skipped": skipped}
