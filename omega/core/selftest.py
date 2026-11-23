"""omega/core/selftest — per-module self-check before deployment.

Runs each offense module against a tiny local mock server exercising
its detection path. A module that cannot prove its own detection on
a known-vulnerable mock is flagged BROKEN and excluded from plans
until fixed. This is the quality gate Dee asked for: self-test runs
as part of the batch, results recorded.
"""
import http.server
import json
import os
import socket
import threading

__all__ = ["run_selftests", "render_selftests"]

# module -> probe lambda(fetch)->bool(detects on the mock below)
_MOCK_ROUTES = {
    "/weak-pass": ("POST", "dashboard"),     # pwdaudit hit
    "/admin": ("ANY", "verb-ok"),            # verbtamper bypass
    "/app.js": ("GET", 'innerHTML = x;'),    # jsmine sink
    "/actuator": ("GET", '{"health":"up"}'), # shadowdisc real
    "/header": ("GET", "crlf-hit"),          # crlfprobe via header
}


class _Mock(http.server.BaseHTTPRequestHandler):
    def _reply(self, status, body, headers=None):
        payload = body.encode()
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path.startswith("/admin"):
            return self._reply(403, "forbidden")
        if self.path.startswith("/app.js"):
            return self._reply(200, "// omega selftest bundle\nel.innerHTML = x;\nfetch(\"/api/v2/users\");")
        if self.path.startswith("/actuator"):
            return self._reply(200, '{"health":"up"}')
        if self.path.startswith("/crlf?next="):
            return self._reply(200, "ok", {"omegcrlf": "injected"})
        if self.path.startswith("/order"):
            return self._reply(200, '{"order":{"owner":"other"}}')
        return self._reply(404, "nope")

    def do_POST(self):
        if self.path.startswith("/weak-pass"):
            return self._reply(200, "dashboard")
        if self.path.startswith("/admin"):
            return self._reply(200, '{"users":[]}')
        return self._reply(404, "nope")

    def log_message(self, *a):
        pass


def _mock_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run_selftests(modules=None, gate_env=True):
    """Run detection-path self-checks. Returns {module: ok|broken+why}."""
    results = {}
    old = os.environ.pop("PTK_OFFENSE", None)
    if gate_env:
        os.environ["PTK_OFFENSE"] = "1"
    try:
        srv = _mock_server()
        port = srv.server_address[1]
        base = f"http://127.0.0.1:{port}"
        try:
            results.update(_check_pwdaudit(base))
            results.update(_check_verbtamper(base))
            results.update(_check_jsmine(base))
            results.update(_check_shadowdisc(base))
            results.update(_check_crlfprobe(base))
        finally:
            srv.shutdown()
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old
        else:
            os.environ.pop("PTK_OFFENSE", None)
    return results


def _check_pwdaudit(base):
    from omega.offensive.offense.pwdaudit import run_pwdaudit
    def fetch(url, method=None, body=None):
        class R: status = 200; text = "dashboard"
        return R() if "weak-pass" in url else None
    out = run_pwdaudit(base + "/weak-pass", fetch=fetch,
                       username="tester", pace_s=0)
    return {"pwdaudit": {"ok": bool(out["findings"])}}


def _check_verbtamper(base):
    from omega.offensive.offense.verbtamper import run_verbtamper
    import urllib.request
    def fetch(url, method="GET", body=None):
        req = urllib.request.Request(url, method=method)
        try:
            r = urllib.request.urlopen(req, timeout=3)
            return type("R", (), {"status": r.status,
                                  "text": r.read().decode()})()
        except Exception:
            return type("R", (), {"status": 403, "text": "forbidden"})()
    out = run_verbtamper(base, fetch=fetch, endpoints=["/admin"])
    return {"verbtamper": {"ok": bool(out["findings"])}}


def _check_jsmine(base):
    from omega.offensive.offense.jsmine import run_jsmine
    import urllib.request
    def fetch(url, method="GET"):
        try:
            r = urllib.request.urlopen(url, timeout=3)
            return type("R", (), {"status": r.status,
                                  "text": r.read().decode()})()
        except Exception:
            return type("R", (), {"status": 404, "text": ""})()
    out = run_jsmine(base, fetch=fetch)
    return {"jsmine": {"ok": bool(out["sinks"])}}


def _check_shadowdisc(base):
    from omega.offensive.offense.shadowdisc import run_shadowdisc
    import urllib.request
    def fetch(url, method="GET"):
        try:
            r = urllib.request.urlopen(url, timeout=3)
            return type("R", (), {"status": r.status,
                                  "text": r.read().decode()})()
        except Exception:
            return type("R", (), {"status": 404, "text": "nope"})()
    out = run_shadowdisc(base, fetch=fetch,
                         candidates=["/actuator"])
    return {"shadowdisc": {"ok": bool(out["findings"])}}


def _check_crlfprobe(base):
    from omega.offensive.offense.crlfprobe import run_crlfprobe
    import urllib.request
    def fetch(url, headers=None):
        req = urllib.request.Request(url)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            r = urllib.request.urlopen(req, timeout=3)
            return type("R", (), {"status": r.status, "text": "",
                                  "headers": dict(r.headers)})()
        except Exception:
            return None
    out = run_crlfprobe(base + "/crlf", fetch=fetch, params=["next"])
    return {"crlfprobe": {"ok": bool(out["findings"])}}


def render_selftests(results):
    lines = ["## Module self-tests"]
    ok = sum(1 for r in results.values() if r.get("ok"))
    lines.append(f"{ok}/{len(results)} modules prove their detection "
                 f"path on the mock target")
    for m, r in sorted(results.items()):
        status = "OK" if r.get("ok") else ("BROKEN — exclude from "
                                           "plans until fixed")
        lines.append(f"- {m}: {status}")
    return "\n".join(lines)
