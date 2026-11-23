"""omega/adapters/gotools_offense — Go offense runners (hackwave, takeover).

Batch-9 "GO BRUTAL": heavy-concurrency offensive sweeps executed by
compiled Go binaries, orchestrated from Python. Both runners are
gate-guarded (PTK_OFFENSE / PTK_EXPLOIT), compile on demand, and emit
CANDIDATE-grade findings only — never auto-confirmed, manual_check
attached everywhere. Never raises outward.
"""
import json
import os
import re

from omega.adapters import native
from omega.adapters.gotools import (_build_tool, _gate_open, _result,
                                     _slug, GATE_KEY)

SUBPROC_TIMEOUT = 600
_SENSITIVE_RE = re.compile(
    r"(admin|login|api|internal|debug|backup|config|secret)", re.I)


def _ensure_go(log=None):
    """Return True when the Go toolchain is available."""
    import shutil
    return bool(shutil.which("go"))


def _build_and_run(tool, stdin_obj, log=None):
    """ensure_native + build + run; returns (parsed dict|None, err)."""
    from omega.adapters.gotools import _run_tool_json
    if not _ensure_go(log):
        return None, "go toolchain unavailable"
    try:
        native.ensure_native(native.DEFAULT_CACHE_DIR, log=log)
    except PermissionError:
        pass  # gate already authorized by the caller
    except Exception as e:
        return None, f"ensure_native error: {e}"
    try:
        os.makedirs(native.DEFAULT_CACHE_DIR, exist_ok=True)
        binary = _build_tool(tool, native.DEFAULT_CACHE_DIR, log=log)
    except Exception as e:
        return None, f"{tool} build failed: {e}"
    return _run_tool_json(binary, stdin_obj, log=log)


# ------------------------------------------------------------------
def run_hackwave(target, params, method="GET", body="", cookie="",
                 concurrency=60, timeout_ms=2500, log=None,
                 gate_open_fn=None):
    """Parallel multi-vector injection wave via the Go binary.

    Requires the OFFENSE gate (PTK_OFFENSE). Findings are CANDIDATE
    only: reflected / error-shape / status-shift classes with the
    payload, signal and baseline attached for manual verification.
    """
    import os
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not _gate_open(gate):
        return _result(skipped={GATE_KEY:
                                "offense gate closed (PTK_OFFENSE)"})
    data, err = _build_and_run("hackwave", {
        "target": str(target or ""), "params": [str(p) for p in
                                                (params or [])][:64],
        "method": str(method or "GET"), "body": str(body or ""),
        "cookie": str(cookie or ""), "concurrency": concurrency,
        "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"hackwave: {err}"},
                       requests_sent=0)
    findings = []
    results = data.get("results") or []
    for r in results:
        klass = r.get("class") or ""
        if not klass:
            continue
        sev = "HIGH" if klass in ("reflected+status-shift", "cmd-exec",
                                  "error-shape") else "MEDIUM"
        loc = f"{target}?{r.get('param')}={r.get('payload')}"
        findings.append({
            "title": f"injection candidate [{r.get('vector')}] on "
                     f"param '{r.get('param')}' ({klass})",
            "severity": sev,
            "source": f"go-hackwave/{_slug(r.get('param') or '')}",
            "evidence": f"payload={r.get('payload')!r} -> HTTP "
                        f"{r.get('baseline_status')}->{r.get('status')}, "
                        f"signal: {r.get('signal')}",
            "location": loc,
            "verification": "candidate",
            "manual_check": "replay with the payload manually and "
                            "confirm impact before reporting",
            "cwe": {"sqli": "CWE-89", "ssti": "CWE-1336",
                    "cmd-echo": "CWE-78", "ssrf": "CWE-918",
                    "traversal": "CWE-22"}.get(r.get("vector"), "CWE-94"),
        })
    if log:
        log(f"gotools: hackwave {target} params={len(params or [])} "
            f"candidates={len(findings)}")
    return _result(findings=findings, ran=["hackwave"],
                   requests_sent=data.get("requests") or 0,
                   surface={"hackwave": results})


# ------------------------------------------------------------------
_TAKEOVER_FINGERPRINTS = {
    "aws-s3": "CWE-350", "azure": "CWE-350", "azure-cdn": "CWE-350",
    "heroku": "CWE-350", "github-pages": "CWE-350", "shopify": "CWE-350",
    "fastly": "CWE-350", "pantheon": "CWE-350", "zendesk": "CWE-350",
    "helpjuice": "CWE-350", "surge": "CWE-350", "bitbucket": "CWE-350",
}


def run_takeover(hosts, concurrency=50, timeout_ms=3000, log=None,
                 gate_open_fn=None):
    """Subdomain takeover hunt via the Go binary.

    Requires the EXPLOIT gate (PTK_EXPLOIT). A provider signature on a
    dangling CNAME is takeover-candidate evidence; the operator must
    prove DNS control before reporting it as exploitable.
    """
    import os
    gate = gate_open_fn or (lambda: os.environ.get("PTK_EXPLOIT") == "1")
    if not _gate_open(gate):
        return _result(skipped={GATE_KEY:
                                "exploit gate closed (PTK_EXPLOIT)"})
    hosts = [str(h).strip() for h in (hosts or []) if str(h).strip()]
    data, err = _build_and_run("takeover", {
        "hosts": hosts[:2048], "concurrency": concurrency,
        "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={GATE_KEY: f"takeover: {err}"})
    findings = []
    for r in (data.get("results") or []):
        klass = r.get("class") or ""
        if klass == "takeover-candidate":
            findings.append({
                "title": f"subdomain takeover candidate on {r.get('host')} "
                         f"({r.get('provider')})",
                "severity": "HIGH",
                "source": f"go-takeover/{_slug(r.get('host') or '')}",
                "evidence": f"CNAME {r.get('host')} -> {r.get('cname')} "
                            f"serves provider signature "
                            f"{r.get('signature')!r} ({r.get('provider')})",
                "location": r.get("cname") or r.get("host"),
                "verification": "candidate",
                "manual_check": "prove DNS control of the dangling "
                                "endpoint before claiming takeover",
                "cwe": _TAKEOVER_FINGERPRINTS.get(r.get("provider"),
                                                  "CWE-350"),
            })
        elif klass == "dangling-cname-unreachable":
            findings.append({
                "title": f"dangling CNAME on {r.get('host')} "
                         f"(endpoint unreachable)",
                "severity": "LOW",
                "source": f"go-takeover/{_slug(r.get('host') or '')}",
                "evidence": f"CNAME {r.get('host')} -> {r.get('cname')} "
                            f"does not resolve/serve (potential dead "
                            f"record)",
                "location": r.get("cname") or r.get("host"),
                "verification": "candidate",
                "manual_check": "verify the record is really orphaned",
                "cwe": "CWE-350",
            })
    if log:
        log(f"gotools: takeover hosts={len(hosts)} "
            f"candidates={len(findings)}")
    return _result(findings=findings, ran=["takeover"],
                   surface={"takeover": data.get("results") or []})


# ------------------------------------------------------------------
# batch-10 BEYOND BRUTAL
# ------------------------------------------------------------------
_TECH_DEFAULT_CREDS = {
    "jenkins": [("admin", "admin"), ("admin", "password"),
                ("admin", "jenkins")],
    "tomcat": [("tomcat", "tomcat"), ("admin", "admin"),
               ("manager", "manager"), ("role1", "role1")],
    "grafana": [("admin", "admin")],
    "gitlab": [("root", "5iveL!fe")],
    "wordpress": [("admin", "admin"), ("admin", "password")],
    "jenkins-cli": [("admin", "admin")],
    "generic": [("admin", "admin"), ("admin", "password"),
                ("admin", "123456"), ("root", "root"),
                ("administrator", "admin"), ("test", "test"),
                ("user", "user"), ("admin", "changeme")],
}


def run_privesc(template, method="GET", body="", cookie="", log=None,
                gate_open_fn=None, confirm_rce=False):
    """Post-exploit enumeration through a CONFIRMED command injection.

    Requires the EXPLOIT gate (PTK_EXPLOIT) AND confirm_rce=True —
    the caller must have verified the RCE first, never from a bare
    candidate. Read-only enumeration of the injected shell.
    """
    import os
    if not confirm_rce:
        return _result(skipped={"gotools":
                                "privesc: no CONFIRMED RCE (candidate "
                                "does not authorize post-exploit)"})
    gate = gate_open_fn or (lambda: os.environ.get("PTK_EXPLOIT") == "1")
    if not _gate_open(gate):
        return _result(skipped={"gotools":
                                "exploit gate closed (PTK_EXPLOIT)"})
    data, err = _build_and_run("privesc_probe", {
        "template": str(template or ""), "method": str(method or "GET"),
        "body": str(body or ""), "cookie": str(cookie or ""),
        "concurrency": 4, "timeout_ms": 4000}, log=log)
    if data is None:
        return _result(skipped={"gotools": f"privesc: {err}"})
    flagged = []
    for r in (data.get("results") or []):
        if r.get("flag"):
            flagged.append(r)
    findings = []
    if flagged:
        findings.append({
            "title": f"post-exploit enumeration: {len(flagged)} notable "
                     f"host-state findings through confirmed RCE",
            "severity": "CRITICAL",
            "source": "go-privesc/confirmed-rce",
            "evidence": "; ".join(
                f"{r['check']}: {str(r.get('output'))[:120]}"
                for r in flagged),
            "location": str(template)[:120],
            "verification": "confirmed",
            "manual_check": "evidence captured from enumerated commands; "
                            "review before including in the report",
            "cwe": "CWE-78",
        })
    if log:
        log(f"gotools: privesc checks={len(data.get('results') or [])} "
            f"notable={len(flagged)}")
    return _result(findings=findings, ran=["privesc_probe"],
                   surface={"privesc": data.get("results") or []})


def run_authblast(logins, techs=None, pairs=None, user_field="username",
                  pass_field="password", fail_pattern="", concurrency=10,
                  timeout_ms=3000, log=None, gate_open_fn=None):
    """Concurrent default-credential stuffing via the Go binary.

    Requires the OFFENSE gate (PTK_OFFENSE). Creds come from the built
    technology lists (or caller-supplied pairs). Every hit is
    candidate: one manual login by the operator confirms it.
    """
    import os
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not _gate_open(gate):
        return _result(skipped={"gotools":
                                "offense gate closed (PTK_OFFENSE)"})
    if not pairs:
        pairs = []
        for t in (techs or ["generic"]):
            pairs.extend(_TECH_DEFAULT_CREDS.get(str(t).lower(),
                        _TECH_DEFAULT_CREDS["generic"]))
    pairs = [[str(a), str(b)] for a, b in pairs][:256]
    data, err = _build_and_run("authblast", {
        "logins": [str(x) for x in (logins or [])][:128],
        "pairs": pairs, "user_field": user_field,
        "pass_field": pass_field, "fail_pattern": fail_pattern,
        "concurrency": concurrency, "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={"gotools": f"authblast: {err}"})
    findings = []
    for r in (data.get("results") or []):
        klass = r.get("class") or ""
        if not klass:
            continue
        sev = "HIGH" if klass in ("no-fail-marker", "success-content") \
            else "MEDIUM"
        findings.append({
            "title": f"default-credential candidate on {r.get('login')} "
                     f"({r.get('user')}:{r.get('pass')} — {klass})",
            "severity": sev,
            "source": f"go-authblast/{_slug(r.get('login') or '')}",
            "evidence": f"POST login {r.get('user')}/{r.get('pass')} -> "
                        f"HTTP {r.get('baseline_status')}->"
                        f"{r.get('status')} ({klass})",
            "location": r.get("login"),
            "verification": "candidate",
            "manual_check": "log in manually with the pair once to "
                            "confirm before reporting",
            "cwe": "CWE-798",
        })
    if log:
        log(f"gotools: authblast logins={len(logins or [])} "
            f"pairs={len(pairs)} candidates={len(findings)}")
    return _result(findings=findings, ran=["authblast"],
                   requests_sent=(len(pairs) + 1) * len(logins or []),
                   surface={"authblast": data.get("results") or []})

def run_racehunter(target, body="", method="POST", race_n=20,
                   success_marker="", cookie="", headers=None,
                   timeout_ms=3000, log=None, gate_open_fn=None):
    """Race-condition wave via the Go binary (TOCTOU detection).

    Requires the OFFENSE gate (PTK_OFFENSE). success_count > 1 on a
    one-time action is race-candidate evidence; operator replays
    manually to confirm.
    """
    import os
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not _gate_open(gate):
        return _result(skipped={"gotools":
                                "offense gate closed (PTK_OFFENSE)"})
    data, err = _build_and_run("racehunter", {
        "target": str(target or ""), "method": str(method or "POST"),
        "body": str(body or ""), "cookie": str(cookie or ""),
        "headers": dict(headers or {}), "race_n": int(race_n or 20),
        "success_marker": str(success_marker or ""),
        "timeout_ms": timeout_ms}, log=log)
    if data is None:
        return _result(skipped={"gotools": f"racehunter: {err}"})
    findings = []
    sc = data.get("success_count") or 0
    if success_marker and sc >= 2:
        findings.append({
            "title": f"race-condition candidate on {target}: "
                     f"{sc}/{data.get('total')} requests reported "
                     f"success simultaneously",
            "severity": "HIGH",
            "source": "go-racehunter/simultaneous-success",
            "evidence": f"{sc} of {data.get('total')} parallel "
                        f"requests matched success marker "
                        f"(outcomes: {data.get('outcomes')})",
            "location": str(target),
            "verification": "candidate",
            "manual_check": "replay the race manually and check the "
                            "resource was consumed more than once",
            "cwe": "CWE-367",
        })
    if log:
        log(f"gotools: racehunter n={race_n} success={sc}")
    return _result(findings=findings, ran=["racehunter"],
                   requests_sent=data.get("total") or 0,
                   surface={"racehunter": {"outcomes":
                            data.get("outcomes"),
                            "success_count": sc}})
