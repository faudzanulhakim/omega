"""omega/offensive/offense/cisweep — secrets & CI exposure sweep.

Checks for exposed VCS/dev/CI artifacts: .git, .env, .svn, Jenkins
/ GitLab runners, backup files, docker socket paths. Read-only GETs;
a hit is candidate + manual_check (a 403 page that LOOKS like .env
is a common trap). OFFENSE-GATED (PTK_OFFENSE).
"""
import os

__all__ = ["run_cisweep"]

PATHS = [
    ("/.git/HEAD", "git repository exposed", "HIGH"),
    ("/.git/config", "git config exposed", "HIGH"),
    ("/.env", "environment file (.env) exposed", "CRITICAL"),
    ("/.svn/entries", "svn metadata exposed", "MEDIUM"),
    ("/.DS_Store", "macOS directory listing artifact", "LOW"),
    ("/backup.zip", "backup archive at web root", "HIGH"),
    ("/db.sql", "database dump at web root", "CRITICAL"),
    ("/jenkins/script", "Jenkins script console reachable", "CRITICAL"),
    ("/runners/check", "gitlab runner probe path", "MEDIUM"),
    ("/var/run/docker.sock", "docker socket over web", "CRITICAL"),
    ("/server-status", "apache server-status enabled", "MEDIUM"),
    ("/debug/vars", "go pprof/expvar exposed", "MEDIUM"),
]

POSITIVE_MARKERS = {
    "/.git/HEAD": ["ref:", "refs/"],
    "/.git/config": ["[core]", "repositoryformatversion"],
    "/.env": ["=", "KEY"],
    "/jenkins/script": ["script console", "jenkins"],
    "/server-status": ["apache", "server uptime", "serverstatus"],
    "/debug/vars": ["cmdline", "memstats"],
}


def run_cisweep(target, fetch=None, log=None, gate_open_fn=None):
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    fetch = fetch or (lambda *a, **k: None)
    base = str(target).rstrip("/")
    findings = []
    probes = 0
    for path, desc, sev in PATHS:
        try:
            resp = fetch(base + path)
            probes += 1
        except Exception:
            continue
        if resp is None:
            continue
        status = getattr(resp, "status", 0)
        body = (getattr(resp, "text", "") or "")
        if status >= 400:
            continue
        markers = POSITIVE_MARKERS.get(path, [])
        looks_html = body.lstrip().lower().startswith("<!doctype") or \
            body.lstrip().lower().startswith("<html") or \
            "</html>" in body.lower()
        if markers:
            if not any(m.lower() in body.lower() for m in markers):
                continue  # 200 but not the real artifact
        elif looks_html:
            # generic HTML page (SPA/soft-404) served for every path —
            # NOT evidence of exposure
            continue
        findings.append({
            "title": f"{desc}: {path} (HTTP {status})",
            "severity": sev,
            "source": "cisweep/exposure",
            "evidence": (body[:120] or "HTTP 200 empty"),
            "location": base + path,
            "verification": "candidate",
            "manual_check": "verify the content is the real artifact "
                            "(custom 403/404 pages often mimic paths)",
            "cwe": "CWE-538",
        })
    if log:
        log(f"cisweep: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
