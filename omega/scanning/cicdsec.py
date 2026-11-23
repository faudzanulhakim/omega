"""omega/scanning/cicdsec.py — CI/CD & supply-chain exposure checks.

Offline file analysis (given a repo dir) plus light network probes:

  (a) git history secret scan — ``git log -p --all`` (subprocess with
      timeout) and secret patterns matched against ADDED lines only;
      CRITICAL confirmed with REDACTED evidence. Skips gracefully when
      the path is not a git repo or git is missing.
  (b) IaC plaintext secrets — *.tf / *.tfvars / *.yaml / docker-compose*
      assignments with literal values -> HIGH candidate.
  (c) dependency confusion — requirements.txt / package.json names that
      look internal (org-prefixed) are checked against the public
      registry (pypi.org / npmjs.org): name FREE -> HIGH (confusion
      possible); registered -> MEDIUM; network failure -> silent skip.
  (d) CI config exposure — /.github/workflows/*.yml publicly fetchable
      on the target -> MEDIUM; Jenkins unauthenticated /script console
      -> CRITICAL fingerprint.

``run_cicdsec`` never raises.
"""

from __future__ import annotations

import json
import os
import re
import subprocess

__all__ = [
    "IAC_SUFFIXES",
    "SECRET_PATTERNS",
    "WORKFLOW_PATHS",
    "dependency_confusion",
    "git_history_secrets",
    "iac_plaintext_secrets",
    "probe_ci_exposure",
    "redact",
    "run_cicdsec",
]

from omega.probes import Finding, allowlist_ok, default_fetch

FETCH_TIMEOUT = 5.0
GIT_TIMEOUT = 30.0

# ------------------------------------------------------- secret patterns

SECRET_PATTERNS = (
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GCP API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS secret key literal",
     re.compile(r"aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+]{32,})"
                r"['\"]?", re.IGNORECASE)),
    ("password/secret/token assignment",
     re.compile(r"(?:password|passwd|secret|token|api_?key)\s*[:=]\s*"
                r"['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE)),
)

IAC_SUFFIXES = (".tf", ".tfvars", ".yaml", ".yml")

WORKFLOW_PATHS = (
    "/.github/workflows/ci.yml",
    "/.github/workflows/deploy.yml",
    "/.github/workflows/main.yml",
    "/.github/workflows/build.yml",
    "/.github/workflows/release.yml",
)

JENKINS_CONSOLE_PATHS = ("/script", "/jenkins/script")

_VAR_REF = re.compile(r"(?:\$\{|\$\(|<<|\bvar\.|\bsecrets\.)")


def redact(value, keep=4):
    """Redact a secret for evidence: keep a short prefix only."""
    value = str(value or "")
    if len(value) <= keep:
        return "***"
    return value[:keep] + "...[REDACTED]"


def _text(body):
    if isinstance(body, bytes):
        return body.decode("utf-8", "replace")
    return str(body or "")


def _fetcher(fetch):
    return fetch or default_fetch


def _get(fetch, url, timeout=FETCH_TIMEOUT):
    try:
        try:
            st, _h, body = fetch("GET", url, timeout=timeout)
        except TypeError:
            st, _h, body = fetch("GET", url)
        return int(st or 0), _text(body)
    except Exception:
        return None


# ------------------------------------------------------------ (a) git

def _added_secret_lines(diff_text):
    """Yield (file, line) pairs for ADDED lines that match a secret
    pattern. Only lines starting with '+' (and not '+++') count."""
    current_file = None
    hits = []
    for line in diff_text.splitlines():
        if line.startswith("--- a/") or line.startswith("+++ b/"):
            current_file = line[6:].split("\t")[0]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        added = line[1:]
        if _VAR_REF.search(added):
            continue  # variable references / interpolations: not literal
        for label, rx in SECRET_PATTERNS:
            m = rx.search(added)
            if m:
                shown = m.group(0) if not m.groups() else m.group(1)
                hits.append((current_file, label, redact(shown)))
                break
    return hits


def git_history_secrets(repo_dir, timeout=GIT_TIMEOUT, git_bin="git"):
    """Scan git history added lines for secrets -> CRITICAL confirmed
    (redacted evidence). Returns ([] , reason) style: findings list and
    a skip-reason string (None when scanned)."""
    if not repo_dir or not os.path.isdir(repo_dir):
        return [], "not a directory"
    try:
        proc = subprocess.run(
            [git_bin, "log", "-p", "--all"],
            cwd=repo_dir, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return [], "git binary not available"
    except subprocess.TimeoutExpired:
        return [], "git log timed out"
    except Exception as exc:
        return [], "%s: %s" % (type(exc).__name__, exc)
    if proc.returncode != 0:
        return [], "not a git repository"
    diff_text = (proc.stdout or b"").decode("utf-8", "replace")
    hits = _added_secret_lines(diff_text)
    findings = []
    seen = set()
    for fname, label, shown in hits:
        key = (fname, label, shown)
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            "Secret committed to git history: %s" % label,
            "critical", "confirmed",
            "added line in git history (file: %s) matches %s "
            "(evidence redacted: %s)" % (fname or "?", label, shown),
            "git -C %s log -p --all  # locate the secret commit" % repo_dir,
            "git:%s" % (fname or "unknown"), shown,
            "omega-cicdsec/git_history_secret", confidence="confirmed"))
    return findings, None


# ------------------------------------------------------------ (b) IaC

_ASSIGN = re.compile(
    r"(?:^|[^A-Za-z])(?:password|passwd|secret|token|api_?key|"
    r"access_?key|private_?key)\w*\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?",
    re.IGNORECASE)


def _iac_file_paths(repo_dir):
    paths = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d != ".git"]
        for f in files:
            if f.startswith("docker-compose") and f.endswith((".yml", ".yaml")):
                paths.append(os.path.join(root, f))
            elif f.endswith(IAC_SUFFIXES):
                paths.append(os.path.join(root, f))
    return sorted(set(paths))


def iac_plaintext_secrets(repo_dir):
    """Scan IaC files for password/secret/token assignments with literal
    values -> HIGH candidate. Variable references are ignored."""
    if not repo_dir or not os.path.isdir(repo_dir):
        return []
    findings = []
    for path in _iac_file_paths(repo_dir)[:200]:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(262144)
        except Exception:
            continue
        rel = os.path.relpath(path, repo_dir)
        for m in _ASSIGN.finditer(text):
            value = m.group(1)
            if _VAR_REF.search(value):
                continue
            findings.append(Finding(
                "Plaintext secret in IaC file: %s" % rel,
                "high", "candidate",
                "literal password/secret assignment in %s (redacted: %s)"
                % (rel, redact(value)),
                "grep -nE 'password|secret|token' %s/%s" % (repo_dir, rel),
                rel, redact(value), "omega-cicdsec/iac_plaintext",
                confidence="candidate"))
            break  # one per file is enough signal
    return findings


# ----------------------------------------------- (c) dependency confusion

_ORG_PREFIXED = re.compile(r"^[a-z0-9][a-z0-9_.\-]*-[a-z0-9_.\-]+$",
                           re.IGNORECASE)


def _parse_requirements(text):
    names = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        m = re.match(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*", line)
        if m and _ORG_PREFIXED.match(m.group(0)):
            names.append(m.group(0).lower())
    return names


def _parse_package_json(text):
    names = []
    try:
        data = json.loads(text)
    except Exception:
        return names
    for section in ("dependencies", "devDependencies"):
        for name in (data.get(section) or {}):
            name = str(name)
            if name.startswith("@"):  # scoped: never registerable publicly
                continue
            if _ORG_PREFIXED.match(name):
                names.append(name.lower())
    return names


def dependency_confusion(paths, fetch=None, budget=20):
    """Check internal-looking package names against the public registry.
    Free -> HIGH (confusion possible); registered -> MEDIUM; network
    failure -> silent skip."""
    fetch = _fetcher(fetch)
    if not paths:
        return []
    names = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(262144)
        except Exception:
            continue
        if os.path.basename(path) == "package.json":
            names.extend(_parse_package_json(text))
        else:
            names.extend(_parse_requirements(text))
    seen, findings = set(), []
    sent = 0
    for name in names:
        if sent >= max(1, budget) or name in seen:
            continue
        seen.add(name)
        sent += 1
        # unscoped names are registered on PyPI; npm registry for exact
        # name too — one registry hit is enough to classify
        res = _get(fetch, "https://pypi.org/pypi/%s/json" % name, 5.0)
        if res is None:
            # registry failure: try npm once; if that also fails, skip
            res = _get(fetch, "https://registry.npmjs.org/%s" % name, 5.0)
            if res is None:
                continue  # network failure: silent skip
        status = res[0]
        if status == 404:
            findings.append(Finding(
                "Dependency confusion possible: internal package name "
                "is unregistered publicly (%s)" % name,
                "high", "candidate",
                "package %r looks internal (org-prefixed) but is FREE on "
                "the public registry — an attacker can register it"
                % name,
                "curl -s -o /dev/null -w '%%{http_code}' "
                "https://pypi.org/pypi/%s/json" % name,
                name, "pypi/npm lookup: HTTP 404 (unregistered)",
                "omega-cicdsec/dependency_confusion", confidence="candidate"))
        elif status == 200:
            findings.append(Finding(
                "Internal-looking package name is registered publicly "
                "(%s)" % name,
                "medium", "candidate",
                "package %r looks internal but is already registered on "
                "the public registry by someone else — verify it is "
                "yours" % name,
                "curl -s https://pypi.org/pypi/%s/json" % name,
                name, "registry lookup: HTTP 200 (registered)",
                "omega-cicdsec/dependency_confusion_registered",
                confidence="candidate"))
        # other statuses (rate limit etc.): silent skip
    return findings


# ------------------------------------------------------- (d) CI exposure

def probe_ci_exposure(target, fetch=None, allowlist=None, budget=10):
    """CI config exposure on the target: publicly fetchable GitHub
    workflow files -> MEDIUM; unauthenticated Jenkins script console
    (GET /script or /jenkins/script) -> CRITICAL fingerprint."""
    fetch = _fetcher(fetch)
    base = target if "://" in target else "http://" + target
    base = base.rstrip("/")
    if not allowlist_ok(base, allowlist):
        return []
    findings = []
    sent = 0
    for path in WORKFLOW_PATHS[:max(1, budget)]:
        url = base + path
        sent += 1
        res = _get(fetch, url)
        if res is not None and res[0] == 200 and \
                ("on:" in res[1] or "jobs:" in res[1] or
                 "runs-on" in res[1]):
            findings.append(Finding(
                "CI workflow definition publicly exposed: %s" % path,
                "medium", "confirmed",
                "GET %s returned GitHub Actions workflow content without "
                "auth" % url,
                "curl -sS -i '%s'" % url,
                url, res[1][:200], "omega-cicdsec/workflow_exposed",
                confidence="confirmed"))
    for path in JENKINS_CONSOLE_PATHS:
        url = base + path
        sent += 1
        res = _get(fetch, url)
        if res is None or res[0] != 200:
            continue
        body = res[1].lower()
        if ("script console" in body or "jenkins" in body or
                "hudson" in body or "groovy" in body):
            findings.append(Finding(
                "Jenkins script console reachable without authentication",
                "critical", "confirmed",
                "GET %s returned the Jenkins script console (Groovy) "
                "without auth — remote code execution surface" % url,
                "curl -sS -i '%s'" % url,
                url, res[1][:200], "omega-cicdsec/jenkins_console",
                confidence="confirmed"))
            break
    return findings


# ---------------------------------------------------------------- entry

def run_cicdsec(target=None, repo_dir=None, manifest_paths=None,
                fetch=None, budget=20, log=None, allowlist=None):
    """Entry point. Returns {findings, ran, skipped}. Never raises."""
    log = log or (lambda msg: None)
    findings, ran, skipped = [], [], []

    def _step(name, fn, *a, **kw):
        try:
            res = fn(*a, **kw)
            if isinstance(res, tuple):  # (findings, skip_reason)
                got, reason = res
                if reason:
                    skipped.append({"tool": name, "reason": reason})
                else:
                    ran.append(name)
                findings.extend(got)
            else:
                ran.append(name)
                findings.extend(res or [])
        except Exception as exc:  # contained
            skipped.append({"tool": name, "reason":
                            "%s: %s" % (type(exc).__name__, exc)})
            log("[cicdsec] %s failed: %s" % (name, exc))

    _step("git_history", git_history_secrets, repo_dir)
    _step("iac_plaintext", iac_plaintext_secrets, repo_dir)
    _step("dependency_confusion", dependency_confusion,
          manifest_paths or [], fetch, max(1, budget))
    if target:
        _step("ci_exposure", probe_ci_exposure, target, fetch, allowlist,
              max(1, budget))
    return {"findings": findings, "ran": ran, "skipped": skipped}
