"""tests/test_cicdsec.py — hermetic tests for omega.scanning.cicdsec.

Git history scans run against a tmp repo fixture built with real
subprocess git (secret planted in history, removed from HEAD).
Registry lookups use a stub fetch; CI/Jenkins probes use loopback
servers. No real egress.
"""

import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest  # noqa: E402

from omega.scanning.cicdsec import (  # noqa: E402
    _added_secret_lines,
    dependency_confusion,
    git_history_secrets,
    iac_plaintext_secrets,
    probe_ci_exposure,
    redact,
    run_cicdsec,
)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def _make_server(routes):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            route = routes.get(self.path)
            if route is None:
                body, status = b"not found", 404
            else:
                status, payload = route
                body = payload.encode() if isinstance(payload, str) else payload
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%s" % srv.server_address[1]


@pytest.fixture(scope="module")
def git_repo(tmp_path_factory):
    """Tmp git repo with a planted AWS secret that only exists in
    HISTORY (second commit removes the file from the tree)."""
    base = tmp_path_factory.mktemp("cicd")
    repo = base / "repo"
    repo.mkdir()
    def _git(*args):
        subprocess.run(["git"] + list(args), cwd=repo, check=True,
                       capture_output=True)
    _git("init", "-q")
    _git("config", "user.email", "t@example.com")
    _git("config", "user.name", "tester")
    (repo / "deploy.env").write_text(
        "AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n"
        % (AWS_KEY, AWS_SECRET))
    _git("add", "deploy.env")
    _git("commit", "-q", "-m", "add deploy env")
    (repo / "deploy.env").unlink()
    _git("rm", "-q", "--cached", "deploy.env")
    (repo / "README.md").write_text("clean\n")
    _git("add", "README.md")
    _git("commit", "-q", "-m", "remove secret, add readme")
    return repo


# ------------------------------------------------------ git history

def test_git_history_secret_critical(git_repo):
    findings, reason = git_history_secrets(str(git_repo))
    assert reason is None
    crit = [f for f in findings if f["severity"] == "critical"]
    assert crit
    assert crit[0]["confidence"] == "confirmed"
    assert any("AWS" in f["title"] or "aws" in f["evidence"].lower()
               for f in crit)


def test_git_history_evidence_redacted(git_repo):
    findings, _ = git_history_secrets(str(git_repo))
    blob = " ".join(f["evidence"] + f["verification_note"]
                    for f in findings)
    assert AWS_KEY not in blob and AWS_SECRET not in blob
    assert "REDACTED" in blob or "AKIA" not in blob


def test_git_history_non_repo_skips(tmp_path):
    findings, reason = git_history_secrets(str(tmp_path))
    assert findings == []
    assert reason and "git" in reason.lower()


def test_git_history_missing_dir_skips():
    findings, reason = git_history_secrets("/nonexistent/path/x")
    assert findings == []
    assert reason


def test_added_secret_lines_only_added():
    diff = ("--- a/env\n+++ b/env\n"
            "+AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
            "-AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
            " context\n")
    hits = _added_secret_lines(diff)
    assert len(hits) == 1  # removed/context lines never match
    assert hits[0][0] == "env"


# ------------------------------------------------------------- IaC

def test_iac_plaintext_high(tmp_path):
    (tmp_path / "terraform.tfvars").write_text(
        'db_password = "Sup3rS3cret!"\n')
    out = iac_plaintext_secrets(str(tmp_path))
    assert out and out[0]["severity"] == "high"
    assert "Sup3rS3cret" not in out[0]["evidence"]


def test_iac_docker_compose(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  db:\n    environment:\n      "
        "DB_TOKEN: 'abcdef123456'\n")
    out = iac_plaintext_secrets(str(tmp_path))
    assert out and "docker-compose.yml" in out[0]["location"]


def test_iac_variable_reference_ignored(tmp_path):
    (tmp_path / "main.tfvars").write_text(
        'password = var.db_password\n'
        'secret = "${vault.secret}"\n')
    assert iac_plaintext_secrets(str(tmp_path)) == []


def test_iac_git_dir_skipped(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "terraform.tfvars").write_text(
        'password = "literal123"\n')
    assert iac_plaintext_secrets(str(tmp_path)) == []


# ------------------------------------------- dependency confusion

def test_dependency_confusion_free_high(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("acme-internal-utils==1.0\nflask==2.0\n")
    def fetch(method, url, timeout=0):
        assert "pypi.org/pypi/acme-internal-utils" in url
        return 404, {}, b"not found"
    out = dependency_confusion([str(req)], fetch=fetch)
    assert out and out[0]["severity"] == "high"
    assert out[0]["location"] == "acme-internal-utils"


def test_dependency_confusion_registered_medium(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text('{"dependencies": {"acme-tools-lib": "^1.0"}}')
    def fetch(method, url, timeout=0):
        return 200, {}, b'{"name":"acme-tools-lib"}'
    out = dependency_confusion([str(pkg)], fetch=fetch)
    assert out and out[0]["severity"] == "medium"


def test_dependency_confusion_public_names_skipped(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask==2.0\nrequests>=2\n")
    def fetch(method, url, timeout=0):  # pragma: no cover
        raise AssertionError("public names must not be queried")
    assert dependency_confusion([str(req)], fetch=fetch) == []


def test_dependency_confusion_network_fail_skips(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("acme-internal-utils==1.0\n")
    def fetch(method, url, timeout=0):
        raise OSError("network down")
    assert dependency_confusion([str(req)], fetch=fetch) == []


# ----------------------------------------------------- CI exposure

def test_github_workflow_exposed_medium():
    srv, base = _make_server({
        "/.github/workflows/ci.yml": (200, "on: push\njobs:\n  build:\n"
                                        "    runs-on: ubuntu-latest\n"),
    })
    try:
        out = probe_ci_exposure(base)
        m = [f for f in out if f["severity"] == "medium"]
        assert m and "workflows" in m[0]["location"]
    finally:
        srv.shutdown()


def test_jenkins_console_critical():
    srv, base = _make_server({
        "/script": (200, "<html><title>Jenkins Script Console</title>"
                         "<body>Groovy script</body></html>"),
    })
    try:
        out = probe_ci_exposure(base)
        c = [f for f in out if f["severity"] == "critical"]
        assert c and c[0]["confidence"] == "confirmed"
        assert "jenkins" in c[0]["title"].lower()
    finally:
        srv.shutdown()


def test_ci_exposure_nothing_exposed():
    srv, base = _make_server({})
    try:
        assert probe_ci_exposure(base) == []
    finally:
        srv.shutdown()


def test_ci_exposure_allowlist_blocks():
    srv, base = _make_server({})
    try:
        assert probe_ci_exposure(base, allowlist=["example.com"]) == []
    finally:
        srv.shutdown()


# --------------------------------------------------------- redaction

def test_redact_keeps_prefix_only():
    r = redact("AKIAIOSFODNN7EXAMPLE", keep=4)
    assert r.startswith("AKIA") and r.endswith("[REDACTED]")
    assert "IOSFODNN7" not in r
    assert redact("abc") == "***"


# ------------------------------------------------------------ entry

def test_run_cicdsec_never_raises():
    out = run_cicdsec(repo_dir="/nonexistent/zz",
                      manifest_paths=["/nonexistent/req.txt"],
                      target="http://127.0.0.1:1", budget=2)
    assert out["findings"] == []
    assert isinstance(out["skipped"], list)


def test_run_cicdsec_end_to_end(git_repo, tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("acme-internal-utils==1.0\n")
    def fetch(method, url, timeout=0):
        return 404, {}, b""
    out = run_cicdsec(repo_dir=str(git_repo),
                      manifest_paths=[str(req)], fetch=fetch)
    assert "git_history" in out["ran"]
    assert any(f["severity"] == "critical" for f in out["findings"])
