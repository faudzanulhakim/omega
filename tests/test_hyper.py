"""Hermetic tests for omega.hyper (the 14-check hyper surface scan).

Local ThreadingHTTPServer fixtures on 127.0.0.1 ephemeral ports or
fully stubbed fetches; no real network egress, no DNS, no destructive
requests. Covers: vulnerable-server discovery, clean-server FP guard,
constant-response FP guard, budget cap, never-raise on broken fetch,
method discipline (GET/OPTIONS only, never TRACE), manual_check real
targets, candidate-only verification, and per-check gates.
"""

import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))))

from omega.hyper import (  # noqa: E402
    backup_artifact_scan,
    directory_listing_detect,
    envfile_exposure,
    fallback_error_intel,
    git_metadata_scan,
    host_header_echo,
    registry,
    run_hyper,
)

ENV_BODY = ("APP_KEY=supersecret\nDB_PASSWORD=hunter2\n"
            "API_KEY=abc123\nMAIL_HOST=smtp.local\n")
SQL_BODY = ("-- MySQL dump 10.13\nCREATE TABLE users (id int);\n"
            "INSERT INTO users VALUES (1,'a');\n")
TRACEBACK_BODY = ("Traceback (most recent call last):\n"
                  "  File \"/app/wsgi.py\", line 42, in <module>\n"
                  "RuntimeError: unhandled\n")


# ------------------------------------------------------------ fixtures

class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # silence
        pass

    def send_response(self, code, message=None):
        # Suppress the default Server header injected by
        # BaseHTTPRequestHandler so the fixtures control their own
        # banner headers exactly.
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def _send(self, status, headers, body=b""):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class VulnHandler(_Base):
    """The 'vulnerable' fixture: every hyper signal present."""

    def _cors_headers(self, headers):
        headers["Access-Control-Allow-Origin"] = "*"
        origin = self.headers.get("Origin")
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        return headers

    def _base_headers(self):
        h = {
            "Server": "TestServ/1.0",
            "X-Powered-By": "PHP/7.9.9",
            "X-XSS-Protection": "1; mode=block",
            "Set-Cookie": "sid=abc123; Path=/",
        }
        return self._cors_headers(h)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path).path
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        h = self._base_headers()
        hosts = ";".join(self.headers.get_all("Host") or [])
        if parsed == "/":
            q = (qs.get("q") or [""])[0]
            self._send(200, h, "Welcome to OmegaTestApp served for %s q=%s"
                       % (hosts, q))
        elif parsed == "/assets/":
            self._send(200, h, "<html><title>Directory listing for "
                               "/assets/</title></html>")
        elif parsed == "/backup.sql":
            self._send(200, h, SQL_BODY)
        elif parsed == "/.env":
            self._send(200, h, ENV_BODY)
        elif parsed == "/.env.local":
            self._send(200, h, ENV_BODY)
        elif parsed == "/.git/HEAD":
            self._send(200, h, "ref: refs/heads/main\n")
        elif parsed == "/.git/config":
            self._send(200, h, "[core]\n\trepositoryformatversion = 0\n")
        elif parsed == "/robots.txt":
            self._send(200, h, "User-agent: *\nDisallow: /admin\n"
                               "Disallow: /private\n")
        elif parsed == "/sitemap.xml":
            self._send(200, h, "<urlset><url><loc>http://x/a</loc></url>"
                               "</urlset>")
        elif parsed == "/.well-known/security.txt":
            self._send(200, h, "Contact: mailto:security@omegatest.example\n")
        else:
            self._send(500, h, TRACEBACK_BODY)

    def do_OPTIONS(self):
        h = self._base_headers()
        h["Allow"] = "GET, HEAD, POST, PUT, DELETE, TRACE"
        self._send(200, h, "")


class CleanHandler(_Base):
    """The clean FP guard: correct headers, 404 for sensitive paths,
    zero findings expected."""

    def do_GET(self):
        h = {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'; "
                                       "frame-ancestors 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        }
        if self.path in ("/", "/login", "/account", "/admin"):
            self._send(200, h, "home page of OmegaTestApp")
        else:
            self._send(404, h, "Not Found - OmegaTestApp")

    def do_OPTIONS(self):
        h = {"Allow": "GET, HEAD, OPTIONS"}
        self._send(200, h, "")


class ConstantHandler(_Base):
    """Identical constant responses for every request (FP guard for the
    differential-first design)."""

    def do_GET(self):
        self._send(200, {"Content-Type": "text/html"}, "static page")

    def do_OPTIONS(self):
        self._send(200, {"Content-Type": "text/html"}, "static page")


class HeadOnlyGitHandler(_Base):
    """/.git/HEAD present but /.git/config absent."""

    def do_GET(self):
        if self.path == "/":
            self._send(200, {}, "home")
        elif self.path == "/.git/HEAD":
            self._send(200, {}, "ref: refs/heads/main\n")
        else:
            self._send(404, {}, "Not Found")


class ThinEnvHandler(_Base):
    """/.env with only 2 KEY=VALUE lines (below the density gate)."""

    def do_GET(self):
        if self.path == "/":
            self._send(200, {}, "home")
        elif self.path == "/.env":
            self._send(200, {}, "APP_NAME=omega\nAPP_ENV=dev\n")
        else:
            self._send(404, {}, "Not Found")


class WildcardOnlyCorsHandler(_Base):
    """ACAO: * on every response, no origin echo (for the cors_wildcard
    check in isolation)."""

    def do_GET(self):
        h = {"Access-Control-Allow-Origin": "*"}
        self._send(200, h, "home")


class BackupFakeHandler(_Base):
    """Returns the SAME generic HTML page for a backup path and the
    fallback path (status 200 alone must not fire)."""

    def do_GET(self):
        self._send(200, {"Content-Type": "text/html"},
                   "<html><body>Not Found</body></html>")


@pytest.fixture
def server_factory():
    made = []

    def make(handler_cls):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        made.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield make
    for srv in made:
        srv.shutdown()


def _sources(findings):
    return [f["source"] for f in findings]


# =============================================== run-level behaviour

def test_vulnerable_server_expected_findings(server_factory):
    base = server_factory(VulnHandler)
    res = run_hyper(base, _real_fetch())
    srcs = _sources(res["findings"])
    for expected in (
        "omega-hyper/directory_listing_detect",
        "omega-hyper/backup_artifact_scan",
        "omega-hyper/envfile_exposure",
        "omega-hyper/git_metadata_scan",
        "omega-hyper/sitemap_robots_intel",
        "omega-hyper/securitytxt_info",
        "omega-hyper/server_banner_fingerprint",
        "omega-hyper/http_methods_preflight",
        "omega-hyper/trace_method_probe",
        "omega-hyper/cookie_flag_audit",
        "omega-hyper/host_header_echo",
        "omega-hyper/content_type_sniffing",
        "omega-hyper/fallback_error_intel",
    ):
        assert expected in srcs, "missing %s (got %s)" % (expected, srcs)
    # origin-echo CORS suppresses the wildcard finding (more specific
    # condition applies)
    assert "omega-hyper/cors_wildcard" not in srcs
    assert res["requests_sent"] <= 60
    assert len(res["ran"]) == len(registry)


def test_clean_server_zero_findings(server_factory):
    base = server_factory(CleanHandler)
    res = run_hyper(base, _real_fetch())
    assert res["findings"] == []
    assert res["requests_sent"] <= 60


def test_constant_server_zero_findings_fp_guard(server_factory):
    """FALSE-POSITIVE GUARD: identical constant responses must produce
    NO findings (differential-first design)."""
    base = server_factory(ConstantHandler)
    res = run_hyper(base, _real_fetch())
    assert res["findings"] == []
    assert set(res["ran"]) == {n for n, _ in registry}


def test_run_never_raises_on_broken_fetch():
    def broken(method, url, headers=None, body=None):
        raise RuntimeError("connection refused")

    res = run_hyper("http://127.0.0.1:1", broken)
    assert res["findings"] == []
    assert len(res["skipped"]) == len(registry)
    assert all(v.startswith("error:") for v in res["skipped"].values())
    assert res["requests_sent"] == 0


def test_budget_cap_enforced(server_factory):
    base = server_factory(VulnHandler)
    res = run_hyper(base, _real_fetch(), budget=5)
    assert res["requests_sent"] <= 5
    assert "budget exhausted" in res["skipped"].values()
    assert len(res["ran"]) < len(registry)


def test_allowlist_blocks_run(server_factory):
    base = server_factory(VulnHandler)
    res = run_hyper(base, _real_fetch(), allowlist=["example.com"])
    assert res["findings"] == []
    assert res["requests_sent"] == 0
    assert "not in allowlist" in res["skipped"]["__all__"]


def test_method_discipline_never_trace(server_factory):
    """Only GET/OPTIONS are ever sent; a real TRACE is never issued."""
    methods = []

    def recording(method, url, headers=None, body=None):
        methods.append(method)
        return 200, {"Set-Cookie": "a=b"}, b"home"

    run_hyper("http://example.test", recording)
    assert set(methods) <= {"GET", "OPTIONS"}


def test_all_verifications_candidate_and_shape(server_factory):
    base = server_factory(VulnHandler)
    res = run_hyper(base, _real_fetch())
    assert res["findings"]
    for f in res["findings"]:
        for key in ("title", "severity", "confidence", "verification",
                    "source", "evidence", "location", "manual_check"):
            assert key in f
        assert f["verification"] == "candidate"  # never 'confirmed'
        assert len(f["evidence"]) <= 300
        assert base in f["manual_check"]  # real target, no placeholder


# ================================================== per-check gates

def test_git_config_high_only_when_config_present(server_factory):
    base = server_factory(HeadOnlyGitHandler)
    findings = git_metadata_scan(base, _real_fetch())
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert all("config" not in f["title"].lower() or f["severity"] != "high"
               for f in findings)


def test_env_density_gate(server_factory):
    """/.env with only 2 KEY=VALUE lines must NOT fire (density gate)."""
    base = server_factory(ThinEnvHandler)
    assert envfile_exposure(base, _real_fetch()) == []


def test_backup_requires_content_differential(server_factory):
    """A 200 status alone on a backup path is never enough."""
    base = server_factory(BackupFakeHandler)
    assert backup_artifact_scan(base, _real_fetch()) == []


def test_cors_wildcard_isolated(server_factory):
    base = server_factory(WildcardOnlyCorsHandler)
    res = run_hyper(base, _real_fetch())
    srcs = _sources(res["findings"])
    assert "omega-hyper/cors_wildcard" in srcs
    assert all(f["severity"] == "low" and f["verification"] == "candidate"
               for f in res["findings"])


def test_directory_listing_needs_marker(server_factory):
    base = server_factory(CleanHandler)
    assert directory_listing_detect(base, _real_fetch()) == []


def test_fallback_error_needs_pattern(server_factory):
    """A plain constant 404 with no traceback/framework pattern is
    silent."""
    base = server_factory(ConstantHandler)
    assert fallback_error_intel(base, _real_fetch()) == []


def test_host_echo_differential(server_factory):
    base = server_factory(VulnHandler)
    findings = host_header_echo(base, _real_fetch())
    assert len(findings) == 1
    assert findings[0]["verification"] == "candidate"
    assert "omega-hh-" in findings[0]["evidence"]
    assert base in findings[0]["manual_check"]


def test_real_fetch_contract():
    """The default fetch contract imported from deepchecks works against
    the local fixture (status, headers dict, bytes body)."""
    from omega.deepchecks import default_fetch  # noqa: E402

    made = []

    def make(handler_cls):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        made.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    try:
        base = make(ConstantHandler)
        st, headers, body = default_fetch("GET", base + "/")
        assert st == 200 and isinstance(headers, dict)
        assert isinstance(body, bytes) and body == b"static page"
    finally:
        for srv in made:
            srv.shutdown()


def _real_fetch():
    from omega.deepchecks import default_fetch  # noqa: E402

    return default_fetch
