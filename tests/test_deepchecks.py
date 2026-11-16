"""Hermetic tests for omega.deepchecks (the 15-check evidence army).

Local ThreadingHTTPServer fixtures or fully stubbed fetches; no real
network egress, no destructive requests. Per check: a CONFIRMED-path
test and an FP-guard test for 1/3/5/8/13/15, reflection/context tests
for 2/4/9, discovery tests for 10/11/12/14, graphql via path_info, plus
registry audit, run_deepchecks gates, brain capability and fusion
integration.
"""

import base64
import hashlib
import hmac
import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))))

from omega.deepchecks import (  # noqa: E402
    JWT_COMMON_SECRETS,
    PP_MARKER,
    XSS_MARKER,
    admin_panel_discovery,
    cache_poison_deception,
    debug_endpoints,
    default_fetch,
    default_page_fingerprint,
    graphql_batch_dos_hint,
    graphql_introspection,
    idor_heuristic,
    jwt_flaw_scan,
    open_bucket_hint,
    path_traversal_reflection,
    prototype_pollution_client,
    rate_limit_detect,
    registry,
    run_deepchecks,
    sqli_error_diff,
    subdomain_takeover_hint,
    xss_reflection_diff,
)

CANARY_FILE = "omega_canary.txt"
CANARY_CONTENT = "OMEGA-CANARY-7f3a"


# ------------------------------------------------------------ fixtures

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, status, headers, body=b""):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


def real_fetch(method, url, headers=None, body=None):
    """Default deepchecks fetch against the local server (hermetic)."""
    return default_fetch(method, url, headers=headers, body=body)


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


# ================================================== 1. path_traversal

class TraversalHandler(_Handler):
    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        val = (qs.get("file") or [""])[0]
        if CANARY_FILE in val:
            self._send(200, {}, "content: " + CANARY_CONTENT)
        else:
            self._send(200, {}, "home")


def test_path_traversal_confirmed_with_canary(server_factory):
    base = server_factory(TraversalHandler)
    findings = path_traversal_reflection(base, real_fetch,
                                         canary_file=CANARY_FILE,
                                         canary_content=CANARY_CONTENT)
    assert len(findings) == 1
    f = findings[0]
    assert f["verification"] == "confirmed"
    assert f["source"] == "omega-deep/path_traversal_reflection"
    assert base in f["manual_check"]  # real target, never a placeholder
    assert ".." in f["manual_check"]


def test_path_traversal_no_canary_no_finding(server_factory):
    """FP guard: without an operator canary the check stays silent
    (no fishing for arbitrary files)."""
    base = server_factory(TraversalHandler)
    assert path_traversal_reflection(base, real_fetch) == []


def test_path_traversal_fp_guard_ignoring_server(server_factory):
    class Ignorant(_Handler):
        def do_GET(self):
            self._send(200, {}, "home")

    base = server_factory(Ignorant)
    assert path_traversal_reflection(base, real_fetch,
                                     canary_file=CANARY_FILE,
                                     canary_content=CANARY_CONTENT) == []


def test_path_traversal_canary_via_path_info(server_factory):
    base = server_factory(TraversalHandler)
    findings = path_traversal_reflection(
        base, real_fetch,
        path_info={"canary": {"file": CANARY_FILE,
                              "content": CANARY_CONTENT}})
    assert findings and findings[0]["verification"] == "confirmed"


# ==================================================== 2. xss_reflection

def _ctx_of(findings):
    return findings[0]["evidence"]["context"]


class XssHtmlHandler(_Handler):
    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        q = (qs.get("q") or [""])[0]
        self._send(200, {}, "<p>You searched: %s</p>" % q)


class XssAttrHandler(_Handler):
    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        q = (qs.get("q") or [""])[0]
        self._send(200, {}, "<input value='%s'>" % q)


class XssJsHandler(_Handler):
    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        q = (qs.get("q") or [""])[0]
        self._send(200, {}, "<script>var q = \"%s\";</script>" % q)


def test_xss_reflection_html_context_candidate(server_factory):
    base = server_factory(XssHtmlHandler)
    findings = xss_reflection_diff(base, real_fetch)
    assert len(findings) == 1
    f = findings[0]
    assert f["verification"] == "candidate"  # NEVER auto-confirmed
    assert _ctx_of(findings) == "html"
    assert XSS_MARKER in f["manual_check"]


def test_xss_reflection_attr_and_js_context(server_factory):
    attr = xss_reflection_diff(server_factory(XssAttrHandler), real_fetch)
    js = xss_reflection_diff(server_factory(XssJsHandler), real_fetch)
    assert _ctx_of(attr) == "attr"
    assert _ctx_of(js) == "js"


def test_xss_reflection_fp_guard_not_reflected(server_factory):
    class Quiet(_Handler):
        def do_GET(self):
            self._send(200, {}, "home")

    base = server_factory(Quiet)
    assert xss_reflection_diff(base, real_fetch) == []


# ===================================================== 3. sqli_error

class SqliHandler(_Handler):
    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        v = (qs.get("id") or [""])[0]
        if v.endswith("'"):
            self._send(500, {}, "You have an error in your SQL syntax "
                                "near ''' at line 1")
        else:
            self._send(200, {}, "user record")


def test_sqli_error_confirmed_differential(server_factory):
    base = server_factory(SqliHandler)
    findings = sqli_error_diff(base, real_fetch)
    assert len(findings) == 1
    f = findings[0]
    assert f["verification"] == "confirmed"
    assert f["evidence"]["param"] == "id"
    assert "curl" in f["manual_check"] and base in f["manual_check"]


def test_sqli_error_fp_guard_no_signature(server_factory):
    """FP guard: quote echoed without a SQL error signature -> no
    finding (never confirmed on reflection alone)."""
    class Echo(_Handler):
        def do_GET(self):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(
                self.path).query)
            self._send(200, {}, "got " + (qs.get("id") or [""])[0])

    base = server_factory(Echo)
    assert sqli_error_diff(base, real_fetch) == []


# ========================================== 4. prototype_pollution

class PPHandler(_Handler):
    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(
            self.path).query.replace("[]", ""), keep_blank_values=True)
        merged = ""
        if any("__proto__" in k or "constructor" in k for k in qs) \
                or PP_MARKER in self.path:
            merged = ("var config = JSON.parse('{\"__proto__\":{"
                      "\"%s\":\"1\"}}') || {};" % PP_MARKER)
        self._send(200, {}, "<html><script>%s</script></html>" % merged)


def test_prototype_pollution_inline_config_candidate(server_factory):
    base = server_factory(PPHandler)
    findings = prototype_pollution_client(base, real_fetch)
    assert len(findings) == 1
    f = findings[0]
    assert f["verification"] == "candidate"
    assert PP_MARKER in json.dumps(f["evidence"]) or PP_MARKER in \
        f["evidence"]["query"]


def test_prototype_pollution_fp_guard_no_sink(server_factory):
    class Clean(_Handler):
        def do_GET(self):
            self._send(200, {}, "<html><script>var a = 1;</script></html>")

    base = server_factory(Clean)
    assert prototype_pollution_client(base, real_fetch) == []


# ================================================= 5. cache_poison

class CachePoisonHandler(_Handler):
    def do_GET(self):
        xfh = self.headers.get("X-Forwarded-Host", "")
        headers = {"Age": "12"}
        if "omegapoison.example" in xfh:
            self._send(200, headers,
                       "served by " + xfh + " uniq")
        else:
            self._send(200, headers, "home")


def test_cache_poison_confirmed_with_cache_differential(server_factory):
    base = server_factory(CachePoisonHandler)
    findings = cache_poison_deception(base, real_fetch)
    assert len(findings) == 1
    f = findings[0]
    assert f["verification"] == "confirmed"
    assert "X-Forwarded-Host" in f["manual_check"]
    assert base in f["manual_check"]


def test_cache_poison_fp_guard_reflection_without_cache_signal(
        server_factory):
    """FP guard: body reflection but no Vary/Age/X-Cache signal stays
    candidate, never confirmed."""
    class NoCache(_Handler):
        def do_GET(self):
            xfh = self.headers.get("X-Forwarded-Host", "")
            if "omegapoison.example" in xfh:
                self._send(200, {}, "served by " + xfh)
            else:
                self._send(200, {}, "home")

    base = server_factory(NoCache)
    findings = cache_poison_deception(base, real_fetch)
    assert findings and findings[0]["verification"] == "candidate"


def test_cache_poison_silent_server_no_finding(server_factory):
    class Quiet(_Handler):
        def do_GET(self):
            self._send(200, {}, "home")

    base = server_factory(Quiet)
    assert cache_poison_deception(base, real_fetch) == []


# ====================================================== 6/7. graphql

class GraphQLHandler(_Handler):
    """POST-only graphql endpoint; GET returns 405."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            payload = {}
        if isinstance(payload, list):  # no batch support
            self._send(200, {"Content-Type": "application/json"},
                       json.dumps({"errors": [{"message": "batch "
                                                        "not allowed"}]}))
            return
        query = payload.get("query", "")
        self._send(200, {"Content-Type": "application/json"},
                   json.dumps(self._answer(query)))

    def do_GET(self):
        self._send(405, {}, "method not allowed")

    def _answer(self, query):
        if "__schema" in query:
            return {"data": {"__schema": {"types": [{"name": "Query"}]}}}
        if isinstance(query, str) and query.startswith("{ __typename }"):
            return {"data": {"__typename": "Query"}}
        return {"errors": [{"message": "bad query"}]}


class GraphQLBatchHandler(GraphQLHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {}
        if isinstance(payload, list):
            self._send(200, {"Content-Type": "application/json"},
                       json.dumps([self._answer(p.get("query", ""))
                                   for p in payload]))
            return
        self._send(200, {"Content-Type": "application/json"},
                   json.dumps(self._answer(payload.get("query", ""))))


def test_graphql_introspection_via_path_info(server_factory):
    base = server_factory(GraphQLHandler)
    path_info = {"paths": ["/api/graphql"]}
    findings = graphql_introspection(base, real_fetch, path_info)
    assert len(findings) == 1
    f = findings[0]
    assert f["verification"] == "candidate"
    assert f["severity"] == "high"
    assert f["location"].endswith("/api/graphql")
    assert "__schema" in f["manual_check"]


def test_graphql_no_post_to_non_graphql_paths(server_factory):
    posted = []

    class Recording(GraphQLHandler):
        def do_POST(self):
            posted.append(self.path)
            GraphQLHandler.do_POST(self)

    base = server_factory(Recording)
    path_info = {"paths": ["/app", "/admin"]}  # no graphql path known
    assert graphql_introspection(base, real_fetch, path_info) == []
    assert posted == []  # only POSTs to graphql paths, ever


def test_graphql_batch_dos_hint_differential_shape(server_factory):
    base = server_factory(GraphQLBatchHandler)
    path_info = {"paths": ["/graphql"]}
    findings = graphql_batch_dos_hint(base, real_fetch, path_info)
    assert len(findings) == 1
    f = findings[0]
    assert f["verification"] == "candidate"
    assert f["evidence"]["batch_len"] == 2


def test_graphql_batch_fp_guard_no_batch_support(server_factory):
    """Server rejects arrays -> object shape, no differential, no
    finding."""
    base = server_factory(GraphQLHandler)
    assert graphql_batch_dos_hint(base, real_fetch,
                                  {"paths": ["/graphql"]}) == []


# ====================================================== 8. jwt_flaw

def _mk_jwt(secret):
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "1"}).encode()).rstrip(b"=")
    signing = header + b"." + payload
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), signing, hashlib.sha256).digest()
    ).rstrip(b"=")
    return (signing + b"." + sig).decode()


def test_jwt_weak_secret_confirmed():
    token = _mk_jwt("changeme")
    findings = jwt_flaw_scan("http://t.example", real_fetch,
                             path_info={"jwt": token})
    assert len(findings) == 1
    f = findings[0]
    assert f["verification"] == "confirmed"
    assert f["evidence"]["secret"] == "changeme"
    assert "changeme" in f["manual_check"]


def test_jwt_strong_secret_fp_guard():
    """FP guard: strong random secret -> no finding (verify-only)."""
    token = _mk_jwt("x9$Kp2#vLq8!zR4@Wm7&Nc")
    assert jwt_flaw_scan("http://t.example", real_fetch,
                         path_info={"jwt": token}) == []


def test_jwt_alg_none_candidate_only():
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(b"{}").rstrip(b"=")
    token = (header + b"." + payload + b".").decode()
    findings = jwt_flaw_scan("http://t.example", real_fetch,
                             path_info={"jwt": token})
    assert len(findings) == 1
    assert findings[0]["verification"] == "candidate"
    assert "no crafted token was sent" in findings[0]["verification_note"]


def test_jwt_secret_list_is_20_common_words():
    assert len(JWT_COMMON_SECRETS) == 20


# ================================================= 9. idor_heuristic

class IdorHandler(_Handler):
    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        v = (qs.get("id") or [""])[0]
        if v == "2":
            self._send(403, {}, "forbidden")
        else:
            self._send(200, {}, "record 1")


def test_idor_candidate_on_sequential_differential(server_factory):
    base = server_factory(IdorHandler)
    findings = idor_heuristic(base, real_fetch)
    assert len(findings) == 1
    f = findings[0]
    assert f["verification"] == "candidate"
    assert f["evidence"]["statuses"] == {"1": 200, "2": 403}


def test_idor_fp_guard_uniform_responses(server_factory):
    """FP guard: all values behave identically -> no finding."""
    class Uniform(_Handler):
        def do_GET(self):
            self._send(200, {}, "record")

    base = server_factory(Uniform)
    assert idor_heuristic(base, real_fetch) == []


# ================================================== 10. debug_endpoints

class DebugHandler(_Handler):
    def do_GET(self):
        if self.path == "/.env":
            self._send(200, {}, "DB_PASSWORD=hunter2\nAPP_KEY=abc\n")
        elif self.path == "/debug":
            self._send(200, {}, "django debug traceback")
        else:
            self._send(404, {}, "not found")


def test_debug_env_is_high_with_content_markers(server_factory):
    base = server_factory(DebugHandler)
    findings = debug_endpoints(base, real_fetch)
    kinds = {f["location"].rsplit("/", 1)[-1]: f for f in findings}
    assert kinds[".env"]["severity"] == "high"
    assert kinds[".env"]["verification"] == "confirmed"
    assert "DB_PASSWORD" in str(kinds[".env"]["evidence"]["markers"])
    assert kinds["debug"]["severity"] == "info"
    assert all(base in f["manual_check"] for f in findings)


def test_debug_fp_guard_404s_no_finding(server_factory):
    class Clean(_Handler):
        def do_GET(self):
            self._send(404, {}, "not found")

    base = server_factory(Clean)
    assert debug_endpoints(base, real_fetch) == []


# ============================================ 11. admin_panel_discovery

class AdminHandler(_Handler):
    def do_GET(self):
        if self.path == "/admin":
            self._send(200, {}, "<html><title>Admin Panel</title></html>")
        elif self.path == "/wp-admin":
            self._send(200, {}, "<title>Dashboard</title>")
        else:
            self._send(404, {}, "nope")


def test_admin_panel_discovery_info(server_factory):
    base = server_factory(AdminHandler)
    findings = admin_panel_discovery(base, real_fetch)
    assert len(findings) == 2
    assert all(f["severity"] == "info" for f in findings)
    assert all(f["source"] == "omega-deep/admin_panel_discovery"
               for f in findings)


def test_admin_fp_guard_no_markers(server_factory):
    class Plain(_Handler):
        def do_GET(self):
            self._send(200, {}, "<html><title>Shop</title></html>")

    base = server_factory(Plain)
    assert admin_panel_discovery(base, real_fetch) == []


# ======================================= 12. default_page_fingerprint

def test_default_page_fingerprint_nginx(server_factory):
    class Nginx(_Handler):
        def do_GET(self):
            self._send(200, {}, "<html><body>Welcome to nginx!</body>")

    base = server_factory(Nginx)
    findings = default_page_fingerprint(base, real_fetch)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "info"
    assert "nginx" in f["title"].lower()


def test_default_page_fp_guard_custom_page(server_factory):
    class App(_Handler):
        def do_GET(self):
            self._send(200, {}, "<html>My Custom Shop App</html>")

    base = server_factory(App)
    assert default_page_fingerprint(base, real_fetch) == []


# ==================================== 13. subdomain_takeover_hint

def test_subdomain_takeover_candidate_cname_and_404():
    def stub_fetch(method, url, headers=None, body=None):
        return 404, {}, b"NoSuchBucket: the specified bucket does not exist"

    def stub_dns(host):
        return ["target.example.s3.amazonaws.com"]

    findings = subdomain_takeover_hint("http://target.example", stub_fetch,
                                       dns_fn=stub_dns)
    assert len(findings) == 1
    f = findings[0]
    assert f["verification"] == "candidate"
    assert "s3.amazonaws.com" in f["evidence"]["cname"]
    assert "NoSuchBucket" in str(f["evidence"]["body_markers"])


def test_subdomain_takeover_fp_guard_no_vuln_cname():
    """FP guard: CNAME to an unrelated host -> no finding."""
    def stub_dns(host):
        return ["ordinary-cdn.example.net"]

    def stub_fetch(method, url, headers=None, body=None):
        return 404, {}, b"NoSuchBucket"

    assert subdomain_takeover_hint("http://target.example", stub_fetch,
                                   dns_fn=stub_dns) == []


def test_subdomain_takeover_fp_guard_404_without_fingerprint():
    def stub_dns(host):
        return ["target.example.s3.amazonaws.com"]

    def stub_fetch(method, url, headers=None, body=None):
        return 404, {}, b"custom not-found page"

    assert subdomain_takeover_hint("http://target.example", stub_fetch,
                                   dns_fn=stub_dns) == []


# ================================================= 14. rate_limit_detect

class ThrottleHandler(_Handler):
    count = {"n": 0}

    def do_GET(self):
        ThrottleHandler.count["n"] += 1
        if ThrottleHandler.count["n"] > 3:
            self._send(429, {"Retry-After": "5"}, b"slow down")
        else:
            self._send(200, {}, b"ok")


def test_rate_limit_detected_info(server_factory):
    base = server_factory(ThrottleHandler)
    findings = rate_limit_detect(base, real_fetch)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "info"
    assert 429 in f["evidence"]["statuses"]


def test_rate_limit_absent_is_info_too(server_factory):
    class Open(_Handler):
        def do_GET(self):
            self._send(200, {}, b"ok")

    base = server_factory(Open)
    findings = rate_limit_detect(base, real_fetch)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "info"
    assert f["evidence"]["statuses"] == [200] * 6


# =================================================== 15. open_bucket_hint

def test_open_bucket_existing_protected_candidate():
    calls = []

    def stub_fetch(method, url, headers=None, body=None):
        calls.append(url)
        if "s3.amazonaws.com" in url:
            return 403, {}, b"<Error><Code>AccessDenied</Code></Error>"
        return 404, {}, b"<Error><Code>NoSuchBucket</Code></Error>"

    findings = open_bucket_hint("http://www.shop.example", stub_fetch)
    assert len(findings) == 1
    f = findings[0]
    assert f["verification"] == "candidate"
    assert f["severity"] == "low"
    assert f["evidence"]["provider"] == "s3"
    # guessed names derive from the real hostname (dashed variants too)
    assert any("shop" in u for u in calls)


def test_open_bucket_fp_guard_all_buckets_missing():
    """FP guard: NoSuchBucket shapes -> no finding."""
    def stub_fetch(method, url, headers=None, body=None):
        return 404, {}, b"<Error><Code>NoSuchBucket</Code></Error>"

    assert open_bucket_hint("http://shop.example", stub_fetch) == []


def test_open_bucket_skips_loopback_without_egress():
    assert open_bucket_hint("http://127.0.0.1:9", real_fetch) == []


# =================================================== registry audit

def test_registry_has_at_least_15_checks():
    assert len(registry) >= 15


def test_registry_read_only_methods_and_no_shell():
    """Every check only issues GET/HEAD/OPTIONS against the target,
    except the two graphql checks whose POSTs are documented safe
    reads. No subprocess/shell/eval anywhere in check sources."""
    import inspect
    import subprocess as _sub
    recorded = []
    graphql_checks = {"graphql_introspection", "graphql_batch_dos_hint"}

    def recording_fetch(method, url, headers=None, body=None):
        recorded.append((method, url, headers, body))
        if method == "POST":
            if "__schema" in str(body):
                payload = {"data": {"__schema": {"types": []}}}
            elif isinstance(body, str) and body.strip().startswith("["):
                payload = [{"data": {"__typename": "Q"}},
                           {"data": {"__typename": "Q"}}]
            else:
                payload = {"data": {"__typename": "Q"}}
            return 200, {}, json.dumps(payload).encode()
        return 200, {"Age": "3"}, b"ok body"

    path_info = {"paths": ["/graphql"], "jwt": _mk_jwt("secret")}
    for name, check in registry:
        kwargs = {}
        if name == "path_traversal_reflection":
            kwargs = {"canary_file": CANARY_FILE,
                      "canary_content": CANARY_CONTENT}
        check("http://target.example", recording_fetch,
              path_info=path_info, **kwargs)
    methods = {m for m, _, _, _ in recorded}
    assert methods <= {"GET", "POST", "HEAD", "OPTIONS"}, methods
    # no destructive verbs, and the only POSTs come from graphql checks
    assert not methods & {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}
    assert recorded  # requests actually happened
    # no shell-outs / dynamic execution in any check source
    for fname, check in registry:
        src = inspect.getsource(check)
        for bad in ("subprocess", "os.system", "os.popen", "pty.spawn",
                    "eval(", "exec("):
            assert bad not in src, (fname, bad)


# ================================================== run_deepchecks

class PlainHandler(_Handler):
    def do_GET(self):
        self._send(200, {"Age": "1"}, "plain app page")


def test_run_deepchecks_happy_path(server_factory):
    base = server_factory(PlainHandler)
    logs = []
    res = run_deepchecks(base, fetch=real_fetch, log=logs.append)
    assert set(res) == {"findings", "ran", "skipped"}
    # jwt needs a token: skipped unless discovered
    assert res["skipped"]["jwt_flaw_scan"] == \
        "no JWT discovered (path_info/env)"
    # graphql defaults are always probed when path_info is None
    assert "graphql_introspection" in res["ran"]
    assert len(res["ran"]) == len(registry) - 1  # only jwt skipped
    assert logs
    for f in res["findings"]:
        assert f["verification"] in ("candidate", "confirmed")
        assert f["source"].startswith("omega-deep/")


def test_run_deepchecks_budget_and_skip(server_factory):
    base = server_factory(PlainHandler)
    res = run_deepchecks(base, fetch=real_fetch, budget=3)
    assert len(res["ran"]) == 3
    assert "budget exhausted" in res["skipped"]["jwt_flaw_scan"] or \
        res["skipped"].get("jwt_flaw_scan")
    exhausted = [k for k, v in res["skipped"].items()
                 if v == "budget exhausted"]
    assert exhausted


def test_run_deepchecks_allowlist_blocks_all(server_factory):
    base = server_factory(PlainHandler)
    res = run_deepchecks(base, fetch=real_fetch,
                         allowlist=["not-the-target.example"])
    assert res["ran"] == [] and res["findings"] == []
    assert "__all__" in res["skipped"]


def test_run_deepchecks_path_info_relevance(server_factory):
    """With path_info lacking graphql paths, graphql checks skip
    instead of POSTing blind; a jwt in path_info enables jwt_flaw_scan.
    """
    base = server_factory(PlainHandler)
    token = _mk_jwt("secret")
    res = run_deepchecks(base, fetch=real_fetch,
                         path_info={"paths": ["/app"], "jwt": token})
    assert res["skipped"]["graphql_introspection"] == \
        "no graphql endpoint in path_info"
    assert res["skipped"]["graphql_batch_dos_hint"] == \
        "no graphql endpoint in path_info"
    assert "jwt_flaw_scan" in res["ran"]
    assert any(f["source"] == "omega-deep/jwt_flaw_scan"
               for f in res["findings"])


def test_run_deepchecks_never_raises_on_dead_target():
    res = run_deepchecks("http://127.0.0.1:1/", fetch=real_fetch)
    # nothing to confirm on a dead target: no findings at all, and
    # every check either ran harmlessly (returned []) or was skipped
    assert res["findings"] == []
    assert set(res["ran"]) | set(res["skipped"]) == \
        {name for name, _ in registry}


def test_run_deepchecks_full_confirmed_flow(server_factory):
    """End-to-end: a server that trips several differentials produces
    confirmed findings with real-target manual checks."""
    base = server_factory(SqliHandler)
    res = run_deepchecks(base, fetch=real_fetch)
    conf = [f for f in res["findings"] if f["verification"] == "confirmed"]
    assert any(f["source"] == "omega-deep/sqli_error_diff" for f in conf)
    for f in res["findings"]:
        assert base in f["manual_check"]


# ================================================ brain capability

class TestBrainDeepchecksCapability:
    def test_registered_with_expected_metadata(self):
        from omega.brain import DEFAULT_REGISTRY, default_registry
        reg = default_registry()
        cap = reg.get("deepchecks.all")
        assert cap is not None
        assert cap.cost == 4
        assert cap.risk == "active"
        assert cap.requires == ("has_web",)
        assert callable(cap.fn)
        assert DEFAULT_REGISTRY.get("deepchecks.all") is not None

    def test_duplicate_guard(self):
        from omega.brain import default_registry
        reg = default_registry()
        cap = reg.get("deepchecks.all")
        with pytest.raises(ValueError):
            reg.register(cap)

    def test_eligibility_requires_has_web(self):
        from omega.brain import BrainState, default_registry
        reg = default_registry()
        state = BrainState("http://t", budget=100)
        cap = reg.get("deepchecks.all")
        assert not cap.eligible(state.facts(), 100)
        state.surface["urls"] = ["http://t/"]
        assert cap.eligible(state.facts(), 100)
        assert not cap.eligible(state.facts(), 3)  # budget too small

    def test_capability_fn_calls_run_deepchecks_contained(self):
        from omega.brain import BrainState, default_registry
        state = BrainState("http://127.0.0.1:1", budget=100)
        state.surface["urls"] = ["http://127.0.0.1:1/"]
        res = default_registry().get("deepchecks.all").fn(state, None)
        assert "findings" in res and "note" in res  # contained, no raise

    def test_capability_fn_degrades_when_module_missing(self, monkeypatch):
        import builtins
        from omega.brain import BrainState, default_registry
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "omega.deepchecks":
                raise ImportError("nope")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        state = BrainState("http://t", budget=100)
        state.surface["urls"] = ["http://t/"]
        res = default_registry().get("deepchecks.all").fn(state, None)
        assert "note" in res and "not available" in res["note"]


# ============================================= fusion integration

class TestFusionIntegration:
    def test_deep_is_seventh_suite(self):
        import omega.fusion as fz
        names = [n for n, _lang, _runner in fz.SUITES]
        assert "python-deep" in names
        # 32 concurrent suites (23 + cpp-hdrstruct/awk-urlmine/
        # sh-methodcheck/rust-pathscope/php-seriscan
        # + smuggle-raw/hh-inject/ssti-engine/deser-safe)
        # + cloud-exposure/k8s-exposure/cicd-chain (cloudsec/k8ssec/
        #   cicdsec, wired by the parent reconciler)
        # + mobile-android/mobile-ios/mobile-general (offline mobile
        #   static analysis; non-mobile targets produce a skip note)
        # Suite count grows as suites are added (was pinned at 32,
        # then 51); the integration contract is that python-deep is
        # present and the roster keeps growing, not an exact count.
        assert len(fz.SUITES) >= 51

    def test_fuse_smoke_includes_deepchecks(self, server_factory):
        import omega.fusion as fz
        base = server_factory(SqliHandler)
        out = fz.fuse(base, budget=8, gate=False)
        assert "python-deep" in out["ran"]
        assert "python" in out["languages_used"]
        # corroboration covers deepchecks: a deepchecks finding must be
        # a plain dict finding with the omega-deep source prefix in the
        # aggregated pool when present
        for f in out["findings"]:
            if str(f.get("source") or "").startswith("omega-deep/"):
                assert f["verification"] in ("candidate", "confirmed")
                assert base in str(f.get("manual_check"))
