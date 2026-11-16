"""Hermetic tests for omega/scanning/jsdeep.py + node/jsdeep.mjs.

The node path is exercised with the REAL node binary (node is installed);
the pure-Python fallback is exercised by forcing the gate/node off.
No network: assets are passed inline; the fetch-based discovery test uses
a fake fetch callable.
"""
import pytest

from omega.scanning.jsdeep import (
    collect_js_assets,
    node_available,
    python_jsdeep,
    run_jsdeep,
    run_node_jsdeep,
)

FIXTURE_JS = """
const LIVE_KEY = "AKIAIOSFODNN7EXAMPLE";
const testPassword = "unittest-password-ignored";
const cfg = { baseURL: "/api/v2" };
fetch("/users/me");
axios.post("/api/login", payload);
xhr.open("GET", "/v1/items");
const g = "AIzaSyA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1v";
//# sourceMappingURL=app.min.js.map
const cdn = `https://cdn.example.com/v1/${id}`;
export default cfg;
"""


@pytest.fixture()
def node_gate(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")


@pytest.fixture()
def no_node(monkeypatch):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)


def kinds(records, kind):
    return [r for r in records if r["kind"] == kind]


def values(records, kind):
    return {r["value"] for r in kinds(records, kind)}


# ------------------------------------------------------------ node engine
def test_node_available_with_gate(node_gate):
    assert node_available() is True


def test_node_unavailable_without_gate(no_node):
    assert node_available() is False


def test_node_jsdeep_finds_secrets(node_gate):
    records = run_node_jsdeep(FIXTURE_JS)
    assert records is not None
    secrets = values(records, "secret")
    assert any(v.startswith("aws_access_key:AKIA") for v in secrets)
    assert any(v.startswith("google_api_key:AIza") for v in secrets)


def test_node_jsdeep_skips_test_vars(node_gate):
    records = run_node_jsdeep(FIXTURE_JS)
    assert records is not None
    joined = " ".join(values(records, "secret"))
    assert "unittest-password" not in joined


def test_node_jsdeep_finds_endpoints_and_sourcemap(node_gate):
    records = run_node_jsdeep(FIXTURE_JS)
    assert records is not None
    eps = values(records, "endpoint")
    assert "/users/me" in eps
    assert "/api/login" in eps
    assert "/api/v2" in eps
    maps = values(records, "sourcemap")
    assert "app.min.js.map" in maps


def test_node_jsdeep_template_literal_urls(node_gate):
    records = run_node_jsdeep(FIXTURE_JS)
    assert records is not None
    assert "https://cdn.example.com/v1/${id}" in values(records, "endpoint")


# --------------------------------------------------------- python fallback
def test_python_fallback_matches_node_secret_kinds(no_node):
    py = run_jsdeep("x", assets=[("inline", FIXTURE_JS)])
    assert py["engine"] == "python"
    recs = python_jsdeep(FIXTURE_JS)
    pysecrets = values(recs, "secret")
    assert any(v.startswith("aws_access_key:AKIA") for v in pysecrets)
    assert any(v.startswith("google_api_key:AIza") for v in pysecrets)


def test_python_fallback_endpoints(no_node):
    recs = python_jsdeep(FIXTURE_JS)
    eps = values(recs, "endpoint")
    assert {"/users/me", "/api/login", "/api/v2", "/v1/items"} <= eps


def test_fallback_on_bad_node(monkeypatch):
    """When node 'exists' but exits non-zero, run_jsdeep falls back."""
    monkeypatch.setenv("PTK_POLYGLOT", "1")
    result = run_jsdeep(
        "x", assets=[("inline", FIXTURE_JS)],
        which_fn=lambda name: "/nonexistent-node" if name == "node" else None)
    assert result["engine"] == "python"
    assert result["findings"]


# ------------------------------------------------------------ orchestration
def test_run_jsdeep_node_engine_findings(node_gate):
    result = run_jsdeep("http://inline.local", assets=[("inline", FIXTURE_JS)])
    assert result["engine"] == "node"
    sev = {f["title"]: f["severity"] for f in result["findings"]}
    assert any(s == "high" for s in sev.values())      # secrets
    assert any(s == "info" for s in sev.values())      # endpoints
    assert any(s == "low" for s in sev.values())       # sourcemap


def test_run_jsdeep_dedupes(node_gate):
    result = run_jsdeep("http://inline.local",
                        assets=[("inline", FIXTURE_JS), ("inline2", FIXTURE_JS)])
    keys = [(f["source"], f["evidence"]["value"])
            for f in result["findings"]]
    assert len(keys) == len(set(keys))


def test_run_jsdeep_finding_shape(node_gate):
    result = run_jsdeep("http://inline.local", assets=[("inline", FIXTURE_JS)])
    for f in result["findings"]:
        assert f["verification"] == "candidate"
        assert f["source"].startswith("omega-jsdeep/")
        assert len(f["evidence"]["matched_line"]) <= 300
        assert isinstance(f["evidence"]["line_no"], int)


def test_run_jsdeep_evidence_is_matched_line(no_node):
    result = run_jsdeep("http://inline.local", assets=[("inline", FIXTURE_JS)])
    secret = next(f for f in result["findings"]
                  if f["source"] == "omega-jsdeep/secret")
    assert "AKIAIOSFODNN7EXAMPLE" in secret["evidence"]["matched_line"]


def test_collect_js_assets_fake_fetch():
    html = b'<html><script src="/static/app.js"></script></html>'
    calls = []

    def fake_fetch(method, url):
        calls.append(url)
        if url == "http://fake.local":
            return 200, {}, html
        return 200, {}, b"fetch('/x'); const k='AKIAIOSFODNN7EXAMPLE';"

    assets = collect_js_assets("http://fake.local", fake_fetch)
    assert len(assets) == 1
    assert assets[0][0] == "http://fake.local/static/app.js"
    assert "AKIA" in assets[0][1]


def test_long_line_evidence_clipped(no_node):
    js = 'const token = "' + "A" * 500 + '";\n'
    recs = python_jsdeep(js)
    for r in recs:
        assert len(r["evidence"]) <= 300
