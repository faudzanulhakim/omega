"""Tests for the attackscan suite: Go core build + Python fallback
checks, fusion registration, and gate behaviour.
"""

import os
import shutil
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


def _fetch_app():
    """In-memory lab app with injectable behaviours."""
    state = {"calls": [], "mode": set()}

    def fetch(method, url, headers=None, body=None):
        state["calls"].append((method, url, body))
        if url.endswith("/nosqli"):
            b = b'{"ok":true}'
            if body and '"$ne"' in body:
                b = (b'{"ok":true,"user":{"name":"admin",'
                     b'"role":"admin","token":"AAAAAAAAAAAAAAAAAAAAAAAA'
                     b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}')
            return (200, {"Content-Type": "application/json"}, b)
        if "omegacp=" in url and state.get("poison_store"):
            # cache-stores the unkeyed header: echoes it on every
            # subsequent request, poisoned or clean
            xfh = (headers or {}).get("X-Forwarded-Host", "")
            if xfh:
                state["xfh"] = xfh
            return (200, {},
                    b"<html>host=" + state.get("xfh", "").encode()
                    + b"</html>")
        if ".js" in url and state.get("cdecep"):
            return (200, {"Content-Type": "text/html"},
                    b"<html>logout dashboard profile</html>")
        if url.endswith("/assign"):
            if body and "role=admin" in body:
                return (201, {}, b'{"created":true,"role":"admin",'
                        b'"granted":["*","*","*","*","*","*"]}')
            return (201, {}, b'{"created":true}')
        return (404, {}, b"not found")

    return fetch, state


# ---------------------------------------------------------------------------
# gate
# ---------------------------------------------------------------------------

def test_gate_closed_returns_empty():
    from omega.scanning.attackscan import run_attackscan
    os.environ.pop("PTK_POLYGLOT", None)
    fetch, _ = _fetch_app()
    assert run_attackscan("http://lab.local", fetch=fetch,
                          gate=lambda: False) == []


# ---------------------------------------------------------------------------
# Go core
# ---------------------------------------------------------------------------

def test_go_core_builds_and_runs_smoke():
    pytest.importorskip("subprocess")
    if shutil.which("go") is None:
        pytest.skip("go toolchain not available")
    src = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "omega", "adapters", "go",
        "attackscan.go")
    out = os.path.join(tempfile.gettempdir(), "attackscan-smoke")
    proc = subprocess.run(["go", "build", "-o", out, src],
                          capture_output=True, timeout=120)
    assert proc.returncode == 0, proc.stderr.decode()
    r = subprocess.run([out],
                       input=b'{"target":"http://127.0.0.1:9",'
                             b'"checks":["cachepoison"]}',
                       capture_output=True, timeout=30)
    assert b'"results"' in r.stdout


def test_native_registry_includes_attackscan():
    from omega.adapters.native import NATIVE_TOOLS
    assert "attackscan" in NATIVE_TOOLS


# ---------------------------------------------------------------------------
# python fallback differentials
# ---------------------------------------------------------------------------

def test_fallback_nosqli_differential():
    from omega.scanning.attackscan import python_fallback
    fetch, _ = _fetch_app()
    findings = python_fallback("http://lab.local", fetch,
                               paths=["/nosqli"],
                               checks=("nosqli",))
    assert any(f["source"] == "omega-attackscan/nosqli" for f in findings)
    f = findings[0]
    assert f["verification"] == "candidate"
    assert f["severity"] == "high"


def test_fallback_clean_target_no_findings():
    from omega.scanning.attackscan import python_fallback
    fetch, _ = _fetch_app()
    findings = python_fallback("http://clean.local", fetch,
                               paths=["/nothing"],
                               checks=("nosqli", "massassign",
                                       "protopoll", "cachepoison"))
    assert findings == []


def test_fallback_massassign_differential():
    from omega.scanning.attackscan import python_fallback
    fetch, _ = _fetch_app()
    findings = python_fallback("http://lab.local", fetch,
                               paths=["/assign"],
                               checks=("massassign",))
    assert findings, "massassign differential must fire"
    assert findings[0]["severity"] == "high"
    assert "status 201->201" in findings[0]["manual_check"] or \
        "body delta" in findings[0]["manual_check"]


def test_fallback_cachepoison_stored_vs_reflected():
    from omega.scanning.attackscan import python_fallback
    fetch, state = _fetch_app()
    state["poison_store"] = True
    findings = python_fallback("http://lab.local", fetch,
                               paths=["/poison"],
                               checks=("cachepoison",))
    assert findings
    assert findings[0]["severity"] == "high"
    assert "stored" in findings[0]["title"].lower()


def test_fallback_cachedecep_needs_cookie():
    from omega.scanning.attackscan import python_fallback
    fetch, state = _fetch_app()
    state["cdecep"] = True
    assert python_fallback("http://lab.local", fetch,
                           checks=("cachedecep",)) == []
    findings = python_fallback("http://lab.local", fetch,
                               cookie="sess=1",
                               paths=["/cache-decep"],
                               checks=("cachedecep",))
    assert findings and findings[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# suite entry
# ---------------------------------------------------------------------------

def test_run_attackscan_uses_go_or_fallback():
    from omega.scanning.attackscan import run_attackscan
    fetch, _ = _fetch_app()
    os.environ["PTK_POLYGLOT"] = "1"
    try:
        findings = run_attackscan("http://lab.local", fetch=fetch,
                                  path_info={"paths": ["/nosqli",
                                                       "/assign"]},
                                  gate=lambda: True)
        assert isinstance(findings, list)
        for f in findings:
            assert f["source"].startswith("omega-attackscan/")
    finally:
        os.environ.pop("PTK_POLYGLOT", None)


def test_run_attackscan_dedupes():
    from omega.scanning.attackscan import run_attackscan
    fetch, _ = _fetch_app()
    findings = run_attackscan("http://lab.local", fetch=fetch,
                              path_info={"paths": ["/nosqli",
                                                   "/nosqli"]},
                              gate=lambda: True)
    titles = [(f["title"], f["location"]) for f in findings]
    assert len(titles) == len(set(titles))


# ---------------------------------------------------------------------------
# fusion registration
# ---------------------------------------------------------------------------

def test_fusion_includes_attackscan_suite():
    from omega.scanning.fusion import SUITES
    names = [s[0] for s in SUITES]
    assert "attackscan" in names
    entry = [s for s in SUITES if s[0] == "attackscan"][0]
    assert entry[1] == "go+python"
