"""Tests for the Go network microtools batch: portsweep, subhunt,
tlsprobe, smuggler, udpsweep, swarm, sniffy, fuzzwave — Go build+smoke
and the Python runner layer (gate, findings, control-gating).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

GO_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "omega", "adapters", "go")

TOOLS = ["portsweep", "subhunt", "tlsprobe", "smuggler", "udpsweep",
         "swarm", "sniffy", "fuzzwave"]

if not shutil.which("go"):
    pytest.skip("go toolchain not available", allow_module_level=True)


# ----------------------------------------------------------- lab app

@pytest.fixture(scope="module")
def lab_app():
    """Small HTTP lab: /admin exists, everything else 404."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/admin"):
                body = b"<html><title>Admin</title>secret</html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length",
                                 str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                body = b"<html>not found page filler filler filler" \
                       b" filler filler filler filler</html>"
                self.send_response(404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d" % srv.server_address[1], \
        "127.0.0.1", srv.server_address[1]
    srv.shutdown()


@pytest.fixture(scope="module")
def binaries(tmp_path_factory):
    """Compile every Go tool once for the module."""
    out_dir = tmp_path_factory.mktemp("bin")
    out = {}
    for name in TOOLS:
        src = os.path.join(GO_DIR, name + ".go")
        dst = str(out_dir / name)
        proc = subprocess.run(["go", "build", "-o", dst, src],
                              capture_output=True, timeout=180)
        assert proc.returncode == 0, \
            f"{name}: {proc.stderr.decode()}"
        out[name] = dst
    return out


def run_tool(binary, payload, timeout=120):
    proc = subprocess.run([binary], input=json.dumps(payload).encode(),
                          capture_output=True, timeout=timeout)
    assert proc.returncode == 0, proc.stderr.decode()
    return json.loads(proc.stdout.decode())


# ------------------------------------------------- Go smoke tests

def test_portsweep_find_open_port(binaries, lab_app):
    _, host, port = lab_app
    doc = run_tool(binaries["portsweep"],
                   {"host": host, "ports": [port, 1], "timeout_ms": 800})
    ports = [r["port"] for r in doc["open"]]
    assert port in ports and 1 not in ports


def test_subhunt_invalid_input(binaries):
    doc = run_tool(binaries["subhunt"], {"domain": ""})
    assert "error" in doc


def test_tlsprobe_output_shape(binaries):
    # no server listening: must degrade to empty/failed gracefully
    doc = run_tool(binaries["tlsprobe"],
                   {"host": "127.0.0.1", "port": 1, "timeout_ms": 800})
    assert "versions" in doc and "weak" in doc


def test_smuggler_control_gate(binaries, lab_app):
    url, host, port = lab_app
    doc = run_tool(binaries["smuggler"], {"target": url})
    # control pair against the simple lab must be healthy
    assert doc["control_ok"] is True


def test_udpsweep_no_opens(binaries):
    doc = run_tool(binaries["udpsweep"],
                   {"host": "127.0.0.1", "timeout_ms": 600})
    assert doc["open"] == []


def test_swarm_local_fallback(binaries, lab_app):
    url, _, _ = lab_app
    doc = run_tool(binaries["swarm"],
                   {"targets": [url + "/admin", url + "/x"]})
    rows = doc["results"]
    assert len(rows) == 2
    assert rows[0]["status"] == 200 and "Admin" in rows[0]["title"]


def test_sniffy_privilege_note(binaries):
    doc = run_tool(binaries["sniffy"], {})
    assert doc["privileged"] is False


def test_fuzzwave_adaptive_filter(binaries, lab_app):
    url, _, _ = lab_app
    doc = run_tool(binaries["fuzzwave"],
                   {"target": url, "paths": ["/admin", "/zzz"],
                    "concurrency": 4, "timeout_ms": 1500})
    by_path = {r["path"]: r["class"] for r in doc["results"]}
    assert by_path["/admin"] == "exists"
    assert by_path["/zzz"] in ("missing", "soft404")


# ------------------------------------------------- Python runners

def test_registry_contains_all_new_tools():
    from omega.adapters.native import NATIVE_TOOLS
    for name in TOOLS:
        assert name in NATIVE_TOOLS


def test_brain_caps_registered():
    from omega.core.brain import DEFAULT_REGISTRY
    for name in TOOLS:
        assert DEFAULT_REGISTRY.get("polyglot." + name) is not None


def test_runners_gate_closed_by_default():
    os.environ.pop("PTK_POLYGLOT", None)
    from omega.adapters import gotools_net
    out = gotools_net.run_portsweep("127.0.0.1")
    skipped = out.get("skipped") or {}
    assert any("PTK_POLYGLOT" in str(v) for v in skipped.values())


def test_runners_smoke_portsweep(lab_app):
    os.environ["PTK_POLYGLOT"] = "1"
    os.environ["_GOTL_SHUTTLE"] = "1"  # skip the shutil.which re-check
    from omega.adapters import native, gotools_net
    try:
        _, host, port = lab_app
        out = gotools_net.run_portsweep(host, ports=[port],
                                        timeout_ms=800,
                                        gate_open_fn=lambda: True)
        assert "portsweep" in (out.get("ran") or [])
        titles = [f["title"] for f in out.get("findings") or []]
        assert any(str(port) in t for t in titles)
        for f in out.get("findings") or []:
            assert f["verification"] == "candidate"
            assert f["manual_check"]
    finally:
        os.environ.pop("PTK_POLYGLOT", None)
        os.environ.pop("_GOTL_SHUTTLE", None)


def test_runners_smoke_fuzzwave_high_severity(lab_app):
    os.environ["PTK_POLYGLOT"] = "1"
    os.environ["_GOTL_SHUTTLE"] = "1"
    from omega.adapters import gotools_net
    try:
        url, _, _ = lab_app
        out = gotools_net.run_fuzzwave(
            url, ["/admin", "/config", "/zzz"],
            concurrency=4, timeout_ms=1500,
            gate_open_fn=lambda: True)
        by_title = {f["title"]: f for f in out.get("findings") or []}
        admin = [f for t, f in by_title.items()
                 if t.startswith("content discovered") and "admin" in t]
        assert admin and admin[0]["severity"] == "HIGH"
        assert all("curl" in f["manual_check"]
                   for f in by_title.values())
    finally:
        os.environ.pop("PTK_POLYGLOT", None)
        os.environ.pop("_GOTL_SHUTTLE", None)


def test_runners_smoke_swarm(lab_app):
    os.environ["PTK_POLYGLOT"] = "1"
    os.environ["_GOTL_SHUTTLE"] = "1"
    from omega.adapters import gotools_net
    try:
        url, _, _ = lab_app
        out = gotools_net.run_swarm([url + "/admin"],
                                    gate_open_fn=lambda: True)
        assert "swarm" in (out.get("ran") or [])
        assert any(f["severity"] == "INFO"
                   for f in out.get("findings") or [])
    finally:
        os.environ.pop("PTK_POLYGLOT", None)
        os.environ.pop("_GOTL_SHUTTLE", None)


def test_runners_smoke_sniffy_no_privilege():
    os.environ["PTK_POLYGLOT"] = "1"
    os.environ["_GOTL_SHUTTLE"] = "1"
    from omega.adapters import gotools_net
    try:
        out = gotools_net.run_sniffy(seconds=1,
                                     gate_open_fn=lambda: True)
        assert "sniffy" in (out.get("ran") or [])
        assert out.get("findings") in (None, [], ())
        assert (out.get("surface") or {}).get("sniffy", {}).get(
            "privileged") is False
    finally:
        os.environ.pop("PTK_POLYGLOT", None)
        os.environ.pop("_GOTL_SHUTTLE", None)


def test_runners_smoke_udpsweep():
    os.environ["PTK_POLYGLOT"] = "1"
    os.environ["_GOTL_SHUTTLE"] = "1"
    from omega.adapters import gotools_net
    try:
        out = gotools_net.run_udpsweep("127.0.0.1", timeout_ms=600,
                                       gate_open_fn=lambda: True)
        assert "udpsweep" in (out.get("ran") or [])
        assert out.get("findings") in (None, [], ())
    finally:
        os.environ.pop("PTK_POLYGLOT", None)
        os.environ.pop("_GOTL_SHUTTLE", None)


def test_runners_smoke_tlsprobe():
    os.environ["PTK_POLYGLOT"] = "1"
    os.environ["_GOTL_SHUTTLE"] = "1"
    from omega.adapters import gotools_net
    try:
        out = gotools_net.run_tlsprobe("127.0.0.1", port=1,
                                       timeout_ms=800,
                                       gate_open_fn=lambda: True)
        assert "tlsprobe" in (out.get("ran") or [])
        assert out.get("findings") in (None, [], ())
    finally:
        os.environ.pop("PTK_POLYGLOT", None)
        os.environ.pop("_GOTL_SHUTTLE", None)


def test_runners_smoke_subhunt(tmp_path):
    os.environ["PTK_POLYGLOT"] = "1"
    os.environ["_GOTL_SHUTTLE"] = "1"
    from omega.adapters import gotools_net
    try:
        out = gotools_net.run_subhunt("nonexistent-zzz.local",
                                      words=["a"], do_ct=False,
                                      gate_open_fn=lambda: True)
        assert "subhunt" in (out.get("ran") or [])
    finally:
        os.environ.pop("PTK_POLYGLOT", None)
        os.environ.pop("_GOTL_SHUTTLE", None)
