"""Tests for batch-16 PHANTOM: verbtamper, jsmine, shadowdisc,
crlfprobe, subdgraph, idororacle, narrgen, noiseaudit."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


class R:
    def __init__(self, text="", status=200, headers=None):
        self.status = status
        self.text = text
        self.headers = headers or {}


def gate_env():
    os.environ["PTK_OFFENSE"] = "1"


def ungate():
    os.environ.pop("PTK_OFFENSE", None)


@pytest.mark.parametrize("mod,fn,args", [
    ("verbtamper", "run_verbtamper", ("http://x/", None)),
    ("jsmine", "run_jsmine", ("http://x/", None)),
    ("shadowdisc", "run_shadowdisc", ("http://x/", None)),
    ("crlfprobe", "run_crlfprobe", ("http://x/", None)),
    ("idororacle", "run_idororacle", ("http://x/", None)),
])
def test_phantom_modules_gate(mod, fn, args):
    import importlib
    m = importlib.import_module(f"omega.offensive.offense.{mod}")
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        out = getattr(m, fn)(*args)
        assert "PTK_OFFENSE" in out.get("note", "")
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


# ---------------------------------------------------------- verbtamper
def test_verbtamper_put_bypass():
    from omega.offensive.offense.verbtamper import run_verbtamper

    def fetch(url, method="GET", body=None):
        if url.endswith("/admin") and method == "GET":
            return R("forbidden", 403)
        if url.endswith("/admin"):
            return R('{"users":[]}', 200)  # non-GET passes = bypass
        return R("ok", 200)

    gate_env()
    try:
        out = run_verbtamper("http://t.local", fetch=fetch)
    finally:
        ungate()
    assert out["findings"]
    f = out["findings"][0]
    assert f["cwe"] == "CWE-285" and "accepts" in f["title"]


def test_verbtamper_generic_200_not_flagged():
    from omega.offensive.offense.verbtamper import run_verbtamper

    def fetch(url, method="GET", body=None):
        # GET denied; non-GET returns SAME body as the denial — no
        # materially different response
        return R("forbidden", 403)

    gate_env()
    try:
        out = run_verbtamper("http://t.local", fetch=fetch)
    finally:
        ungate()
    assert out["findings"] == []


# -------------------------------------------------------------- jsmine
def test_jsmine_endpoints_and_sink():
    from omega.offensive.offense.jsmine import run_jsmine

    def fetch(url, method="GET"):
        if url.endswith("/app.js"):
            return R('fetch("/api/v2/users");el.innerHTML = userInput;',
                     200)
        return R("", 404)

    gate_env()
    try:
        out = run_jsmine("http://t.local", fetch=fetch)
    finally:
        ungate()
    assert "/api/v2/users" in out["endpoints"]
    assert any("innerHTML" in s for s in out["sinks"])
    assert any("DOM sinks" in f["title"] for f in out["findings"])


def test_jsmine_key_shape_never_value():
    from omega.offensive.offense.jsmine import run_jsmine

    def fetch(url, method="GET"):
        if url.endswith("/app.js"):
            return R('cfg={apiKey:"AKIAIOSFODNN7EXAMPLE12345"};', 200)
        return R("", 404)

    gate_env()
    try:
        out = run_jsmine("http://t.local", fetch=fetch)
    finally:
        ungate()
    assert "AKIAIOSFODNN7EXAMPLE12345" not in str(out)
    assert out["key_hints"] and "SHAPE ONLY" in out["key_hints"][0]


# ----------------------------------------------------------- shadowdisc
def test_shadowdisc_real_endpoint_found():
    from omega.offensive.offense.shadowdisc import run_shadowdisc

    def fetch(url, method="GET"):
        if "omegq" in url or "omegz" in url:
            return R("not found page", 404)
        if url.endswith("/actuator"):
            return R('{"_links":{"health":{}}}', 200)
        return R("not found page", 404)

    gate_env()
    try:
        out = run_shadowdisc("http://t.local", fetch=fetch)
    finally:
        ungate()
    assert any("/actuator" in f["title"] for f in out["findings"])
    assert all("/omeg" not in f["title"] for f in out["findings"])


def test_shadowdisc_soft404_mirage_ignored():
    from omega.offensive.offense.shadowdisc import run_shadowdisc

    def fetch(url, method="GET"):
        # SPA serves the SAME 200 page for everything
        return R("<html>spa</html>", 200)

    gate_env()
    try:
        out = run_shadowdisc("http://t.local", fetch=fetch)
    finally:
        ungate()
    assert out["findings"] == []


# ------------------------------------------------------------ crlfprobe
def test_crlfprobe_header_injection_hit():
    from omega.offensive.offense.crlfprobe import run_crlfprobe

    def fetch(url, headers=None):
        if "next=" in url and "%0d%0a" in url:
            return R("ok", 302, headers={"omegcrlf": "injected"})
        return R("ok", 200, headers={})

    gate_env()
    try:
        out = run_crlfprobe("http://t.local/go", fetch=fetch)
    finally:
        ungate()
    assert out["findings"][0]["cwe"] == "CWE-113"


def test_crlfprobe_body_reflection_not_flagged():
    from omega.offensive.offense.crlfprobe import run_crlfprobe

    def fetch(url, headers=None):
        # marker appears only in the body — NOT header injection
        return R("redirect to omegcrlf: injected", 200, headers={})

    gate_env()
    try:
        out = run_crlfprobe("http://t.local/go", fetch=fetch)
    finally:
        ungate()
    assert out["findings"] == []


# ------------------------------------------------------------ subdgraph
def test_subdgraph_ct_graph(tmp_path, monkeypatch):
    import json as _j
    from omega.core import subdgraph as sg

    def fetch(url, method="GET"):
        data = [{"name_value": f"a.{sg_domain}\nb.{sg_domain}"},
                {"name_value": f"c.{sg_domain}"}]
        return R(_j.dumps(data), 200)

    sg_domain = "t.local"
    monkeypatch.setattr(sg.socket, "gethostbyname",
                        lambda h: "127.0.0.5")
    gate_env()
    try:
        out = sg.run_subdgraph("https://t.local", fetch=fetch)
    finally:
        ungate()
    assert set(out["subdomains"]) == {"a.t.local", "b.t.local",
                                      "c.t.local"}
    assert len(out["resolved"]) == 3


# ----------------------------------------------------------- idororacle
def test_idororacle_uuid_scheme_skips_sweep():
    from omega.offensive.offense.idororacle import (classify_scheme,
                                                    run_idororacle)
    scheme, why = classify_scheme(["1b7e2c3a-1111-2222-3333-444455556666"])
    assert scheme == "uuid"
    gate_env()
    try:
        out = run_idororacle(
            "http://t.local", fetch=lambda *a, **k: R("x"),
            known_ids=["1b7e2c3a-1111-2222-3333-444455556666"])
    finally:
        ungate()
    assert "skipped" in out["note"]


def test_idororacle_sequential_sweep_hit():
    from omega.offensive.offense.idororacle import run_idororacle

    def fetch(url, method="GET"):
        if "id=101" in url or "id=99" in url or "id=100" in url:
            return R('{"order":{"owner":"someone-else"}}', 200)
        return R("not found", 404)

    gate_env()
    try:
        out = run_idororacle("http://t.local/api/order", fetch=fetch,
                             known_ids=["100"], sweep=3, pace_s=0)
    finally:
        ungate()
    assert out["findings"] and out["findings"][0]["cwe"] == "CWE-639"


# -------------------------------------------------------------- narrgen
def test_narrgen_three_audiences():
    from omega.reporting.narrgen import render_narrative
    findings = [{"severity": "CRITICAL", "cwe": "CWE-918"}]
    txt = render_narrative(findings, target="http://t.local",
                           chains=[{"name": "cloud-takeover",
                                    "status": "partial",
                                    "broken_link": "metadata-token"}])
    assert "for developers" in txt and "egress allowlist" in txt
    assert "for security" in txt and "cloud-takeover" in txt
    assert "for management" in txt


def test_narrgen_clean_target():
    from omega.reporting.narrgen import render_narrative
    txt = render_narrative([])
    assert "nothing to fix" in txt


# ------------------------------------------------------------ noiseaudit
def test_noiseaudit_wasteful_and_ratio():
    from omega.core.noiseaudit import audit_noise, render_noise_audit
    history = [{"capability": "offense.a", "new_facts": 3},
               {"capability": "offense.b", "new_facts": 0},
               {"capability": "offense.b", "new_facts": 0}]
    a = audit_noise(history=history, findings=[{}, {}, {}])
    assert a["wasteful_capabilities"][0]["capability"] == "offense.b"
    assert a["requests_per_finding"] == 1.0
    txt = render_noise_audit(a)
    assert "offense.b" in txt


# -------------------------------------------------------- brain / CLI
def test_brain_caps_197():
    from omega.core.brain import DEFAULT_REGISTRY as reg
    assert len(reg.ids()) == 197
    for cid in ("offense.verbtamper", "offense.jsmine",
                "offense.shadowdisc", "offense.crlfprobe",
                "core.subdgraph", "offense.idororacle",
                "core.narrgen", "core.noiseaudit"):
        assert reg.get(cid) is not None


def test_cli_phantom_flags():
    import contextlib
    import io
    from omega.core import cli as climod
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            climod.main(["brain", "--help"])
        except SystemExit:
            pass
    txt = buf.getvalue()
    for flag in ("--verb-tamper", "--js-mine", "--shadow-disc",
                 "--crlf-probe", "--subd-graph", "--idor-oracle",
                 "--narrative", "--noise-audit"):
        assert flag in txt
