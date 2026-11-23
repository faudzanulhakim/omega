"""Tests for batch-14 MELTDOWN: deserprobe, metassrf, authzmatrix,
cisweep, corsprobe, adaptive."""
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
    ("deserprobe", "run_deserprobe", ("http://x/", None)),
    ("metassrf", "run_metassrf", ("http://x/",)),
    ("authzmatrix", "run_authzmatrix", ("http://x/",)),
    ("cisweep", "run_cisweep", ("http://x/", None)),
    ("corsprobe", "run_corsprobe", ("http://x/", None)),
])
def test_all_melt_modules_gate(mod, fn, args):
    import importlib
    m = importlib.import_module(f"omega.offensive.offense.{mod}")
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        out = getattr(m, fn)(*args)
        assert "PTK_OFFENSE" in out.get("note", "")
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


# ------------------------------------------------------------- deserprobe
def test_deserprobe_error_disclosure():
    from omega.offensive.offense.deserprobe import run_deserprobe

    def fetch(url, method="GET"):
        if "unserialize" in url or "O%3A8" in url or "O:8" in url:
            return R("Warning: unserialize(): Error at offset 0", 500)
        return R("ok")

    gate_env()
    try:
        out = run_deserprobe("http://t.local/api", fetch=fetch)
    finally:
        ungate()
    assert out["findings"]
    assert out["findings"][0]["cwe"] == "CWE-502"
    assert out["findings"][0]["verification"] == "candidate"


def test_deserprobe_no_fabricated_confirm():
    from omega.offensive.offense.deserprobe import run_deserprobe
    gate_env()
    try:
        out = run_deserprobe("http://t.local/", fetch=lambda u, **k: R("ok"))
    finally:
        ungate()
    assert out["findings"] == []


# ------------------------------------------------------------- metassrf
def test_metassrf_imdsv1_confirmed_redacted():
    from omega.offensive.offense.metassrf import run_metassrf

    def fetch(url, method="GET"):
        if "169.254.169.254/latest/meta-data/ami-id" in url:
            return R("ami-id\nami-0abc123 omega-secret-token=SECRETVAL", 200)
        if "/latest/api/token" in url:
            return R("", 405)
        return R("nope", 200)

    gate_env()
    try:
        out = run_metassrf("http://t.local/fetch?url=", fetch=fetch)
    finally:
        ungate()
    f = [x for x in out["findings"] if "aws-imdsv1" in x["title"]]
    assert f and f[0]["verification"] == "confirmed"
    assert f[0]["severity"] == "CRITICAL"
    assert "SECRETVAL" not in f[0]["evidence"]  # redacted shape only
    # stop-on-first-confirm: no duplicate findings per SSRF param
    assert len([x for x in out["findings"] if x["severity"] == "CRITICAL"]) == 1


# ----------------------------------------------------------- authzmatrix
def test_authzmatrix_anon_equals_role():
    from omega.offensive.offense.authzmatrix import run_authzmatrix
    protected = {"http://t.local/api/users", "http://t.local/admin"}

    def fetch(url, headers=None):
        if url in protected and (headers or {}).get("X-Role") == "user":
            return R('{"users":[1,2]}', 200)
        if url in protected:
            return R('{"users":[1,2]}', 200)  # anon sees the same = flaw
        return R("ok", 200)

    gate_env()
    try:
        out = run_authzmatrix(
            "http://t.local",
            roles={"anonymous": None, "user": {"X-Role": "user"}},
            fetch=fetch, endpoints=["/api/users", "/admin"])
    finally:
        ungate()
    assert out["findings"]
    assert out["findings"][0]["cwe"] == "CWE-285"


def test_authzmatrix_no_fp_when_403():
    from omega.offensive.offense.authzmatrix import run_authzmatrix

    def fetch(url, headers=None):
        return R("forbidden", 403)

    gate_env()
    try:
        out = run_authzmatrix("http://t.local",
                              roles={"anonymous": None, "user": {}},
                              fetch=fetch, endpoints=["/admin"])
    finally:
        ungate()
    assert out["findings"] == []


# -------------------------------------------------------------- cisweep
def test_cisweep_real_git_head_positive():
    from omega.offensive.offense.cisweep import run_cisweep

    def fetch(url, method="GET"):
        if url.endswith("/.git/HEAD"):
            return R("ref: refs/heads/main", 200)
        return R("", 404)

    gate_env()
    try:
        out = run_cisweep("http://t.local", fetch=fetch)
    finally:
        ungate()
    assert out["findings"] and out["findings"][0]["cwe"] == "CWE-538"


def test_cisweep_spa_404_not_flagged():
    from omega.offensive.offense.cisweep import run_cisweep

    def fetch(url, method="GET"):
        return R("<html>my spa</html>", 200)  # everything "200" but SPA

    gate_env()
    try:
        out = run_cisweep("http://t.local", fetch=fetch)
    finally:
        ungate()
    assert out["findings"] == []


# ------------------------------------------------------------ corsprobe
def test_corsprobe_reflected_with_creds_confirmed():
    from omega.offensive.offense.corsprobe import run_corsprobe

    def fetch(url, headers=None, method="GET"):
        origin = (headers or {}).get("Origin")
        if origin:
            return R("ok", 200, headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true"})
        return R("ok", 200, headers={
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=63072000"})

    gate_env()
    try:
        out = run_corsprobe("http://t.local/api", fetch=fetch)
    finally:
        ungate()
    hits = [x for x in out["findings"] if "WITH credentials" in x["title"]]
    assert hits and hits[0]["verification"] == "confirmed"
    assert hits[0]["severity"] == "HIGH"
    assert not any("hardening" in x["title"] for x in out["findings"])


# ------------------------------------------------------------- adaptive
def test_adaptive_ranks_by_cwe_evidence():
    from omega.core.adaptive import recommend, render_recommendation
    findings = [{"cwe": "CWE-918"}, {"cwe": "CWE-918"}, {"cwe": "CWE-89"}]
    recs = recommend(findings=findings, stack="node.js + express")
    assert recs[0]["attack"] == "metassrf"  # 2x CWE-918 dominates
    assert recs[0]["score"] > recs[-1]["score"]
    txt = render_recommendation(recs)
    assert "next-attack playbook" in txt and "metassrf" in txt


def test_adaptive_empty_findings():
    from omega.core.adaptive import recommend
    assert recommend(findings=[]) == []


# --------------------------------------------------------- brain / CLI
def test_brain_caps_197():
    from omega.core.brain import DEFAULT_REGISTRY as reg
    assert len(reg.ids()) == 197
    for cid in ("offense.deserprobe", "offense.metassrf",
                "offense.authzmatrix", "offense.cisweep",
                "offense.corsprobe", "core.adaptive"):
        assert reg.get(cid) is not None


def test_cli_melt_flags():
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
    for flag in ("--deser-probe", "--meta-ssrf", "--authz-matrix",
                 "--ci-sweep", "--cors-probe", "--adaptive"):
        assert flag in txt
