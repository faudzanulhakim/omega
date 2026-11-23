"""Tests for batch-15 NIGHTFALL: pocgen, chaincomposer, impactscorer,
jwtdeep, fpexploit, reportdiff, wordlistgen, ratefprint, dosexpose,
destrshape, pwdaudit."""
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


GATED = [("jwtdeep", "run_jwtdeep", ("http://x/",)),
         ("wordlistgen", "run_wordlistgen", ("http://x/", None)),
         ("ratefprint", "run_ratefprint", ("http://x/", None)),
         ("dosexpose", "run_dosexpose", ("http://x/", None)),
         ("destrshape", "run_destrshape", ("http://x/", None)),
         ("pwdaudit", "run_pwdaudit", ("http://x/", None))]


@pytest.mark.parametrize("mod,fn,args", GATED)
def test_night_modules_gate(mod, fn, args):
    import importlib
    m = importlib.import_module(f"omega.offensive.offense.{mod}")
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        out = getattr(m, fn)(*args)
        assert "PTK_OFFENSE" in out.get("note", "")
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


# ------------------------------------------------------------- pocgen
def test_pocgen_curl_and_python_from_real_evidence():
    from omega.reporting.pocgen import render_pocs
    f = {"title": "git exposed", "severity": "HIGH", "cwe": "CWE-538",
         "location": "http://t.local/.git/HEAD",
         "evidence": "ref: refs/heads/main"}
    txt = render_pocs([f])
    assert "curl -sk -i 'http://t.local/.git/HEAD'" in txt
    assert "urllib.request" in txt
    assert "authorized target" in txt


def test_pocgen_low_severity_excluded():
    from omega.reporting.pocgen import render_pocs
    f = {"title": "info", "severity": "LOW", "location": "http://x/"}
    assert "no HIGH/CRITICAL" in render_pocs([f])


# ------------------------------------------------------- chaincomposer
def test_chaincomposer_partial_names_broken_link():
    from omega.core.chaincomposer import compose_chains, render_chains
    findings = [{"cwe": "CWE-444", "verification": "confirmed"}]
    doc = compose_chains(findings=findings)
    hijack = [c for c in doc["chains"] if c["name"] == "smuggle-cache-hijack"]
    assert hijack[0]["status"] == "partial"
    assert hijack[0]["broken_link"] == "victim-reflection"
    txt = render_chains(doc["chains"])
    assert "broken link: victim-reflection" in txt


def test_chaincomposer_plan_only_when_no_evidence():
    from omega.core.chaincomposer import compose_chains
    doc = compose_chains(findings=[], gate_open_fn=lambda: False)
    assert all(c["status"] == "plan-only" for c in doc["chains"])


# ------------------------------------------------------- impactscorer
def test_impactscorer_confirmed_medium_rises():
    from omega.core.impactscorer import score_finding
    f = {"severity": "MEDIUM", "verification": "confirmed",
         "cwe": "CWE-444"}
    sc = score_finding(f)
    assert sc["adjusted"] == "HIGH"
    assert any("confirmed" in r for r in sc["reasons"])


def test_impactscorer_info_stays():
    from omega.core.impactscorer import score_finding
    assert score_finding({"severity": "INFO"})["adjusted"] == "INFO"


# ------------------------------------------------------------ jwtdeep
def _b64e(b):
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def test_jwtdeep_none_alg_confirmed():
    from omega.offensive.offense.jwtdeep import run_jwtdeep
    import json
    hdr = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    pay = _b64e(json.dumps({"sub": "1", "iss": "t.local"}).encode())
    tok = f"{hdr}.{pay}.sigsig"
    calls = []

    def fetch(url, headers=None, method=None, body=None):
        calls.append((url, headers, method, body))
        from omega.offensive.offense.jwtdeep import _b64d
        auth = (headers or {}).get("Authorization", "")
        seg = auth.replace("Bearer ", "").split(".")[0]
        alg = (_b64d(seg) or b"{}").decode(errors="ignore")
        if '"none"' in alg:
            return R("dashboard", 200)  # none accepted = flaw
        return R("unauthorized", 401)

    gate_env()
    try:
        out = run_jwtdeep("http://t.local/api", fetch=fetch,
                          tokens=[tok])
    finally:
        ungate()
    assert any("none-alg" in f["title"] for f in out["findings"])
    assert out["findings"][0]["cwe"] == "CWE-347"


def test_jwtdeep_refresh_replay():
    from omega.offensive.offense.jwtdeep import run_jwtdeep

    def fetch(url, headers=None, method=None, body=None):
        if method == "POST" and "refresh" in (body or ""):
            return R('{"token":"x"}', 200)
        return R("ok", 200)

    gate_env()
    try:
        out = run_jwtdeep("http://t.local", fetch=fetch,
                          refresh_token="omegrt123")
    finally:
        ungate()
    assert any("replayed" in f["title"] for f in out["findings"])


# ----------------------------------------------------------- fpexploit
def test_fpexploit_actuator_confirmed():
    from omega.core.fpexploit import map_exploits, verify_candidates
    cands = map_exploits(stack="Spring Boot 2.7")
    assert any(c["name"] == "spring-actuator-env" for c in cands)

    def fetch(url, method="GET"):
        if url.endswith("/actuator/env"):
            return R('{"propertySources":[]}', 200)
        return R("", 404)

    gate_env()
    try:
        out = verify_candidates("http://t.local", cands=cands, fetch=fetch)
    finally:
        ungate()
    assert out["findings"] and out["findings"][0]["cwe"] == "CWE-200"


def test_fpexploit_unknown_stack_empty():
    from omega.core.fpexploit import map_exploits
    assert map_exploits(stack="wordpress") == []


# ---------------------------------------------------------- reportdiff
def test_reportdiff_new_fixed_still(tmp_path):
    from omega.core.reportdiff import diff_snapshots, save_snapshot
    old = [{"title": "a", "location": "/a", "severity": "HIGH"},
           {"title": "b", "location": "/b", "severity": "LOW"}]
    p = save_snapshot("http://t.local", old, label="prev")
    new = [{"title": "a", "location": "/a", "severity": "HIGH"},
           {"title": "c", "location": "/c", "severity": "CRITICAL"}]
    d = diff_snapshots(p, new)
    assert len(d["new"]) == 1 and d["new"][0]["title"] == "c"
    assert len(d["still"]) == 1
    assert d["fixed_count"] == 1  # finding b gone


# ---------------------------------------------------------- wordlistgen
def test_wordlistgen_context_harvest():
    from omega.offensive.offense.wordlistgen import run_wordlistgen

    def fetch(url, method="GET"):
        if url.endswith("/main.js"):
            return R('var cfg={"api_base":"/api/v2","pageSize":25};'
                     'fetch("/admin/users")', 200)
        return R("", 404)

    gate_env()
    try:
        out = run_wordlistgen("http://t.local", fetch=fetch)
    finally:
        ungate()
    assert "/api/v2" in out["paths"] or "/admin/users" in out["paths"]
    assert "pageSize" in out["wordlist"]


def test_wordlistgen_cred_hint_not_value():
    from omega.offensive.offense.wordlistgen import run_wordlistgen

    def fetch(url, method="GET"):
        return R('var s={"secret_value":"REALSECRET123"};', 200)

    gate_env()
    try:
        out = run_wordlistgen("http://t.local", fetch=fetch)
    finally:
        ungate()
    assert "REALSECRET123" not in str(out)
    assert out["credential_key_hints"]


# ---------------------------------------------------------- ratefprint
def test_ratefprint_hard_limit_429():
    from omega.offensive.offense.ratefprint import run_ratefprint
    n = {"c": 0}

    def fetch(url, method="GET"):
        n["c"] += 1
        if n["c"] > 3:
            return R("slow down", 429)
        return R("ok", 200)

    gate_env()
    try:
        out = run_ratefprint("http://t.local", fetch=fetch, gap_s=0)
    finally:
        ungate()
    assert out["profile"]["/login"]["verdict"] == "hard limit (429)"
    assert out["findings"] == []  # limit exists -> not "no limit" finding


def test_ratefprint_no_limit_flagged():
    from omega.offensive.offense.ratefprint import run_ratefprint

    def fetch(url, method="GET"):
        return R("ok", 200)

    gate_env()
    try:
        out = run_ratefprint("http://t.local", fetch=fetch, gap_s=0)
    finally:
        ungate()
    assert any("no rate limiting" in f["title"] for f in out["findings"])


# ------------------------------------------------------------ dosexpose
def test_dosexpose_unbounded_pagination():
    from omega.offensive.offense.dosexpose import run_dosexpose

    def fetch(url, method="GET", body=None):
        if "limit=9999999999" in url:
            return R("x" * 150000, 200)
        return R("ok", 200)

    gate_env()
    try:
        out = run_dosexpose("http://t.local", fetch=fetch, timeout=0.2)
    finally:
        ungate()
    assert any("unbounded pagination" in f["title"] for f in out["findings"])


# ------------------------------------------------------------ destrshape
def test_destrshape_cmd_echo_inert():
    from omega.offensive.offense.destrshape import run_destrshape

    def fetch(url, method="GET"):
        if "omegdsr" in url and "echo" in url:
            return R("ping omegdsr done", 200)
        return R("ok", 200)

    gate_env()
    try:
        out = run_destrshape("http://t.local/dns", fetch=fetch)
    finally:
        ungate()
    f = [x for x in out["findings"] if "cmd" in x["title"]]
    assert f and f[0]["severity"] == "CRITICAL"
    assert "no state was changed" in f[0]["evidence"]


# -------------------------------------------------------------- pwdaudit
def test_pwdaudit_weak_cred_found_capped():
    from omega.offensive.offense.pwdaudit import run_pwdaudit
    n = {"c": 0}

    def fetch(url, method=None, body=None):
        n["c"] += 1
        if "password=admin123" in (body or ""):
            return R("dashboard", 200)
        return R("invalid credentials", 401)

    gate_env()
    try:
        out = run_pwdaudit("http://t.local", fetch=fetch,
                           username="admin", pace_s=0)
    finally:
        ungate()
    assert out["findings"] and out["findings"][0]["cwe"] == "CWE-521"
    assert len(out["attempts"]) <= 8


def test_pwdaudit_lockout_aware_stop():
    from omega.offensive.offense.pwdaudit import run_pwdaudit
    n = {"c": 0}

    def fetch(url, method=None, body=None):
        n["c"] += 1
        return R("account locked", 423)

    gate_env()
    try:
        out = run_pwdaudit("http://t.local", fetch=fetch,
                           username="admin", pace_s=0)
    finally:
        ungate()
    assert out["stopped_early"] is True
    assert n["c"] <= 4  # stops after 2 unknown-fail streak


def test_pwdaudit_requires_username():
    from omega.offensive.offense.pwdaudit import run_pwdaudit
    gate_env()
    try:
        out = run_pwdaudit("http://t.local", fetch=lambda *a, **k: R("x"))
    finally:
        ungate()
    assert "username required" in out["note"]


# -------------------------------------------------------- brain / CLI
def test_brain_caps_197():
    from omega.core.brain import DEFAULT_REGISTRY as reg
    assert len(reg.ids()) == 197
    for cid in ("core.pocgen", "core.chaincomposer", "core.impactscorer",
                "auth.jwtdeep", "core.fpexploit", "core.reportdiff",
                "offense.wordlistgen", "offense.ratefprint",
                "offense.dosexpose", "offense.destrshape",
                "offense.pwdaudit"):
        assert reg.get(cid) is not None


def test_cli_night_flags():
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
    for flag in ("--poc-gen", "--chain-compose", "--impact-score",
                 "--jwt-deep", "--fp-exploit", "--report-diff",
                 "--wordlist-gen", "--rate-fprint", "--dos-expose",
                 "--destruct-shape", "--pwd-audit"):
        assert flag in txt
