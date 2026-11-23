"""Tests for batch-12 RED APEX: crawlstate, attackprofiles, horizontal,
scheduler, chainrun, evadechain, apispecial, uploadfuzz."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


class R:
    def __init__(self, text, status=200):
        self.status = status
        self.text = text


# ---------------------------------------------------------------- crawlstate
def test_crawlstate_discovers_behind_links():
    from omega.scanning.crawlstate import crawl_flows
    html = ('<html><a href="/admin/dashboard">x</a>'
            '<a href="/api/v2/orders">y</a>'
            '<form action="/checkout" method="POST">'
            '<input name="qty"><input type="password" name="pw">'
            '</form></html>')
    seen = []

    def fetch(url, method="GET", body=None):
        seen.append(f"{url} {body or ''}")
        return R(html)

    doc = crawl_flows(fetch, "http://t.local/", ["http://t.local/"],
                      submit=True)
    urls = " ".join(doc["urls"])
    assert "/admin/dashboard" in urls and "/api/v2/orders" in urls
    assert doc["forms"], "checkout form must be captured"
    fields = [f["name"] for f in doc["forms"][0]["fields"]]
    assert "qty" in fields and "pw" in fields  # password NOT skipped
    # submit flow: sensitive field must NOT be filled
    assert doc["flows"], "inert-marker submit expected"
    sent = " ".join(seen)
    assert "omegastate" in sent
    assert "omegastate_pw" not in sent


# ---------------------------------------------------------------- profiles
def test_profiles_plan_only_when_gates_closed():
    from omega.core.attackprofiles import run_profile
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        doc = run_profile("external", None)
        assert doc["gates_open"] is False
        assert doc["note"] and "gates closed" in doc["note"]
        assert all(not s["executed"] for s in doc["steps"])
        assert doc["steps"][0]["attack_id"] == "T1595"
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


def test_profiles_executes_with_gates_and_executor():
    from omega.core.attackprofiles import run_profile
    os.environ["PTK_OFFENSE"] = "1"
    try:
        doc = run_profile("external", None, execute_fn=lambda st: {
            "ok": True, "caps": st["caps"]})
    finally:
        os.environ.pop("PTK_OFFENSE", None)
    assert doc["gates_open"] is True
    assert all(s["executed"] for s in doc["steps"])


def test_profiles_unknown():
    from omega.core.attackprofiles import run_profile
    assert "unknown profile" in run_profile("nope", None).get("note")


# ---------------------------------------------------------------- horizontal
def test_horizontal_idor_sweep():
    from omega.offensive.offense.horizontal import run_horizontal

    def fetch(url, method="GET", headers=None, body=None):
        if "id=" in url and url.split("id=")[1].split("&")[0].isdigit():
            return R('{"email":"u@x.com"}', 200)  # every id readable
        return R("ok", 200)

    os.environ["PTK_OFFENSE"] = "1"
    try:
        out = run_horizontal("http://t.local/api/user",
                             [{"param": "id", "value": "1"}],
                             fetch=fetch, budget=15)
    finally:
        os.environ.pop("PTK_OFFENSE", None)
    assert out["findings"]
    f = out["findings"][0]
    assert f["cwe"] == "CWE-639" and f["verification"] == "candidate"


def test_horizontal_gates():
    from omega.offensive.offense.horizontal import run_horizontal
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        out = run_horizontal("http://x", [{"param": "id", "value": "1"}],
                             fetch=lambda *a, **k: None)
        assert "PTK_OFFENSE" in out.get("note", "")
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


# ---------------------------------------------------------------- scheduler
def test_scheduler_ranks_admin_over_static():
    from omega.core.scheduler import rank_targets
    doc = rank_targets({"urls": ["/static/style.css", "/admin/panel",
                                 "/api/v1/orders?user_id=1&id=2"],
                        "forms": [{"url": "/admin/panel"}]})
    q = doc["queue"]
    scores = {x["url"]: x["score"] for x in q}
    assert scores["/admin/panel"] > scores["/static/style.css"]
    assert scores["/api/v1/orders?user_id=1&id=2"] > \
        scores["/static/style.css"]
    why = {x["url"]: x["why"] for x in q}
    assert any("admin" in w for w in why["/admin/panel"])


# ---------------------------------------------------------------- chainrun
def test_chainrun_plan_only_without_gate():
    from omega.core.chainrun import run_chain
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        out = run_chain([{"title": "SSRF", "cwe": "CWE-918"}],
                        "http://x/", fetch=None)
        assert "plan-only" in out.get("note", "")
        assert out["plan"]  # graph still built
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


def test_chainrun_confirms_step():
    from omega.core.chainrun import run_chain

    def fetch(url, method="GET", body=None, headers=None):
        if "id=1'" in url:
            return R("MySQL syntax error near", 200)
        return R("ok", 200)

    os.environ["PTK_OFFENSE"] = "1"
    try:
        out = run_chain([{"title": "SQLi candidate", "cwe": "CWE-89"}],
                        "http://t.local/item", fetch=fetch)
    finally:
        os.environ.pop("PTK_OFFENSE", None)
    assert out["steps"], "sql error signal must confirm the edge"
    assert out["steps"][0]["status"] == "confirmed"


# ---------------------------------------------------------------- evadechain
def test_evadechain_finds_encoder():
    from omega.offensive.offense.evadechain import run_evadechain

    def send(payload, headers=None):
        # everything blocked EXCEPT url-encoded form
        if payload == urllib.parse.quote("' OR 1=1 --"):
            return "query result"
        return "403 blocked"

    import urllib.parse
    os.environ["PTK_OFFENSE"] = "1"
    try:
        out = run_evadechain("' OR 1=1 --", send)
    finally:
        os.environ.pop("PTK_OFFENSE", None)
    assert out["passed"], "url encoder must pass"
    assert out["passed"][0][0] == "url"


def test_evadechain_all_blocked_honest():
    from omega.offensive.offense.evadechain import run_evadechain
    os.environ["PTK_OFFENSE"] = "1"
    try:
        out = run_evadechain("x", lambda p, h=None: "403 forbidden")
    finally:
        os.environ.pop("PTK_OFFENSE", None)
    assert "hardened target" in out.get("note", "")


# ---------------------------------------------------------------- apispecial
def test_apispecial_introspection_and_bola():
    from omega.offensive.offense.apispecial import run_apispecial

    def fetch(url, method="GET", body=None, headers=None):
        if body and "__schema" in str(body):
            return R(json.dumps({"data": {"__schema":
                                          {"types": []}}}), 200)
        if body and "__typename" in str(body):
            return R('[{"data":"Query"}]', 200)
        if "/api/v1/users/" in url:
            return R('{"email":"other@x.com","username":"bob"}', 200)
        if "role" in str(body):
            return R('{"id":5}', 201)
        return R("", 404)

    os.environ["PTK_OFFENSE"] = "1"
    try:
        out = run_apispecial("http://t.local/graphql", fetch=fetch,
                             budget=30)
    finally:
        os.environ.pop("PTK_OFFENSE", None)
    titles = [f["title"] for f in out["findings"]]
    assert any("introspection" in t for t in titles)
    assert any("BOLA" in t for t in titles)


# ---------------------------------------------------------------- uploadfuzz
def test_uploadfuzz_inert_marker_and_candidates():
    from omega.offensive.offense.uploadfuzz import run_uploadfuzz
    seen_bodies = []

    def fetch(url, method="POST", body=None, headers=None):
        seen_bodies.append(body or b"")
        return R('{"filename":"shell.php5"}', 200)

    os.environ["PTK_OFFENSE"] = "1"
    try:
        out = run_uploadfuzz("http://t.local/upload", fetch=fetch)
    finally:
        os.environ.pop("PTK_OFFENSE", None)
    assert out["findings"], "accepted variants must be reported"
    assert out["findings"][0]["cwe"] == "CWE-434"
    # inert: every body is marker text, never a functional webshell
    for b in seen_bodies:
        assert b"omeguploadmarker-" in b
        assert b"system(" not in b and b"exec(" not in b


def test_uploadfuzz_gates():
    from omega.offensive.offense.uploadfuzz import run_uploadfuzz
    old = os.environ.pop("PTK_OFFENSE", None)
    try:
        out = run_uploadfuzz("http://x", fetch=lambda *a, **k: None)
        assert "PTK_OFFENSE" in out.get("note", "")
    finally:
        if old:
            os.environ["PTK_OFFENSE"] = old


# ---------------------------------------------------------------- brain/CLI
def test_brain_caps_197():
    from omega.core.brain import DEFAULT_REGISTRY as reg
    assert len(reg.ids()) == 197
    for cid in ("scanning.crawlstate", "core.profiles",
                "offense.horizontal", "core.scheduler",
                "core.chainrun", "offense.evadechain",
                "offense.apispecial", "offense.uploadfuzz"):
        assert reg.get(cid) is not None


def test_cli_flags_present():
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
    for flag in ("--crawl-state", "--profiles", "--horizontal",
                 "--chain-run", "--evade-chain", "--api-special",
                 "--upload-fuzz", "--rank-targets"):
        assert flag in txt
