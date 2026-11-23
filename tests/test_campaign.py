"""Hermetic tests for omega/core/campaign.py (multi-target campaigns).

Two loopback fixtures: one healthy ThreadingHTTPServer and one dead
(closed) port. All fuse() interactions are either real-but-local or
stubbed; no external network access.
"""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, __import__("os").path.dirname(
    __import__("os").path.dirname(__import__("os").path.abspath(__file__))))

from omega.core.campaign import (  # noqa: E402
    campaign_max_targets,
    dedupe_findings,
    normalize_target,
    run_campaign,
)


def _finding(title="Missing security response headers", loc="", **extra):
    f = {"title": title, "severity": "low", "confidence": "candidate",
         "verification": "signature", "verification_note": "sig",
         "manual_check": True, "location": loc or "http://t",
         "param": "", "evidence": "evidence", "source": "omega-x/tool"}
    f.update(extra)
    return f


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (http.server API)
        body = (b"<html><body><h1>omega campaign fixture"
                b"</h1></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


@pytest.fixture()
def healthy_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d/" % srv.server_address[1]
    srv.shutdown()


@pytest.fixture()
def dead_url():
    # grab a port, then release it: nothing listens there
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    srv.server_close()
    return "http://127.0.0.1:%d/" % port


@pytest.fixture()
def fake_fuse(monkeypatch):
    """Replace omega.fusion.fuse with a scripted stub."""
    calls = []

    def install(fn):
        def wrapper(target, **kwargs):
            calls.append({"target": target, **kwargs})
            return fn(target, kwargs) if callable(fn) else fn
        monkeypatch.setattr("omega.fusion.fuse", wrapper)
        return calls

    return install


# ------------------------------------------------------------ helpers

def test_normalize_target():
    assert normalize_target("example.com") == "https://example.com"
    assert normalize_target("http://a/") == "http://a/"
    assert normalize_target("  ") == ""
    assert normalize_target(None) == ""


def test_dedupe_keeps_first_by_title_location():
    fs = [_finding(loc="http://a"), _finding(loc="http://a"),
          _finding(title="Other", loc="http://a")]
    out = dedupe_findings(fs)
    assert len(out) == 2
    assert out[0]["title"] == "Missing security response headers"
    assert dedupe_findings([]) == []
    assert dedupe_findings([None, "x", _finding()]) == [_finding()]


def test_campaign_max_targets_env(monkeypatch):
    monkeypatch.delenv("OMEGA_CAMPAIGN_MAX", raising=False)
    assert campaign_max_targets() == 10
    monkeypatch.setenv("OMEGA_CAMPAIGN_MAX", "3")
    assert campaign_max_targets() == 3
    monkeypatch.setenv("OMEGA_CAMPAIGN_MAX", "bogus")
    assert campaign_max_targets() == 10


# ------------------------------------------------------- scope gate

def test_scope_ack_required(dead_url):
    res = run_campaign([dead_url], scope_ack=False)
    assert res["ok"] is False
    assert "scope-ack" in (res.get("error") or "").lower()
    assert res["per_target"] == {}
    assert res["report_path"] is None


def test_scope_ack_true_runs(dead_url, tmp_path, fake_fuse):
    fake_fuse(lambda t, kw: {"findings": [_finding(loc=t)],
                             "corroborated": []})
    res = run_campaign([dead_url], profile="quick", scope_ack=True,
                       out=str(tmp_path / "r.md"))
    assert res["ok"] is True


# ------------------------------------------------- failure containment

def test_dead_target_skipped_with_reason(dead_url, tmp_path, fake_fuse):
    calls = fake_fuse(lambda t, kw: {"findings": [], "corroborated": []})
    res = run_campaign([dead_url], profile="quick", scope_ack=True,
                       out=str(tmp_path / "r.md"))
    assert res["ok"] is True
    info = res["per_target"][dead_url]
    assert info["status"] == "skipped"
    assert "unreachable" in (info.get("reason") or "")
    assert calls == []  # fuse never ran for the dead target


def test_broken_fuse_never_fails_campaign(healthy_url, tmp_path,
                                          fake_fuse):
    def boom(target, **kw):
        raise RuntimeError("scanner exploded")
    fake_fuse(boom)
    res = run_campaign([healthy_url], profile="quick", scope_ack=True,
                       out=str(tmp_path / "r.md"))
    assert res["ok"] is True
    # a scanner crash is a contained per-target failure, never a
    # campaign failure
    info = res["per_target"][healthy_url]
    assert info["status"] == "skipped"
    # reason is operator-facing: clean text, no raw exception leak
    assert "scan skipped" in (info.get("reason") or "")
    assert "RuntimeError" not in (info.get("reason") or "")


def test_healthy_target_collected_and_tagged(healthy_url, tmp_path,
                                             fake_fuse):
    calls = fake_fuse(lambda t, kw: {"findings": [_finding(loc=t)],
                                     "corroborated": []})
    res = run_campaign([healthy_url], profile="quick", scope_ack=True,
                       out=str(tmp_path / "r.md"))
    assert res["ok"] is True
    info = res["per_target"][healthy_url]
    assert info["status"] == "ran"
    assert info["count"] == 1
    assert info["findings"][0]["target"] == healthy_url
    assert calls and calls[0]["target"] == healthy_url
    assert calls[0]["suites"] == ("python-deep", "python-headerscan",
                                  "python-probes")
    assert calls[0]["budget"] == 60


def test_global_dedupe_across_targets(healthy_url, dead_url, tmp_path,
                                      fake_fuse):
    same = _finding(loc="/x")
    fake_fuse(lambda t, kw: {"findings": [dict(same)], "corroborated": []})
    res = run_campaign([healthy_url, dead_url], profile="quick",
                       scope_ack=True, out=str(tmp_path / "r.md"))
    assert len(res["findings"]) == 1
    assert res["findings"][0]["target"] == healthy_url


def test_max_targets_cap_truncates(dead_url, tmp_path, monkeypatch,
                                   fake_fuse):
    fake_fuse(lambda t, kw: {"findings": [], "corroborated": []})
    monkeypatch.setenv("OMEGA_CAMPAIGN_MAX", "1")
    res = run_campaign([dead_url, dead_url], profile="quick",
                       scope_ack=True, out=str(tmp_path / "r.md"))
    assert res["truncated"] is True
    assert len(res["per_target"]) == 1


# ------------------------------------------------------------- gates

def test_aggressive_opens_offense_gate(healthy_url, tmp_path, fake_fuse,
                                       monkeypatch):
    monkeypatch.delenv("PTK_OFFENSE", raising=False)
    calls = fake_fuse(lambda t, kw: {"findings": [], "corroborated": []})
    run_campaign([healthy_url], profile="quick", scope_ack=True,
                 aggressive=True, out=str(tmp_path / "r.md"))
    assert calls[0]["gate"] is True
    assert os.environ.get("PTK_OFFENSE") != "1"  # restored afterwards


def test_gates_off_by_default(healthy_url, tmp_path, fake_fuse,
                              monkeypatch):
    monkeypatch.delenv("PTK_OFFENSE", raising=False)
    calls = fake_fuse(lambda t, kw: {"findings": [], "corroborated": []})
    run_campaign([healthy_url], profile="quick", scope_ack=True,
                 out=str(tmp_path / "r.md"))
    assert calls[0]["gate"] is False


def test_unknown_profile_falls_back_to_web(healthy_url, tmp_path,
                                           fake_fuse):
    fake_fuse(lambda t, kw: {"findings": [], "corroborated": []})
    res = run_campaign([healthy_url], profile="bogus", scope_ack=True,
                       out=str(tmp_path / "r.md"))
    assert res["profile"] == "web"


# ----------------------------------------------------------- reports

def test_combined_markdown_report(healthy_url, dead_url, tmp_path,
                                  fake_fuse):
    fake_fuse(lambda t, kw: {"findings": [_finding(loc=t)],
                             "corroborated": []})
    out = tmp_path / "rep.md"
    res = run_campaign([healthy_url, dead_url], profile="quick",
                       scope_ack=True, out=str(out))
    assert res["report_path"] == str(out)
    text = out.read_text(encoding="utf-8")
    assert "Executive summary" in text
    assert "Target: %s" % healthy_url in text
    assert "SKIPPED" in text and "unreachable" in text
    assert "%d target(s)" % 2 in text


def test_pdf_report_magic_bytes(healthy_url, tmp_path, fake_fuse):
    fake_fuse(lambda t, kw: {"findings": [_finding(loc=t)],
                             "corroborated": []})
    out = tmp_path / "rep.pdf"
    res = run_campaign([healthy_url], profile="quick", scope_ack=True,
                       out=str(out))
    assert res["report_path"] == str(out)
    blob = out.read_bytes()
    assert blob[:5] == b"%PDF-"


def test_empty_targets_refused(tmp_path):
    res = run_campaign([], scope_ack=True)
    assert res["ok"] is False
    assert "no usable targets" in (res.get("error") or "")


# --------------------------------------------------------- real fusion

def test_real_fusion_quick_profile_on_loopback(healthy_url, tmp_path):
    out = tmp_path / "real.md"
    res = run_campaign([healthy_url], profile="quick", scope_ack=True,
                       out=str(out))
    assert res["ok"] is True
    info = res["per_target"][healthy_url]
    assert info["status"] == "ran"
    assert "python-headerscan" in (info.get("ran") or [])
    assert info["count"] >= 0


# --------------------------------------------------------------- CLI

def test_cli_campaign_exit_2_without_scope_ack(dead_url, capsys):
    from omega.core import cli
    code = cli.main(["campaign", dead_url, "--profile", "quick"])
    assert code == 2
    assert "--scope-ack" in capsys.readouterr().err


def test_cli_target_parsing_csv_and_file(tmp_path):
    from omega.core.cli import _parse_campaign_targets
    assert _parse_campaign_targets("a.com, http://b") == \
        ["a.com", "http://b"]
    f = tmp_path / "targets.txt"
    f.write_text("one.com\n# comment\ntwo.com\n", encoding="utf-8")
    assert _parse_campaign_targets(str(f)) == ["one.com", "two.com"]
    # a non-existent path is treated as a literal target string
    missing = str(tmp_path / "missing.txt")
    assert _parse_campaign_targets(missing) == [missing]
    assert _parse_campaign_targets("") == []


if __name__ == "__main__":
    pytest.main([__file__])
