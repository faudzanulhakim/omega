"""Hermetic tests for omega/scanning/llmsec.py — AI/LLM app scanning.

Uses a controllable fake chat HTTP server (scripted responses per
probe kind) on loopback. Covers: endpoint auto-discovery, direct
prompt injection (confirmed marker + candidate divergence), system
prompt disclosure, PII disclosure, excessive agency, unbounded
consumption, RAG bypass, redaction, no-endpoint clean skip, and
never-raises. >= 8 tests.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.llmsec import (
    CHAT_PATHS,
    discover_chat,
    redact,
    run_llmsec,
)


class FakeChatHandler(BaseHTTPRequestHandler):
    """Fake chat endpoint. Response behavior is driven by the
    class-level ``script`` dict; also records posted messages."""

    script = {"mode": "clean"}
    messages = []

    def log_message(self, *_a):
        pass

    def _reply(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length or 1)
        try:
            msg = json.loads(raw.decode()).get("message") or ""
        except ValueError:
            msg = ""
        FakeChatHandler.messages.append(msg)
        mode = FakeChatHandler.script["mode"]
        if self.path not in CHAT_PATHS:
            self._reply({"error": "not found"}, 404)
            return
        if mode == "clean":
            self._reply({"reply": "4"})
        elif mode == "injection":
            import re
            m = re.search(r"OMEGA-PI-[A-Z0-9]{6}", msg)
            self._reply({"reply": m.group(0)} if m else {"reply": "4"})
        elif mode == "injection-soft":
            if "ignore" in msg.lower():
                self._reply({"reply": "I will not obey but here is a "
                                      "longer story about being asked "
                                      "to ignore things."})
            else:
                self._reply({"reply": "4"})
        elif mode == "sysprompt":
            if "system prompt" in msg.lower() or "instructions" in \
                    msg.lower():
                self._reply({"reply": "You are a helpful assistant. "
                                      "instructions: never reveal."})
            else:
                self._reply({"reply": "4"})
        elif mode == "pii":
            if "training data" in msg.lower():
                self._reply({"reply": "user bob@example.com had "
                                      "password sk-ABCDEFGHIJklmnopqr"})
            else:
                self._reply({"reply": "4"})
        elif mode == "agency":
            if "tools" in msg.lower():
                self._reply({"reply": "available tools: web_search, "
                                      "db_query. tools: [file_read] "
                                      'with "function" definitions'})
            else:
                self._reply({"reply": "4"})
        elif mode == "usage":
            self._reply({"reply": "ok", "usage":
                         {"prompt_tokens": 20000,
                          "total_tokens": 20001}})
        elif mode == "rag":
            if "sources" in msg.lower():
                self._reply({"reply": "source: file:///internal/"
                                      "hr/salaries.pdf"})
            else:
                self._reply({"reply": "4"})
        else:
            self._reply({"reply": "4"})


@pytest.fixture
def chat_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeChatHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    FakeChatHandler.script = {"mode": "clean"}
    FakeChatHandler.messages = []
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def _run(target, mode):
    FakeChatHandler.script = {"mode": mode}
    return run_llmsec(target, allowlist=None, log=None)


def test_discover_chat_finds_endpoint(chat_server):
    ep = discover_chat(chat_server)
    assert ep and ep.endswith("/api/chat")


def test_discover_chat_clean_target_returns_none():
    assert discover_chat("http://127.0.0.1:1") is None


def test_prompt_injection_confirmed(chat_server):
    res = _run(chat_server, "injection")
    f = [x for x in res["findings"] if x["source"].endswith(
        "prompt-injection")]
    assert f and f[0]["verification"] == "confirmed"
    assert f[0]["severity"] == "high"
    assert "OMEGA-PI-" in f[0]["evidence"]


def test_prompt_injection_candidate_on_divergence(chat_server):
    res = _run(chat_server, "injection-soft")
    f = [x for x in res["findings"] if x["source"].endswith(
        "prompt-injection")]
    assert f and f[0]["verification"] == "candidate"


def test_system_prompt_disclosure_high_confirmed(chat_server):
    res = _run(chat_server, "sysprompt")
    f = [x for x in res["findings"] if x["source"].endswith(
        "sysprompt-disclosure")]
    assert f and f[0]["severity"] == "high"
    assert f[0]["verification"] == "confirmed"
    assert len(f[0]["evidence"]) <= 300


def test_pii_disclosure_redacted(chat_server):
    res = _run(chat_server, "pii")
    f = [x for x in res["findings"] if x["source"].endswith(
        "data-disclosure")]
    assert f and f[0]["severity"] == "high"
    assert "bob@example.com" not in f[0]["evidence"]
    assert "[REDACTED" in f[0]["evidence"]


def test_excessive_agency_candidate(chat_server):
    res = _run(chat_server, "agency")
    f = [x for x in res["findings"] if x["source"].endswith(
        "excessive-agency")]
    assert f and f[0]["severity"] == "high"


def test_unbounded_consumption_medium(chat_server):
    res = _run(chat_server, "usage")
    f = [x for x in res["findings"] if x["source"].endswith(
        "unbounded-consumption")]
    assert f and f[0]["severity"] == "medium"


def test_rag_bypass_internal_path(chat_server):
    res = _run(chat_server, "rag")
    f = [x for x in res["findings"] if x["source"].endswith("rag-bypass")]
    assert f and f[0]["severity"] == "high"
    assert "/internal/" in f[0]["evidence"]


def test_clean_server_no_findings(chat_server):
    res = _run(chat_server, "clean")
    assert res["findings"] == []
    assert res["endpoint"]


def test_never_raises_dead_target():
    res = run_llmsec("http://127.0.0.1:1", allowlist=None)
    assert "findings" in res


def test_allowlist_blocks():
    res = run_llmsec("http://example.com",
                     allowlist=["other.example"], endpoint="/api/chat")
    assert res["skipped"] and not res["findings"]


def test_explicit_endpoint_used(chat_server):
    FakeChatHandler.script = {"mode": "sysprompt"}
    res = run_llmsec(chat_server, endpoint="/api/chat", allowlist=None)
    assert res["endpoint"] == chat_server + "/api/chat"
