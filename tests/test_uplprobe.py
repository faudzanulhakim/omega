"""Hermetic tests for omega.scanning.uplprobe (benign-marker upload
probe). Local ThreadingHTTPServer fixtures only; no real egress. Key
invariants: CONFIRMED only on stored+retrieved differential, and the
suite NEVER uploads webshell content — every POST body is the inert
plain-text marker.
"""

import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(
    __import__("os").path.abspath(__file__))))

from omega.scanning.uplprobe import (  # noqa: E402
    MARKER_CONTENT_PREFIX,
    EXEC_EXTENSIONS,
    find_upload_forms,
    multipart_encode,
    run_uplprobe,
    stored_path_extract,
)

FORM_HTML = (b"<html><body><form action=\"/upload\" method=\"post\" "
             b"enctype=\"multipart/form-data\">"
             b"<input type=\"file\" name=\"file\">"
             b"<input type=\"submit\"></form></body></html>")


class UploadServer(BaseHTTPRequestHandler):
    """Hermetic upload endpoint. Behaviour knobs are class attrs:

    reject_exts   -- extensions answered with 403
    store         -- whether uploads are stored at all
    retrievable   -- whether stored files are served back on GET
    """
    reject_exts = ()
    store = True
    retrievable = True
    stored = None  # set per-server: {path: bytes}
    posted_bodies = None

    def log_message(self, *a):
        pass

    def _send(self, status, body=b"", ctype="text/html"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/upload", "/upload.html"):
            self._send(200, FORM_HTML)
            return
        if self.path.startswith("/uploads/"):
            if self.retrievable and self.path in (self.stored or {}):
                self._send(200, self.stored[self.path], "text/plain")
            else:
                self._send(404, b"not found")
            return
        self._send(404, b"nope")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        if self.posted_bodies is not None:
            self.posted_bodies.append(raw)
        m = re.search(rb'filename="([^"]+)"', raw)
        fname = m.group(1).decode() if m else "unknown"
        ext = ("." + fname.rsplit(".", 1)[-1]) if "." in fname else ""
        if ext in self.reject_exts:
            self._send(403, b"extension not allowed")
            return
        if self.store:
            content = raw.split(b"\r\n\r\n", 1)[-1].rsplit(b"--", 1)[0]
            self.stored["/uploads/" + fname] = content
            self._send(200, ("stored at /uploads/%s" % fname).encode())
        else:
            self._send(200, b"upload processed (not stored)")


@pytest.fixture
def up_server():
    made = []

    def make(**attrs):
        attrs.setdefault("stored", {})
        attrs.setdefault("posted_bodies", [])
        handler = type("H", (UploadServer,), attrs)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        made.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1], \
            handler.stored, handler.posted_bodies

    yield make
    for srv in made:
        srv.shutdown()


def _find(findings, source_suffix):
    return [f for f in findings if f["source"].endswith(source_suffix)]


# ------------------------------------------------------------- discovery

def test_find_upload_forms_parses_multipart_file_input(up_server):
    base, _stored, _bodies = up_server()
    forms = find_upload_forms(base + "/",
                              lambda m, u, headers=None, body=None:
                              (200, {}, FORM_HTML))
    assert forms == [{"page": "/", "action": "/upload"}]


def test_find_upload_forms_ignores_plain_forms():
    html = (b"<form action=\"/x\" method=\"post\">"
            b"<input type=\"text\" name=\"q\"></form>")
    assert find_upload_forms("http://t.example",
                             lambda m, u, headers=None, body=None:
                             (200, {}, html)) == []


# -------------------------------------------------------------- baseline

def test_baseline_txt_upload_stored_is_info_candidate(up_server):
    base, stored, _bodies = up_server()
    res = run_uplprobe(base, _default_fetch, budget=60)
    hits = _find(res["findings"], "baseline")
    assert len(hits) == 1
    assert hits[0]["severity"] == "info"
    assert hits[0]["verification"] == "candidate"
    assert base in hits[0]["manual_check"]


# --------------------------------------------------- exec-extension diff

def test_exec_extension_stored_and_retrievable_is_confirmed_high(
        up_server):
    base, stored, _bodies = up_server()
    res = run_uplprobe(base, _default_fetch, budget=80)
    hits = _find(res["findings"], "exec-upload")
    assert len(hits) == 1
    f = hits[0]
    assert f["verification"] == "confirmed"
    assert f["severity"] == "high"
    assert f["confidence"] == "high"
    # evidence names at least one executable extension that was stored
    # AND retrieved with the marker
    assert ".php" in f["evidence"]


def test_exec_extension_accepted_without_retrieval_is_candidate(
        up_server):
    base, stored, _bodies = up_server(retrievable=False)
    res = run_uplprobe(base, _default_fetch, budget=80)
    hits = _find(res["findings"], "exec-upload-accepted")
    assert len(hits) == 1
    f = hits[0]
    assert f["verification"] == "candidate"
    assert f["severity"] == "medium"
    assert "could NOT be confirmed" in f["verification_note"]


def test_validating_server_rejects_exec_extensions(up_server):
    base, stored, _bodies = up_server(
        reject_exts=tuple(list(EXEC_EXTENSIONS) +
                          [".pdf.php", ".jpg.php", ".png.jsp"]))
    res = run_uplprobe(base, _default_fetch, budget=80)
    assert _find(res["findings"], "exec-upload") == []
    assert _find(res["findings"], "exec-upload-accepted") == []
    assert _find(res["findings"], "double-ext") == []


# ------------------------------------------------------ double extension

def test_double_extension_accepted_is_candidate_only(up_server):
    base, stored, _bodies = up_server()
    res = run_uplprobe(base, _default_fetch, budget=80)
    hits = _find(res["findings"], "double-ext")
    assert len(hits) == 1
    f = hits[0]
    assert f["verification"] == "candidate"
    assert ".pdf.php" in f["title"]
    assert "not confirmed" in f["verification_note"]


# ------------------------------------------------- validation signals

def test_missing_validation_signals_candidate(up_server):
    base, stored, _bodies = up_server()
    res = run_uplprobe(base, _default_fetch, budget=80)
    hits = _find(res["findings"], "validation-signals")
    assert len(hits) == 1
    ev = hits[0]["evidence"]
    assert "executable extensions accepted" in ev
    assert "echoes stored path" in ev


# ----------------------------------------------------- SAFETY CONTRACT

WEBSHELL_MARKERS = (b"<?php", b"eval(", b"system(", b"shell_exec",
                    b"<%@", b"runtime.exec", b"ProcessBuilder",
                    b"cmd.exe", b"/bin/sh", b"passthru")


def test_never_uploads_webshell_only_inert_markers(up_server):
    base, stored, bodies = up_server()
    res = run_uplprobe(base, _default_fetch, budget=80)
    assert bodies, "the probe must actually have uploaded something"
    for raw in bodies:
        low = raw.lower()
        for marker in WEBSHELL_MARKERS:
            assert marker not in low, (marker, raw[:200])
    # every upload is the inert marker text
    for path, content in stored.items():
        assert MARKER_CONTENT_PREFIX.encode() in content
        assert b"inert test file, no executable content" in content


def test_stored_content_is_plain_text_not_executable(up_server):
    base, stored, _bodies = up_server()
    run_uplprobe(base, _default_fetch, budget=80)
    assert stored
    for content in stored.values():
        text = content.decode("latin-1")
        assert text.startswith(MARKER_CONTENT_PREFIX)
        assert "<%" not in text and "<?" not in text


# ------------------------------------------------------------ multipart

def test_multipart_encode_wellformed():
    ct, body = multipart_encode("a.php", "hello")
    assert ct.startswith("multipart/form-data; boundary=")
    assert b'name="file"; filename="a.php"' in body
    assert b"hello" in body
    assert body.endswith(b"--\r\n")


def test_stored_path_extract_prefers_upload_token():
    assert stored_path_extract("ok saved to /uploads/x.php") == \
        "/uploads/x.php"
    assert stored_path_extract("saved as foo.php", "foo.php") == "foo.php"
    assert stored_path_extract("nothing here", "foo.php") is None


# ---------------------------------------------------------------- gates

def _default_fetch(method, url, headers=None, body=None):
    from omega.deepchecks import default_fetch
    return default_fetch(method, url, headers=headers, body=body)


def test_run_uplprobe_allowlist_blocks_all(up_server):
    base, stored, _bodies = up_server()
    res = run_uplprobe(base, _default_fetch,
                       allowlist=["not-the-target.example"])
    assert res["findings"] == [] and res["ran"] == []
    assert "__all__" in res["skipped"]
    assert stored == {}


def test_run_uplprobe_dead_target_never_raises():
    res = run_uplprobe("http://127.0.0.1:1/", _default_fetch, budget=5)
    assert res["findings"] == []
    assert res["requests_sent"] <= 5


def test_run_uplprobe_result_shape(up_server):
    base, stored, _bodies = up_server()
    res = run_uplprobe(base, _default_fetch, budget=80)
    assert set(res) == {"findings", "skipped", "ran", "requests_sent"}
    assert "form_discovery" in res["ran"]
    for f in res["findings"]:
        assert f["verification"] in ("candidate", "confirmed")
        assert f["source"].startswith("omega-uplprobe/")
        assert len(f["evidence"]) <= 300
        assert base in f["manual_check"]
