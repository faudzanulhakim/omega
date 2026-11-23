"""Hermetic tests for omega.scanning.blotamper (business-logic tamper
heuristics). Local ThreadingHTTPServer "order" endpoints; the suite
must only flag SAFE-READ differentials, never touch final-submit
endpoints, and always stay candidate with a manual-confirmation note.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(
    __import__("os").path.abspath(__file__))))

from omega.scanning.blotamper import (  # noqa: E402
    FINAL_SUBMIT_HINTS,
    MONEY_FIELDS,
    extract_money_fields,
    find_money_forms,
    is_final_submit,
    run_blotamper,
    tamper_values,
)

MONEY_FORM = (b"<html><form action=\"/order/update\" method=\"post\">"
              b"<input name=\"item\" value=\"widget\">"
              b"<input name=\"price\" value=\"10\">"
              b"<input name=\"total\" value=\"10\">"
              b"</form></html>")


class OrderHandler(BaseHTTPRequestHandler):
    """Fake order endpoint. Knobs:

    tamper_accepted -- if True, a tampered price=0 gets a DIFFERENT
                       total echoed back with 200 (vulnerable).
    reject_tamper   -- if True, tampered requests get 400.
    """
    tamper_accepted = True
    reject_tamper = False
    posted = None  # list of (path, body)

    def log_message(self, *a):
        pass

    def _send(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/checkout", "/cart", "/order", "/buy",
                         "/store"):
            self._send(200, MONEY_FORM)
        else:
            self._send(404, b"nope")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("latin-1")
        if self.posted is not None:
            self.posted.append((self.path, raw))
        fields = dict(p.split("=", 1) for p in raw.split("&") if "=" in p)
        tampered = fields.get("price") == "0" or \
            fields.get("total") == "0"
        if tampered and self.reject_tamper:
            self._send(400, b'{"error": "invalid amount"}')
            return
        if tampered and self.tamper_accepted:
            self._send(200, b'{"status": "ok", "total": 0, "amount": 0}')
            return
        self._send(200, b'{"status": "ok", "total": 10, "amount": 10}')


@pytest.fixture
def order_server():
    made = []

    def make(**attrs):
        attrs.setdefault("posted", [])
        handler = type("H", (OrderHandler,), attrs)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        made.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1], handler.posted

    yield make
    for srv in made:
        srv.shutdown()


def _fetch_of(base):
    from omega.deepchecks import default_fetch
    def fetch(method, url, headers=None, body=None):
        return default_fetch(method, url, headers=headers, body=body)
    return fetch


# ------------------------------------------------------- unit helpers

def test_money_fields_constant():
    assert set(MONEY_FIELDS) == {"price", "amount", "qty", "quantity",
                                 "discount", "coupon", "total"}


def test_extract_money_fields_subset():
    fields = {"item": "x", "price": "10", "total": "10", "color": "red"}
    assert extract_money_fields(fields) == {"price": "10", "total": "10"}


def test_tamper_rules_price_qty_discount_total():
    assert tamper_values("price", "10") == "0"
    assert tamper_values("quantity", "3") == "-1"
    assert tamper_values("qty", "3") == "-1"
    assert tamper_values("discount", "0") == "100"
    assert tamper_values("total", "10") == "0"


def test_tamper_coupon_duplicated():
    assert tamper_values("coupon", "SAVE10") == "SAVE10,SAVE10"
    assert tamper_values("coupon", "") == "OMEGA,OMEGA"


def test_tamper_non_money_field_returns_none():
    assert tamper_values("item", "widget") is None


def test_is_final_submit_guard_paths():
    for hint in ("pay", "purchase", "complete", "confirm", "finalize"):
        assert is_final_submit("/" + hint)
    assert is_final_submit("/order/update") is False


def test_find_money_forms_parses_form_fields(order_server):
    base, _posted = order_server()
    flows = find_money_forms(base, _fetch_of(base))
    assert flows and flows[0]["action"] == "/order/update"
    assert flows[0]["fields"]["price"] == "10"


# --------------------------------------------------------- differential

def test_tampered_total_accepted_differentially_is_candidate(order_server):
    base, _posted = order_server()
    res = run_blotamper(base, _fetch_of(base), budget=30)
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["verification"] == "candidate"  # ALWAYS candidate
    assert f["severity"] == "high"
    assert "requires manual business confirmation" in f["verification_note"]
    assert "No purchase was completed" in f["verification_note"]
    assert base in f["manual_check"]
    assert "price=0" in f["evidence"] or "price=0" in f["title"] or \
        "price=0" in f["verification_note"]
    assert f["source"] == "omega-blotamper/differential"


def test_validating_server_no_finding(order_server):
    base, posted = order_server(reject_tamper=True)
    res = run_blotamper(base, _fetch_of(base), budget=30)
    assert res["findings"] == []
    assert any("rejected" in v for v in res["skipped"].values())


def test_accepted_but_identical_totals_no_finding(order_server):
    """Differential guard: server echoes the same total regardless ->
    no finding."""
    class Flat(OrderHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            self._send(200, b'{"status": "ok", "total": 10}')

    base = "http://127.0.0.1:%d" % 0  # replaced below
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Flat)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        res = run_blotamper(base, _fetch_of(base), budget=30)
        assert res["findings"] == []
        assert any("totals identical" in v
                   for v in res["skipped"].values())
    finally:
        srv.shutdown()


def test_baseline_failure_skips_flow_as_unsafe(order_server):
    class Broken(OrderHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            self._send(500, b"boom")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Broken)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        res = run_blotamper(base, _fetch_of(base), budget=30)
        assert res["findings"] == []
        assert any("cannot be identified as safe" in v
                   for v in res["skipped"].values())
    finally:
        srv.shutdown()


# ------------------------------------------------- purchase-completion guard

def test_final_submit_endpoint_never_tampered(order_server):
    """A money-bearing form pointing at a final submit endpoint must be
    skipped with the guard note and receive NO POST at all."""
    final_form = MONEY_FORM.replace(b"/order/update", b"/pay/confirm")

    class Final(OrderHandler):
        def do_GET(self):
            self._send(200, final_form)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Final)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        res = run_blotamper(base, _fetch_of(base), budget=30)
        assert res["findings"] == []
        assert any("purchase-completion guard" in v
                   for v in res["skipped"].values())
    finally:
        srv.shutdown()


def test_no_post_ever_reaches_final_submit_path(order_server):
    base, posted = order_server()
    run_blotamper(base, _fetch_of(base), budget=30)
    for path, _body in posted:
        low = path.lower()
        assert not any(h in low for h in FINAL_SUBMIT_HINTS), path


# ------------------------------------------------------------- API specs

def test_spec_driven_flow_produces_candidate(order_server):
    base, _posted = order_server()
    specs = [{"method": "POST", "url": "/order/update",
              "body": {"item": "widget", "price": "10", "total": "10"}}]
    res = run_blotamper(base, _fetch_of(base), budget=30, specs=specs)
    assert len(res["findings"]) == 1
    assert res["findings"][0]["verification"] == "candidate"


def test_malformed_spec_body_is_contained(order_server):
    base, _posted = order_server()
    specs = [{"method": "POST", "url": "/order/update", "body": "{bad json"}]
    res = run_blotamper(base, _fetch_of(base), budget=30, specs=specs)
    # contained: the malformed spec is ignored, the form flow still runs
    assert isinstance(res["findings"], list)


# ---------------------------------------------------------------- gates

def test_no_money_flow_skips_cleanly():
    def fetch(method, url, headers=None, body=None):
        return 200, {}, b"<form action=\"/x\"><input name=\"q\"></form>"
    res = run_blotamper("http://t.example", fetch)
    assert res["findings"] == []
    assert "no money-bearing flow" in res["skipped"]["__all__"]


def test_allowlist_blocks_all(order_server):
    base, posted = order_server()
    res = run_blotamper(base, _fetch_of(base),
                        allowlist=["not-the-target.example"])
    assert res["findings"] == [] and res["ran"] == []
    assert "__all__" in res["skipped"]
    assert posted == []


def test_dead_target_never_raises():
    res = run_blotamper("http://127.0.0.1:1/", _fetch_of("http://127.0.0.1:1"))
    assert res["findings"] == []


def test_result_shape_and_evidence_cap(order_server):
    base, _posted = order_server()
    res = run_blotamper(base, _fetch_of(base), budget=30)
    assert set(res) == {"findings", "skipped", "ran", "requests_sent"}
    for f in res["findings"]:
        assert f["verification"] == "candidate"
        assert f["severity"] == "high"
        assert len(f["evidence"]) <= 300
