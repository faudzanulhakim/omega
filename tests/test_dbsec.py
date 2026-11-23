"""Hermetic tests for omega/scanning/dbsec.py — database backend checks.

Loopback TCP servers fake Redis (PING -> +PONG) and Mongo (isMaster
reply); port fingerprinting is injectable; the SQLi-channel feature
probe uses a fake fetch. Covers: fingerprint, exposure findings,
dangerous-feature matrix notes, MySQL LOAD_FILE confirm through the
SQLi channel, MSSQL xp_cmdshell differential, SQLi-channel gating,
Redis/Mongo unauth confirmed findings, no-limits gate skip note,
TLS-transit indicator, allowlist, never-raises. >= 8 tests.
"""

import socket
import threading

import pytest

from omega.scanning.dbsec import (
    DANGEROUS_FEATURES,
    fingerprint_ports,
    run_dbsec,
    sqli_feature_probe,
    unauth_checks,
)


def _tcp_server(responder):
    """Loopback TCP server that runs ``responder(sock)`` per client."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                responder(conn)
            except OSError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield srv.getsockname()[1]
    stop.set()
    srv.close()


@pytest.fixture
def redis_server():
    def responder(conn):
        data = conn.recv(64)
        if b"PING" in data:
            conn.sendall(b"+PONG\r\n")
    for port in _tcp_server(responder):
        yield port


@pytest.fixture
def mongo_server():
    def responder(conn):
        conn.recv(256)
        conn.sendall(b"isMaster\x00ok\x00")
    for port in _tcp_server(responder):
        yield port


def _probe_map(open_ports, banners=None):
    banners = banners or {}

    def probe(host, port, timeout, payload=None, read=True):
        if port in open_ports:
            return banners.get(port, b"").encode() \
                if isinstance(banners.get(port, b""), str) \
                else banners.get(port, b"")
        return None
    return probe


def test_fingerprint_ports_identifies_services():
    probe = _probe_map({3306, 6379}, {3306: "5.7.37 MySQL"})
    out = fingerprint_ports("127.0.0.1", timeout=0.1, probe_fn=probe)
    assert out[3306]["service"] == "mysql"
    assert "MySQL" in out[3306]["banner"]
    assert 6379 in out and out[6379]["banner"] == ""


def test_redis_unauth_confirmed(redis_server):
    findings = unauth_checks("127.0.0.1",
                             {redis_server: {"service": "redis"}},
                             gate_open=False, timeout=2.0)
    f = [x for x in findings if x["source"].endswith("redis-unauth")]
    assert f and f[0]["verification"] == "confirmed"
    assert f[0]["severity"] == "high"


def test_mongo_unauth_confirmed(mongo_server):
    findings = unauth_checks("127.0.0.1",
                             {mongo_server: {"service": "mongodb"}},
                             gate_open=False, timeout=2.0)
    f = [x for x in findings if x["source"].endswith("mongo-unauth")]
    assert f and f[0]["verification"] == "confirmed"
    assert f[0]["severity"] == "high"


def test_default_creds_skipped_only_with_gate():
    findings = unauth_checks("127.0.0.1", {3306, 5432}, gate_open=True)
    notes = [x for x in findings
             if x["source"].endswith("default-creds-skipped")]
    assert len(notes) == 2
    assert "hydra" in notes[0]["verification_note"]
    # without the gate nothing is emitted
    assert unauth_checks("127.0.0.1", {3306}, gate_open=False) == []


def test_mysql_loadfile_confirmed_via_sqli_channel():
    import urllib.parse

    def fetch(method, url, headers=None, body=None):
        assert "LOAD_FILE('/etc/hostname')" in urllib.parse.unquote(url)
        return 200, {}, b"web-prod-01 <html></html>"

    finding = {"source": "omega-exploit/sqli_union", "param": "q"}
    out = sqli_feature_probe(finding, fetch, "http://target", "mysql")
    assert out is not None
    assert out["severity"] == "critical"
    assert out["verification"] == "confirmed"


def test_mssql_xpcmdshell_differential_candidate():
    def fetch(method, url, headers=None, body=None):
        if "xp_cmdshell" in url:
            return 500, {}, b"Could not find procedure xp_cmdshell."
        return 200, {}, b"ok"

    finding = {"source": "omega-offense/sqli", "param": "q"}
    out = sqli_feature_probe(finding, fetch, "http://target", "mssql")
    assert out is not None and out["severity"] == "high"
    assert out["verification"] == "candidate"


def test_feature_probe_requires_sqli_channel():
    state = {"findings": [{"source": "omega-llmsec/prompt-injection"}]}
    probe = _probe_map({3306}, {3306: "5.7.37 MySQL"})
    res = run_dbsec("http://target", fetch=lambda *a, **k: (200, {}, b""),
                    state=state, probe_fn=probe, timeout=0.1)
    assert any("no confirmed SQLi channel" in str(v)
               for v in res["skipped"].values())


def test_run_dbsec_exposure_and_matrix():
    probe = _probe_map({3306, 5432, 6379},
                       {3306: "5.7.37 MySQL Community",
                        5432: "PostgreSQL 14.2"})
    res = run_dbsec("http://127.0.0.1", probe_fn=probe, timeout=0.1)
    srcs = [f["source"] for f in res["findings"]]
    assert srcs.count("omega-dbsec/db-exposure") == 3
    assert "omega-dbsec/feature-matrix" in srcs
    assert sorted(DANGEROUS_FEATURES) == \
        ["mssql", "mysql", "postgres"]
    exposure = [f for f in res["findings"]
                if f["source"].endswith("db-exposure")]
    mysql = [f for f in exposure if "mysql" in f["title"]]
    assert mysql[0]["severity"] == "high"


def test_redis_no_tls_indicator(redis_server):
    probe = _probe_map({6379})
    res = run_dbsec("http://127.0.0.1", probe_fn=probe, timeout=0.1)
    f = [x for x in res["findings"]
         if x["source"].endswith("no-tls-transit")]
    assert f and f[0]["severity"] == "medium"


def test_run_dbsec_real_redis_end_to_end(redis_server, monkeypatch):
    """Full run_dbsec pass: fingerprint sees 6379 open and the unauth
    PING check confirms against the loopback fake Redis."""
    import omega.scanning.dbsec as dbsec
    monkeypatch.setattr(
        dbsec, "_redis_probe",
        lambda h, p, t: dbsec._default_probe(
            "127.0.0.1", redis_server, t, payload=b"PING\r\n"))

    def probe(host, port, timeout, payload=None, read=True):
        return b"" if port == 6379 else None

    res = run_dbsec("http://127.0.0.1", probe_fn=probe, timeout=0.5)
    assert 6379 in res["open_ports"]
    assert any(x["source"].endswith("redis-unauth") and
               x["verification"] == "confirmed"
               for x in res["findings"])


def test_never_raises_and_allowlist():
    res = run_dbsec("http://127.0.0.1:1", timeout=0.1,
                    allowlist=["other.example"])
    assert res["skipped"] and not res["findings"]
    closed = lambda *a, **k: None  # all ports closed
    res2 = run_dbsec("http://127.0.0.1:1", timeout=0.1, probe_fn=closed)
    assert "findings" in res2 and res2["open_ports"] == []
