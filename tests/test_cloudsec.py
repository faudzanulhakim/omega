"""tests/test_cloudsec.py — hermetic tests for omega.scanning.cloudsec.

Loopback-only: bucket probes run against a local ThreadingHTTPServer
via base overrides, IMDS/SSRF via a stub fetch. No real egress.
Covers bucket XML/403/404, fingerprint paths, IMDSv1 SSRF, budget,
never-raise and allowlist gating.
"""

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omega.scanning.cloudsec import (  # noqa: E402
    bucket_names,
    probe_buckets,
    probe_cloud_paths,
    probe_imds_ssrf,
    run_cloudsec,
)


# ------------------------------------------------------------- fixtures

def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _make_server(routes, port=None):
    """routes: {path: (status, body)}; unmatched -> 404 NoSuchBucket."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            route = routes.get(self.path)
            if route is None:
                body = (b'<?xml version="1.0" encoding="UTF-8"?>'
                        b"<Error><Code>NoSuchBucket</Code></Error>")
                self.send_response(404)
            else:
                status, payload = route
                body = payload.encode() if isinstance(payload, str) else payload
                self.send_response(status)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port or 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, "http://127.0.0.1:%s" % srv.server_address[1]


LIST_XML = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            "<Name>acme-backup</Name>"
            "<Contents><Key>dump.sql</Key></Contents></ListBucketResult>")
DENIED_XML = ('<?xml version="1.0" encoding="UTF-8"?>'
              "<Error><Code>AccessDenied</Code>"
              "<Message>Access Denied</Message></Error>")


@pytest.fixture
def bucket_server():
    srv, base = _make_server({
        "/acme-backup": (200, LIST_XML),
        "/acme-dev": (403, DENIED_XML),
    })
    yield srv, base
    srv.shutdown()


@pytest.fixture
def path_server():
    srv, base = _make_server({
        "/.aws/credentials": (200, "[default]\naws_access_key_id = AKIA1234\n"
                                   "aws_secret_access_key = abcd\n"),
        "/appspec.yml": (200, "version: 0.0\nos: linux\nhooks:\n"),
        "/docker-compose.yml": (200, "services:\n  db:\n    environment:\n"
                                     "      password: changeme\n"),
        "/config.json": (200, "{}\n"),
    })
    yield srv, base
    srv.shutdown()


# ------------------------------------------------------------- buckets

def test_bucket_names_candidates():
    names = bucket_names("ACME corp")
    assert names[0] == "acmecorp"
    assert "acmecorp-backup" in names
    assert "acmecorp-dev" in names
    assert "acmecorp-assets" in names


def test_bucket_public_listing_critical(bucket_server):
    srv, base = bucket_server
    out = probe_buckets("acme", s3_base=base, gcs_base=base,
                        azure_base=base, budget=10)
    crit = [f for f in out if f["severity"] == "critical"
            and f["confidence"] == "confirmed"]
    assert crit, out
    assert "ListBucketResult" in crit[0]["evidence"]
    assert crit[0]["verification"] == "confirmed"


def test_bucket_private_info(bucket_server):
    srv, base = bucket_server
    out = probe_buckets("acme", s3_base=base, gcs_base=base,
                        azure_base=base, budget=10)
    infos = [f for f in out if f["severity"] == "info"]
    assert infos, out
    assert "AccessDenied" in infos[0]["evidence"] or \
        "AccessDenied" in infos[0]["verification_note"]


def test_bucket_missing_silent():
    srv, base = _make_server({})
    try:
        out = probe_buckets("nosuchorg", s3_base=base, gcs_base=base,
                            azure_base=base, budget=6)
        assert out == []
    finally:
        srv.shutdown()


def test_bucket_budget_cap():
    calls = []

    def fetch(method, url, timeout=0):
        calls.append(url)
        return 404, {}, b""

    probe_buckets("acme", fetch=fetch, budget=3)
    assert len(calls) == 3


# ------------------------------------------------- exposed cloud paths

def test_aws_credentials_exposed_high(path_server):
    srv, base = path_server
    out = probe_cloud_paths(base)
    f = [x for x in out if "/.aws/credentials" in x["location"]]
    assert f and f[0]["severity"] == "high"
    assert f[0]["confidence"] == "confirmed"


def test_docker_compose_and_appspec_exposed(path_server):
    srv, base = path_server
    out = probe_cloud_paths(base)
    locs = " ".join(x["location"] for x in out)
    assert "/appspec.yml" in locs
    assert "/docker-compose.yml" in locs


def test_path_without_fingerprint_no_finding():
    srv, base = _make_server({
        "/.aws/credentials": (200, "# nothing sensitive here\n"),
        "/docker-compose.yml": (200, "services:\n  web:\n    image: nginx\n"),
    })
    try:
        out = probe_cloud_paths(base)
        assert out == []
    finally:
        srv.shutdown()


def test_cloud_paths_allowlist_blocks(path_server):
    srv, base = path_server
    out = probe_cloud_paths(base, allowlist=["example.com"])
    assert out == []


# ----------------------------------------------------- IMDSv1 via SSRF

def test_imds_ssrf_critical():
    def fetch(method, url, timeout=0):
        assert "169.254" in url and "meta-data" in url
        return 200, {}, "ami-id\nami-launch-index\n"

    out = probe_imds_ssrf("http://127.0.0.1:9", ["next"], fetch=fetch)
    assert out and out[0]["severity"] == "critical"
    assert out[0]["confidence"] == "confirmed"


def test_imds_ssrf_no_metadata_no_finding():
    def fetch(method, url, timeout=0):
        return 200, {}, "not found"

    assert probe_imds_ssrf("http://127.0.0.1:9", ["next"], fetch=fetch) == []


def test_imds_ssrf_transport_error_silent():
    def fetch(method, url, timeout=0):
        raise OSError("refused")

    assert probe_imds_ssrf("http://127.0.0.1:9", ["next"], fetch=fetch) == []


# ------------------------------------------------------------- entry

def test_run_cloudsec_never_raises_unreachable():
    dead = "http://127.0.0.1:1"  # closed loopback: bucket probes fail fast
    out = run_cloudsec("http://127.0.0.1:9", org="acme",
                       ssrf_params=["url"], budget=2,
                       s3_base=dead, gcs_base=dead, azure_base=dead)
    assert out["findings"] == []
    assert isinstance(out["ran"], list) and isinstance(out["skipped"], list)


def test_run_cloudsec_end_to_end(path_server, bucket_server):
    _, base = path_server
    _, bbase = bucket_server
    out = run_cloudsec(base, org="acme", ssrf_params=["next"],
                       s3_base=bbase, gcs_base=bbase, azure_base=bbase,
                       budget=20)
    assert "cloud_paths" in out["ran"]
    assert any(f["severity"] == "high" for f in out["findings"])


def test_run_cloudsec_allowlist_gates_target_checks(path_server):
    srv, base = path_server
    dead = "http://127.0.0.1:1"
    out = run_cloudsec(base, org="acme", allowlist=["other.example"],
                       budget=20, s3_base=dead, gcs_base=dead,
                       azure_base=dead)
    assert not [f for f in out["findings"]
                if f["source"] == "omega-cloudsec/cloud_path"]
    assert not [f for f in out["findings"]
                if f["source"].startswith("omega-cloudsec/")]
