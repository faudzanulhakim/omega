"""omega/scanning/k8ssec.py — Kubernetes / container exposure checks.

External + network-reachable, read-only checks against a host derived
from the target URL:

  * unauthenticated API server on 6443/8443/8080 — GET /version returns
    API-server JSON (gitVersion/major) without auth -> HIGH confirmed;
    GET /api/v1/pods distinguishes 403 (RBAC enforced, no finding) from
    200 with pod listing JSON -> CRITICAL confirmed.
  * kubelet 10250 /pods readable without auth -> HIGH confirmed.
  * Kubernetes dashboard paths on 80/443 -> HIGH confirmed when the
    dashboard service route answers.
  * Docker daemon API on 2375 GET /version (ApiVersion JSON) ->
    CRITICAL confirmed. READ-ONLY: only a single GET /version is sent —
    pull/exec/containers are NEVER touched.
  * etcd 2379 GET /version (etcdserver JSON) -> HIGH confirmed.

Every check has a tight connect pre-check and per-request timeout; port
connect failures are silent skips. Findings carry fingerprint evidence.
``run_k8ssec`` never raises.
"""

from __future__ import annotations

import json
import socket
import urllib.parse

__all__ = [
    "API_PORTS",
    "DASHBOARD_PORTS",
    "DOCKER_PORTS",
    "ETCD_PORTS",
    "KUBELET_PORTS",
    "run_k8ssec",
]

from omega.probes import Finding, default_fetch

FETCH_TIMEOUT = 3.0
CONNECT_TIMEOUT = 1.0

API_PORTS = (6443, 8443, 8080)
KUBELET_PORTS = (10250,)
DASHBOARD_PORTS = (80, 443)
DOCKER_PORTS = (2375,)
ETCD_PORTS = (2379,)

DASHBOARD_PATHS = (
    "/api/v1/namespaces/kubernetes-dashboard/services",
    "/#/login",
)

HTTPS_PORTS = (443, 6443, 8443)


def _text(body):
    if isinstance(body, bytes):
        return body.decode("utf-8", "replace")
    return str(body or "")


def _host_of(target):
    host = urllib.parse.urlparse(
        target if "://" in target else "//" + target, scheme="http").hostname
    return host


def _tcp_open(host, port, timeout=CONNECT_TIMEOUT):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def _get(fetch, url):
    """GET with fallback: https first for TLS ports, then plain http
    (covers loopback/plain-HTTP test endpoints). Returns (status, body)
    or None on total failure. Never raises."""
    schemes = ("https", "http") if url.startswith("https://") else ("http",)
    for scheme in schemes:
        u = scheme + "://" + url.split("://", 1)[1]
        try:
            st, _h, body = fetch("GET", u)
            return int(st or 0), _text(body)
        except Exception:
            continue
    return None


def _fetcher(fetch):
    return fetch or default_fetch


def _url_for(host, port, path, scheme=None):
    if scheme is None:
        scheme = "https" if port in HTTPS_PORTS else "http"
    return "%s://%s:%s%s" % (scheme, host, port, path)


def _api_server(host, port, fetch):
    findings = []
    res = _get(fetch, _url_for(host, port, "/version"))
    if res is not None and res[0] == 200:
        try:
            data = json.loads(res[1])
        except Exception:
            data = None
        if isinstance(data, dict) and ("gitVersion" in data or
                                       ("major" in data and "minor" in data)):
            findings.append(Finding(
                "Kubernetes API server reachable without authentication",
                "high", "confirmed",
                "GET /version on port %s returned API-server version JSON "
                "without credentials (gitVersion=%s)"
                % (port, data.get("gitVersion", "?")),
                "curl -sk https://%s:%s/version" % (host, port),
                _url_for(host, port, "/version"), res[1][:200],
                "omega-k8ssec/api_server", confidence="confirmed"))
    res = _get(fetch, _url_for(host, port, "/api/v1/pods"))
    if res is not None and res[0] == 200:
        try:
            data = json.loads(res[1])
        except Exception:
            data = None
        if isinstance(data, dict) and ("items" in data or
                                       data.get("kind") == "PodList"):
            findings.append(Finding(
                "Kubernetes API lists pods without authentication",
                "critical", "confirmed",
                "GET /api/v1/pods on port %s returned %s pod entries "
                "without credentials (200, not RBAC 403)"
                % (port, len(data.get("items") or [])),
                "curl -sk https://%s:%s/api/v1/pods" % (host, port),
                _url_for(host, port, "/api/v1/pods"), res[1][:200],
                "omega-k8ssec/api_pods", confidence="confirmed"))
    # 401/403 on /api/v1/pods = RBAC enforced: no finding, silent
    return findings


def _kubelet(host, port, fetch):
    res = _get(fetch, _url_for(host, port, "/pods"))
    if res is not None and res[0] == 200:
        try:
            data = json.loads(res[1])
        except Exception:
            data = None
        if isinstance(data, dict) and ("items" in data or
                                       data.get("kind") == "PodList"):
            return [Finding(
                "Kubelet read-only API lists pods without authentication",
                "high", "confirmed",
                "GET /pods on kubelet port %s returned pod listing without "
                "auth (%d entries)" % (port, len(data.get("items") or [])),
                "curl -sk https://%s:%s/pods" % (host, port),
                _url_for(host, port, "/pods"), res[1][:200],
                "omega-k8ssec/kubelet_pods", confidence="confirmed")]
    return []


def _dashboard(host, port, fetch):
    for path in DASHBOARD_PATHS:
        res = _get(fetch, _url_for(host, port, path))
        if res is not None and res[0] == 200 and \
                "kubernetes-dashboard" in res[1].lower():
            return [Finding(
                "Kubernetes dashboard reachable without authentication",
                "high", "confirmed",
                "GET %s on port %s returned the dashboard (200, anonymous)"
                % (path, port),
                "curl -sk https://%s:%s%s" % (host, port, path),
                _url_for(host, port, path), res[1][:200],
                "omega-k8ssec/dashboard", confidence="confirmed")]
    return []


def _docker(host, port, fetch):
    # READ-ONLY: a single anonymous GET /version — never pull/exec/list
    res = _get(fetch, _url_for(host, port, "/version"))
    if res is not None and res[0] == 200:
        try:
            data = json.loads(res[1])
        except Exception:
            data = None
        if isinstance(data, dict) and ("ApiVersion" in data or
                                       ("Version" in data and
                                        "Os" in data)):
            return [Finding(
                "Docker daemon API exposed without authentication",
                "critical", "confirmed",
                "GET /version on port %s returned daemon JSON "
                "(Version=%s, ApiVersion=%s) — root-equivalent API open"
                % (port, data.get("Version", "?"),
                   data.get("ApiVersion", "?")),
                "curl -s http://%s:%s/version  # read-only check" %
                (host, port),
                _url_for(host, port, "/version"), res[1][:200],
                "omega-k8ssec/docker_api", confidence="confirmed")]
    return []


def _etcd(host, port, fetch):
    res = _get(fetch, _url_for(host, port, "/version"))
    if res is not None and res[0] == 200:
        body = res[1]
        if "etcdserver" in body:
            return [Finding(
                "etcd cluster endpoint reachable without authentication",
                "high", "confirmed",
                "GET /version on port %s returned etcd version JSON (%s)"
                % (port, body.strip()[:80]),
                "curl -s http://%s:%s/version" % (host, port),
                _url_for(host, port, "/version"), body[:200],
                "omega-k8ssec/etcd", confidence="confirmed")]
    return []


def run_k8ssec(target, fetch=None, budget=20, log=None,
               api_ports=API_PORTS, kubelet_ports=KUBELET_PORTS,
               dashboard_ports=DASHBOARD_PORTS, docker_ports=DOCKER_PORTS,
               etcd_ports=ETCD_PORTS, connect_timeout=CONNECT_TIMEOUT):
    """Entry point. Returns {findings, ran, skipped}. Never raises.
    Port tuples are overridable (tests / scoped engagement profiles)."""
    log = log or (lambda msg: None)
    fetch = _fetcher(fetch)
    host = _host_of(target)
    ran, skipped = [], []
    findings = []
    if not host:
        skipped.append({"tool": "k8ssec", "reason": "no host in target"})
        return {"findings": findings, "ran": ran, "skipped": skipped}

    checks = (
        ("api_server", api_ports, _api_server),
        ("kubelet", kubelet_ports, _kubelet),
        ("dashboard", dashboard_ports, _dashboard),
        ("docker_api", docker_ports, _docker),
        ("etcd", etcd_ports, _etcd),
    )
    sent = 0
    for name, ports, fn in checks:
        for port in ports:
            if sent >= max(1, budget):
                return {"findings": findings, "ran": ran,
                        "skipped": skipped}
            try:
                if not _tcp_open(host, port, connect_timeout):
                    continue  # closed port: silent skip
            except Exception:
                continue
            sent += 1
            try:
                got = fn(host, port, fetch) or []
                ran.append("%s:%s" % (name, port))
                findings.extend(got)
            except Exception as exc:  # contained
                skipped.append({"tool": "%s:%s" % (name, port),
                                "reason": "%s: %s"
                                          % (type(exc).__name__, exc)})
                log("[k8ssec] %s:%s failed: %s" % (name, port, exc))
    return {"findings": findings, "ran": ran, "skipped": skipped}
