"""tests/test_k8ssec.py — hermetic tests for omega.scanning.k8ssec.

Loopback ThreadingHTTPServers fake the Kubernetes API server /version
and /api/v1/pods, kubelet /pods, Docker daemon /version and etcd
/version. Port tuples are overridden to point at the local fixtures —
no real network, no real clusters, read-only GETs only.
"""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from omega.scanning.k8ssec import run_k8ssec  # noqa: E402

K8S_VERSION = json.dumps({
    "major": "1", "minor": "29", "gitVersion": "v1.29.1",
    "gitCommit": "abc", "platform": "linux/amd64",
})
K8S_PODS = json.dumps({"kind": "PodList",
                       "items": [{"metadata": {"name": "web"}}]})
DOCKER_VERSION = json.dumps({"Version": "24.0.7", "ApiVersion": "1.43",
                             "Os": "linux", "Arch": "amd64"})
ETCD_VERSION = json.dumps({"etcdserver": "3.5.9", "etcdcluster": "3.5.0"})


def _make_server(routes, methods=None):
    """routes: {path: (status, body)}; methods records request methods."""

    class Handler(BaseHTTPRequestHandler):
        def _serve(self):
            if methods is not None:
                methods.append(self.command)
            route = routes.get(self.path)
            if route is None:
                body = b"{}"
                status = 404
            else:
                status, payload = route
                body = (payload.encode() if isinstance(payload, str)
                        else payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _serve
        do_POST = _serve
        do_HEAD = _serve

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _target(port):
    return "http://127.0.0.1:%s" % port


# -------------------------------------------------------- API server

def test_api_server_version_high():
    srv, port = _make_server({"/version": (200, K8S_VERSION)})
    try:
        out = run_k8ssec(_target(port), api_ports=(port,), kubelet_ports=(),
                         dashboard_ports=(), docker_ports=(), etcd_ports=())
        f = [x for x in out["findings"]
             if x["source"] == "omega-k8ssec/api_server"]
        assert f and f[0]["severity"] == "high"
        assert f[0]["confidence"] == "confirmed"
        assert "gitVersion" in f[0]["evidence"]
    finally:
        srv.shutdown()


def test_api_pods_200_critical():
    routes = {"/version": (200, K8S_VERSION), "/api/v1/pods": (200, K8S_PODS)}
    srv, port = _make_server(routes)
    try:
        out = run_k8ssec(_target(port), api_ports=(port,), kubelet_ports=(),
                         dashboard_ports=(), docker_ports=(), etcd_ports=())
        f = [x for x in out["findings"]
             if x["source"] == "omega-k8ssec/api_pods"]
        assert f and f[0]["severity"] == "critical"
        assert f[0]["confidence"] == "confirmed"
    finally:
        srv.shutdown()


def test_api_pods_403_no_finding():
    routes = {"/version": (200, K8S_VERSION),
              "/api/v1/pods": (403, '{"kind":"Status"}')}
    srv, port = _make_server(routes)
    try:
        out = run_k8ssec(_target(port), api_ports=(port,), kubelet_ports=(),
                         dashboard_ports=(), docker_ports=(), etcd_ports=())
        assert not [x for x in out["findings"]
                    if x["source"] == "omega-k8ssec/api_pods"]
    finally:
        srv.shutdown()


# ------------------------------------------------------------ kubelet

def test_kubelet_pods_high():
    srv, port = _make_server({"/pods": (200, K8S_PODS)})
    try:
        out = run_k8ssec(_target(port), api_ports=(), kubelet_ports=(port,),
                         dashboard_ports=(), docker_ports=(), etcd_ports=())
        f = [x for x in out["findings"]
             if x["source"] == "omega-k8ssec/kubelet_pods"]
        assert f and f[0]["severity"] == "high"
        assert "items" in f[0]["evidence"] or "1 entries" in f[0]["evidence"]
    finally:
        srv.shutdown()


def test_kubelet_403_silent():
    srv, port = _make_server({"/pods": (403, "forbidden")})
    try:
        out = run_k8ssec(_target(port), api_ports=(), kubelet_ports=(port,),
                         dashboard_ports=(), docker_ports=(), etcd_ports=())
        assert out["findings"] == []
    finally:
        srv.shutdown()


# ------------------------------------------------------------ docker

def test_docker_api_critical():
    methods = []
    srv, port = _make_server({"/version": (200, DOCKER_VERSION)},
                             methods=methods)
    try:
        out = run_k8ssec(_target(port), api_ports=(), kubelet_ports=(),
                         dashboard_ports=(), docker_ports=(port,),
                         etcd_ports=())
        f = [x for x in out["findings"]
             if x["source"] == "omega-k8ssec/docker_api"]
        assert f and f[0]["severity"] == "critical"
        assert f[0]["confidence"] == "confirmed"
        assert "ApiVersion" in f[0]["evidence"]
    finally:
        srv.shutdown()


def test_docker_api_read_only_gets_only():
    """Read-only contract: only GET /version is ever sent — no pull,
    exec, containers or creates."""
    methods = []
    srv, port = _make_server({"/version": (200, DOCKER_VERSION)},
                             methods=methods)
    try:
        run_k8ssec(_target(port), api_ports=(), kubelet_ports=(),
                   dashboard_ports=(), docker_ports=(port,), etcd_ports=())
        assert methods and set(methods) == {"GET"}
    finally:
        srv.shutdown()


def test_docker_api_no_json_no_finding():
    srv, port = _make_server({"/version": (200, "<html>nginx</html>")})
    try:
        out = run_k8ssec(_target(port), api_ports=(), kubelet_ports=(),
                         dashboard_ports=(), docker_ports=(port,),
                         etcd_ports=())
        assert out["findings"] == []
    finally:
        srv.shutdown()


# -------------------------------------------------------------- etcd

def test_etcd_version_high():
    srv, port = _make_server({"/version": (200, ETCD_VERSION)})
    try:
        out = run_k8ssec(_target(port), api_ports=(), kubelet_ports=(),
                         dashboard_ports=(), docker_ports=(),
                         etcd_ports=(port,))
        f = [x for x in out["findings"] if x["source"] == "omega-k8ssec/etcd"]
        assert f and f[0]["severity"] == "high"
        assert "etcdserver" in f[0]["evidence"]
    finally:
        srv.shutdown()


# --------------------------------------------------------- dashboard

def test_dashboard_probe_high():
    routes = {"/api/v1/namespaces/kubernetes-dashboard/services":
              (200, "<html>kubernetes-dashboard</html>")}
    srv, port = _make_server(routes)
    try:
        out = run_k8ssec(_target(port), api_ports=(), kubelet_ports=(),
                         dashboard_ports=(port,), docker_ports=(),
                         etcd_ports=())
        f = [x for x in out["findings"]
             if x["source"] == "omega-k8ssec/dashboard"]
        assert f and f[0]["severity"] == "high"
    finally:
        srv.shutdown()


# ------------------------------------------------------------ silent

def test_closed_ports_silent_skip():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()
    out = run_k8ssec(_target(dead_port), api_ports=(dead_port,),
                     kubelet_ports=(dead_port,), dashboard_ports=(dead_port,),
                     docker_ports=(dead_port,), etcd_ports=(dead_port,))
    assert out["findings"] == []
    assert out["ran"] == []


def test_run_k8ssec_never_raises():
    out = run_k8ssec("http://127.0.0.1:1", budget=1)
    assert isinstance(out, dict) and out["findings"] == []


def test_run_k8ssec_budget_cap():
    srv, port = _make_server({"/version": (200, K8S_VERSION),
                              "/api/v1/pods": (200, K8S_PODS)})
    try:
        out = run_k8ssec(_target(port), api_ports=(port,), kubelet_ports=(),
                         dashboard_ports=(), docker_ports=(), etcd_ports=(),
                         budget=1)
        assert len(out["ran"]) <= 1
    finally:
        srv.shutdown()
