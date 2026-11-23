"""Hermetic tests for omega.scanning.hpp (parameter pollution +
mass assignment). Loopback ThreadingHTTPServer fixtures; benign inert
values only."""

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(
    __import__("os").path.abspath(__file__))))

from omega.scanning.hpp import (  # noqa: E402
    candidate_pairs,
    mass_assignment_probe,
    run_hpp,
)


class HppHandler(BaseHTTPRequestHandler):
    """Knobs:
    last_value_differential (bool): when True, duplicate parameters
      resolve to the LAST value (classic HPP stack behavior); when
      False, the response is identical regardless of duplicates.
    echo_post (bool): echo the POST body back (accepted); otherwise a
      constant body (no mass-assignment differential).
    """
    last_value_differential = True
    echo_post = False

    def log_message(self, *a):
        pass

    def _respond(self, text, status=200):
        body = text.encode("latin-1")
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.last_value_differential:
            # clean stack: constant response, duplicates change nothing
            self._respond("static")
            return
        qs = parse_qs(self.path.split("?", 1)[-1] if "?" in self.path else "")
        vals = {k: v[-1] for k, v in qs.items()}
        self._respond("values=%s" % sorted(vals.items()))

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("latin-1", "replace")
        if self.echo_post:
            self._respond("posted=%s" % body)
        else:
            self._respond("accepted")


@pytest.fixture
def hpp_server():
    made = []

    def make(**attrs):
        handler = type("H", (HppHandler,), attrs)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        made.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield make
    for srv in made:
        srv.shutdown()


def test_hpp_differential_found(hpp_server):
    base = hpp_server()
    out = run_hpp(base, path_info={"paths": ["/search"],
                                   "params": ["q"]})
    hits = [f for f in out if f["source"] == "omega-hpp/hpp_differential"]
    assert hits
    f = hits[0]
    assert f["verification"] == "candidate"
    assert f["severity"] in ("low", "medium")
    assert "param=q" in f["evidence"] and "repeat_ok=True" in f["evidence"]


def test_hpp_differential_is_consistent(hpp_server):
    """The finding requires the duplicate request to reproduce the same
    differential twice; the stack here is deterministic so one finding
    per (path, param) pair."""
    base = hpp_server()
    out = run_hpp(base, path_info={"paths": ["/search"],
                                   "params": ["q", "lang"]})
    hits = [f for f in out if f["source"] == "omega-hpp/hpp_differential"]
    assert len(hits) == 2


def test_clean_server_no_findings(hpp_server):
    base = hpp_server(last_value_differential=False)
    assert run_hpp(base, path_info={"paths": ["/search"],
                                    "params": ["q"]}) == []


def test_mass_assignment_found(hpp_server):
    base = hpp_server(echo_post=True)
    out = run_hpp(base, path_info={"post_paths": ["/profile"]})
    hits = [f for f in out if f["source"] == "omega-hpp/mass_assignment"]
    assert hits
    f = hits[0]
    assert f["severity"] == "medium"
    assert f["verification"] == "candidate"
    assert "accepted the extra parameter without rejection" in f["verification_note"]


def test_mass_assignment_skipped_without_post_paths(hpp_server):
    base = hpp_server(echo_post=True)
    assert run_hpp(base) == []


def test_mass_assignment_no_diff_when_constant(hpp_server):
    base = hpp_server(echo_post=False)
    out = run_hpp(base, path_info={"post_paths": ["/profile"]})
    assert not [f for f in out if f["source"] == "omega-hpp/mass_assignment"]


def test_mass_assignment_probe_direct(hpp_server):
    base = hpp_server(echo_post=True)

    def fetch(method, url, headers=None, body=None):
        return 200, {}, ("posted=%s" % body).encode()

    f = mass_assignment_probe(base, "/profile", fetch)
    assert f is not None and f["source"] == "omega-hpp/mass_assignment"


def test_candidate_pairs_shape():
    pi = {"paths": ["/a", "/b"], "params": ["x", "y"]}
    pairs = candidate_pairs(pi)
    assert ("/a", "x") in pairs and ("/b", "y") in pairs
    assert all(isinstance(p, tuple) and len(p) == 2 for p in pairs)
    # no params -> no pairs
    assert candidate_pairs({"paths": ["/a"], "params": []}) == []


def test_never_raises_on_dead_target():
    import socket as _s
    s = _s.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert run_hpp("http://127.0.0.1:%d" % port,
                   path_info={"paths": ["/a"], "params": ["q"]}) == []
    assert run_hpp("") == []
