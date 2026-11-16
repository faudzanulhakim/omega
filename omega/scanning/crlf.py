"""omega/scanning/crlf.py — CRLF injection / response splitting
(fusion suite name: ``crlf``).

For path+param pairs from ``path_info`` (plus the root), send values
containing ``%0d%0a`` and raw ``\\r\\n`` variants followed by the
marker header name ``X-Omega-Probe``:

  injected_header   — the injected ``X-Omega-Probe`` header appears in
                      the response header block (verified, medium —
                      actual response splitting)
  reflected_crlf    — the CRLF marker is reflected literally in the
                      response body (low candidate)

Also probes path variants (``/x%0d%0aX-Omega-Probe: 1``) over a raw
socket. All payloads are inert markers; never raises.
"""

from __future__ import annotations

from omega.scanning.deepchecks import Finding, default_fetch

import socket
import urllib.parse

__all__ = [
    "REQUEST_BUDGET",
    "PROBE_HEADER",
    "candidate_pairs",
    "crlf_param_probe",
    "crlf_path_probe",
    "run_crlf",
]

REQUEST_BUDGET = 30
PROBE_HEADER = "X-Omega-Probe"
_PROBE_VALUE = "1"
_SOCKET_TIMEOUT = 3.0


def candidate_pairs(path_info=None):
    """(path, param) pairs; falls back to ('/', 'q') so the root path
    variant is always probed."""
    info = path_info or {}
    paths = ["/"] + [p for p in (info.get("paths") or []) if p not in ("/",)]
    params = list(info.get("params") or []) or ["q"]
    pairs = []
    for path in paths[:8]:
        for param in params[:5]:
            pairs.append((path, param))
    return pairs[:12]


def _hdr_get(headers, name):
    lname = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == lname:
            return v
    return None


def _raw_get(host, port, target):
    """Raw HTTP GET over a plain socket (allows raw CRLF in the target).
    Returns (status, headers_dict, body) or (None, {}, b'')."""
    req = ("GET %s HTTP/1.1\r\n"
           "Host: %s:%s\r\n"
           "Connection: close\r\n"
           "\r\n" % (target, host, port))
    sock = None
    try:
        sock = socket.create_connection((host, port),
                                        timeout=_SOCKET_TIMEOUT)
        sock.sendall(req.encode("latin-1"))
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    except Exception:
        return None, {}, b""
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    status = None
    headers = {}
    if lines and lines[0].startswith("HTTP/"):
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            status = None
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


def crlf_param_probe(base_url, path, param, fetch):
    """CRLF-in-parameter probe. Returns (list_of_findings, used_budget).
    Never raises."""
    findings = []
    base = base_url.rstrip("/")
    url = base + (path if path.startswith("/") else "/" + path)
    injection = "%%0d%%0a%s: %s" % (PROBE_HEADER, _PROBE_VALUE)
    enc_tail = urllib.parse.quote(
        "%s: %s" % (PROBE_HEADER, _PROBE_VALUE), safe="")
    variants = (
        urllib.parse.quote(param, safe="") + "=1%0d%0a" + enc_tail,
        urllib.parse.quote(param, safe="") + "=1%0D%0A" + enc_tail,
    )
    used = 0
    for q in variants:
        used += 1
        sep = "&" if "?" in url else "?"
        probe_url = url + sep + q
        try:
            st, headers, body = fetch("GET", probe_url)
        except Exception:
            continue
        if _hdr_get(headers, PROBE_HEADER):
            findings.append(Finding(
                title="CRLF injection produces injected response header "
                      "at %s (%s)" % (path, param),
                severity="medium", verification="verified",
                verification_note=(
                    "A parameter value containing %%0d%%0a followed by "
                    "%s: %s made the injected header appear in the "
                    "response header block — the application reflects "
                    "unencoded CRLF into the response, enabling response "
                    "splitting. Verified by header observation." % (
                        PROBE_HEADER, _PROBE_VALUE)),
                manual_check=(
                    'curl -sS -i "%s?%s=1%%0d%%0a%s:%%201"'
                    % (base + path, param, PROBE_HEADER)),
                location=probe_url,
                evidence="injected_header=%s status=%s" % (PROBE_HEADER, st),
                source="omega-crlf/injected_header"))
        elif PROBE_HEADER in _text_of(body):
            findings.append(Finding(
                title="CRLF marker reflected literally in response body "
                      "at %s (%s)" % (path, param),
                severity="low", verification="candidate",
                verification_note=(
                    "The CRLF payload is echoed literally in the body — "
                    "the input is reflected without sanitization, but "
                    "the CRLF did not reach the header block. Candidate "
                    "only; splitting impact depends on downstream "
                    "parsing."),
                manual_check=(
                    'curl -sS "%s?%s=1%%0d%%0a%s:%%201" | grep -F "%s"'
                    % (base + path, param, PROBE_HEADER, PROBE_HEADER)),
                location=probe_url,
                evidence="reflected=True status=%s" % st,
                source="omega-crlf/reflected_crlf"))
    return findings, used


def _text_of(body):
    if isinstance(body, bytes):
        return body.decode("latin-1", "replace")
    return str(body or "")


def crlf_path_probe(base_url, path="/"):
    """Raw-socket path-variant probe: /x%0d%0aX-Omega-Probe: 1 (the raw
    CRLF is decoded by the server only if it URL-decodes the path).
    Returns a Finding or None. Never raises."""
    import urllib.parse as _up
    p = _up.urlparse(base_url if "://" in base_url else "http://" + base_url)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    if not host:
        return None
    target = (path if path.startswith("/") else "/" + path).rstrip("/")
    target += "/x%%0d%%0a%s:%%20%s" % (PROBE_HEADER, _PROBE_VALUE)
    st, headers, _body = _raw_get(host, port, target)
    if st is None:
        return None
    if _hdr_get(headers, PROBE_HEADER):
        return Finding(
            title="CRLF path injection produces injected response header "
                  "at %s" % path,
            severity="medium", verification="verified",
            verification_note=(
                "A path variant containing %%0d%%0a followed by %s: %s "
                "made the injected header appear in the raw response — "
                "URL-decoded CRLF reaches the response header block "
                "(response splitting). Verified by header observation."
                % (PROBE_HEADER, _PROBE_VALUE)),
            manual_check=(
                'curl -sS --path-as-is -i "%s%s"'
                % (base_url.rstrip("/"), target)),
            location=base_url.rstrip("/") + target,
            evidence="injected_header=%s status=%s" % (PROBE_HEADER, st),
            source="omega-crlf/path_injected_header")
    return None


def run_crlf(base_url, fetch=default_fetch, path_info=None, gate=False):
    """CRLF injection suite. Returns a list of Finding dicts; never
    raises; budget-capped."""
    findings = []
    budget = REQUEST_BUDGET
    base = (base_url or "").rstrip("/")
    if not base:
        return findings
    for path, param in candidate_pairs(path_info):
        if budget <= 0:
            break
        try:
            found, used = crlf_param_probe(base, path, param, fetch)
        except Exception:
            continue
        budget -= max(1, used)
        findings.extend(found)
    if budget > 0:
        budget -= 1
        try:
            f = crlf_path_probe(base)
        except Exception:
            f = None
        if f is not None:
            findings.append(f)
    # keep evidence small and stable
    for f in findings:
        f["evidence"] = str(f.get("evidence") or "")[:300]
    return findings
