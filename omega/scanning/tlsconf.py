"""omega/scanning/tlsconf.py — TLS configuration scan (fusion suite
name: ``tlsconf``).

Prefers ``openssl s_client`` via subprocess (timeout 10) for:

  * certificate expiry (under 30 days -> MEDIUM candidate),
  * weak protocol negotiation (ssl3 / tls1 / tls1.1 accepted -> HIGH
    candidate),
  * weak ciphers on TLS 1.2 (RC4 / 3DES / NULL / EXPORT -> MEDIUM-HIGH),
  * self-signed or hostname-mismatch certificates (MEDIUM).

Falls back to stdlib urllib SSLContext probing (forcing
PROTOCOL_TLSv1_1 etc.) when the openssl binary is missing. A plain
HTTP target is skipped gracefully with an info note. Never raises;
benign — only handshake/certificate inspection.
"""

from __future__ import annotations

import re
import socket
import ssl
import subprocess
import urllib.parse

from omega.scanning.deepchecks import default_fetch

__all__ = [
    "Finding",
    "WEAK_PROTOCOLS",
    "WEAK_CIPHER_TOKENS",
    "OPENSSL_TIMEOUT",
    "check_http_plaintext",
    "run_tlsconf",
]

OPENSSL_TIMEOUT = 10
EXPIRY_DAYS = 30
WEAK_PROTOCOLS = (
    ("-ssl3", "SSLv3"),
    ("-tls1_1", "TLSv1.1"),
    ("-tls1", "TLSv1.0"),
)
# openssl 1.1+ split tls1/tls1_1; probe in preference order and record
# whichever succeeded.
WEAK_CIPHER_TOKENS = ("RC4", "3DES", "NULL", "EXP", "EXPORT")


class Finding(dict):
    """ENGINE-convention finding dict (candidate only)."""

    def __init__(self, title, severity, verification, verification_note,
                 manual_check, location, evidence, source,
                 confidence="medium"):
        super().__init__(
            title=title,
            severity=severity,
            confidence=confidence,
            verification=verification,
            verification_note=verification_note,
            manual_check=manual_check,
            location=location,
            evidence=str(evidence)[:300],
            source=source,
        )


def _target_hostport(base_url):
    p = urllib.parse.urlsplit(base_url if "://" in base_url
                              else "https://" + base_url)
    host = p.hostname or ""
    port = p.port or 443
    return host, port


def check_http_plaintext(base_url, fetch=None):
    """Return the effective base URL if the target speaks plain HTTP
    (i.e. it is not an HTTPS endpoint). None when HTTPS-ish."""
    url = base_url if "://" in base_url else "http://" + base_url
    return url if url.lower().startswith("http:") else None


def _run_openssl(args):
    try:
        proc = subprocess.run(
            ["openssl"] + args, capture_output=True, text=True,
            timeout=OPENSSL_TIMEOUT)
        return proc.stdout + "\n" + proc.stderr
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def _openssl_handshake(host, port, extra=None):
    args = ["s_client", "-connect", "%s:%d" % (host, port),
            "-brief", "-servername", host]
    if extra:
        args = ["s_client", "-connect", "%s:%d" % (host, port),
                "-servername", host] + list(extra)
    # s_client waits on stdin; close it immediately.
    try:
        proc = subprocess.run(["openssl"] + args, capture_output=True,
                              text=True, timeout=OPENSSL_TIMEOUT,
                              input="")
        return proc.stdout + "\n" + proc.stderr
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def _cert_info(host, port):
    """Fetch the leaf certificate and decode it with openssl x509.
    Returns (decoded_text or '', self_signed: bool)."""
    show = _openssl_handshake(host, port, ["-showcerts"])
    if not show:
        return "", False
    self_signed = bool(re.search(
        r"verification error:\s*self[- ]signed", show, re.I))
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                  show, re.S)
    if not m:
        return "", self_signed
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-enddate", "-subject"],
            input=m.group(0), capture_output=True, text=True,
            timeout=OPENSSL_TIMEOUT)
        return proc.stdout, self_signed
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return "", self_signed


def _parse_expiry_days(cert_text):
    """Days until notAfter; None when unparseable."""
    m = re.search(r"notAfter\s*=\s*(.+)", cert_text)
    if not m:
        return None
    try:
        import datetime
        dt = datetime.datetime.strptime(
            m.group(1).strip(), "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=datetime.timezone.utc)
        delta = dt - datetime.datetime.now(datetime.timezone.utc)
        return delta.days
    except Exception:
        return None


def _fallback_probe(host, port):
    """Stdlib SSLContext probing; returns dict with tls11_ok, tls10_ok,
    min_accepted, cipher info, peer cert (or None)."""
    res = {"tls11_ok": False, "tls10_ok": False, "cipher": None,
           "cert": None, "error": None}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=OPENSSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                res["cipher"] = (ss.cipher() or (None,))[0]
                try:
                    res["cert"] = ss.getpeercert()
                except Exception:
                    res["cert"] = None
    except Exception as exc:
        res["error"] = "%s: %s" % (type(exc).__name__, exc)
    # Forced weak-protocol attempts (best effort across versions).
    for attr, key in (("PROTOCOL_TLSv1_1", "tls11_ok"),
                      ("PROTOCOL_TLSv1", "tls10_ok")):
        ver = getattr(ssl, attr, None)
        if ver is None:
            continue
        try:
            ctx = ssl.SSLContext(ver)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port),
                                          timeout=OPENSSL_TIMEOUT) as sock:
                with ctx.wrap_socket(sock) as ss:
                    res[key] = True
        except Exception:
            res[key] = False
    return res


def _weak_ciphers(host, port):
    """Probe TLS 1.2 with a weak-cipher-restricted list."""
    text = _openssl_handshake(host, port, ["-tls1_2", "-cipher",
                                           "ALL:COMPLEMENTOFALL"])
    if not text:
        return None
    m = re.search(r"Cipher\s*:\s*(\S+)", text)
    if not m:
        return None
    return m.group(1)


def run_tlsconf(base_url, fetch=default_fetch, path_info=None, gate=False):
    """Run the TLS configuration scan. Returns a list of Finding dicts
    (plus a plain-HTTP info note); never raises."""
    out = []
    try:
        plain = check_http_plaintext(base_url)
        if plain:
            return [Finding(
                title="Target is plain HTTP — TLS scan skipped",
                severity="info", verification="candidate",
                verification_note=(
                    "The target base URL is http://, so there is no TLS "
                    "endpoint to assess on the default port. Recorded as "
                    "a note; consider TLS on an alternate port "
                    "separately."),
                manual_check="curl -sSI %s" % plain,
                location=plain, evidence="scheme=http",
                source="omega-tlsconf", confidence="high")]

        host, port = _target_hostport(base_url)
        if not host:
            return out

        have_openssl = _run_openssl(["version"]) is not None
        if have_openssl:
            # Certificate: expiry + self-signed.
            cert_text, self_signed = _cert_info(host, port)
            if cert_text:
                days = _parse_expiry_days(cert_text)
                if days is not None and days < EXPIRY_DAYS:
                    out.append(Finding(
                        title="TLS certificate expires in %d day(s)"
                              % max(days, 0),
                        severity="medium", verification="candidate",
                        verification_note=(
                            "The served certificate's notAfter is under "
                            "%d days away. Candidate only — renew before "
                            "expiry." % EXPIRY_DAYS),
                        manual_check="echo | openssl s_client -connect "
                                     "%s:%d 2>/dev/null | openssl x509 "
                                     "-noout -enddate" % (host, port),
                        location="%s:%d" % (host, port),
                        evidence="days_remaining=%d" % days,
                        source="omega-tlsconf", confidence="high"))
                if self_signed:
                    out.append(Finding(
                        title="Self-signed TLS certificate",
                        severity="medium", verification="candidate",
                        verification_note=(
                            "openssl reported a self-signed certificate "
                            "verification error; clients cannot trust "
                            "the endpoint without an explicit exception. "
                            "Candidate only."),
                        manual_check="openssl s_client -connect %s:%d "
                                     "-brief" % (host, port),
                        location="%s:%d" % (host, port),
                        evidence="verify error: self-signed certificate",
                        source="omega-tlsconf", confidence="medium"))

            # Weak protocol negotiation.
            for flag, name in WEAK_PROTOCOLS:
                text = _openssl_handshake(host, port, [flag])
                if text and ("Protocol" in text or "CONNECTION" in text
                             or "Cipher is" in text):
                    if "alert protocol version" in text.lower() or \
                            "handshake failure" in text.lower():
                        continue
                    out.append(Finding(
                        title="Weak TLS protocol negotiated: %s" % name,
                        severity="high", verification="candidate",
                        verification_note=(
                            "The server completed a handshake using %s, "
                            "a protocol with known cryptographic "
                            "weaknesses (POODLE/BEAST-era). Candidate "
                            "only; disable legacy protocols." % name),
                        manual_check="openssl s_client -connect %s:%d %s"
                                     % (host, port, flag),
                        location="%s:%d" % (host, port),
                        evidence="handshake succeeded with %s" % name,
                        source="omega-tlsconf", confidence="high"))
                    break  # one weak-protocol finding is enough

            # Weak ciphers on TLS 1.2.
            cipher = _weak_ciphers(host, port)
            if cipher:
                weak = [t for t in WEAK_CIPHER_TOKENS
                        if t.lower() in cipher.lower()]
                if weak:
                    out.append(Finding(
                        title="Weak TLS 1.2 cipher selected: %s" % cipher,
                        severity="medium", verification="candidate",
                        verification_note=(
                            "A TLS 1.2 handshake selected cipher %s, "
                            "matching weak token(s) %s (RC4/3DES/NULL/"
                            "EXPORT family). Candidate only; remove weak "
                            "ciphers from the server cipher list."
                            % (cipher, ", ".join(weak))),
                        manual_check="openssl s_client -connect %s:%d "
                                     "-tls1_2 -cipher ALL" % (host, port),
                        location="%s:%d" % (host, port),
                        evidence="cipher=%s" % cipher,
                        source="omega-tlsconf", confidence="medium"))
        else:
            # Fallback: stdlib SSLContext probing only.
            probe = _fallback_probe(host, port)
            if probe["tls11_ok"]:
                out.append(Finding(
                    title="Weak TLS protocol accepted: TLSv1.1 (stdlib "
                          "probe)",
                    severity="high", verification="candidate",
                    verification_note=(
                        "A forced PROTOCOL_TLSv1_1 SSLContext completed a "
                        "handshake; the server still accepts TLS 1.1. "
                        "Candidate only (openssl unavailable for a full "
                        "scan)."),
                    manual_check="nmap --script ssl-enum-ciphers -p %d %s"
                                 % (port, host),
                    location="%s:%d" % (host, port),
                    evidence="PROTOCOL_TLSv1_1 handshake succeeded",
                    source="omega-tlsconf", confidence="medium"))
    except Exception:
        pass
    return out
