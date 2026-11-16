"""omega/scanning/deser.py — unsafe-deserialization endpoint detection
(fusion suite name: ``deser-safe``).

SAFE-SIGNATURE-ONLY probe: the module NEVER sends a serialized gadget
chain — payloads are inert marker bytes (a truncated native-serialization
header, a malformed PHP object stub, a garbage pickle stream) whose only
purpose is to make a mishandling endpoint FAIL LOUDLY. Detection is by
error fingerprints in the response:

  Java    java.io.StreamCorruptedException / ClassNotFoundException /
          InvalidClassException / "invalid stream header"
  PHP     unserialize() error text / wddx / "__PHP_Incomplete_Class"
  Python  pickle / unpickling / "python/pickle" error strings /
          "_pickle.UnpicklingError"

Also: base64 ACED0005 (native Java stream magic) reflection — an
endpoint that echoes the magic back is a candidate for accepting
base64-wrapped native streams.

Findings are ``verification='candidate'`` unless an error fingerprint
CONFIRMS the endpoint mishandles the format (then confidence=high and
the verification_note states the fingerprint); the verification label
stays 'candidate' — a fingerprint is a signature, not proof (honesty
contract).
"""

from __future__ import annotations

import base64
import secrets

__all__ = [
    "Finding",
    "LANG_FINGERPRINTS",
    "PAYLOADS",
    "classify_response",
    "registry",
    "run_deser",
]

# (lang, payload bytes, fingerprints list, note)
PAYLOADS = [
    ("java", b"\xac\xed\x00\x05" + b"omega-marker",
     ["java.io.StreamCorruptedException", "ClassNotFoundException",
      "InvalidClassException", "invalid stream header",
      "java.io.OptionalDataException"],
     "truncated Java native stream header (inert marker, no gadget)"),
    ("java_b64", None,
     ["java.io.StreamCorruptedException", "invalid stream header",
      "ClassNotFoundException"],
     "base64-wrapped ACED0005 magic (inert marker, no gadget)"),
    ("php", b'O:8:"OmegaStub":1:{s:4:"mark";s:4:"xxxx";}',
     ["unserialize()", "wddx", "__PHP_Incomplete_Class",
      "Error at offset"],
     "malformed PHP object stub (no real class, no gadget)"),
    ("python", b"\x80\x04\x95" + b"omega-marker",
     ["pickle", "unpickling", "_pickle.UnpicklingError",
      "python/pickle", "cPickle"],
     "truncated pickle stream header (inert, no GLOBAL opcode)"),
]

LANG_FINGERPRINTS = {
    "java": ["java.io.StreamCorruptedException", "ClassNotFoundException",
             "InvalidClassException", "invalid stream header",
             "java.io.OptionalDataException"],
    "php": ["unserialize()", "wddx", "__PHP_Incomplete_Class",
            "Error at offset"],
    "python": ["pickle", "unpickling", "_pickle.UnpicklingError",
               "python/pickle", "cPickle"],
}

PROBE_PATHS = ["/api", "/deserialize", "/import", "/session", "/upload",
               "/rpc", "/"]


class Finding(dict):
    """ENGINE-convention finding dict (candidate-only)."""

    def __init__(self, title, severity, verification_note, manual_check,
                 location, evidence, source, confidence="medium"):
        super().__init__(
            title=title,
            severity=severity,
            confidence=confidence,
            verification="candidate",
            verification_note=verification_note,
            manual_check=manual_check,
            location=location,
            evidence=evidence[:300],
            source=source,
        )


def _text(body):
    if isinstance(body, bytes):
        return body.decode("latin-1", "replace")
    return str(body or "")


def _payload_for(name):
    for lang, data, _fps, _note in PAYLOADS:
        if lang != name:
            continue
        if data is None:  # base64-wrapped ACED0005
            return base64.b64encode(b"\xac\xed\x00\x05\x70\x6f").decode()
        return data
    return b""


def classify_response(text):
    """Return list of (lang, fingerprint) hits for a response body."""
    low = text.lower()
    hits = []
    for lang, fps in LANG_FINGERPRINTS.items():
        for fp in fps:
            if fp.lower() in low:
                hits.append((lang, fp))
    return hits


def _is_magic_reflected(body):
    return b"\xac\xed\x00\x05" in (body if isinstance(body, bytes)
                                   else str(body).encode("latin-1",
                                                         "replace"))


def probe_endpoint(base_url, fetch, path, payload_name, payload_bytes,
                   fingerprints, note):
    """POST one inert marker payload to one path; return finding or
    None. A baseline GET to the same path guards against static error
    pages that already contain the fingerprints."""
    url = base_url.rstrip("/") + path
    st0, _h0, b0 = fetch("GET", url)
    base_text = _text(b0)
    st, _h, body = fetch("POST", url,
                         headers={"Content-Type":
                                  "application/octet-stream"},
                         body=payload_bytes)
    text = _text(body)
    # CONTROL POST: inert random bytes. A static error page (or any
    # endpoint that errors on ANY body) returns the same fingerprints
    # without the payload — those hits are not payload-triggered and
    # must be suppressed (differential honesty guard).
    control_bytes = ("ctrl-%s" % secrets.token_hex(8)).encode("ascii")
    _stc, _hc, cbody = fetch("POST", url,
                             headers={"Content-Type":
                                      "application/octet-stream"},
                             body=control_bytes)
    control_text = _text(cbody)
    hits = [fp for fp in fingerprints if fp.lower() in text.lower()
            and fp.lower() not in base_text.lower()
            and fp.lower() not in control_text.lower()]
    magic = (_is_magic_reflected(body) and not _is_magic_reflected(b0)
             and not _is_magic_reflected(cbody))
    if not hits and not magic:
        return None
    confirmed = bool(hits)
    lang = payload_name.split("_")[0]
    return Finding(
        title="Deserialization endpoint fingerprint (%s): %s"
              % (lang, path),
        severity="high" if confirmed else "medium",
        verification_note=(
            "%s endpoint %s %s a malformed %s payload and responded "
            "with %s — the endpoint accepts and parses serialized input "
            "of that format. Payload was an INERT MARKER only (no "
            "gadget chain, no callable opcodes); %s."
            % ("POST", url, "with", lang,
               hits[0] if hits else "the ACED0005 magic echoed back",
               "error fingerprint confirms the endpoint mishandles the "
               "format (signature-level: manual exploitation testing "
               "required for real impact)"
               if confirmed else
               "magic-byte reflection alone is a weak candidate")),
        manual_check=(
            "printf '\\xac\\xed\\x00\\x05\\x00' | curl -sS -i --data-binary "
            "@- -H 'Content-Type: application/octet-stream' %s" % url),
        location=url,
        evidence="lang=%s fingerprint=%s reflected_magic=%s status=%s "
                 "baseline_status=%s"
                 % (lang, (hits[0] if hits else "none"),
                    magic, st, st0),
        source="omega-deser/%s" % payload_name,
        confidence="high" if confirmed else "low")


registry = [
    ("java", "java"),
    ("java_b64", "java_b64"),
    ("php", "php"),
    ("python", "python"),
]


class _BudgetExhausted(Exception):
    pass


class _CountingFetch:
    def __init__(self, fetch, cap):
        self._fetch = fetch
        self.cap = cap
        self.sent = 0

    def __call__(self, method, url, headers=None, body=None):
        if self.sent >= self.cap:
            raise _BudgetExhausted()
        resp = self._fetch(method, url, headers=headers, body=body)
        self.sent += 1
        return resp


def run_deser(target, fetch, budget=100, log=None, allowlist=None):
    """Run the safe-signature deserialization probe suite. Never raises;
    per-check errors become skipped entries. Returns
    {findings, skipped, requests_sent, ran}."""
    from omega.probes import allowlist_ok

    result = {"findings": [], "skipped": {}, "requests_sent": 0, "ran": []}
    base_url = target if "://" in target else "http://" + target
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = \
            "target %r not in allowlist" % target
        if log:
            log("deser skipped: target not in allowlist: %r" % target)
        return result
    fb = _CountingFetch(fetch, budget)
    exhausted = False
    for name, lang in registry:
        if exhausted:
            result["skipped"][name] = "budget exhausted"
            continue
        payload = _payload_for(name)
        payload_bytes = payload if isinstance(payload, bytes) \
            else payload.encode("ascii")
        fps = LANG_FINGERPRINTS[lang.split("_")[0]]
        try:
            found = []
            for path in PROBE_PATHS:
                found.append(probe_endpoint(
                    base_url, fb, path, name, payload_bytes, fps, None))
        except _BudgetExhausted:
            result["skipped"][name] = "budget exhausted"
            exhausted = True
            continue
        except Exception as exc:
            result["skipped"][name] = "error: %s" % exc
            if log:
                log("deser %s failed: %s" % (name, exc))
            continue
        result["ran"].append(name)
        result["findings"].extend(
            f for f in found if f is not None)
        if log:
            log("deser %s: %d finding(s)"
                % (name, len([f for f in found if f])))
    result["requests_sent"] = fb.sent
    return result
