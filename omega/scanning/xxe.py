"""omega/scanning/xxe.py — XXE / XML injection probe (fusion suite
name: ``xxe``).

Discovers XML-accepting endpoints (paths containing xml/soap/api from
path_info plus the well-known /xmlrpc and /soap), POSTs benign XML
bodies containing external-entity markers:

  * a SYSTEM file:// URL pointing at a fixed benign marker path
    (never an interesting file), and
  * an OOB variant referencing a nonexistent-but-unique hostname that
    is only recorded in the finding evidence — never resolved or
    contacted by this module.

A finding is a HIGH candidate when the response echoes entity content
or an error discloses entity expansion; verbose SAX/DTD parse errors
are surfaced as LOW candidates (info leak). Benign markers only,
bounded request count, never raises.
"""

from __future__ import annotations

import secrets

from omega.scanning.deepchecks import default_fetch

__all__ = [
    "Finding",
    "XML_PATH_HINTS",
    "EXTRA_XML_PATHS",
    "MARKER_FILE",
    "build_xml_payloads",
    "run_xxe",
]

XML_PATH_HINTS = ("xml", "soap", "api")
EXTRA_XML_PATHS = ("/xmlrpc", "/soap")
MAX_ENDPOINTS = 8
MARKER_FILE = "/nonexistent/omega/xxe/marker.txt"
MARKER_TAG = "omega-xxe-marker"

ENTITY_ECHO_HINTS = ("omega-xxe", "root:", "file:///nonexistent")
EXPANSION_ERROR_HINTS = (
    "entity", "dtd", "saxparseexception", "externalsubset",
    "external entity", "failed to load external",
)
VERBOSE_ERROR_HINTS = (
    "exception", "stack trace", "traceback", "at line", "column",
    "stacktrace", "org.xml.sax", "lxml.etree",
)


class Finding(dict):
    """ENGINE-convention finding dict (candidate/info only)."""

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


def _text(body):
    if isinstance(body, bytes):
        return body.decode("latin-1")
    return str(body or "")


def _post(fetch, url, body, ctype="application/xml"):
    try:
        st, _h, raw = fetch("POST", url, headers={"Content-Type": ctype},
                            body=body)
        return st, _text(raw)
    except Exception:
        return None, ""


def xml_endpoints(base_url, path_info=None):
    """Bounded list of candidate XML endpoints (discovery only)."""
    base = base_url.rstrip("/")
    paths = []
    for p in (path_info or {}).get("paths") or []:
        try:
            low = str(p).lower()
        except Exception:
            continue
        if any(h in low for h in XML_PATH_HINTS) and p not in paths:
            paths.append(p)
    for p in EXTRA_XML_PATHS:
        if p not in paths:
            paths.append(p)
    return [base + "/" + str(p).lstrip("/") for p in paths[:MAX_ENDPOINTS]]


def build_xml_payloads(oob_host):
    """Benign external-entity marker payloads (no interesting files,
    OOB host recorded in evidence only — never contacted)."""
    local = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE omega [<!ENTITY xxe SYSTEM "file://%s">]>\n'
        '<omega><probe>%s</probe><data>&xxe;</data></omega>'
        % (MARKER_FILE, MARKER_TAG)
    )
    oob = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE omega [<!ENTITY xxe SYSTEM "http://%s/xxe">]>\n'
        '<omega><probe>%s</probe><data>&xxe;</data></omega>'
        % (oob_host, MARKER_TAG)
    )
    plain = ('<?xml version="1.0"?>\n<omega><probe>%s</probe></omega>'
             % MARKER_TAG)
    malformed = ('<?xml version="1.0"?>\n<omega><unclosed>')
    return (("local-entity", local), ("oob-entity", oob),
            ("plain", plain), ("malformed", malformed))


def run_xxe(base_url, fetch=default_fetch, path_info=None, gate=False):
    """Run the XXE probe. Returns a list of Finding dicts; never
    raises. Benign markers only; bounded endpoint/payload count."""
    out = []
    try:
        endpoints = xml_endpoints(base_url, path_info)
        oob_host = "%s.oob.omega-xxe.invalid" % secrets.token_hex(6)
        payloads = build_xml_payloads(oob_host)
        seen = set()
        for url in endpoints:
            for kind, body in payloads:
                st, resp = _post(fetch, url, body)
                if st is None:
                    continue
                low = resp.lower()
                key = (url, kind)
                if kind in ("local-entity", "oob-entity"):
                    echoed = any(h in low for h in ENTITY_ECHO_HINTS)
                    expanded = any(h in low for h in EXPANSION_ERROR_HINTS)
                    if echoed or expanded:
                        if key in seen:
                            continue
                        seen.add(key)
                        out.append(Finding(
                            title="%s external entity behavior at %s"
                                  % ("Entity content echoed" if echoed
                                     else "Entity expansion disclosed",
                                     url),
                            severity="high", verification="candidate",
                            verification_note=(
                                "The endpoint (%s payload) %s. External "
                                "entity processing appears ENABLED — a "
                                "classic XXE condition. Candidate only: "
                                "no interesting file was requested (the "
                                "marker path is benign) and the OOB "
                                "hostname was never contacted by this "
                                "scanner; confirm interactively."
                                % (kind, "echoed entity content in the "
                                        "response" if echoed else
                                        "disclosed entity expansion in a "
                                        "parser error")),
                            manual_check="curl -sS -X POST -H "
                                         "'Content-Type: application/xml' "
                                         "--data @payload.xml %s" % url,
                            location=url,
                            evidence="payload=%s response=%s"
                                     % (kind, resp[:200]),
                            source="omega-xxe", confidence="medium"))
                elif kind == "malformed" and st in (200, 500):
                    if any(h in low for h in VERBOSE_ERROR_HINTS):
                        if (url, "verbose") in seen:
                            continue
                        seen.add((url, "verbose"))
                        out.append(Finding(
                            title="Verbose XML parser error disclosed at %s"
                                  % url,
                            severity="low", verification="candidate",
                            verification_note=(
                                "A malformed XML body produced a response "
                                "that looks like a parser/framework error "
                                "with internal detail (SAX/DTD/stack "
                                "trace). Information-leak hygiene issue; "
                                "candidate only."),
                            manual_check="curl -sS -X POST -H "
                                         "'Content-Type: application/xml' "
                                         "--data '<broken>' %s" % url,
                            location=url, evidence=resp[:200],
                            source="omega-xxe", confidence="medium"))
    except Exception:
        pass
    return out
