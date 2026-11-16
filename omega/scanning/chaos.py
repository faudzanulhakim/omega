"""omega/chaos.py — behavioral mutation fuzzer (parameter-value chaos).

Python-only, evidence-only, non-destructive. The module mutates existing
parameter VALUES with pure string/semantic transforms and compares the
responses against a baseline (differential anomaly detection). No payload
executes on the target: format-string and template markers are inert
strings whose only documented signal is their REFLECTION (or the
reflection of an evaluated arithmetic result such as ``49`` for ``7*7``
— labeled ``SSTI-evidence``, always a candidate, never confirmed).

Design (mirrors omega/probes.py + omega/deepchecks.py):
- ``fetch(method, url, headers=None, body=None) -> (status, headers,
  body_bytes)`` is injectable; default is deepchecks' stdlib fetch.
- Mutators are pure functions ``str -> str`` (25+ in ``MUTATORS``).
- ``fuzz_params(target, params, fetch, baseline_fn, budget)`` sends the
  baseline value plus each mutated value per parameter, rate-capped at
  ``budget`` requests TOTAL (default 60). Anomalies vs the baseline:
  status change, body-length delta > 30%, NEW error signature
  (stack-trace / exception / SQL / PHP / Java tokens not present in the
  baseline), reflected mutation evidence, timing anomaly (> 3x baseline).
- ``ResponseCluster`` / ``cluster_signature`` / ``is_wildcard_noise``
  cluster responses by (status, body-length bucket, body-sha prefix) so
  soft-404 / wildcard noise in discovery lists can be suppressed.
- ``run_chaos`` never raises; returns {findings, ran, skipped, clusters}.
- Findings follow the ENGINE convention (omega.probes.Finding) with
  source=omega-chaos/<name>. Evidence strings are truncated to 300 chars.
"""

from __future__ import annotations

import hashlib
import time
import urllib.parse

from omega.deepchecks import default_fetch
from omega.probes import Finding, allowlist_ok

__all__ = [
    "DEFAULT_PARAM_VALUES",
    "DEFAULT_PARAMS",
    "ERROR_SIGNATURES",
    "MUTATORS",
    "ResponseCluster",
    "cluster_signature",
    "filter_wildcard_paths",
    "fuzz_params",
    "header_mutators",
    "is_wildcard_noise",
    "run_chaos",
]

EVIDENCE_MAX = 300
DEFAULT_BUDGET = 60
LENGTH_DELTA = 0.30
TIMING_FACTOR = 3.0
TIMING_FLOOR = 0.05  # seconds; guards against ~0 baselines

DEFAULT_PARAMS = ["id", "q", "ref", "user", "next", "redirect", "file",
                  "template"]
DEFAULT_PARAM_VALUES = {
    "id": "1", "q": "test", "ref": "home", "user": "admin", "next": "/",
    "redirect": "/", "file": "readme.txt", "template": "index",
}

ERROR_SIGNATURES = [
    "traceback (most recent call last)",
    "stack trace",
    "exception",
    "warning:",
    "fatal error",
    "sql syntax",
    "sqlstate",
    "mysql_fetch",
    "ora-",
    "psycopg",
    "sqlite3.",
    "pdoexception",
    "at java.",
    "java.lang.nullpointerexception",
    "php notice",
    "php warning",
    "uncaught error",
    "system.exception",
]


def _clip(text, limit=EVIDENCE_MAX):
    text = str(text)
    return text if len(text) <= limit else text[:limit - 3] + "..."


# ---------------------------------------------------------------- mutators
# Every mutator is a PURE transform (str -> str, deterministic, no I/O,
# no execution). Mutation payloads are inert marker strings only.

def _m_case_flip(v):
    return v.swapcase()


def _m_upper(v):
    return v.upper()


def _m_lower(v):
    return v.lower()


def _m_double_urlencode(v):
    return urllib.parse.quote(urllib.parse.quote(v, safe=""), safe="")


def _m_urldecode(v):
    return urllib.parse.unquote(v)


def _m_null_byte_append(v):
    return v + "%00"


def _m_null_byte_raw(v):
    return v + "\x00"


def _m_unicode_confusable(v):
    """Homoglyph swap: a/e/o/p/x -> Cyrillic/Greek look-alikes."""
    table = {"a": "\u0430", "e": "\u0435", "o": "\u043e",
             "p": "\u0440", "x": "\u0445", "c": "\u0441"}
    return "".join(table.get(ch, ch) for ch in v)


def _m_comment_inject(v):
    return v + "/**/"


def _m_comment_inject_mid(v):
    if len(v) < 2:
        return "/**/" + v
    mid = len(v) // 2
    return v[:mid] + "/**/" + v[mid:]


def _m_tab(v):
    return v + "%09"


def _m_cr(v):
    return v + "%0d"


def _m_lf(v):
    return v + "%0a"


def _m_crlf(v):
    return v + "%0d%0a"


def _m_crlf_raw(v):
    return v + "\r\n"


def _m_negative_number(v):
    return "-9999"


def _m_large_number(v):
    return "2147483647"


def _m_huge_number(v):
    return "99999999999999999999"


def _m_float_overflow(v):
    return "1.7976931348623157e+308"


def _m_zero(v):
    return "0"


def _m_type_array(v):
    return "[]"


def _m_type_object(v):
    return '{"a":1}'


def _m_type_null(v):
    return "null"


def _m_json_quote_inject(v):
    return '"' + v + '"'


def _m_json_bracket(v):
    return "[" + v + "]"


def _m_param_pollution(v):
    # value unchanged; fuzz_params sends the key twice for this mutator
    return v


def _m_param_pollution_diff(v):
    return v


def _m_long_1k(v):
    return "A" * 1024


def _m_long_10k(v):
    return "A" * 10240


def _m_format_string(v):
    return v + "%s%s%n%x%n"


def _m_format_string_bare(v):
    return "%s%n%x%n"


def _m_template_double_brace(v):
    return "{{7*7}}"


def _m_template_dollar_brace(v):
    return "${7*7}"


def _m_template_hash_brace(v):
    return "#{7*7}"


def _m_template_percent(v):
    return "%{7*7}"


def _m_path_dot(v):
    return v + "/./"


def _m_path_dotdot(v):
    return v + "/../"


def _m_path_double_slash(v):
    return "//" + v


def _m_path_encoded_dotdot(v):
    return v + "%2f%2e%2e"


def _m_empty(v):
    return ""


def _m_percent_append(v):
    return v + "%"


def _m_semicolon(v):
    return v + ";"


def _m_space_append(v):
    return v + "%20"


# name -> transform. Order matters for reporting only. All are pure.
MUTATORS = [
    ("case-flip", _m_case_flip),
    ("upper", _m_upper),
    ("lower", _m_lower),
    ("double-urlencode", _m_double_urlencode),
    ("url-decode", _m_urldecode),
    ("null-byte-append", _m_null_byte_append),
    ("null-byte-raw", _m_null_byte_raw),
    ("unicode-confusable", _m_unicode_confusable),
    ("comment-inject", _m_comment_inject),
    ("comment-inject-mid", _m_comment_inject_mid),
    ("tab-append", _m_tab),
    ("cr-append", _m_cr),
    ("lf-append", _m_lf),
    ("crlf-append", _m_crlf),
    ("crlf-raw", _m_crlf_raw),
    ("negative-number", _m_negative_number),
    ("large-number", _m_large_number),
    ("huge-number", _m_huge_number),
    ("float-overflow", _m_float_overflow),
    ("zero-value", _m_zero),
    ("type-confusion-array", _m_type_array),
    ("type-confusion-object", _m_type_object),
    ("type-confusion-null", _m_type_null),
    ("json-quote-inject", _m_json_quote_inject),
    ("json-bracket", _m_json_bracket),
    ("param-pollution", _m_param_pollution),
    ("param-pollution-diff-value", _m_param_pollution_diff),
    ("long-1k", _m_long_1k),
    ("long-10k", _m_long_10k),
    ("format-string", _m_format_string),
    ("format-string-bare", _m_format_string_bare),
    ("template-double-brace", _m_template_double_brace),
    ("template-dollar-brace", _m_template_dollar_brace),
    ("template-hash-brace", _m_template_hash_brace),
    ("template-percent-brace", _m_template_percent),
    ("path-dot", _m_path_dot),
    ("path-dotdot", _m_path_dotdot),
    ("path-double-slash", _m_path_double_slash),
    ("path-encoded-dotdot", _m_path_encoded_dotdot),
    ("empty-value", _m_empty),
    ("percent-append", _m_percent_append),
    ("semicolon-append", _m_semicolon),
    ("space-append", _m_space_append),
]

TEMPLATE_MUTATORS = {n for n, _ in MUTATORS if n.startswith("template-")}
POLLUTION_MUTATORS = {n for n, _ in MUTATORS
                      if n.startswith("param-pollution")}


def header_mutators(value):
    """Header-VALUE mutations for header-oriented tests.

    Returns a list of (name, mutated_value) — same pure-transform
    guarantees as MUTATORS (inert strings, evidence-only reflection).
    """
    return [
        ("header-crlf", value + "\r\nX-Injected: 1"),
        ("header-lf", value + "\nX-Injected: 1"),
        ("header-tab", value + "\t"),
        ("header-null-byte", value + "\x00"),
        ("header-double-urlencode", _m_double_urlencode(value)),
        ("header-unicode-confusable", _m_unicode_confusable(value)),
        ("header-long-1k", "A" * 1024),
        ("header-comment-inject", value + "/**/"),
    ]


# ------------------------------------------------------- anomaly detection

def _lower(text):
    return text.decode("latin-1").lower() if isinstance(text, bytes) \
        else str(text).lower()


def _error_sigs(text):
    return [s for s in ERROR_SIGNATURES if s in text]


def _reflected(value, body_text, baseline_text):
    """Reflection evidence: a distinctive chunk of the mutated value
    appears in the response but NOT in the baseline body."""
    chunk = urllib.parse.unquote(value)[:48]
    if len(chunk) < 4:
        return False
    if chunk.isalnum() and chunk.isdigit():
        return False  # pure digits: too generic to call reflection
    return chunk.lower() in body_text and chunk.lower() not in baseline_text


def _anomalies(baseline, resp, elapsed, mutator_name, param, value):
    """Differential anomaly list vs the baseline response tuple.

    baseline/resp: (status, headers, body_bytes). Returns a list of
    (kind, detail) tuples.
    """
    st0, _h0, b0 = baseline
    st1, _h1, b1 = resp
    t0, t1 = _lower(b0), _lower(b1)
    out = []
    if st1 != st0:
        out.append(("status-change",
                    "status %s -> %s" % (st0, st1)))
    len0, len1 = len(b0), len(b1)
    if len0 and abs(len1 - len0) > LENGTH_DELTA * len0:
        out.append(("body-length",
                    "body length %d -> %d (%+.0f%%)"
                    % (len0, len1, 100.0 * (len1 - len0) / len0)))
    sigs0 = set(_error_sigs(t0))
    new_sigs = [s for s in _error_sigs(t1) if s not in sigs0]
    if new_sigs:
        out.append(("error-signature",
                    "new error signature(s): %s" % ", ".join(new_sigs[:3])))
    if _reflected(value, t1, t0):
        out.append(("reflection",
                    "mutated value reflected in body (not in baseline)"))
    if elapsed is not None and elapsed > TIMING_FACTOR * \
            max(TIMING_FLOOR, 0.0):
        out.append(("timing", "response took %.2fs" % elapsed))
    return out


def _ssti_evidence(baseline_body, body, mutator_name):
    """Documented differential for template markers: the arithmetic
    result 49 is reflected while the raw marker is NOT (i.e. the
    template engine evaluated 7*7) and the baseline shows neither."""
    if mutator_name not in TEMPLATE_MUTATORS:
        return False
    t1 = _lower(body)
    t0 = _lower(baseline_body)
    return "49" in t1 and "{{7*7}}" not in t1 \
        and "${7*7}" not in t1 and "#{7*7}" not in t1 \
        and "49" not in t0


_SEVERITY_BY_KIND = {
    "error-signature": "medium",
    "status-change": "medium",
    "reflection": "medium",
    "body-length": "low",
    "timing": "low",
}

_TITLES = {
    "error-signature": "Mutation-triggered error signature (param "
                       "'{param}', mutator {mutator})",
    "status-change": "Mutation-triggered status change (param "
                     "'{param}', mutator {mutator})",
    "reflection": "Mutation value reflected in response (param "
                  "'{param}', mutator {mutator})",
    "body-length": "Mutation-triggered body-length change (param "
                   "'{param}', mutator {mutator})",
    "timing": "Timing anomaly on mutated request (param "
              "'{param}', mutator {mutator})",
}


def _finding(kind, param, mutator_name, url, evidence, elapsed=None,
             ssti=False):
    if ssti:
        title = ("SSTI-evidence: template marker evaluated (param "
                 "'%s', mutator %s)" % (param, mutator_name))
        note = ("The template marker 7*7 was sent as an inert string; "
                "the response contains the arithmetic result 49 while "
                "the raw marker is absent and the baseline shows "
                "neither — server-side template evaluation evidence. "
                "Candidate HIGH (SSTI-evidence label); no exploit "
                "payload was sent.")
    else:
        title = _TITLES[kind].format(param=param, mutator=mutator_name)
        note = ("Behavioral mutation fuzzing differential: %s. "
                "Evidence-only candidate; manual verification required."
                % evidence)
    ev = {"param": param, "mutator": mutator_name, "kind": kind,
          "detail": _clip(evidence), "url": _clip(url, 200)}
    if elapsed is not None:
        ev["elapsed_s"] = round(elapsed, 3)
    if ssti:
        ev["evaluated_result"] = "49"
    out = Finding(
        title=title,
        severity="high" if ssti else _SEVERITY_BY_KIND.get(kind, "low"),
        verification="candidate",  # honesty contract: never auto-confirmed
        verification_note=note,
        manual_check="curl -sS -i \"%s\"" % url,
        location=_clip(url, 300),
        evidence=ev,
        source="omega-chaos/fuzz_params",
        confidence="medium" if not ssti else "high",
    )
    if kind == "timing":
        # timing differentials are stochastic (network jitter, GC, server
        # load): tag and flag so consistency gates and report consumers
        # can separate them from deterministic evidence
        out["tags"] = ["timing-heuristic"]
        out["flaky"] = True
    return out


# ------------------------------------------------------------- fuzz_params

def fuzz_params(target, params, fetch=None, baseline_fn=None, budget=None,
                log=None):
    """Mutate each parameter's value and diff responses vs baseline.

    fetch          — injectable transport (default: deepchecks fetch).
    baseline_fn    — optional callable(param) -> (status, headers, body)
                     for the unmutated request; default sends
                     ``target?param=<default value>``.
    budget         — max TOTAL requests (default 60); rate cap.

    Returns a list of candidate findings (empty when nothing anomalous).
    Never raises.
    """
    budget = DEFAULT_BUDGET if budget is None else int(budget)
    fetch = fetch or default_fetch
    base_url = target if "://" in target else "http://" + target
    base_url = base_url.rstrip("/")
    findings = []
    sent = {"n": 0}

    def do_fetch(url):
        if sent["n"] >= budget:
            return None
        sent["n"] += 1
        t0 = time.monotonic()
        try:
            resp = fetch("GET", url)
        except Exception as exc:
            if log:
                log("chaos fetch failed: %s" % exc)
            return None
        return resp + (time.monotonic() - t0,)

    for param in params:
        if sent["n"] >= budget:
            break
        default_value = DEFAULT_PARAM_VALUES.get(param, "1")
        if baseline_fn is not None:
            try:
                baseline = tuple(baseline_fn(param)) + (None,)
            except Exception:
                continue
        else:
            url0 = "%s/?%s" % (base_url, urllib.parse.urlencode(
                {param: default_value}))
            got = do_fetch(url0)
            if got is None:
                break
            baseline = got
        st0, _h0, b0, el0 = baseline

        for name, fn in MUTATORS:
            if sent["n"] >= budget:
                break
            try:
                value = fn(default_value)
            except Exception:
                continue
            q = urllib.parse.urlencode({param: value})
            if name in POLLUTION_MUTATORS:
                # param pollution: duplicate the key
                extra = "bogus" if name.endswith("diff-value") else value
                q = "%s&%s" % (q, urllib.parse.urlencode(
                    {param: extra}))
            url = "%s/?%s" % (base_url, q)
            got = do_fetch(url)
            if got is None:
                break
            st1, _h1, b1, elapsed = got
            if name in POLLUTION_MUTATORS and st1 == st0 and \
                    len(b1) == len(b0):
                continue
            for kind, detail in _anomalies(
                    (st0, {}, b0), (st1, {}, b1), elapsed,
                    name, param, value):
                # timing: only when clearly above 3x the baseline latency
                if kind == "timing":
                    if el0 is not None and \
                            elapsed <= TIMING_FACTOR * max(el0,
                                                           TIMING_FLOOR):
                        continue
                findings.append(_finding(
                    kind, param, name, url, "%s (status %s)" % (detail, st1),
                    elapsed=elapsed))
            if _ssti_evidence(b0, b1, name):
                findings.append(_finding(
                    "reflection", param, name, url,
                    "template marker 7*7 evaluated to 49 in response; "
                    "raw marker absent, baseline shows neither",
                    elapsed=elapsed, ssti=True))
    if log:
        log("chaos fuzz_params: %d request(s), %d finding(s)"
            % (sent["n"], len(findings)))
    return findings


# --------------------------------------------------------- ResponseCluster

_LENGTH_BUCKETS = ((0, 256, "xs"), (257, 1024, "s"), (1025, 8192, "m"),
                   (8193, 65536, "l"), (65537, 1 << 40, "xl"))


def cluster_signature(body):
    """(status-less) body signature: length bucket + sha1 prefix."""
    data = body if isinstance(body, bytes) else str(body).encode()
    bucket = "xl"
    for lo, hi, tag in _LENGTH_BUCKETS:
        if lo <= len(data) <= hi:
            bucket = tag
            break
    return "len-%s:%s" % (bucket, hashlib.sha1(data).hexdigest()[:12])


def is_wildcard_noise(cluster, samples, min_samples=3, ratio=0.6):
    """True when ``cluster`` (a ResponseCluster or signature string) is
    the DOMINANT cluster among ``samples`` (bodies or signatures) by the
    >= ratio majority of >= min_samples — i.e. soft-404/wildcard noise.

    A distinct response falling outside the dominant cluster is kept.
    """
    sigs = [cluster_signature(s) if not isinstance(s, str) or ":" not in s
            else s for s in samples]
    if len(sigs) < min_samples:
        return False
    counts = {}
    for s in sigs:
        counts[s] = counts.get(s, 0) + 1
    dom, dom_n = max(counts.items(), key=lambda kv: (kv[1], kv[0]))
    if dom_n / len(sigs) < ratio:
        return False
    target = cluster if isinstance(cluster, str) else cluster.dominant()
    return target == dom


class ResponseCluster:
    """Online (status, body-length bucket, body-sha prefix) clustering.

    ``add(status, body)`` records a response; ``dominant()`` returns the
    modal signature; ``is_noise(sig)`` reports whether ``sig`` falls in
    the dominant wildcard cluster (soft-404 suppression) given enough
    samples.
    """

    def __init__(self, min_samples=3, ratio=0.6):
        self.min_samples = int(min_samples)
        self.ratio = float(ratio)
        self._by_status = {}     # status -> {sig: count}
        self._total = 0

    def add(self, status, body):
        sig = cluster_signature(body)
        cur = self._by_status.setdefault(status, {})
        cur[sig] = cur.get(sig, 0) + 1
        self._total += 1
        return sig

    def dominant(self, status=None):
        counts = {}
        for st, sigs in self._by_status.items():
            if status is not None and st != status:
                continue
            for sig, n in sigs.items():
                counts[sig] = counts.get(sig, 0) + n
        if not counts:
            return None
        return max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]

    def is_noise(self, sig, status=None):
        if self._total < self.min_samples:
            return False
        counts = {}
        for st, sigs in self._by_status.items():
            if status is not None and st != status:
                continue
            for s, n in sigs.items():
                counts[s] = counts.get(s, 0) + n
        total = sum(counts.values())
        if total < self.min_samples:
            return False
        dom, dom_n = max(counts.items(), key=lambda kv: (kv[1], kv[0]))
        if dom_n / total < self.ratio:
            return False
        return sig == dom

    def summary(self):
        out = []
        for st in sorted(self._by_status):
            for sig, n in sorted(self._by_status[st].items(),
                                 key=lambda kv: (-kv[1], kv[0])):
                out.append({"status": st, "signature": sig, "count": n})
        return out

    def __len__(self):
        return self._total


def filter_wildcard_paths(base_url, paths, fetch=None, samples=None):
    """Probe discovery-list paths and suppress those in the dominant
    wildcard (soft-404) cluster.

    Returns (kept_paths, suppressed_paths). Each path is probed once
    (GET); responses are clustered; a path whose response signature
    matches the dominant cluster (majority of the samples) is treated
    as wildcard noise and suppressed. Paths with distinct responses are
    kept. Never raises.
    """
    fetch = fetch or default_fetch
    base_url = base_url.rstrip("/")
    cluster = ResponseCluster()
    sigs = {}
    for path in paths:
        url = base_url + (path if path.startswith("/") else "/" + path)
        try:
            st, _h, body = fetch("GET", url)
        except Exception:
            continue
        sig = cluster.add(st, body)
        sigs[path] = sig
    kept, suppressed = [], []
    for path in paths:
        sig = sigs.get(path)
        if sig is not None and cluster.is_noise(sig):
            suppressed.append(path)
        else:
            kept.append(path)
    return kept, suppressed


# ---------------------------------------------------------------- run_chaos

def run_chaos(target, fetch=None, path_info=None, budget=DEFAULT_BUDGET,
              log=None, allowlist=None):
    """Run the chaos fuzzer against ``target``. Never raises.

    Parameters come from ``path_info['params']`` when discovered,
    otherwise the common defaults (id=1, q=test, ref=home, user=admin,
    next=/, redirect=/, file=readme.txt, template=index). When
    ``path_info`` carries discovery paths, they are probed once and
    wildcard-cluster noise is suppressed before parameter fuzzing.

    Returns {findings, ran, skipped, clusters}.
    """
    result = {"findings": [], "ran": [], "skipped": {}, "clusters": []}
    base_url = target if "://" in target else "http://" + target
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = (
            "target %r not in allowlist" % target)
        if log:
            log("chaos skipped: target not in allowlist: %r" % target)
        return result
    fetch = fetch or default_fetch
    try:
        path_info = path_info or {}
        params = [str(p) for p in (path_info.get("params") or [])] \
            or list(DEFAULT_PARAMS)
        paths = [str(p) for p in (path_info.get("paths") or [])]

        if paths:
            try:
                kept, suppressed = filter_wildcard_paths(
                    base_url, paths, fetch=fetch)
                if suppressed and log:
                    log("chaos: suppressed %d wildcard-noise path(s)"
                        % len(suppressed))
                result["ran"].append("path-cluster-filter")
            except Exception as exc:
                kept, suppressed = paths, []
                result["skipped"]["path-cluster-filter"] = \
                    "error: %s" % exc
            result["clusters"].append({
                "scope": "paths", "kept": kept,
                "suppressed": suppressed})

        cluster = ResponseCluster()
        # baseline + sample responses for clustering
        try:
            for param in params[:4]:
                val = DEFAULT_PARAM_VALUES.get(param, "1")
                st, _h, body = fetch("GET", "%s/?%s" % (
                    base_url.rstrip("/"), urllib.parse.urlencode(
                        {param: val})))
                cluster.add(st, body)
        except Exception:
            pass

        findings = fuzz_params(base_url, params, fetch=fetch,
                               baseline_fn=None, budget=budget, log=log)
        result["ran"].append("fuzz_params")
        result["findings"].extend(findings)
        result["clusters"].append({
            "scope": "params", "summary": cluster.summary(),
            "dominant": cluster.dominant()})
    except Exception as exc:  # never raise
        result["skipped"]["fuzz_params"] = "error: %s" % exc
        if log:
            log("chaos run failed: %s" % exc)
    return result
