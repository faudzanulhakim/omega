"""omega/scanning/uplprobe.py — unrestricted file-upload prober
(fusion suite name: ``upl-hygiene``).

EVIDENCE-FIRST, benign-marker only:

  stage 1  discover upload forms: parse HTML for
           <form enctype="multipart/form-data"> containing
           <input type="file">.
  stage 2  probe with INERT marker files only:
           (a) marker.txt with a unique marker -> baseline: is the
               endpoint reachable and does it store files?
           (b) the SAME inert text content re-named with executable
               extensions (.php/.jsp/.asp/.aspx) -> if the upload is
               ACCEPTED and the stored file is RETRIEVABLE (marker
               echoed back), that is a CONFIRMED HIGH finding: the
               server stores and serves dangerous types.
           (c) double-extension / dot-style names (test.pdf.php) ->
               candidate only.
           (d) validation-signal analysis: executable extension
               accepted + stored-path echo + no content-type
               rejection -> "missing file-type validation" candidate.

SAFETY CONTRACT: we NEVER upload webshell code, executable content or
parser-confusing payloads — every probe body is the same plain-text
marker ("inert test file, no executable content"). Findings are
"confirmed" only on the documented differential (upload accepted AND
stored copy retrieved with the marker echoed); everything else stays
candidate. Evidence is truncated to 300 chars per convention.
"""

from __future__ import annotations

import re
import secrets
import urllib.parse

__all__ = [
    "Finding",
    "EXEC_EXTENSIONS",
    "MARKER_CONTENT_PREFIX",
    "find_upload_forms",
    "multipart_encode",
    "run_uplprobe",
    "stored_path_extract",
]

EXEC_EXTENSIONS = [".php", ".jsp", ".asp", ".aspx"]
DOUBLE_EXTENSIONS = [".pdf.php", ".jpg.php", ".png.jsp"]
FORM_PATHS = ["", "/upload", "/upload.html", "/file-upload", "/form"]
MARKER_CONTENT_PREFIX = "OMEGA-UPLOAD-MARKER-"
MARKER_TAIL = "\ninert test file, no executable content.\n"

_FORM_RE = re.compile(r"<form\b[^>]*>", re.I)
_ACTION_RE = re.compile(r"""action\s*=\s*["']?([^"'\s>]+)""", re.I)
_ENCTYPE_RE = re.compile(r"""enctype\s*=\s*["']?([^"'\s>]+)""", re.I)
_FILE_INPUT_RE = re.compile(r"<input\b[^>]*type\s*=\s*[\"']file[\"']", re.I)
_METHOD_RE = re.compile(r"""method\s*=\s*["']?([a-z]+)""", re.I)
_PATHISH_RE = re.compile(r"[\w./\\-]*uploads?[\w./\\-]*", re.I)


class Finding(dict):
    """ENGINE-convention finding dict (differential, candidate default)."""

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


def multipart_encode(filename, content):
    """Build a multipart/form-data (content_type, body) pair with one
    file part named ``file``. Content is bytes-safe."""
    boundary = "----omegaboundary" + secrets.token_hex(8)
    part = (
        "--%s\r\n"
        'Content-Disposition: form-data; name="file"; filename="%s"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n" % (boundary, filename)
    ).encode() + (content if isinstance(content, bytes)
                  else content.encode()) + b"\r\n"
    body = part + ("--%s--\r\n" % boundary).encode()
    return "multipart/form-data; boundary=%s" % boundary, body


def find_upload_forms(base_url, fetch, pages=None):
    """Return upload-form dicts [{action, page}] for pages under
    base_url whose HTML contains a multipart form with a file input.
    Deduplicated by action URL."""
    out, seen = [], set()
    for page in (pages if pages is not None else FORM_PATHS):
        url = base_url.rstrip("/") + "/" + page.lstrip("/")
        try:
            _st, _h, body = fetch("GET", url)
        except Exception:
            continue
        html = _text(body)
        for form_tag in _FORM_RE.findall(html):
            if "multipart" not in form_tag.lower():
                continue
            if not _FILE_INPUT_RE.search(html):
                continue
            action = _ACTION_RE.search(form_tag)
            act = action.group(1) if action else page or "/"
            if act in seen:
                continue
            seen.add(act)
            out.append({
                "page": page or "/",
                "action": act,
            })
            break  # one form per page is enough for the probe
    return out


def stored_path_extract(resp_text, filename=None):
    """Best-effort stored-path extraction: an uploads/-ish token or the
    uploaded filename echoed in the response."""
    m = _PATHISH_RE.search(resp_text)
    if m:
        return m.group(0)
    if filename and filename in resp_text:
        return filename
    return None


def _resolve_action(base_url, page, action):
    if action.startswith("http"):
        return action
    if action.startswith("/"):
        return base_url.rstrip("/") + action
    if not action or action == page or action == "#":
        return base_url.rstrip("/") + "/" + (page or "").lstrip("/")
    return base_url.rstrip("/") + "/" + action.lstrip("/")


def _retrieve_stored(base_url, fetch, path):
    """Try to GET a stored upload; return the body text or ''. Never
    follows anything outside base_url."""
    candidates = []
    if path:
        p = path if path.startswith("/") else "/" + path
        candidates.append(base_url.rstrip("/") + p)
        # some servers echo only a basename like x.php under /uploads/
        if not p.startswith("/uploads"):
            candidates.append(
                base_url.rstrip("/") + "/uploads/" + p.rsplit("/", 1)[-1])
    for url in candidates:
        try:
            st, _h, body = fetch("GET", url)
        except Exception:
            continue
        if 200 <= st < 300:
            return _text(body)
    return ""


def run_uplprobe(target, fetch, budget=40, log=None, allowlist=None):
    """Run the benign-marker upload suite. Never raises; per-check
    errors become skipped entries. Returns
    {findings, skipped, ran, requests_sent}."""
    from omega.probes import allowlist_ok

    result = {"findings": [], "skipped": {}, "ran": [],
              "requests_sent": 0}
    base_url = target if "://" in target else "http://" + target
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = \
            "target %r not in allowlist" % target
        if log:
            log("uplprobe skipped: target not in allowlist: %r" % target)
        return result

    sent = 0

    def counted(method, url, headers=None, body=None):
        nonlocal sent
        if sent >= budget:
            return 499, {}, b"budget exhausted"
        sent += 1
        return fetch(method, url, headers=headers, body=body)

    # ---- stage 1: form discovery ---------------------------------------
    try:
        forms = find_upload_forms(base_url, counted)
    except Exception as exc:
        result["skipped"]["form_discovery"] = \
            "%s: %s" % (type(exc).__name__, exc)
        forms = []

    if not forms:
        # fall back: probe the conventional endpoint directly, only if
        # the site root answered (a dead target yields nothing)
        try:
            st, _h, _b = counted("GET", base_url + "/")
        except Exception:
            result["skipped"]["__all__"] = "target unreachable"
            result["requests_sent"] = sent
            return result
        forms = [{"page": "/", "action": "/upload"}]

    result["ran"].append("form_discovery")
    marker = MARKER_CONTENT_PREFIX + secrets.token_hex(6)
    content = marker + MARKER_TAIL
    baseline_ok = False

    for form in forms:
        if sent >= budget:
            result["skipped"][form["action"]] = "budget exhausted"
            continue
        url = _resolve_action(base_url, form["page"], form["action"])
        fname_base = "omega_marker_" + secrets.token_hex(4)

        # (a) baseline: inert .txt
        try:
            ct, body = multipart_encode(fname_base + ".txt", content)
            st, _h, resp = counted("POST", url, headers={"Content-Type": ct},
                                   body=body)
        except Exception as exc:
            result["skipped"][form["action"]] = \
                "%s: %s" % (type(exc).__name__, exc)
            continue
        resp_text = _text(resp)
        if not (200 <= st < 300):
            result["skipped"][form["action"]] = \
                "baseline txt upload rejected (status %s)" % st
            continue
        baseline_ok = True
        stored = stored_path_extract(resp_text, fname_base)
        retrieved = _retrieve_stored(base_url, counted,
                                     stored or fname_base + ".txt")
        baseline_stored = marker in resp_text or marker in retrieved
        if baseline_stored:
            result["findings"].append(Finding(
                title="File upload endpoint accepts and stores files at %s"
                      % form["action"],
                severity="info", verification="candidate",
                verification_note=(
                    "An inert .txt marker file was uploaded and either "
                    "the response or a subsequent GET echoed it back. "
                    "Baseline observation only: storing benign files is "
                    "expected behaviour, not by itself a vulnerability."),
                manual_check="curl -sS -F file=@marker.txt %s" % url,
                location=url, evidence=resp_text or retrieved,
                source="omega-uplprobe/baseline", confidence="medium"))

        # (b) executable extensions, SAME inert text content
        exec_accepted, exec_retrieved = [], []
        for ext in EXEC_EXTENSIONS:
            if sent >= budget:
                result["skipped"][ext] = "budget exhausted"
                continue
            try:
                ct, body = multipart_encode(fname_base + ext, content)
                st, _h, resp = counted("POST", url,
                                       headers={"Content-Type": ct},
                                       body=body)
            except Exception as exc:
                result["skipped"][ext] = "%s: %s" % (type(exc).__name__, exc)
                continue
            rtext = _text(resp)
            if not (200 <= st < 300):
                continue
            exec_accepted.append(ext)
            stored = stored_path_extract(rtext, fname_base) or \
                fname_base + ext
            got = _retrieve_stored(base_url, counted, stored)
            if marker in got:
                exec_retrieved.append(ext)

        if exec_retrieved:
            result["findings"].append(Finding(
                title="Unrestricted upload: executable extension stored "
                      "AND retrievable at %s" % form["action"],
                severity="high", verification="confirmed",
                verification_note=(
                    "The server accepted an upload named with an "
                    "executable extension (%s) and the stored copy was "
                    "retrievable with the original marker echoed back. "
                    "The uploaded content was INERT plain text — no "
                    "webshell or executable code was ever sent — but a "
                    "server that stores and serves these extensions can "
                    "be abused by an attacker who uploads real code. "
                    "Confirmed by the documented differential; "
                    "exploitability requires manual authorized testing."
                    % ", ".join(exec_retrieved)),
                manual_check="curl -sS -F file=@shell.php %s" % url,
                location=url,
                evidence="accepted=%s retrieved-with-marker=%s"
                         % (",".join(exec_accepted),
                            ",".join(exec_retrieved)),
                source="omega-uplprobe/exec-upload",
                confidence="high"))
        elif exec_accepted:
            result["findings"].append(Finding(
                title="Executable-extension upload accepted but not "
                      "confirmed retrievable at %s" % form["action"],
                severity="medium", verification="candidate",
                verification_note=(
                    "The server accepted uploads with executable "
                    "extensions (%s) but the stored copy could not be "
                    "retrieved with the marker echo, so execution/"
                    "serving could NOT be confirmed. Candidate only."
                    % ", ".join(exec_accepted)),
                manual_check="curl -sS -F file=@shell.php %s" % url,
                location=url,
                evidence="accepted=%s; no marker retrieval"
                         % ",".join(exec_accepted),
                source="omega-uplprobe/exec-upload-accepted",
                confidence="medium"))

        # (c) double extensions (candidate)
        for dex in DOUBLE_EXTENSIONS:
            if sent >= budget:
                result["skipped"][dex] = "budget exhausted"
                continue
            try:
                ct, body = multipart_encode(fname_base + dex, content)
                st, _h, resp = counted("POST", url,
                                       headers={"Content-Type": ct},
                                       body=body)
            except Exception as exc:
                result["skipped"][dex] = "%s: %s" % (type(exc).__name__, exc)
                continue
            rtext = _text(resp)
            if 200 <= st < 300:
                stored = stored_path_extract(rtext, fname_base) or \
                    fname_base + dex
                got = _retrieve_stored(base_url, counted, stored)
                result["findings"].append(Finding(
                    title="Double-extension upload accepted at %s (%s)"
                          % (form["action"], dex),
                    severity="medium", verification="candidate",
                    verification_note=(
                        "A double-extension filename (%s) was accepted "
                        "by the upload endpoint. Depending on server "
                        "configuration this can bypass extension "
                        "allow-lists. Candidate only — retrieval or "
                        "execution was not confirmed."
                        % dex),
                    manual_check="curl -sS -F file=@test.pdf.php %s" % url,
                    location=url,
                    evidence="stored-path=%s marker_retrieved=%s"
                             % (stored, marker in got),
                    source="omega-uplprobe/double-ext",
                    confidence="medium"))
                break  # one double-ext hit is enough evidence

        # (d) missing file-type validation signals
        signals = []
        if exec_accepted:
            signals.append("executable extensions accepted (%s)"
                           % ",".join(exec_accepted))
        if stored_path_extract(resp_text):
            signals.append("server echoes stored path")
        if baseline_ok and not exec_retrieved and exec_accepted:
            signals.append("no content-type check observed")
        if len(signals) >= 2:
            result["findings"].append(Finding(
                title="Missing file-type validation signals at %s"
                      % form["action"],
                severity="medium", verification="candidate",
                verification_note=(
                    "Multiple missing-validation signals observed: %s. "
                    "The upload endpoint appears to lack file-type "
                    "validation. Candidate only — requires manual "
                    "review of the server-side validation chain."
                    % "; ".join(signals)),
                manual_check="curl -sS -F file=@test.php %s" % url,
                location=url, evidence="; ".join(signals),
                source="omega-uplprobe/validation-signals",
                confidence="medium"))

    result["requests_sent"] = sent
    if log and baseline_ok:
        log("uplprobe: baseline upload succeeded on %d form(s); %d "
            "finding(s)" % (len(forms), len(result["findings"])))
    return result
