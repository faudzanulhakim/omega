"""omega/scanning/_mobcommon.py — shared helpers for the mobile
static-analysis layer (mobandroid / mobios / mobgeneral).

All checks are OFFLINE: they read local files only, never touch the
network. Findings are candidate/info only (honesty contract: static
signals, not exploits). A match is a lead requiring manual review,
never a confirmed vulnerability or a live credential.

Secret patterns are LIFTED from the engine bundle
(engine/engine/secretpatterns.py — the exact mobile pattern set used by
engine/tools/mobile.py) with attribution so the two analyzers agree;
androguard is OPTIONAL and never required.
"""

from __future__ import annotations

import os
import re

__all__ = [
    "Finding", "SECRET_PATTERNS", "GENERIC_SECRET_RE", "mask_secret",
    "STRING_RUN_RE", "extract_printable_strings", "read_bytes_capped",
    "MAX_EVIDENCE", "walk_text_files", "check_list",
]

# ---------------------------------------------------------------- finding

MAX_EVIDENCE = 300


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
            evidence=str(evidence or "")[:MAX_EVIDENCE],
            source=source,
        )


# ------------------------------------------------------- secret patterns
# Lifted verbatim (mobile subset) from engine/engine/secretpatterns.py so
# the ENGINE mobile analyzer and this layer never diverge. Do not edit one
# without the other.
SECRET_PATTERNS = [
    ("aws", re.compile(r"AKIA[0-9A-Z]{16}"),
     "AWS Access Key ID embedded in the package"),
    ("gcp_api", re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
     "Google API Key embedded in the package"),
    ("privkey", re.compile(r"BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY"),
     "Private key embedded in the package"),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}"
                       r"\.[A-Za-z0-9_\-]{8,}"),
     "JWT token embedded in the package"),
]

GENERIC_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|app[_-]?secret|client[_-]?secret|password|passwd|"
    r"auth[_-]?token)\s*[:=]\s*[\"'][^\"'\s]{8,64}[\"']")

# Published example keys / placeholders are never findings (same policy
# as the engine denylist).
_DENIED_SUBSTRINGS = ("example", "sample", "dummy", "your-", "your_",
                      "xxxx", "****", "changeme", "placeholder", "test")


def mask_secret(s):
    """Mask the middle of a secret for evidence output (<=300 chars)."""
    s = str(s or "")
    if len(s) > 8:
        return s[:4] + "***" + s[-2:]
    return "***"


def is_denied_secret_value(value):
    low = str(value or "").lower()
    return any(d in low for d in _DENIED_SUBSTRINGS)


# ------------------------------------------------------- text extraction
# DEX/resources store strings sequentially separated by \x00 etc.; a
# loose negated regex would melt several strings into one blob.
STRING_RUN_RE = re.compile(rb"[\x20-\x7e]{5,}")

_READ_BUDGET = 24 * 1024 * 1024


def extract_printable_strings(data, min_len=5):
    """Printable ASCII runs (>= min_len chars) from binary data."""
    if not isinstance(data, (bytes, bytearray)):
        return []
    if len(data) > _READ_BUDGET:
        data = data[:_READ_BUDGET]
    out = []
    for m in STRING_RUN_RE.finditer(data):
        try:
            s = m.group(0).decode("utf-8")
        except Exception:
            continue
        if len(s) >= min_len:
            out.append(s)
    return out


def read_bytes_capped(path, cap=_READ_BUDGET):
    """Read a file, truncating large files to the budget. None on error."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(cap + 1)
        return data[:cap]
    except Exception:
        return None


_TEXT_SUFFIXES = (".java", ".kt", ".js", ".ts", ".dart", ".xml", ".json",
                  ".yaml", ".yml", ".plist", ".properties", ".swift",
                  ".m", ".h", ".txt", ".html", ".env", ".gradle", ".cfg",
                  ".ini", ".toml")
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".gradle", "build",
              "Pods", ".svn"}
_TEXT_CAP = 2 * 1024 * 1024


def walk_text_files(root):
    """Yield (relative_path, text) for text-ish files under root.

    Binary-looking files are skipped silently; the walk never raises.
    """
    if not root or not os.path.isdir(root):
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in sorted(filenames):
            path = os.path.join(dirpath, fn)
            if os.path.getsize(path) > _TEXT_CAP:
                continue
            if os.path.splitext(fn)[1].lower() not in _TEXT_SUFFIXES:
                continue
            try:
                with open(path, "r", encoding="utf-8",
                          errors="replace") as fh:
                    yield os.path.relpath(path, root), fh.read()
            except Exception:
                continue
