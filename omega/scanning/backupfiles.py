"""omega/scanning/backupfiles.py — secret and backup file sweep
(fusion suite name: ``backupfiles``).

GETs a bounded list (25 requests max) of high-value backup/secret
paths against the target and classifies each response:

  - HIGH candidate: 200 with plausible content, i.e. the body differs
    substantially from a random-404 baseline fetched on the same host
    (avoids soft-404 false positives).
  - MEDIUM candidate: the response looks like a directory listing.

All GET-only, non-destructive, benign markers only. Never raises.
"""

from __future__ import annotations

import random
import re

__all__ = [
    "Finding",
    "HIGH_VALUE_PATHS",
    "MAX_REQUESTS",
    "run_backupfiles",
]

from omega.scanning.deepchecks import default_fetch

HIGH_VALUE_PATHS = (
    "/.bak", "/index.php.bak", "/config.php.bak", "/wp-config.php.bak",
    "/web.config.bak", "/.env.local", "/.env.bak", "/.DS_Store",
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/backup.sql",
    "/dump.sql", "/database.sql", "/db.sql", "/site.sql",
    "/docker-compose.yml", "/Jenkinsfile", "/.htaccess", "/index.old",
    "/index.orig", "/index.save", "/index.swp", "/index.bak",
    "/app.py.old",
)
MAX_REQUESTS = 25

LISTING_RE = re.compile(
    r"index of /|directory listing for|<title>directory listing</title>",
    re.I)

FALLBACK_PATHS = ("/.bak", "/.old", "/.orig", "/.save", "/.swp", "/.sql",
                  "/.sqlite", "/.DS_Store", "/.git/config", "/.git/HEAD",
                  "/.svn/entries", "/.env.local", "/.env.bak",
                  "/config.php.bak", "/docker-compose.yml", "/Jenkinsfile",
                  "/.htaccess", "/wp-config.php.bak", "/dump.sql",
                  "/web.config.bak")


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


def _text(body):
    if isinstance(body, bytes):
        return body.decode("latin-1")
    return str(body or "")


def _get(fetch, url):
    """Contained GET -> (status, text) or (None, ''); never raises."""
    try:
        st, _h, raw = fetch("GET", url)
        return st, _text(raw)
    except Exception:
        return None, ""


def _probe_paths(path_info):
    """Bounded probe list (max MAX_REQUESTS paths). path_info-derived
    paths (plus .bak/.old variants) come first so they always fit."""
    paths = []
    info = path_info if isinstance(path_info, dict) else {}
    for p in info.get("paths") or []:
        p = str(p)
        if not p:
            continue
        stem = p.rstrip("/")
        for cand in (stem + "/", stem + ".bak", stem + ".old"):
            if cand not in paths:
                paths.append(cand)
    for p in HIGH_VALUE_PATHS:
        if p not in paths:
            paths.append(p)
    return paths[:MAX_REQUESTS]


def _plausible(st, body, base_status, base_body):
    """200 whose body clearly differs from the soft-404 baseline."""
    if st != 200:
        return False
    if not body.strip():
        return False
    if base_status == 200 and body.strip() == base_body.strip():
        return False
    return True


def run_backupfiles(base_url, fetch=default_fetch, path_info=None,
                    gate=False, budget=MAX_REQUESTS + 1):
    """Secret/backup file sweep. Returns a list of Finding dicts;
    never raises. ``gate`` is accepted for symmetry with the other
    scanning suites and does not change candidate-only behavior."""
    out = []
    base = base_url if "://" in base_url else "http://" + base_url
    base = base.rstrip("/")
    sent = 0
    try:
        marker = "omega-%d" % random.randint(10**8, 10**9 - 1)
        base_status, base_body = _get(fetch, base + "/" + marker)
        sent += 1
        for path in _probe_paths(path_info):
            if sent >= budget:
                break
            url = base + path
            st, body = _get(fetch, url)
            sent += 1
            if st is None:
                continue
            if LISTING_RE.search(body):
                out.append(Finding(
                    title="Directory listing exposed at %s" % path,
                    severity="medium", verification="candidate",
                    verification_note=(
                        "%s returns a directory listing. Exposed listings "
                        "disclose file inventories and can lead attackers "
                        "to backup/source files. Candidate only." % url),
                    manual_check="curl -sS %s" % url,
                    location=url, evidence=body[:200],
                    source="omega-backupfiles", confidence="medium"))
                continue
            if _plausible(st, body, base_status, base_body):
                out.append(Finding(
                    title="Possible exposed backup/secret file: %s" % path,
                    severity="high", verification="candidate",
                    verification_note=(
                        "%s returned 200 with content that differs from a "
                        "random-404 baseline (baseline status %s), which "
                        "suggests a real backup, database dump, VCS "
                        "metadata or secret file is exposed. Requires "
                        "human confirmation; candidate only." %
                        (url, base_status)),
                    manual_check="curl -sS -i %s" % url,
                    location=url, evidence=body[:200],
                    source="omega-backupfiles", confidence="medium"))
    except Exception:
        pass
    return out
