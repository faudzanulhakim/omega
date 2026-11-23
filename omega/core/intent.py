"""OMEGA intent — parse a free-form (Indonesian/English) pentest prompt.

parse_prompt(text) turns a natural-language request into an intent dict:

    {target, mode, depth, with_tools, polyglot, max_steps, acked, raw}

Safety invariants:
  * acked is NEVER True from parsing alone — it only becomes True from
    an explicit authorization phrase ('saya berhak', 'authorized',
    'scope-ack') supplied by the operator, or from a second confirm
    step. Missing target is reported as a problem, never guessed.
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------
# Keyword tables (English + Indonesian)
# --------------------------------------------------------------------------

_MODE_KEYWORDS = (
    # (mode, regex over lowercased text)
    ("bug-bounty",
     r"bug\s*bounty|bugbounty|bug[- ]?hunting|bug\s*hunter"),
    ("red-team",
     r"red\s*team|tim\s*merah|\bmerah\b|redteaming"),
    ("ctf",
     r"\bctf\b|hackthebox|htb\b|tryhackme|thm\b"),
    ("forensic",
     r"forensi[kc]|digital\s*forensics|analisis\s*forensik"),
    ("mobile-pentest",
     r"\bmobile\b|\bapk\b|android|aplikasi\s*mobile|pentest\s*android"),
    ("blue-team",
     r"blue\s*team|tim\s*biru|\bbiru\b|defens\w*|defensif"),
)

_RECON_WORDS = (r"recon", r"reconnaissance", r"attack\s*surface",
                r"permukaan\s*serangan", r"pemetaan")

_DEEP_WORDS = (r"\bdeep\b", r"\bdalam\b", r"lengkap", r"gila",
               r"all[- ]?out", r"menyeluruh", r"maksimal")
_LIGHT_WORDS = (r"cepat", r"quick", r"ringan", r"fast\b", r"singkat")

_TOOLS_WORDS = (r"pakai\s*tools?", r"dengan\s*tools?", r"with\s*tools",
                r"semua\s*tool", r"use\s*tools?", r"tools?\s*aktif",
                r"aktifkan\s*tools?")
_POLYGLOT_WORDS = (r"polyglot", r"semua\s*tool", r"all\s*tools",
                   r"native\s*adapters?")

_ACK_WORDS = (r"saya\s*berhak", r"\bi\s*am\s*authorized\b",
              r"authorized", r"scope[- ]?ack", r"saya\s*memiliki\s*izin",
              r"ada\s*izin", r"berizin", r"dengan\s*izin")

# Indonesian / filler tokens stripped around an extracted target.
_FILLER = (
    "untuk", "kepada", "pada", "dari", "terhadap", "silakan", "tolong",
    "coba", "lakukan", "jalankan", "scan", "pentest", "test", "uji",
    "engage", "audit", "cek", "periksa", "ke", "ya", "aja", "saja",
    "dong", "the", "a", "target", "host", "site", "situs", "please",
)

# --------------------------------------------------------------------------
# Target extraction
# --------------------------------------------------------------------------

_URL_RE = re.compile(
    r"\bhttps?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I)
_CIDR_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}/(?:\d|[12]\d|3[0-2])\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_APK_RE = re.compile(r"\b[\w.-]+\.apk\b", re.I)
_HOST_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"[a-z]{2,}\b", re.I)

_TRAIL_PUNCT = ".,;:!?)\u3001\u3002\"'"


def _extract_target(text):
    """Return the first URL / host / IP / CIDR / .apk in text, or None."""
    for regex in (_URL_RE, _CIDR_RE, _APK_RE, _IPV4_RE, _HOST_RE):
        m = regex.search(text)
        if m:
            tok = m.group(0).strip()
            if regex is _URL_RE:
                # trim trailing sentence punctuation from the URL
                tok = tok.rstrip(_TRAIL_PUNCT)
            else:
                tok = tok.strip(_TRAIL_PUNCT)
            if tok:
                return tok
    return None


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def parse_prompt(text):
    """Parse a free-form prompt into an intent dict (never acks)."""
    low = (text or "").lower()

    target = _extract_target(text or "")

    mode = "auto"
    for cand, pattern in _MODE_KEYWORDS:
        if re.search(pattern, low):
            mode = cand
            break

    # OSINT/recon-only wording keeps mode auto but lightens the depth.
    reconish = any(re.search(p, low) for p in _RECON_WORDS)
    if mode == "auto" and reconish and not target:
        pass  # nothing to do; target stays missing (reported, not guessed)

    depth = "normal"
    if any(re.search(p, low) for p in _DEEP_WORDS):
        depth = "deep"
    elif any(re.search(p, low) for p in _LIGHT_WORDS) or reconish:
        depth = "light"

    max_steps = {"deep": 40, "normal": 25, "light": 12}[depth]
    polyglot = depth == "deep" or any(
        re.search(p, low) for p in _POLYGLOT_WORDS)
    with_tools = any(re.search(p, low) for p in _TOOLS_WORDS) or polyglot

    acked = any(re.search(p, low) for p in _ACK_WORDS)
    # SAFETY: parsing alone never authorizes. An ack *phrase* marks the
    # intent as "operator claims authorization", but acked stays False
    # until a confirm step (or explicit --scope-ack) flips it.
    ack_claimed = acked

    return {
        "target": target,
        "mode": mode,
        "depth": depth,
        "with_tools": bool(with_tools),
        "polyglot": bool(polyglot),
        "max_steps": max_steps,
        "acked": False,
        "ack_claimed": ack_claimed,
        "raw": text or "",
    }


def validate_intent(intent):
    """Return a list of human-readable problems (empty when valid)."""
    problems = []
    if not intent.get("target"):
        problems.append(
            "missing target: no URL, host, IP, CIDR or .apk found in "
            "the prompt (OMEGA does not guess targets)")
    mode = intent.get("mode", "auto")
    if mode != "auto" and mode not in (
            "auto", "bug-bounty", "red-team", "ctf", "forensic",
            "mobile-pentest", "blue-team", "grey-hat", "offensive",
            "reverse-engineering"):
        problems.append(f"unknown mode: {mode!r}")
    return problems
