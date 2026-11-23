"""omega/scanning/mobios.py — iOS static analysis (.ipa or extracted .app).

OFFLINE only: reads local files, never touches the network. Info.plist is
parsed with plistlib (handles XML + binary plists); when plistlib fails,
a UTF-16/UTF-8 regex pass over the plist bytes provides keyword-only
hints. Every check is self-contained: a raise becomes a skipped entry,
never an exception; a bad path yields a skip note (never a raise).

Checks (entry run_ios(app_path) -> {findings, ran, skipped}):
  ats             NSAllowsArbitraryLoads=true                  MEDIUM
  ats_local       NSAllowsLocalNetworking=true                 LOW
  url_schemes     CFBundleURLTypes exported schemes            MEDIUM
  keychain        kSecAttrAccessibleAlways* in binary strings  MEDIUM
  secrets         AKIA/AIza/private key/JWT/generic in binary  HIGH/…
  defaults_keys   sensitive NSUserDefaults/plist keys          LOW
  (snapshot/pasteboard + secureTextEntry proximity heuristics are
   deliberately NOT implemented — not reliable enough to report;
   recorded as a skipped note.)
"""

from __future__ import annotations

import os
import plistlib
import re
import zipfile

from omega.scanning._mobcommon import (
    Finding, GENERIC_SECRET_RE, SECRET_PATTERNS, extract_printable_strings,
    is_denied_secret_value, mask_secret,
)

__all__ = ["run_ios", "SENSITIVE_DEFAULT_KEYS", "KEYCHAIN_INSECURE_MARKERS"]

KEYCHAIN_INSECURE_MARKERS = (
    "kSecAttrAccessibleAlwaysThisDeviceOnly",
    "kSecAttrAccessibleAlways",
    "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
)

SENSITIVE_DEFAULT_KEYS = (
    "password", "passwd", "userPassword", "authToken", "access_token",
    "refreshToken", "apiKey", "api_key", "clientSecret", "sessionToken",
    "creditCard", "cardNumber", "ssn",
)

_BINARY_SUFFIXES = (".dylib", ".a", "")  # "" = raw executable


def _secrets_in_strings(strings, where, findings):
    """Shared secret scan (same pattern set as mobandroid)."""
    hit = False
    for s in strings:
        for kind, rx, _title in SECRET_PATTERNS:
            for m in rx.finditer(s):
                val = m.group(0)
                if is_denied_secret_value(val):
                    continue
                sev = ("critical" if kind == "privkey"
                       else "high" if kind == "aws" else "medium")
                findings.append(Finding(
                    title="Hardcoded secret (%s) in iOS package" % kind,
                    severity=sev,
                    verification="candidate",
                    verification_note="static pattern match only; the "
                    "credential was NOT validated against its provider",
                    manual_check="Confirm and revoke/rotate the credential; "
                    "move it to a backend. Matched value redacted.",
                    location=where,
                    evidence=mask_secret(val),
                    source="omega-mobios/secrets",
                    confidence="medium"))
                hit = True
        for m in GENERIC_SECRET_RE.finditer(s):
            if is_denied_secret_value(m.group(0)):
                continue
            findings.append(Finding(
                title="Hardcoded credential-style assignment in iOS "
                      "package",
                severity="medium",
                verification="candidate",
                verification_note="generic key=value pattern match; may be "
                "a non-secret constant",
                manual_check="Check whether the value is a real secret and "
                "rotate if so. Matched value redacted.",
                location=where,
                evidence=mask_secret(m.group(0)),
                source="omega-mobios/secrets",
                confidence="low"))
            hit = True
    return hit


def _load_info_plist(data):
    """plistlib first (XML + binary); returns (dict, ok)."""
    try:
        return plistlib.loads(data), True
    except Exception:
        return {}, False


def _plist_regex_hints(data):
    """Keyword hints from a plist that plistlib could not parse."""
    hints = {}
    if not data:
        return hints
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        text = data.decode(enc, errors="replace")
        if "NSAllowsArbitraryLoads" in text:
            hints["NSAllowsArbitraryLoads"] = bool(
                re.search(r"NSAllowsArbitraryLoads[\s\x00]{0,80}true",
                          text, re.I))
        if "NSAllowsLocalNetworking" in text:
            hints["NSAllowsLocalNetworking"] = True
        if re.search(r"NSAllowsArbitraryLoads[\s\x00]{0,80}true", text,
                     re.I):
            hints["NSAllowsArbitraryLoads"] = True
        if hints:
            break
    return hints


def _url_schemes(info):
    out = []
    for entry in info.get("CFBundleURLTypes") or []:
        if not isinstance(entry, dict):
            continue
        for s in entry.get("CFBundleURLSchemes") or []:
            if s:
                out.append(str(s))
    return out


def _iter_app_files(app_path):
    """Yield (relpath, fullpath) for every file under app_path."""
    for dirpath, _dirs, filenames in os.walk(app_path):
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            yield os.path.relpath(full, app_path), full


def _find_info_plist(app_path):
    if os.path.isfile(os.path.join(app_path, "Info.plist")):
        return os.path.join(app_path, "Info.plist")
    for _rel, full in _iter_app_files(app_path):
        if os.path.basename(full).lower() == "info.plist":
            return full
    return None


def run_ios(app_path):
    """iOS .ipa / .app static analysis. Never raises; a missing/invalid
    path yields a skip note."""
    skipped = {}
    ran = []
    findings = []
    if not app_path or not os.path.exists(str(app_path)):
        skipped["app"] = "path does not exist: %r" % (app_path,)
        return {"findings": findings, "ran": ran, "skipped": skipped}

    data_plist = None
    binaries = []  # (name, bytes) of Mach-O executables / embedded libs
    extra_plists = []  # (name, bytes) of other plists (defaults hints)

    if os.path.isfile(str(app_path)):
        if not zipfile.is_zipfile(str(app_path)):
            skipped["app"] = "not a zip archive: %s" % app_path
            return {"findings": findings, "ran": ran, "skipped": skipped}
        try:
            zf = zipfile.ZipFile(str(app_path))
        except Exception as exc:
            skipped["app"] = "unreadable zip: %s" % exc
            return {"findings": findings, "ran": ran, "skipped": skipped}
        with zf:
            names = zf.namelist()
            plist_names = [n for n in names
                           if n.rsplit("/", 1)[-1].lower().endswith(".plist")]
            for n in plist_names:
                try:
                    b = zf.read(n)
                except Exception:
                    continue
                if n.lower().endswith("info.plist"):
                    data_plist = b
                else:
                    extra_plists.append((n, b))
            for n in names:
                low = n.lower()
                if low.endswith(".plist"):
                    continue  # collected above (data_plist / extra_plists)
                if low.endswith((".png", ".jpg", ".jpeg", ".gif",
                                 ".car", ".nib")):
                    continue
                try:
                    binaries.append((n, zf.read(n)))
                except Exception:
                    continue
    else:
        ip = _find_info_plist(str(app_path))
        if ip:
            try:
                with open(ip, "rb") as fh:
                    data_plist = fh.read()
            except Exception:
                data_plist = None
        else:
            skipped["info_plist"] = "no Info.plist found in .app directory"
        for rel, full in _iter_app_files(str(app_path)):
            low = rel.lower()
            if low.endswith((".plist", ".png", ".jpg", ".jpeg", ".gif",
                             ".car", ".nib", ".lproj")):
                if low.endswith(".plist") and low != "info.plist":
                    try:
                        with open(full, "rb") as fh:
                            extra_plists.append((rel, fh.read()))
                    except Exception:
                        continue
                continue
            try:
                with open(full, "rb") as fh:
                    binaries.append((rel, fh.read()))
            except Exception:
                continue

    # ---------------------------------------------------------- ATS
    info = {}
    hints = {}
    if data_plist:
        info, _ok = _load_info_plist(data_plist)
        hints = _plist_regex_hints(data_plist) if not info else {}
    else:
        skipped["info_plist"] = skipped.get(
            "info_plist", "no Info.plist data available")
    ran.append("info_plist")

    ats = info.get("NSAppTransportSecurity") or {}
    arbitrary = bool(ats.get("NSAllowsArbitraryLoads")
                     or hints.get("NSAllowsArbitraryLoads"))
    if arbitrary:
        findings.append(Finding(
            title="ATS disabled: NSAllowsArbitraryLoads=true",
            severity="medium",
            verification="candidate",
            verification_note="Info.plist setting; confirms app-level "
            "ATS exception, not per-domain scope",
            manual_check="Remove the global ATS exception or scope it to "
            "specific domains with a reason.",
            location="Info.plist",
            evidence="NSAppTransportSecurity.NSAllowsArbitraryLoads=true",
            source="omega-mobios/ats"))
    ran.append("ats")

    if ats.get("NSAllowsLocalNetworking") or hints.get(
            "NSAllowsLocalNetworking"):
        findings.append(Finding(
            title="ATS local-networking exception enabled",
            severity="low",
            verification="info",
            verification_note="informational: cleartext to local network "
            "hosts is allowed",
            manual_check="Confirm the app actually needs plaintext local "
            "networking.",
            location="Info.plist",
            evidence="NSAllowsLocalNetworking=true",
            source="omega-mobios/ats_local",
            confidence="low"))
    ran.append("ats_local")

    # ------------------------------------------------------ URL schemes
    schemes = _url_schemes(info)
    if schemes:
        findings.append(Finding(
            title="App registers custom URL schemes (%d)" % len(schemes),
            severity="medium",
            verification="candidate",
            verification_note="schemes are invocable by any app; whether "
            "a handler accepts untrusted input must be verified",
            manual_check="Review scheme handlers for unvalidated input "
            "and confirm each scheme is required.",
            location="Info.plist",
            evidence="CFBundleURLSchemes: " + ", ".join(schemes[:12]),
            source="omega-mobios/url_schemes"))
    ran.append("url_schemes")

    # ------------------------------------------------------ keychain
    keychain_hits = set()
    for name, data in binaries:
        for s in extract_printable_strings(data):
            for marker in KEYCHAIN_INSECURE_MARKERS:
                if marker in s:
                    keychain_hits.add(marker)
    if keychain_hits:
        findings.append(Finding(
            title="Insecure keychain accessibility attributes present (%d)"
                  % len(keychain_hits),
            severity="medium",
            verification="candidate",
            verification_note="string-level indicator; whether the "
            "attribute is applied to secret items must be verified",
            manual_check="Confirm kSecAttrAccessibleAlways* is not used "
            "for credential items; prefer "
            "AfterFirstUnlock/WhenUnlockedThisDeviceOnly.",
            location="application binaries (strings)",
            evidence=", ".join(sorted(keychain_hits)),
            source="omega-mobios/keychain"))
    ran.append("keychain")

    # ------------------------------------------------------ secrets
    secret_strings = []
    for name, data in binaries:
        secret_strings.extend(extract_printable_strings(data))
    for n, b in extra_plists:
        try:
            d, _ok2 = _load_info_plist(b)
            for k, v in (d or {}).items():
                if isinstance(v, str):
                    secret_strings.append("%s=%s" % (k, v))
        except Exception:
            secret_strings.extend(extract_printable_strings(b))
    _secrets_in_strings(secret_strings, "application binaries/plists",
                        findings)
    ran.append("secrets")  # ran with no hits is still "ran"

    # ------------------------------------------------ defaults keys
    sensitive_keys = set()
    srcs = [info]
    for _n, b in extra_plists:
        d, _ok2 = _load_info_plist(b)
        if d:
            srcs.append(d)
    for src in srcs:
        for k in (src or {}):
            lk = str(k).lower()
            if any(w.lower() in lk for w in SENSITIVE_DEFAULT_KEYS):
                sensitive_keys.add(str(k))
    if sensitive_keys:
        findings.append(Finding(
            title="Sensitive-looking keys in plist storage (%d)"
                  % len(sensitive_keys),
            severity="low",
            verification="candidate",
            verification_note="key-name indicator only; the stored value "
            "type/sensitivity must be verified",
            manual_check="Confirm NSUserDefaults/plist does not store "
            "credentials (use the Keychain instead).",
            location="Info.plist / embedded plists",
            evidence=", ".join(sorted(sensitive_keys)[:12]),
            source="omega-mobios/defaults_keys",
            confidence="low"))
    ran.append("defaults_keys")

    # snapshot / pasteboard heuristics deliberately NOT implemented:
    # proximity of 'setSecureTextEntry' to credential fields is not
    # reliable from static strings.
    skipped["snapshot_pasteboard"] = (
        "snapshot/pasteboard + secureTextEntry proximity heuristics "
        "skipped: not reliable from static strings")

    seen = set()
    ran = [c for c in ran if not (c in seen or seen.add(c))]
    return {"findings": findings, "ran": ran, "skipped": skipped}
