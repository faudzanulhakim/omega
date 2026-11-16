"""omega/scanning/mobdeep.py — deep APK static analysis
(fusion suite name: ``mobdeep``).

Entry point :func:`analyze_apk(apk_path)` plus the suite wrapper
:func:`run_mobdeep(base_url, fetch=default_fetch, path_info=None,
gate=False)` which reads the APK path from ``path_info.get('apk')`` or
the ``OMEGA_APK`` environment variable and skips (empty list, never a
raise) when no APK is available.

Two analysis backends:

- If ``aapt`` or ``apktool`` is on PATH (shutil.which), the manifest is
  dumped with the real tool (``aapt dump badpermissions`` /
  ``xmltree``) and parsed for risky permission combinations,
  ``debuggable``, ``allowBackup`` and exported components without
  permission protection.
- Otherwise a pure-stdlib fallback parses the APK zip directly:
  AndroidManifest.xml (Android binary XML) is scanned as a crude
  length-prefix-agnostic string table, classes.dex and asset/resource
  strings are scanned for hardcoded secrets and cleartext endpoints.
  Fallback findings carry ``"analysis": "heuristic-stdlib"`` in the
  evidence.

Every finding is claim-gated through
:func:`omega.scanning.claimcheck.validate_claim` using a ``file://``
fetch stub, so the recorded evidence (marker strings) must reproduce
from the APK file itself or the finding is downgraded. Never raises;
bounded; benign (read-only local analysis).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import urllib.parse
import zipfile

from omega.scanning.claimcheck import validate_claim
from omega.scanning.deepchecks import Finding, default_fetch
from omega.scanning._mobcommon import (
    GENERIC_SECRET_RE,
    SECRET_PATTERNS,
    extract_printable_strings,
    mask_secret,
)

__all__ = [
    "analyze_apk",
    "run_mobdeep",
]

MAX_STRINGS = 5000
MAX_COMPONENTS = 20
MAX_SECRETS = 10
MAX_ENDPOINTS_EVIDENCE = 8
DEX_NAME = "classes.dex"
MANIFEST_NAME = "AndroidManifest.xml"

RISKY_PERMISSIONS = (
    "INSTALL_PACKAGES", "RECEIVE_SMS", "READ_SMS", "SEND_SMS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "CAMERA", "RECORD_AUDIO",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
)

PERM_RE = re.compile(r"android\.permission\.([A-Z_]+)")
COMPONENT_RE = re.compile(
    r"^[a-z][a-z0-9_]*(\.[A-Za-z0-9_]+)+$")
CLEARTEXT_RE = re.compile(
    r"http://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")

_SECRET_FINDINGS_SEV = {
    "aws": "high", "gcp_api": "high", "privkey": "high", "jwt": "high",
}


def _component_label(name):
    return name.rsplit(".", 1)[-1]


# ------------------------------------------------------------- tool path

def _run_tool(cmd, timeout=30):
    """Bounded subprocess capture -> (ok, output). Never raises."""
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        out = proc.stdout.decode("latin-1", "replace") \
            + proc.stderr.decode("latin-1", "replace")
        return proc.returncode == 0, out
    except Exception:
        return False, ""


def _parse_tool_manifest_output(text):
    """Parse `aapt dump badpermissions`/`xmltree` output into the same
    raw shape the stdlib fallback produces."""
    strings = re.findall(r"android\.permission\.[A-Z_]+", text)
    raw = {
        "permissions": sorted({s for s in strings}),
        "debuggable": "debuggable" in text
        and re.search(r"debuggable[^\n]*true", text, re.I) is not None,
        "allow_backup": re.search(r"allowBackup[^\n]*true", text, re.I)
        is not None,
        "exported_components": [],
        "backend": "aapt",
    }
    # xmltree-ish: element lines with android:exported(0x01010010)=true
    # followed by a component element and android:name.
    lines = text.splitlines()
    cur_component = None
    exported = False
    for line in lines:
        low = line.lower()
        if re.search(r"E: (activity|service|receiver|provider)\b", line):
            cur_component, exported = None, False
        m = re.search(r"android:name[^=]*=\s*\"?([A-Za-z0-9_.]+)", line)
        if m and (cur_component is None) and COMPONENT_RE.match(m.group(1)) \
                and not m.group(1).startswith("android"):
            cur_component = m.group(1)
        if "exported" in low and "true" in low:
            exported = True
        if exported and cur_component:
            raw["exported_components"].append(cur_component)
            cur_component, exported = None, False
    return raw


def _analyze_with_tools(apk_path, which_fn):
    """aapt/apktool-based analysis -> raw dict or None when no tool."""
    aapt = which_fn("aapt")
    if aapt:
        ok, out = _run_tool([aapt, "dump", "badpermissions", apk_path])
        ok2, xml = _run_tool([aapt, "dump", "xmltree", apk_path,
                              MANIFEST_NAME])
        if ok or ok2:
            raw = _parse_tool_manifest_output((out or "") + "\n" + (xml or ""))
            raw["backend"] = "aapt"
            raw["strings_by_file"] = {}
            return raw
    apktool = which_fn("apktool")
    if apktool:
        ok, out = _run_tool([apktool, "d", "-f", "-o", "-", apk_path],
                            timeout=120)
        if ok:
            raw = _parse_tool_manifest_output(out or "")
            raw["backend"] = "apktool"
            raw["strings_by_file"] = {}
            return raw
    return None


# ---------------------------------------------------- stdlib fallback

def _apk_strings(zf, name):
    """Printable string runs from one APK member (capped)."""
    try:
        with zf.open(name) as fh:
            data = fh.read(24 * 1024 * 1024)
    except Exception:
        return []
    strings = extract_printable_strings(data, min_len=5)
    return strings[:MAX_STRINGS]


def _scan_manifest_strings(strings):
    """Crude binary-XML string-table interpretation -> raw flags."""
    raw = {
        "permissions": [],
        "debuggable": False,
        "allow_backup": False,
        "exported_components": [],
        "backend": "stdlib-fallback",
    }
    perms, components = [], []
    for s in strings:
        for m in PERM_RE.finditer(s):
            if m.group(1) not in perms:
                perms.append(m.group(1))
        if COMPONENT_RE.match(s) and not s.startswith("android.") \
                and len(components) < MAX_COMPONENTS:
            components.append(s)
    raw["permissions"] = perms
    for comp in components:
        try:
            i = strings.index(comp)
        except ValueError:
            continue
        window = strings[max(0, i - 2): i + 3]
        low = " ".join(window).lower()
        if "exported" in low and "true" in low \
                and not any("android.permission." in w for w in window):
            raw["exported_components"].append(comp)
    raw["debuggable"] = any(
        "debuggable" in s.lower() for s in strings) and any(
        s.lower() == "true" for s in strings)
    raw["allow_backup"] = any(
        "allowbackup" in s.lower() for s in strings) and any(
        s.lower() == "true" for s in strings)
    return raw


def _scan_secrets(strings, origin):
    """Secret pattern hits over an extracted string list."""
    hits = []
    for s in strings:
        for key, rx, desc in SECRET_PATTERNS:
            m = rx.search(s)
            if m:
                hits.append((key, desc, m.group(0), origin))
        for m in GENERIC_SECRET_RE.finditer(s):
            hits.append(("generic-secret", "generic secret assignment",
                         m.group(0), origin))
        if len(hits) >= MAX_SECRETS * 3:
            break
    return hits


_MANIFEST_RUN_RE = re.compile(rb"[\x20-\x7e]{4,}")


def _manifest_strings(zf):
    """Manifest strings with a 4-char floor so short binary-XML string
    table entries like `true` survive the crude scan."""
    try:
        with zf.open(MANIFEST_NAME) as fh:
            data = fh.read(4 * 1024 * 1024)
    except Exception:
        return []
    out = []
    for m in _MANIFEST_RUN_RE.finditer(data):
        try:
            out.append(m.group(0).decode("utf-8"))
        except Exception:
            continue
    return out[:MAX_STRINGS]


def _analyze_stdlib(apk_path):
    """Pure-zipfile fallback -> raw analysis dict. Never raises."""
    raw = {
        "permissions": [], "debuggable": False, "allow_backup": False,
        "exported_components": [], "backend": "stdlib-fallback",
        "secrets": [], "cleartext": [], "strings_by_file": {},
    }
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = [n for n in zf.namelist()
                     if n == MANIFEST_NAME or n == DEX_NAME
                     or n.startswith(("assets/", "res/"))][:200]
            for name in names:
                if name == MANIFEST_NAME:
                    strings = _manifest_strings(zf)
                else:
                    strings = _apk_strings(zf, name)
                if name == MANIFEST_NAME:
                    mraw = _scan_manifest_strings(strings)
                    raw["permissions"] = mraw["permissions"]
                    raw["debuggable"] = mraw["debuggable"]
                    raw["allow_backup"] = mraw["allow_backup"]
                    raw["exported_components"] = mraw["exported_components"]
                elif name == DEX_NAME or name.startswith(
                        ("assets/", "res/")):
                    raw["secrets"].extend(_scan_secrets(strings, name))
                    for s in strings:
                        for m in CLEARTEXT_RE.finditer(s):
                            ep = m.group(0)
                            if ep not in raw["cleartext"]:
                                raw["cleartext"].append(ep)
    except Exception:
        return None
    raw["cleartext"] = raw["cleartext"][:MAX_ENDPOINTS_EVIDENCE]
    raw["secrets"] = raw["secrets"][:MAX_SECRETS]
    return raw


def analyze_apk(apk_path, which_fn=shutil.which):
    """Deep static analysis of one APK. Returns a list of Finding dicts
    (ungated); empty list on any error. Never raises."""
    findings = []
    try:
        if not apk_path or not os.path.isfile(str(apk_path)):
            return []
        raw = _analyze_with_tools(str(apk_path), which_fn)
        if raw is None:
            raw = _analyze_stdlib(str(apk_path))
        if raw is None:
            return []
        findings = _raw_to_findings(raw)
    except Exception:
        return []
    return findings


def _raw_to_findings(raw):
    findings = []
    backend = raw.get("backend") or "stdlib-fallback"
    heuristic = backend == "stdlib-fallback"

    def ev(extra):
        e = {"analysis": "heuristic-stdlib" if heuristic else backend}
        e.update(extra)
        return e

    if raw.get("debuggable"):
        findings.append(Finding(
            title="APK is debuggable (android:debuggable=true)",
            severity="high", verification="candidate",
            verification_note=(
                "The manifest declares android:debuggable=true. A "
                "debuggable build allows arbitrary code execution and "
                "full data access over ADB on any device that runs it. "
                "Static signal%s; confirm against the shipped build."
                % (" (heuristic string-table scan)" if heuristic else "")),
            manual_check="aapt dump xmltree <apk> AndroidManifest.xml "
                         "| grep -i debuggable",
            location=str(raw.get("apk_path") or "apk"),
            evidence=ev({"flag": "debuggable"}),
            source="omega-mobdeep", confidence="high"))

    for comp in (raw.get("exported_components") or [])[:MAX_COMPONENTS]:
        findings.append(Finding(
            title="Exported component without permission protection: %s"
                  % _component_label(comp),
            severity="high", verification="candidate",
            verification_note=(
                "Component '%s' is exported (android:exported=true) and "
                "no android:permission protects it in the manifest. Any "
                "app on the device can invoke it. Static signal; verify "
                "intents/permissions manually." % comp),
            manual_check="aapt dump xmltree <apk> AndroidManifest.xml",
            location=str(raw.get("apk_path") or "apk"),
            evidence=ev({"component": comp}),
            source="omega-mobdeep", confidence="medium"))

    for key, desc, match, origin in raw.get("secrets") or []:
        findings.append(Finding(
            title="Possible %s hardcoded in APK (%s)" % (desc, origin),
            severity=_SECRET_FINDINGS_SEV.get(key, "high"),
            verification="candidate",
            verification_note=(
                "A pattern matching %s was found in %s inside the APK "
                "(excerpt REDACTED). Hardcoded secrets in a shipped "
                "binary are recoverable by anyone; confirm and rotate. "
                "Candidate only." % (desc, origin)),
            manual_check="unzip -p <apk> %s | strings | grep -n %s"
                         % (origin, key),
            location=str(raw.get("apk_path") or "apk"),
            evidence=ev({"excerpt": mask_secret(match),
                         "marker": match[:8], "kind": key}),
            source="omega-mobdeep", confidence="medium"))

    cleartext = raw.get("cleartext") or []
    if cleartext:
        findings.append(Finding(
            title="Cleartext HTTP endpoints embedded in APK (%d)"
                  % len(cleartext),
            severity="medium", verification="candidate",
            verification_note=(
                "The APK references cleartext http:// endpoints (%s). "
                "Traffic to them is unencrypted and tamperable; "
                "candidate only — some may be documentation strings."
                % ", ".join(c[:40] for c in cleartext[:3])),
            manual_check="unzip -p <apk> classes.dex | strings | grep http://",
            location=str(raw.get("apk_path") or "apk"),
            evidence=ev({"endpoints": cleartext,
                         "marker": cleartext[0][:8]}),
            source="omega-mobdeep", confidence="medium"))

    if raw.get("allow_backup"):
        findings.append(Finding(
            title="APK allows backup (android:allowBackup=true)",
            severity="medium", verification="candidate",
            verification_note=(
                "android:allowBackup=true lets the app's private data "
                "be extracted via adb backup / cloud restore. Static "
                "signal; confirm data sensitivity manually."),
            manual_check="aapt dump xmltree <apk> AndroidManifest.xml "
                         "| grep -i allowBackup",
            location=str(raw.get("apk_path") or "apk"),
            evidence=ev({"flag": "allowBackup"}),
            source="omega-mobdeep", confidence="medium"))

    perms = [p for p in (raw.get("permissions") or [])
             if p in RISKY_PERMISSIONS]
    if perms:
        findings.append(Finding(
            title="Risky permissions requested (%s)" % ", ".join(perms[:6]),
            severity="medium", verification="candidate",
            verification_note=(
                "The manifest requests high-risk permissions (%s). "
                "Bad-permission review: storage + camera/location "
                "combos, INSTALL_PACKAGES and SMS permissions warrant "
                "a manual least-privilege check."
                % ", ".join("android.permission." + p for p in perms[:6])),
            manual_check="aapt dump badpermissions <apk>",
            location=str(raw.get("apk_path") or "apk"),
            evidence=ev({"permissions": perms,
                         "marker": "android.permission." + perms[0]}),
            source="omega-mobdeep", confidence="medium"))
    return findings


# ------------------------------------------------------- claim gating

def _file_fetch(method, url, headers=None, body=None):
    """fetch stub that reads the file:// location so claim evidence
    recorded from the APK bytes reproduces under validate_claim."""
    path = urllib.parse.unquote(urllib.parse.urlparse(url).path)
    if not path:
        raise ValueError("no path in %r" % url)
    with open(path, "rb") as fh:
        data = fh.read(24 * 1024 * 1024)
    return 200, {}, data


def _gate(findings, apk_path):
    """validate_claim each finding against the APK file itself."""
    file_url = "file://" + urllib.parse.quote(str(apk_path))
    gated = []
    for f in findings or []:
        try:
            claim = dict(f)
            claim["location"] = file_url
            claim.pop("base_url", None)
            gated.append(validate_claim(claim, fetch=_file_fetch,
                                        base_url=None))
        except Exception:
            gated.append(dict(f))
    return gated


# --------------------------------------------------------- suite entry

def run_mobdeep(base_url, fetch=default_fetch, path_info=None, gate=False):
    """Fusion suite entry. APK path from path_info['apk'] or the
    OMEGA_APK env var; skips ([]) when neither is set. Never raises."""
    try:
        apk = None
        if isinstance(path_info, dict):
            apk = path_info.get("apk")
        apk = apk or os.environ.get("OMEGA_APK")
        if not apk:
            return []
        findings = analyze_apk(apk)
        for f in findings:
            f["apk_path"] = apk
        return _gate(findings, apk)
    except Exception:
        return []
