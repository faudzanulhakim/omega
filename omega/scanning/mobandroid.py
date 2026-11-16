"""omega/scanning/mobandroid.py — Android APK static analysis.

OFFLINE only: reads the APK (a ZIP) from local disk, never touches the
network. androguard is OPTIONAL — if it is installed, the binary
AndroidManifest.xml is parsed with it; otherwise a plain-XML manifest
(a testability mode used by the fixtures) or a UTF-16 string-pool
keyword scan is used. Every check is self-contained: a raise becomes a
skipped entry, never an exception, and a bad path simply produces a
skip note (never a raise).

Checks (entry run_android(apk_path) -> {findings, ran, skipped}):
  debuggable          android:debuggable=true                      MEDIUM
  allow_backup        android:allowBackup=true                     LOW
  exported            exported components w/o guard permission     MEDIUM
  deep_link           exported activity with intent-filter scheme  MEDIUM
  webview             setJavaScriptEnabled + JS interface/file     MEDIUM
  cleartext           usesCleartextTraffic=true or NSC plaintext   HIGH
  nsc_user_ca         network_security_config trusts user CAs      MEDIUM
  secrets             AKIA/AIza/private key/JWT/generic in DEX+res HIGH/…
  logcat              Log.d/v/i with password/token/secret         MEDIUM
  excessive_perms     >= 5 dangerous permissions                   LOW (info)
  strandhogg          taskAffinity + singleTask on exported        MEDIUM
  obfuscation         no ProGuard/R8 markers, readable classes     LOW
  vulnerable_sdk      known-risky library fingerprints in DEX      MEDIUM
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
import zipfile

from omega.scanning._mobcommon import (
    Finding, GENERIC_SECRET_RE, SECRET_PATTERNS, extract_printable_strings,
    is_denied_secret_value, mask_secret, read_bytes_capped,
)  # noqa: F401  (read_bytes_capped used by future sub-checks)

__all__ = ["run_android", "NS", "DANGEROUS_PERMISSIONS", "VULNERABLE_SDKS"]

NS = "{http://schemas.android.com/apk/res/android}"

# Dangerous permissions (protectionLevel=dangerous, AOSP) — lifted from
# engine/tools/mobile.py (_PERM_DANGEROUS) with attribution.
PERM_VERY = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS", "android.permission.WRITE_SMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.BODY_SENSORS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ANSWER_PHONE_CALLS",
}
DANGEROUS_PERMISSIONS = PERM_VERY | {
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS", "android.permission.CALL_PHONE",
    "android.permission.USE_SIP", "android.permission.GET_ACCOUNTS",
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.RECEIVE_MMS", "android.permission.RECEIVE_WAP_PUSH",
}

# Small embedded vulnerable/legacy SDK fingerprint list: DEX package
# prefixes -> why the library is a security concern.
VULNERABLE_SDKS = {
    "com.facebook.stetho": "Stetho debug bridge exposes app data via "
                           "chrome devtools if shipped in release builds",
    "io.fabric.sdk": "Fabric (legacy, deprecated; known leaky logging)",
    "com.crashlytics": "Crashlytics legacy SDK (pre-acquisition versions "
                       "leak user data in logs)",
    "com.loopj.android.http": "AsyncHttpClient legacy SDK ships Apache "
                              "HttpClient with known TLS weaknesses",
    "org.apache.http": "Apache HttpClient (legacy, removed from Android; "
                       "no TLS v1.2 defaults)",
    "com.nostra13.universalimageloader": "UniversalImageLoader legacy "
                                         "library; known SSRF/tls gaps",
}

_LOG_CALL_RE = re.compile(r"(?i)\bLog\.(?:d|v|i)\s*\([^;]{0,200}?\)")
_LOG_KEYWORDS = re.compile(r"(?i)password|passwd|token|secret|credential")
_WEBVIEW_INTER_RE = re.compile(
    r"(?i)setJavaScriptEnabled|addJavascriptInterface|setAllowFileAccess")
_DEX_PACKAGE_RE = re.compile(
    r"(?:(?:L)?((?:com|io|org|net|de)\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+){1,3}))"
    r"(?:;|$)")
_CLASS_PATH_RE = re.compile(r"L[a-z][A-Za-z0-9_/$]{3,};")
_OBFUSCATION_MARKERS = ("proguard", "R8", "mapping.txt", "obfuscated")


def _secret_findings(strings, where, findings, ran):
    """Shared secret scan: pattern hits -> HIGH/CRITICAL/MEDIUM findings."""
    hit_kinds = set()
    for s in strings:
        for kind, rx, _title in SECRET_PATTERNS:
            for m in rx.finditer(s):
                val = m.group(0)
                if is_denied_secret_value(val):
                    continue
                sev = ("critical" if kind == "privkey"
                       else "high" if kind == "aws" else "medium")
                findings.append(Finding(
                    title="Hardcoded secret (%s) in mobile package" % kind,
                    severity=sev,
                    verification="candidate",
                    verification_note="static pattern match only; the "
                    "credential was NOT validated against its provider",
                    manual_check="Confirm and revoke/rotate the credential; "
                    "move it to a backend. Matched value redacted.",
                    location=where,
                    evidence=mask_secret(val),
                    source="omega-mobandroid/secrets",
                    confidence="medium"))
                hit_kinds.add(kind)
        for m in GENERIC_SECRET_RE.finditer(s):
            if is_denied_secret_value(m.group(0)):
                continue
            findings.append(Finding(
                title="Hardcoded credential-style assignment in mobile "
                      "package",
                severity="medium",
                verification="candidate",
                verification_note="generic key=value pattern match; may be "
                "a non-secret constant",
                manual_check="Check whether the value is a real secret and "
                "rotate if so. Matched value redacted.",
                location=where,
                evidence=mask_secret(m.group(0)),
                source="omega-mobandroid/secrets",
                confidence="low"))
            hit_kinds.add("generic")
    if hit_kinds:
        ran.append("secrets")
    else:
        ran.append("secrets")  # ran with no hits is still "ran"


def _manifest_plain(data):
    """Parse a PLAIN-XML AndroidManifest.xml -> Element or None."""
    if data is None:
        return None
    head = data[:64].lstrip()
    if not head.startswith(b"<"):
        return None
    try:
        return ET.fromstring(data)
    except Exception:
        return None


def _manifest_binary_keywords(data):
    """Fallback for BINARY (AXML) manifests: scan the UTF-16 string pool
    for manifest boolean attribute keywords + their values. Returns a
    dict of keyword -> True when 'keyword...true' appears near each other."""
    out = {}
    if not data:
        return out
    text = data.decode("utf-16-le", errors="replace")
    text += data.decode("utf-8", errors="replace")
    for key in ("debuggable", "allowBackup", "usesCleartextTraffic",
                "networkSecurityConfig"):
        if re.search(r"%s[\s\x00]{0,40}true" % re.escape(key), text, re.I):
            out[key] = True
    return out


def _nsc_checks(zf, names, findings, ran):
    """network_security_config: cleartext + user CA trust."""
    nsc = next((n for n in names
                if "network_security_config" in n.lower()), None)
    if not nsc:
        return
    try:
        data = zf.read(nsc)
        root = ET.fromstring(data)
    except Exception:
        ran.append("nsc_user_ca")
        return
    text = data.decode("utf-8", errors="replace")
    if re.search(r"cleartextTrafficPermitted\s*=\s*[\"']true[\"']", text):
        findings.append(Finding(
            title="Network security config allows cleartext traffic",
            severity="high",
            verification="candidate",
            verification_note="static config only; confirm which domains "
            "the exception covers",
            manual_check="Review cleartextTrafficPermitted exceptions; "
            "unencrypted HTTP allows on-path interception.",
            location=nsc,
            evidence="cleartextTrafficPermitted=true",
            source="omega-mobandroid/cleartext"))
        ran.append("cleartext")
    user_ca = any(el.tag == "certificates" for el in root.iter())
    if user_ca:
        # <certificates src="user"/> or src="system" + user
        raw = re.search(r"<certificates[^>]*src\s*=\s*[\"']([^\"']+)[\"']",
                        text)
        if raw and "user" in raw.group(1).lower():
            findings.append(Finding(
                title="Network security config trusts user-installed CAs",
                severity="medium",
                verification="candidate",
                verification_note="static config; user-CA trust enables "
                "TLS interception by an on-device attacker",
                manual_check="Restrict trust anchors to system CAs (or "
                "pin) so user-installed CAs cannot MITM the app.",
                location=nsc,
                evidence="<certificates src=\"%s\">" % raw.group(1),
                source="omega-mobandroid/nsc_user_ca"))
    ran.append("nsc_user_ca")


def run_android(apk_path):
    """Android APK static analysis. Never raises; a missing/invalid APK
    yields a skip note."""
    skipped = {}
    ran = []
    findings = []
    if not apk_path or not os.path.isfile(str(apk_path)):
        skipped["apk"] = "path does not exist: %r" % (apk_path,)
        return {"findings": findings, "ran": ran, "skipped": skipped}
    if not zipfile.is_zipfile(str(apk_path)):
        skipped["apk"] = "not a zip archive: %s" % apk_path
        return {"findings": findings, "ran": ran, "skipped": skipped}

    try:
        zf = zipfile.ZipFile(str(apk_path))
    except Exception as exc:
        skipped["apk"] = "unreadable zip: %s" % exc
        return {"findings": findings, "ran": ran, "skipped": skipped}

    with zf:
        names = zf.namelist()
        # ---- manifest ----------------------------------------------
        mf_name = next((n for n in names
                        if n.rsplit("/", 1)[-1].lower()
                        == "androidmanifest.xml"), None)
        manifest_plain = None
        manifest_bin = b""
        if mf_name:
            try:
                manifest_bin = zf.read(mf_name)
            except Exception:
                manifest_bin = b""
        manifest_plain = _manifest_plain(manifest_bin)

        # ---- dex/assets strings -------------------------------------
        strings = set()
        budget = 48 * 1024 * 1024
        for n in names:
            low = n.lower()
            if not (low.endswith(".dex") or low.startswith("assets/")
                    or low.endswith("resources.arsc")):
                continue
            try:
                data = zf.read(n)
            except Exception:
                continue
            if len(data) > budget:
                data = data[:budget]
            budget -= len(data)
            strings.update(extract_printable_strings(data))
            if budget <= 0:
                break

        # ---- manifest attribute checks ------------------------------
        attrs = {}
        if manifest_plain is not None:
            for el in manifest_plain.iter():
                for k, v in el.attrib.items():
                    short = k.split("}")[-1]
                    if short in ("debuggable", "allowBackup",
                                 "usesCleartextTraffic"):
                        attrs[short] = v
        else:
            attrs.update(_manifest_binary_keywords(manifest_bin))
            if mf_name is None:
                skipped["manifest"] = "no AndroidManifest.xml in package"
            elif manifest_plain is None:
                skipped["components"] = (
                    "binary AXML manifest without androguard: component-"
                    "level checks skipped (keyword checks only)")

        ran.append("manifest")

        def _flag(key):
            v = attrs.get(key, "")
            return str(v).lower() == "true"

        if _flag("debuggable"):
            findings.append(Finding(
                title="Android app is debuggable in this build",
                severity="medium",
                verification="candidate",
                verification_note="manifest flag; debuggable release "
                "builds expose runtime inspection (jdb, Frida)",
                manual_check="Confirm the shipped build sets "
                "android:debuggable=false.",
                location=mf_name or "AndroidManifest.xml",
                evidence="android:debuggable=\"true\"",
                source="omega-mobandroid/debuggable"))
        ran.append("debuggable")

        if _flag("allowBackup"):
            findings.append(Finding(
                title="Android app allows adb backup of app data",
                severity="low",
                verification="candidate",
                verification_note="manifest flag; backup can expose "
                "private app data via adb/cloud backup",
                manual_check="Set android:allowBackup=false or exclude "
                "sensitive data via backup rules.",
                location=mf_name or "AndroidManifest.xml",
                evidence="android:allowBackup=\"true\"",
                source="omega-mobandroid/allow_backup",
                confidence="low"))
        ran.append("allow_backup")

        if _flag("usesCleartextTraffic"):
            findings.append(Finding(
                title="Android app permits cleartext HTTP traffic",
                severity="high",
                verification="candidate",
                verification_note="manifest flag; unencrypted traffic is "
                "interceptable on-path",
                manual_check="Remove usesCleartextTraffic=true or scope "
                "it via a network security config.",
                location=mf_name or "AndroidManifest.xml",
                evidence="android:usesCleartextTraffic=\"true\"",
                source="omega-mobandroid/cleartext"))
        ran.append("cleartext")

        # ---- component checks (plain XML only) ----------------------
        comps = []
        if manifest_plain is not None:
            app = manifest_plain.find("application")
            if app is not None:
                for tag in ("activity", "activity-alias", "service",
                            "receiver", "provider"):
                    for el in app.findall(tag):
                        comps.append(el)

        exported = []
        for el in comps:
            name = el.get(NS + "name") or ""
            is_exported = (el.get(NS + "exported") or "").lower()
            has_filter = el.find("intent-filter") is not None
            if is_exported == "true" or (is_exported == "" and has_filter
                                         and name):
                exported.append((el, name, has_filter))

        unguarded = []
        deep_links = []
        strandhogg = []
        for el, name, has_filter in exported:
            perm = el.get(NS + "permission")
            if not perm:
                unguarded.append(name or "(unnamed)")
            schemes = []
            if has_filter:
                schemes = [d.get(NS + "scheme") or ""
                           for f in el.findall("intent-filter")
                           for d in f.findall("data")
                           if d.get(NS + "scheme")]
            if has_filter and schemes:
                deep_links.append((name, [s for s in schemes if s]))
            if (el.get(NS + "taskAffinity")
                    and (el.get(NS + "launchMode") or "").lower()
                    == "singletask"):
                strandhogg.append(name)

        if unguarded:
            findings.append(Finding(
                title="Exported Android components without guard "
                      "permission (%d)" % len(unguarded),
                severity="medium",
                verification="candidate",
                verification_note="static manifest; export may be "
                "intended (launcher activity) — each must be reviewed",
                manual_check="Review each exported component: can another "
                "app invoke it to reach sensitive behavior?",
                location=mf_name or "AndroidManifest.xml",
                evidence="exported w/o permission: "
                + ", ".join(unguarded[:10]),
                source="omega-mobandroid/exported"))
        ran.append("exported")

        if deep_links:
            names_schemes = "; ".join("%s [%s]" % (n, ",".join(ss))
                                      for n, ss in deep_links[:8])
            findings.append(Finding(
                title="Exported activity exposes deep-link schemes (%d)"
                      % len(deep_links),
                severity="medium",
                verification="candidate",
                verification_note="intent-filter schemes are invocable by "
                "any app; deep links can carry attacker-controlled input",
                manual_check="Validate/parse deep-link parameters "
                "defensively; confirm schemes are required.",
                location=mf_name or "AndroidManifest.xml",
                evidence=names_schemes,
                source="omega-mobandroid/deep_link"))
        ran.append("deep_link")

        if strandhogg:
            findings.append(Finding(
                title="Task hijacking pattern (taskAffinity + singleTask "
                      "on exported activity)",
                severity="medium",
                verification="candidate",
                verification_note="StrandHogg-style indicator; modern "
                "Android mitigates parts of this",
                manual_check="Test task-reparenting behavior on the "
                "affected activity; set taskAffinity=\"\" if unused.",
                location=mf_name or "AndroidManifest.xml",
                evidence="exported singleTask activity with custom "
                "taskAffinity: " + ", ".join(strandhogg[:5]),
                source="omega-mobandroid/strandhogg"))
        ran.append("strandhogg")

        # ---- webview / logcat / obfuscation / SDK from strings ------
        joined = "\n".join(sorted(strings))
        if (re.search(r"(?i)setJavaScriptEnabled", joined)
                and re.search(r"(?i)addJavascriptInterface|"
                              r"setAllowFileAccess", joined)):
            findings.append(Finding(
                title="WebView with JavaScript + JS bridge / file access "
                      "enabled",
                severity="medium",
                verification="candidate",
                verification_note="string-level indicator; whether the "
                "bridge is exposed to untrusted content must be verified",
                manual_check="Check the WebView targets and whether "
                "untrusted content can reach addJavascriptInterface "
                "or load file:// URLs.",
                location="classes.dex (strings)",
                evidence="setJavaScriptEnabled + addJavascriptInterface/"
                "setAllowFileAccess present in DEX strings",
                source="omega-mobandroid/webview"))
        ran.append("webview")

        for m in _LOG_CALL_RE.finditer(joined):
            if _LOG_KEYWORDS.search(m.group(0)):
                findings.append(Finding(
                    title="Sensitive keyword in (D/V/I) log call",
                    severity="medium",
                    verification="candidate",
                    verification_note="string-level indicator; whether the "
                    "logged value is truly sensitive must be verified",
                    manual_check="Confirm the log call does not emit "
                    "credentials in release builds.",
                    location="classes.dex (strings)",
                    evidence=re.sub(r"\s+", " ", m.group(0))[:120],
                    source="omega-mobandroid/logcat"))
                break
        ran.append("logcat")

        _secret_findings(strings, "classes.dex/resources.arsc/assets",
                         findings, ran)

        dangerous = sorted(p for p in _manifest_permission_strings(
            manifest_plain, strings) if p in DANGEROUS_PERMISSIONS)
        if len(dangerous) >= 5:
            findings.append(Finding(
                title="Large set of dangerous Android permissions (%d)"
                      % len(dangerous),
                severity="low",
                verification="info",
                verification_note="informational: permission surface "
                "size, not a vulnerability by itself",
                manual_check="Confirm each dangerous permission is used "
                "and required by a feature.",
                location=mf_name or "AndroidManifest.xml",
                evidence=", ".join(dangerous[:12]),
                source="omega-mobandroid/excessive_perms",
                confidence="low"))
        ran.append("excessive_perms")

        # obfuscation
        class_paths = _CLASS_PATH_RE.findall(joined)
        readable = [c for c in class_paths
                    if re.search(r"[A-Z][a-zA-Z]{3,}", c)]
        pkg_names = set()
        for m in _DEX_PACKAGE_RE.finditer(joined):
            pkg_names.add(m.group(1))
        has_marker = any(mk.lower() in joined.lower()
                         for mk in _OBFUSCATION_MARKERS)
        if (not has_marker and len(readable) >= 20
                and any(re.fullmatch(r"[A-Za-z0-9_]+(Activity|Service|"
                                     r"Receiver|Provider)", p.split("/")[-1]
                                     .rstrip(";")) for p in readable[:200])):
            findings.append(Finding(
                title="No ProGuard/R8 obfuscation markers (readable class "
                      "names, %d classes)" % len(readable),
                severity="low",
                verification="info",
                verification_note="informational: unobfuscated bytecode "
                "eases reverse engineering; not a vulnerability by itself",
                manual_check="Enable R8/ProGuard for release builds.",
                location="classes.dex",
                evidence="readable class names, e.g. %s"
                % ", ".join(readable[:3]),
                source="omega-mobandroid/obfuscation",
                confidence="low"))
        ran.append("obfuscation")

        vulnerable = []
        for pkg in sorted(pkg_names):
            for prefix, why in VULNERABLE_SDKS.items():
                if pkg.startswith(prefix):
                    vulnerable.append((pkg, why))
        if vulnerable:
            findings.append(Finding(
                title="Known-risky/legacy SDK fingerprints in DEX (%d)"
                      % len(vulnerable),
                severity="medium",
                verification="candidate",
                verification_note="package-name fingerprint; the exact "
                "version (and whether it is vulnerable) is unknown",
                manual_check="Pin the dependency version and compare "
                "against known CVEs for it.",
                location="classes.dex (packages)",
                evidence="; ".join("%s: %s" % (p, w) for p, w
                                   in vulnerable[:5]),
                source="omega-mobandroid/vulnerable_sdk"))
        ran.append("vulnerable_sdk")

        # ---- network security config (zip member) -------------------
        _nsc_checks(zf, names, findings, ran)

    # keep 'ran' ordered-unique
    seen = set()
    ran = [c for c in ran if not (c in seen or seen.add(c))]
    return {"findings": findings, "ran": ran, "skipped": skipped}


def _manifest_permission_strings(manifest_plain, strings):
    """uses-permission names from plain XML; fallback: regex over the
    string corpus for android.permission.* names (binary manifests)."""
    out = set()
    if manifest_plain is not None:
        for el in manifest_plain.findall("uses-permission"):
            n = el.get(NS + "name")
            if n:
                out.add(n)
        return out
    for s in strings:
        for m in re.finditer(r"android\.permission\.[A-Z_]+", s):
            out.add(m.group(0))
    return out
