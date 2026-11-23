"""omega/scanning/mobgeneral.py — cross-platform mobile checks over an
extracted source/config directory (JS/Dart/Java/Kotlin/Swift/XML/JSON).

OFFLINE only: walks a local directory, never touches the network. All
checks are string/regex based, self-contained (a raise becomes a skip
entry, never an exception) and candidate/info only (honesty contract).

Checks (entry run_mobile_general(dir_path) -> {findings, ran, skipped}):
  pinning          TrustManager / SSL-error-proceed / NSAllowsArbitraryLoads
                   hints -> certificate pinning likely absent        LOW-MEDIUM
  client_trust     security-relevant flags assigned from client input
                   (price/role/isAdmin/balance = req.body/params...) HIGH candidate
  hooking          no root/jailbreak detection strings found +       MEDIUM
                   debuggable/release indicators
  excessive_perms  Android dangerous permissions in manifest-like    LOW
                   files / iOS entitlements
  push             push notification payload keys with sensitive     LOW
                   keywords
"""

from __future__ import annotations

import os
import re

from omega.scanning._mobcommon import Finding, walk_text_files
from omega.scanning.mobandroid import DANGEROUS_PERMISSIONS

__all__ = ["run_mobile_general", "CLIENT_TRUST_RE", "ROOT_DETECTION_RE"]

# --- certificate pinning absence hints -------------------------------------
PINNING_PRESENT_RE = re.compile(
    r"(?i)CertificatePinner|certificate_pinning|SSLPinning|"
    r"pinnedCertificates|TrustKit")
_SSL_SKIP_RE = re.compile(
    r"(?i)onReceivedSslError|ShouldSkip|checkServerTrusted\s*\([^)]*\)\s*\{"
    r"[^}]*$|NSAllowsArbitraryLoads|kCFNetworkProhibitTLS")
ROOT_DETECTION_RE = re.compile(
    r"(?i)RootBeer|jailbr[eé]ak|\bsu\b\s*binary|Superuser\.apk|"
    r"FridaGadget|IsDebuggerAttached|"
    r"cydia|Magisk|checkForRoot|deviceIsJailbroken")

# --- client-side trust ------------------------------------------------------
CLIENT_TRUST_RE = re.compile(
    r"(?i)\b(is[_A-Za-z0-9]*admin|is[_A-Za-z0-9]*premium|role|price|"
    r"amount|balance|discount|is[_A-Za-z0-9]*paid)\b\s*[:=]\s*"
    r"(req(uest)?\.body|req\.query|params\.get|getParameter\(|"
    r"input\.|formData\.get|jsonBody\[|window\.location\.search)")

# --- entitlements (iOS) -----------------------------------------------------
_ENTITLEMENT_RE = re.compile(
    r"(?i)com\.apple\.security\.personal-information\.(location|calendars|"
    r"photos)|com\.apple\.security\.device\.camera|"
    r"com\.apple\.security\.microphone")

# --- push payload -----------------------------------------------------------
_PUSH_FILE_RE = re.compile(r"(?i)(push|notification|fcm|apns|payload)")
_PUSH_KEY_RE = re.compile(r"(?i)(password|passwd|token|secret|ssn|"
                          r"creditcard|cardnumber|health)")
_PUSH_FILE_SUFFIXES = (".json", ".js", ".ts", ".dart", ".py", ".java",
                       ".kt", ".swift")


def run_mobile_general(dir_path):
    """Cross-platform mobile checks over an extracted source/config dir.
    Never raises; a bad path yields a skip note."""
    skipped = {}
    ran = []
    findings = []
    if not dir_path or not os.path.isdir(str(dir_path)):
        skipped["dir"] = "not a directory: %r" % (dir_path,)
        return {"findings": findings, "ran": ran, "skipped": skipped}

    # Collect per-check data in ONE walk (bounded by walk_text_files).
    pinning_present = False
    ssl_skip_hits = []
    client_trust_hits = []
    root_detection_hits = []
    debuggable_hits = []
    dangerous_perms = set()
    entitlement_hits = set()
    push_key_hits = set()

    for rel, text in walk_text_files(str(dir_path)):
        if PINNING_PRESENT_RE.search(text):
            pinning_present = True
        for m in _SSL_SKIP_RE.finditer(text):
            if len(ssl_skip_hits) < 5 and rel not in [h[0] for h
                                                      in ssl_skip_hits]:
                ssl_skip_hits.append((rel, re.sub(r"\s+", " ",
                                                  m.group(0))[:100]))
        for m in CLIENT_TRUST_RE.finditer(text):
            client_trust_hits.append((rel, re.sub(r"\s+", " ",
                                                  m.group(0))[:120]))
        for m in ROOT_DETECTION_RE.finditer(text):
            root_detection_hits.append(rel)
        if re.search(r"(?i)debuggable\s*[=:]\s*true|"
                     r"android:debuggable\s*=\s*\"true\"", text):
            debuggable_hits.append(rel)
        for m in re.finditer(r"android\.permission\.[A-Z_]{3,}", text):
            if m.group(0) in DANGEROUS_PERMISSIONS:
                dangerous_perms.add(m.group(0))
        for m in _ENTITLEMENT_RE.finditer(text):
            entitlement_hits.add(m.group(0))
        if (_PUSH_FILE_RE.search(os.path.basename(rel))
                and rel.endswith(_PUSH_FILE_SUFFIXES)):
            for line in text.splitlines():
                if _PUSH_KEY_RE.search(line):
                    key_ctx = re.sub(r"\s+", " ", line)[:120]
                    if key_ctx:
                        push_key_hits.add(key_ctx)

    # ---------------------------------------------------------- pinning
    ran.append("pinning")
    if not pinning_present and ssl_skip_hits:
        findings.append(Finding(
            title="No certificate pinning found; SSL error handling may "
                  "proceed",
            severity="low",
            verification="candidate",
            verification_note="string-level hints; absence of pinning is "
            "not itself a vulnerability but weakens MITM resistance",
            manual_check="Confirm whether the app should pin its backend "
            "CA/TLS chain and whether SSL errors are silently skipped.",
            location=", ".join(sorted({r for r, _ in ssl_skip_hits})),
            evidence="; ".join(e for _r, e in ssl_skip_hits[:3]),
            source="omega-mobgeneral/pinning",
            confidence="low"))
    elif ssl_skip_hits:
        findings.append(Finding(
            title="Pinning indicators present but SSL-error-skip patterns "
                  "also found",
            severity="low",
            verification="candidate",
            verification_note="both pinning and permissive SSL error "
            "handling present; verify per-client behavior",
            manual_check="Verify that the permissive SSL error handling "
            "is not used for production connections.",
            location=", ".join(sorted({r for r, _ in ssl_skip_hits})),
            evidence="; ".join(e for _r, e in ssl_skip_hits[:3]),
            source="omega-mobgeneral/pinning",
            confidence="low"))

    # ----------------------------------------------------- client trust
    ran.append("client_trust")
    if client_trust_hits:
        findings.append(Finding(
            title="Client-side trust: security flag assigned from client "
                  "input (%d)" % len(client_trust_hits),
            severity="high",
            verification="candidate",
            verification_note="regex match on source; the actual request "
            "flow and server-side enforcement must be verified",
            manual_check="Confirm the server independently enforces "
            "price/role/balance — never trust client-supplied values.",
            location=client_trust_hits[0][0],
            evidence="; ".join("%s: %s" % (r, e)
                               for r, e in client_trust_hits[:3]),
            source="omega-mobgeneral/client_trust",
            confidence="medium"))

    # ---------------------------------------------------------- hooking
    ran.append("hooking")
    if not root_detection_hits:
        findings.append(Finding(
            title="No root/jailbreak/hooking detection strings found",
            severity="medium",
            verification="candidate",
            verification_note="absence indicator only; detection may be "
            "implemented in native code not covered by this scan",
            manual_check="Confirm whether the threat model requires "
            "root/jailbreak detection (e.g. banking apps).",
            location=str(dir_path),
            evidence="no RootBeer/jailbreak/FridaGadget/Magisk markers in "
            "scanned source",
            source="omega-mobgeneral/hooking"))
        if debuggable_hits:
            findings.append(Finding(
                title="Debuggable build flag found together with no "
                      "anti-hooking detection",
                severity="medium",
                verification="candidate",
                verification_note="debuggable=true materially eases "
                "Frida/ptrace-based instrumentation",
                manual_check="Ship release builds with debuggable=false "
                "and add anti-tamper checks if required.",
                location=debuggable_hits[0],
                evidence="debuggable=true found in %s" % debuggable_hits[0],
                source="omega-mobgeneral/hooking",
                confidence="low"))

    # ------------------------------------------------- excessive perms
    ran.append("excessive_perms")
    if len(dangerous_perms) >= 5:
        findings.append(Finding(
            title="Large set of dangerous Android permissions declared "
                  "(%d)" % len(dangerous_perms),
            severity="low",
            verification="info",
            verification_note="informational: permission surface size, "
            "not a vulnerability by itself",
            manual_check="Confirm each dangerous permission is required "
            "by a shipped feature.",
            location="manifest files under %s" % dir_path,
            evidence=", ".join(sorted(dangerous_perms)[:12]),
            source="omega-mobgeneral/excessive_perms",
            confidence="low"))
    if entitlement_hits:
        findings.append(Finding(
            title="Sensitive iOS entitlements declared (%d)"
                  % len(entitlement_hits),
            severity="low",
            verification="info",
            verification_note="informational: entitlements are declared "
            "access, not a vulnerability by itself",
            manual_check="Confirm each sensitive entitlement is required "
            "by a shipped feature.",
            location="entitlements files under %s" % dir_path,
            evidence=", ".join(sorted(entitlement_hits)[:10]),
            source="omega-mobgeneral/excessive_perms",
            confidence="low"))

    # ------------------------------------------------------------- push
    ran.append("push")
    if push_key_hits:
        findings.append(Finding(
            title="Sensitive keywords in push notification payload keys",
            severity="low",
            verification="candidate",
            verification_note="push payloads transit provider "
            "infrastructure (APNs/FCM) and may be shown on lock screens",
            manual_check="Remove sensitive values from push payloads; "
            "push a silent trigger and fetch from the backend instead.",
            location="push payload files under %s" % dir_path,
            evidence="; ".join(sorted(push_key_hits)[:3]),
            source="omega-mobgeneral/push",
            confidence="low"))

    seen = set()
    ran = [c for c in ran if not (c in seen or seen.add(c))]
    return {"findings": findings, "ran": ran, "skipped": skipped}
