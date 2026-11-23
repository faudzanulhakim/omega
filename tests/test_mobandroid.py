"""Hermetic tests for omega/scanning/mobandroid.py — offline Android APK
static analysis. Fixtures are tiny ZIPs with a PLAIN-XML
AndroidManifest.xml (accepted for testability) and a text classes.dex
with marker strings; no network access, androguard never required.
"""

from __future__ import annotations

import os
import zipfile

import pytest

from omega.scanning.mobandroid import run_android

AIZA_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrstuvw"  # 35 chars after AIza


def _manifest(**app_attrs):
    attrs = "".join(' android:%s="%s"' % (k, v)
                    for k, v in app_attrs.items())
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        ' package="com.test.app">\n'
        '  <uses-permission android:name="android.permission.CAMERA"/>\n'
        '  <uses-permission android:name="android.permission.RECORD_AUDIO"/>\n'
        '  <uses-permission'
        ' android:name="android.permission.ACCESS_FINE_LOCATION"/>\n'
        '  <uses-permission android:name="android.permission.READ_SMS"/>\n'
        '  <uses-permission'
        ' android:name="android.permission.READ_CONTACTS"/>\n'
        '  <application%s>\n'
        '    <activity android:name="com.test.app.MainActivity"'
        ' android:exported="true"'
        ' android:taskAffinity="com.test.app.main"'
        ' android:launchMode="singleTask">\n'
        '      <intent-filter><data android:scheme="myapp"/></intent-filter>\n'
        '    </activity>\n'
        '    <activity android:name="com.test.app.HiddenActivity"'
        ' android:exported="true"/>\n'
        '  </application>\n'
        '</manifest>' % attrs)


def _dex(extra=""):
    return (
        "classes.dex fixture\n"
        'Lcom/test/app/MainActivity;\nLcom/test/app/MainService;\n'
        "Lcom/test/app/FooActivity;\nLcom/test/app/BarActivity;\n"
        + extra)


def _apk(tmp_path, manifest=None, dex_extra="", extra=None,
         nsc=None, name="t.apk"):
    apk = str(tmp_path / name)
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml",
                   manifest if manifest is not None else _manifest())
        z.writestr("classes.dex", _dex(dex_extra))
        if extra:
            for n, b in extra.items():
                z.writestr(n, b)
        if nsc:
            z.writestr("res/xml/network_security_config.xml", nsc)
    return apk


def _sources(out):
    return {f["source"] for f in out["findings"]}


# ------------------------------------------------------------ happy path

def test_vulnerable_apk_produces_expected_findings(tmp_path):
    out = run_android(_apk(
        tmp_path,
        manifest=_manifest(debuggable="true", allowBackup="true",
                           usesCleartextTraffic="true"),
        extra={"res/values/strings.xml": AIZA_KEY}))
    srcs = _sources(out)
    assert "omega-mobandroid/debuggable" in srcs
    assert "omega-mobandroid/allow_backup" in srcs
    assert "omega-mobandroid/cleartext" in srcs
    assert "omega-mobandroid/exported" in srcs
    assert "omega-mobandroid/deep_link" in srcs
    assert "omega-mobandroid/strandhogg" in srcs
    assert "omega-mobandroid/excessive_perms" in srcs
    assert not out["skipped"]
    for f in out["findings"]:
        assert f["verification"] in ("candidate", "info")


def test_run_and_skip_lists(tmp_path):
    out = run_android(_apk(tmp_path))
    for check in ("manifest", "debuggable", "allow_backup", "cleartext",
                  "exported", "deep_link", "webview", "logcat", "secrets",
                  "excessive_perms", "obfuscation", "vulnerable_sdk"):
        assert check in out["ran"], check
    assert "mobile" not in out["ran"]  # sanity: no stray suites


# ------------------------------------------------------------ manifests

def test_clean_manifest_flags_not_flagged(tmp_path):
    out = run_android(_apk(tmp_path))
    srcs = _sources(out)
    assert "omega-mobandroid/debuggable" not in srcs
    assert "omega-mobandroid/allow_backup" not in srcs
    assert "omega-mobandroid/cleartext" not in srcs


def test_binary_manifest_keyword_fallback(tmp_path):
    # A binary AXML manifest is emulated as UTF-16LE keyword text.
    mf = "debuggable\x00true\x00allowBackup\x00false".encode("utf-16-le")
    out = run_android(_apk(tmp_path, manifest=mf))
    assert "omega-mobandroid/debuggable" in _sources(out)
    assert "components" in out["skipped"]  # binary: component checks skipped


def test_nsc_user_ca_and_cleartext(tmp_path):
    nsc = ('<network-security-config><base-config'
           ' cleartextTrafficPermitted="true"/>'
           '<trust-anchors><certificates src="user"/></trust-anchors>'
           '</network-security-config>')
    out = run_android(_apk(tmp_path, nsc=nsc))
    srcs = _sources(out)
    assert "omega-mobandroid/nsc_user_ca" in srcs
    assert any(f["severity"] == "high" and f["source"]
               == "omega-mobandroid/cleartext" for f in out["findings"])


# -------------------------------------------------------- secrets etc.

def test_hardcoded_secret_high_with_masked_evidence(tmp_path):
    out = run_android(_apk(
        tmp_path,
        extra={"assets/config.bin": "AKIA" + "A1B2C3D4E5F6G7H8"  # 16 chars
               + "\x00" + AIZA_KEY}))
    secret_f = [f for f in out["findings"]
                if f["source"] == "omega-mobandroid/secrets"]
    assert secret_f
    aws = [f for f in secret_f if f["severity"] == "high"]
    assert aws
    ev = aws[0]["evidence"]
    assert "A1B2C3D4E5F6G7H8" not in ev  # middle redacted
    assert len(ev) <= 300


def test_example_key_is_not_a_finding(tmp_path):
    out = run_android(_apk(
        tmp_path,
        extra={"assets/config.bin": "AKIAIOSEXAMPLE1234"}))
    assert not [f for f in out["findings"]
                if f["source"] == "omega-mobandroid/secrets"]


def test_webview_and_logcat_markers(tmp_path):
    out = run_android(_apk(
        tmp_path,
        dex_extra='setJavaScriptEnabled\naddJavascriptInterface\n'
                  'Log.d("AUTH", "password=hunter2token")\n'))
    srcs = _sources(out)
    assert "omega-mobandroid/webview" in srcs
    assert "omega-mobandroid/logcat" in srcs


def test_missing_obfuscation_low_info(tmp_path):
    # >= 20 DISTINCT readable class names and no ProGuard/R8 markers
    extra = "\n".join("Lcom/test/app/Class%dActivity;" % i
                      for i in range(30)) + "\n"
    out = run_android(_apk(tmp_path, dex_extra=extra))
    obf = [f for f in out["findings"]
           if f["source"] == "omega-mobandroid/obfuscation"]
    assert obf and obf[0]["severity"] == "low"
    assert obf[0]["verification"] == "info"


def test_vulnerable_sdk_fingerprint(tmp_path):
    out = run_android(_apk(
        tmp_path, dex_extra="com.facebook.stetho.Stetho\n"))
    vuln = [f for f in out["findings"]
            if f["source"] == "omega-mobandroid/vulnerable_sdk"]
    assert vuln and vuln[0]["severity"] == "medium"
    assert "stetho" in vuln[0]["evidence"].lower()


# ------------------------------------------------------------ skip paths

def test_missing_path_skips_never_raises(tmp_path):
    out = run_android(str(tmp_path / "does-not-exist.apk"))
    assert out["findings"] == [] and out["ran"] == []
    assert "apk" in out["skipped"]


def test_non_zip_file_skips_never_raises(tmp_path):
    p = tmp_path / "notzip.apk"
    p.write_bytes(b"definitely not a zip")
    out = run_android(str(p))
    assert out["findings"] == []
    assert "not a zip" in out["skipped"]["apk"]


def test_none_path_skips_never_raises():
    out = run_android(None)
    assert "apk" in out["skipped"]
