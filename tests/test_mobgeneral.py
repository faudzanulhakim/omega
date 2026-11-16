"""Hermetic tests for omega/scanning/mobgeneral.py — offline
cross-platform mobile checks over a small extracted source/config dir.
Fixtures built in tmp; no network access.
"""

from __future__ import annotations

import os

import pytest

from omega.scanning.mobgeneral import run_mobile_general

PERMS = (
    '<manifest package="com.test.app">'
    '<uses-permission android:name="android.permission.CAMERA"/>'
    '<uses-permission android:name="android.permission.RECORD_AUDIO"/>'
    '<uses-permission android:name="android.permission.'
    'ACCESS_FINE_LOCATION"/>'
    '<uses-permission android:name="android.permission.READ_SMS"/>'
    '<uses-permission android:name="android.permission.READ_CONTACTS"/>'
    "</manifest>"
)


def _write(tmp_path, rel, text):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return str(tmp_path)


def _sources(out):
    return {f["source"] for f in out["findings"]}


# --------------------------------------------------------------- checks

def test_client_side_trust_high(tmp_path):
    src = _write(tmp_path, "src/Order.js",
                 "let price = req.body.price;\n"
                 "var isAdmin = params.get('isAdmin');\n")
    out = run_mobile_general(src)
    ct = [f for f in out["findings"]
          if f["source"] == "omega-mobgeneral/client_trust"]
    assert ct and ct[0]["severity"] == "high"
    assert ct[0]["verification"] == "candidate"


def test_no_root_detection_medium_candidate(tmp_path):
    src = _write(tmp_path, "src/Logic.kt", "fun main() { nothing() }\n")
    out = run_mobile_general(src)
    hk = [f for f in out["findings"]
          if f["source"] == "omega-mobgeneral/hooking"]
    assert hk and hk[0]["severity"] == "medium"
    assert hk[0]["verification"] == "candidate"


def test_root_detection_present_no_hooking_finding(tmp_path):
    src = _write(tmp_path, "src/Sec.java",
                 "if (RootBeer.isRooted(context)) { exit(1); }\n")
    out = run_mobile_general(src)
    assert "omega-mobgeneral/hooking" not in _sources(out)


def test_debuggable_plus_no_detection_two_findings(tmp_path):
    src = _write(tmp_path, "src/build.gradle",
                 "debuggable = true\n")
    out = run_mobile_general(src)
    hk = [f for f in out["findings"]
          if f["source"] == "omega-mobgeneral/hooking"]
    assert len(hk) == 2  # absence + debuggable-strengthens note


def test_excessive_dangerous_permissions(tmp_path):
    src = _write(tmp_path, "src/AndroidManifest.xml", PERMS)
    out = run_mobile_general(src)
    ep = [f for f in out["findings"]
          if f["source"] == "omega-mobgeneral/excessive_perms"]
    assert ep and ep[0]["severity"] == "low"
    assert "android.permission.CAMERA" in ep[0]["evidence"]


def test_few_permissions_no_finding(tmp_path):
    src = _write(
        tmp_path, "src/AndroidManifest.xml",
        '<manifest><uses-permission android:name='
        '"android.permission.INTERNET"/></manifest>')
    out = run_mobile_general(src)
    assert "omega-mobgeneral/excessive_perms" not in _sources(out)


def test_push_payload_sensitive_keyword(tmp_path):
    src = _write(tmp_path, "src/push_config.json",
                 '{"title": "Payment", "body": "cardNumber on file"}\n')
    out = run_mobile_general(src)
    push = [f for f in out["findings"]
            if f["source"] == "omega-mobgeneral/push"]
    assert push and push[0]["severity"] == "low"
    assert "cardNumber" in push[0]["evidence"]


def test_pinning_absent_with_ssl_skip_hint(tmp_path):
    src = _write(tmp_path, "src/WebView.java",
                 "@Override public void onReceivedSslError(WebView v, "
                 "SslErrorHandler h, SslError e) { h.proceed(); }\n")
    out = run_mobile_general(src)
    pin = [f for f in out["findings"]
           if f["source"] == "omega-mobgeneral/pinning"]
    assert pin and pin[0]["severity"] == "low"


def test_pinning_present_no_finding(tmp_path):
    src = _write(tmp_path, "src/Tls.java",
                 "CertificatePinner pinner = new CertificatePinner();\n")
    out = run_mobile_general(src)
    assert "omega-mobgeneral/pinning" not in _sources(out)


# ------------------------------------------------------------ structure

def test_run_and_skip_lists(tmp_path):
    src = _write(tmp_path, "src/a.js", "x = 1\n")
    out = run_mobile_general(src)
    for check in ("pinning", "client_trust", "hooking", "excessive_perms",
                  "push"):
        assert check in out["ran"], check
    assert not out["skipped"]


def test_missing_dir_skips_never_raises(tmp_path):
    out = run_mobile_general(str(tmp_path / "missing-dir"))
    assert out["findings"] == [] and out["ran"] == []
    assert "dir" in out["skipped"]


def test_none_dir_skips_never_raises():
    out = run_mobile_general(None)
    assert "dir" in out["skipped"]
