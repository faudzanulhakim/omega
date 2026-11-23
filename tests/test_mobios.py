"""Hermetic tests for omega/scanning/mobios.py — offline iOS static
analysis of a .ipa (ZIP) or an extracted .app directory. Tiny fixtures
built in tmp; no network access.
"""

from __future__ import annotations

import os
import plistlib
import zipfile

import pytest

from omega.scanning.mobios import run_ios

_INFO = {
    "CFBundleIdentifier": "com.test.app",
    "NSAppTransportSecurity": {
        "NSAllowsArbitraryLoads": True,
        "NSAllowsLocalNetworking": True,
    },
    "CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp", "fb123"]}],
    "userPassword": "placeholder-not-a-secret",
}

# A structurally valid JWT-looking string (matches the embedded pattern).
JWT = ("eyJhbGciOiJIUzI1NiJ9."        # 8+ chars before the dot
       "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")


def _app_dir(tmp_path, info=None, binary=b"", name="Foo.app"):
    app = tmp_path / name
    app.mkdir()
    plist_bytes = plistlib.dumps(info if info is not None else _INFO,
                                 fmt=plistlib.FMT_XML)
    (app / "Info.plist").write_bytes(plist_bytes)
    (app / "Foo").write_bytes(b"Mach-O\x00binary\x00" + binary)
    return str(app)


def _ipa(tmp_path, info=None, binary=b"", name="t.ipa"):
    ipa = tmp_path / name
    plist_bytes = plistlib.dumps(info if info is not None else _INFO,
                                 fmt=plistlib.FMT_XML)
    with zipfile.ZipFile(str(ipa), "w") as z:
        z.writestr("Payload/Foo.app/Info.plist", plist_bytes)
        z.writestr("Payload/Foo.app/Foo", b"Mach-O\x00" + binary)
    return str(ipa)


def _sources(out):
    return {f["source"] for f in out["findings"]}


# ------------------------------------------------------------ happy path

def test_vulnerable_app_dir_produces_expected_findings(tmp_path):
    out = run_ios(_app_dir(
        tmp_path,
        binary=b"kSecAttrAccessibleAlways\x00"
               b"AKIA1234567890ABCDEF12\x00"))
    srcs = _sources(out)
    assert "omega-mobios/ats" in srcs
    assert "omega-mobios/ats_local" in srcs
    assert "omega-mobios/url_schemes" in srcs
    assert "omega-mobios/keychain" in srcs
    assert "omega-mobios/secrets" in srcs
    assert "omega-mobios/defaults_keys" in srcs
    for f in out["findings"]:
        assert f["verification"] in ("candidate", "info")


def test_ipa_zip_same_checks(tmp_path):
    out = run_ios(_ipa(tmp_path,
                       binary=b"kSecAttrAccessibleAlwaysThisDeviceOnly"))
    srcs = _sources(out)
    assert {"omega-mobios/ats", "omega-mobios/keychain"} <= srcs


def test_run_and_skip_lists(tmp_path):
    out = run_ios(_app_dir(tmp_path))
    for check in ("info_plist", "ats", "ats_local", "url_schemes",
                  "keychain", "secrets", "defaults_keys"):
        assert check in out["ran"], check
    # snapshot/pasteboard heuristic deliberately skipped, with a note.
    assert "snapshot_pasteboard" in out["skipped"]
    assert "reliable" in out["skipped"]["snapshot_pasteboard"]


# --------------------------------------------------------------- checks

def test_clean_info_plist_no_ats_finding(tmp_path):
    info = {"CFBundleIdentifier": "com.test.app"}
    out = run_ios(_app_dir(tmp_path, info=info))
    srcs = _sources(out)
    assert "omega-mobios/ats" not in srcs
    assert "omega-mobios/url_schemes" not in srcs
    assert "omega-mobios/defaults_keys" not in srcs


def test_url_schemes_listed_in_evidence(tmp_path):
    out = run_ios(_app_dir(tmp_path))
    schemes = [f for f in out["findings"]
               if f["source"] == "omega-mobios/url_schemes"]
    assert schemes
    assert "myapp" in schemes[0]["evidence"]
    assert "fb123" in schemes[0]["evidence"]


def test_keychain_marker_finding(tmp_path):
    out = run_ios(_app_dir(
        tmp_path, binary=b"\x00kSecAttrAccessibleAlwaysThisDeviceOnly\x00"))
    kc = [f for f in out["findings"]
          if f["source"] == "omega-mobios/keychain"]
    assert kc and kc[0]["severity"] == "medium"


def test_secret_evidence_is_masked(tmp_path):
    out = run_ios(_app_dir(tmp_path,
                           binary=b"AKIA" + b"A1B2C3D4E5F6G7H8"))
    secret_f = [f for f in out["findings"]
                if f["source"] == "omega-mobios/secrets"]
    assert secret_f
    ev = secret_f[0]["evidence"]
    assert "A1B2C3D4E5F6G7H8" not in ev
    assert len(ev) <= 300


def test_jwt_secret_detected(tmp_path):
    out = run_ios(_app_dir(tmp_path, binary=JWT.encode()))
    assert [f for f in out["findings"]
            if f["source"] == "omega-mobios/secrets"
            and f["severity"] == "medium"]


# ------------------------------------------------------------ skip paths

def test_missing_path_skips_never_raises(tmp_path):
    out = run_ios(str(tmp_path / "missing.app"))
    assert out["findings"] == [] and out["ran"] == []
    assert "app" in out["skipped"]


def test_non_zip_file_skips_never_raises(tmp_path):
    p = tmp_path / "notzip.ipa"
    p.write_bytes(b"garbage")
    out = run_ios(str(p))
    assert out["findings"] == []
    assert "not a zip" in out["skipped"]["app"]


def test_app_dir_without_info_plist_still_runs_binaries(tmp_path):
    app = tmp_path / "Bare.app"
    app.mkdir()
    (app / "Foo").write_bytes(b"kSecAttrAccessibleAlways\x00")
    out = run_ios(str(app))
    assert "info_plist" in out["skipped"]
    assert "omega-mobios/keychain" in _sources(out)
