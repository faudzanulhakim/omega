"""Hermetic tests for omega.scanning.mobdeep (deep APK analysis).

Builds tiny real APK-like zips in tmp (zipfile: fake Android binary
XML string table + classes.dex with secret strings) — no aapt/apktool
required, no network egress. Covers the skip-when-no-apk contract,
vuln + clean variants, claim-gating against the APK file, REDACTED
evidence, and never-raise behavior.
"""

import os
import zipfile

import pytest

from omega.scanning.mobdeep import analyze_apk, run_mobdeep

PERM = b"android.permission."


def _join(strings):
    # crude Android binary-XML string table: length-prefix byte + string
    # + NUL separator (the scanner is length-prefix-agnostic).
    out = b""
    for s in strings:
        out += bytes([len(s) & 0xFF]) + s + b"\x00\x00"
    return out


VULN_MANIFEST = _join([
    b"manifest", b"activity", b"com.example.app.MainActivity",
    b"android:exported", b"true", b"uses-permission",
    PERM + b"RECEIVE_SMS", PERM + b"INSTALL_PACKAGES",
    b"android:debuggable", b"true", b"android:allowBackup", b"true",
])

CLEAN_MANIFEST = _join([
    b"manifest", b"application", b"com.example.app.MainActivity",
])

VULN_DEX = (
    b"\x64\x65\x78\x0a" + b"\x00\x00"
    + b"AKIAIOSFODNN7EXAMPLE" + b"\x00"
    + b'api_key = "sup3rs3cretvalue1"' + b"\x00"
    + b"http://api.example.com/v2/login" + b"\x00"
)
CLEAN_DEX = b"\x64\x65\x78\x0a" + b"Lcom/example/app/MainActivity;\x00" \
    + b"hello world\x00"


def _make_apk(path, manifest, dex, extra_assets=True):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
        if extra_assets:
            zf.writestr("assets/config.properties",
                        b"endpoint=http://api.example.com/v2/login\n")


@pytest.fixture
def vuln_apk(tmp_path):
    p = tmp_path / "vuln.apk"
    _make_apk(str(p), VULN_MANIFEST, VULN_DEX)
    return str(p)


@pytest.fixture
def clean_apk(tmp_path):
    p = tmp_path / "clean.apk"
    _make_apk(str(p), CLEAN_MANIFEST, CLEAN_DEX, extra_assets=False)
    return str(p)


@pytest.fixture(autouse=True)
def _no_env_apk(monkeypatch):
    monkeypatch.delenv("OMEGA_APK", raising=False)


def test_skip_when_no_apk():
    assert run_mobdeep("http://127.0.0.1:1", lambda *a, **k: (200, {}, b""),
                       path_info={}) == []
    assert run_mobdeep("http://127.0.0.1:1", lambda *a, **k: (200, {}, b""),
                       path_info=None) == []
    # nonexistent path -> skip, never raise
    assert run_mobdeep("http://127.0.0.1:1", lambda *a, **k: (200, {}, b""),
                       path_info={"apk": "/nonexistent/x.apk"}) == []


def test_omega_apk_env_var(vuln_apk, monkeypatch):
    monkeypatch.setenv("OMEGA_APK", vuln_apk)
    found = run_mobdeep("http://127.0.0.1:1",
                        lambda *a, **k: (200, {}, b""), path_info=None)
    assert found, "env-provided APK must be analyzed"
    assert all(f["source"] == "omega-mobdeep" for f in found)


def test_vuln_apk_finding_families(vuln_apk):
    found = analyze_apk(vuln_apk)
    titles = " ".join(f["title"] for f in found)
    assert "debuggable" in titles
    assert "Exported component" in titles
    assert "AWS Access Key ID" in titles
    assert "Cleartext HTTP" in titles
    assert "allowBackup" in titles
    assert "Risky permissions" in titles
    sevs = {f["title"]: f["severity"] for f in found}
    for t, s in sevs.items():
        if "debuggable" in t or "Exported" in t or "AWS" in t:
            assert s == "high", t
        if "Cleartext" in t or "allowBackup" in t or "Risky" in t:
            assert s == "medium", t


def test_claim_gate_reproduces_evidence(vuln_apk):
    found = run_mobdeep("http://127.0.0.1:1",
                        lambda *a, **k: (200, {}, b""),
                        path_info={"apk": vuln_apk})
    assert found
    for f in found:
        assert f["validation"] == "verified", f["title"]
        assert "ai-claim:validated" in f.get("tags", [])
        # evidence reproduces from the APK file bytes
        with open(vuln_apk, "rb") as fh:
            blob = fh.read()
        marker = f["evidence"].get("marker")
        if marker:
            assert marker.encode() in blob


def test_secret_evidence_redacted(vuln_apk):
    found = analyze_apk(vuln_apk)
    secrets = [f for f in found if "AWS" in f["title"]]
    assert secrets
    ev = secrets[0]["evidence"]
    assert "AKIAIOSFODNN7EXAMPLE" not in ev["excerpt"]
    assert ev["analysis"] == "heuristic-stdlib"


def test_clean_apk_no_findings(clean_apk):
    assert analyze_apk(clean_apk) == []
    assert run_mobdeep("http://127.0.0.1:1",
                       lambda *a, **k: (200, {}, b""),
                       path_info={"apk": clean_apk}) == []


def test_never_raises_on_bad_inputs():
    assert analyze_apk(None) == []
    assert analyze_apk("") == []
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".apk") as fh:
        fh.write(b"not a zip at all")
        fh.flush()
        assert analyze_apk(fh.name) == []
    assert run_mobdeep("http://127.0.0.1:1",
                       lambda *a, **k: (_ for _ in ()).throw(
                           RuntimeError("boom")),
                       path_info={"apk": "/nonexistent.apk"}) == []


def test_suites_registered_in_fusion():
    from omega.scanning.fusion import SUITES
    names = [s[0] for s in SUITES]
    assert "mobdeep" in names and "mobapi" in names


def test_stdlib_fallback_used_when_no_tools(vuln_apk):
    # tools absent on this box: backend must be the stdlib fallback
    found = analyze_apk(vuln_apk, which_fn=lambda name: None)
    assert found
    assert all(f["evidence"].get("analysis") == "heuristic-stdlib"
               for f in found)
