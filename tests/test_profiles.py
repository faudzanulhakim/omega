"""Hermetic tests for omega/core/profiles.py (scan profile packs)."""

import sys

import pytest

sys.path.insert(0, __import__("os").path.dirname(
    __import__("os").path.dirname(__import__("os").path.abspath(__file__))))

from omega.core.profiles import (  # noqa: E402
    DEFAULT_PROFILE,
    PROFILES,
    list_profiles,
    resolve_profile,
)

EXPECTED = {"quick", "web", "full", "cloud", "mobile", "api", "llm"}


def suite_names():
    from omega.fusion import SUITES
    return {name for name, _lang, _runner in SUITES}


def test_list_profiles_contains_all_packs():
    assert EXPECTED.issubset(set(list_profiles()))


def test_resolve_quick_suite_subset():
    p = resolve_profile("quick")
    assert p["name"] == "quick"
    assert p["suites"] == ("python-deep", "python-headerscan",
                           "python-probes")
    assert p["budget"] == 60


def test_resolve_unknown_falls_back_to_web():
    p = resolve_profile("no-such-profile")
    assert p["name"] == DEFAULT_PROFILE == "web"
    assert p == resolve_profile("web")


def test_resolve_empty_and_none_fall_back_to_web():
    assert resolve_profile(None)["name"] == "web"
    assert resolve_profile("")["name"] == "web"


def test_resolve_is_case_insensitive():
    assert resolve_profile("FULL")["name"] == "full"
    assert resolve_profile(" Cloud ")["name"] == "cloud"


def test_every_explicit_suite_is_a_valid_fusion_suite_name():
    names = suite_names()
    for pname in list_profiles():
        p = resolve_profile(pname)
        if p["suites"] is None:  # 'full' runs every suite
            continue
        assert set(p["suites"]) <= names, (
            "profile %s references unknown suites: %s"
            % (pname, set(p["suites"]) - names))


def test_full_profile_runs_every_suite():
    assert resolve_profile("full")["suites"] is None


def test_budgets_positive_and_profiles_match_expected():
    assert resolve_profile("web")["budget"] == 200
    assert resolve_profile("full")["budget"] == 400
    assert resolve_profile("llm")["budget"] == 80
    for pname in list_profiles():
        b = resolve_profile(pname)["budget"]
        assert isinstance(b, int) and b > 0


def test_extras_are_known_capabilities():
    known = {"tfinger", "apimap"}
    for pname in list_profiles():
        assert set(resolve_profile(pname)["extras"]) <= known


def test_resolve_returns_fresh_copies():
    p = resolve_profile("quick")
    p["suites"] = ("tampered",)
    assert resolve_profile("quick")["suites"] == (
        "python-deep", "python-headerscan", "python-probes")
    # raw PROFILES data untouched
    assert PROFILES["quick"]["budget"] == 60


def test_mobile_and_cloud_and_api_and_llm_pack_contents():
    assert resolve_profile("mobile")["suites"] == (
        "mobile-android", "mobile-ios", "mobile-general")
    assert set(resolve_profile("cloud")["suites"]) == {
        "cloud-exposure", "k8s-exposure", "cicd-chain"}
    assert set(resolve_profile("api")["suites"]) == {
        "python-api", "python-graphql-deep", "deser-safe",
        "python-jsrender"}
    assert set(resolve_profile("llm")["suites"]) == {"llm-app",
                                                     "python-api"}


def test_never_raises_on_weird_input():
    for bad in (123, [], {}, b"web"):
        assert resolve_profile(bad)["name"] in list_profiles()


if __name__ == "__main__":
    pytest.main([__file__])
