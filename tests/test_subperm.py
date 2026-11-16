"""Hermetic tests for omega.subperm (in-memory fake resolver, no real DNS)."""

import socket

import pytest

import omega.subperm as sp


TARGET = "example-notreal.test"


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    """No sleeps, no real DNS: getaddrinfo and default UDP DNS are faked."""
    monkeypatch.setattr(sp, "_sleep", lambda *_a, **_k: None)
    monkeypatch.setattr(sp.socket, "getaddrinfo",
                        _raise_gai)
    monkeypatch.setattr(sp, "_dns_query", lambda name, qtype: [])


def _raise_gai(*args, **kwargs):
    raise socket.gaierror(socket.EAI_NONAME, "hermetic: no DNS in tests")


def _install(monkeypatch, mapping, dns=None):
    """Install an in-memory fake resolver (full domain name -> ip or None)."""
    monkeypatch.setattr(
        sp, "_resolve",
        lambda name: mapping.get(name, mapping.get("*")))
    if dns is not None:
        monkeypatch.setattr(sp, "_dns_query",
                            lambda name, qtype: dns.get((name, qtype), []))


# ---------------------------------------------------------------------------
# Permutation correctness
# ---------------------------------------------------------------------------

def test_permutation_finds_alive_hosts(monkeypatch):
    mapping = {"www." + TARGET: "93.184.216.34",
               "mail." + TARGET: "198.51.100.7"}
    _install(monkeypatch, mapping)
    res = sp.run_subperm(TARGET)
    assert res["ran"] == ["subperm"]
    subs = {a["subdomain"] for a in res["alive"]}
    assert "www." + TARGET in subs and "mail." + TARGET in subs
    assert all(a["ip"] and a["wildcard_noise"] is False for a in res["alive"])
    assert res["requests_sent"] > 0
    # Only resolvable candidates appear.
    assert "ftp." + TARGET not in subs


def test_extra_words_appended(monkeypatch):
    mapping = {"customword." + TARGET: "93.184.216.34"}
    _install(monkeypatch, mapping)
    res = sp.run_subperm(TARGET, extra=["customword"])
    subs = {a["subdomain"] for a in res["alive"]}
    assert "customword." + TARGET in subs


def test_no_alive_hosts_no_inventory_finding(monkeypatch):
    _install(monkeypatch, {})
    res = sp.run_subperm(TARGET)
    assert res["alive"] == []
    assert not any("Resolvable subdomains" in f["title"] for f in res["findings"])


# ---------------------------------------------------------------------------
# Cap enforcement
# ---------------------------------------------------------------------------

def test_lookup_cap_enforced(monkeypatch):
    _install(monkeypatch, {})
    res = sp.run_subperm(TARGET, extra=["w%d" % i for i in range(500)])
    assert res["requests_sent"] <= sp.LOOKUP_CAP


# ---------------------------------------------------------------------------
# Wildcard FP guard
# ---------------------------------------------------------------------------

def test_wildcard_probe_tags_everything_and_no_host_low_findings(monkeypatch):
    # Fake wildcard: EVERY name resolves to the same dummy IP. DMARC record
    # present so the DMARC-missing LOW doesn't mix into the host-noise check.
    mapping = {"*": "203.0.113.99"}
    _install(monkeypatch, mapping, dns={("_dmarc." + TARGET, "TXT"): ["v=DMARC1; p=reject"]})
    res = sp.run_subperm(TARGET)
    assert res["alive"], "wildcard fake must resolve wordlist candidates"
    assert all(a["wildcard_noise"] is True for a in res["alive"])
    # No LOW finding about individual hosts (private-IP analysis suppressed);
    # the only LOW allowed is the wildcard-DNS detection itself.
    lows = [f for f in res["findings"] if f["severity"] == "low"]
    assert all("Wildcard DNS detected" in f["title"] for f in lows)
    assert all(f["verification"] == "candidate" for f in lows)
    # Subdomain positives stay at info, never scored as candidates.
    inventories = [f for f in res["findings"]
                   if "Resolvable subdomains" in f["title"]]
    assert inventories and inventories[0]["verification"] == "info"
    assert "wildcard" in inventories[0]["verification_note"].lower()


def test_no_wildcard_probe_is_random_high_entropy(monkeypatch):
    seen = {}

    def spy(name):
        if name.startswith("omega-"):
            seen["probe"] = name
        return mapping.get(name)

    mapping = {}
    monkeypatch.setattr(sp, "_resolve", spy)
    res = sp.run_subperm(TARGET)
    assert seen.get("probe", "").startswith("omega-")
    assert TARGET in seen["probe"]
    assert len(seen["probe"].split(".")[0]) > len("omega-") + 20
    assert "Wildcard DNS" not in str([f["title"] for f in res["findings"]])


# ---------------------------------------------------------------------------
# Private-IP finding
# ---------------------------------------------------------------------------

def test_private_ip_finding(monkeypatch):
    mapping = {"db." + TARGET: "10.0.0.42", "www." + TARGET: "93.184.216.34"}
    _install(monkeypatch, mapping, dns={})
    res = sp.run_subperm(TARGET)
    privates = [f for f in res["findings"]
                if "Internal host resolvable" in f["title"]]
    assert len(privates) == 1
    f = privates[0]
    assert f["severity"] == "low" and f["verification"] == "candidate"
    assert "db." + TARGET in f["title"] and "10.0.0.42" in f["evidence"]
    # Public host must NOT be flagged.
    assert "www." + TARGET not in f["title"]


# ---------------------------------------------------------------------------
# Zone apex / MX / TXT parsing
# ---------------------------------------------------------------------------

def test_zone_dump_and_dmarc_missing(monkeypatch):
    dns = {
        (TARGET, "MX"): ["10 mail.example-notreal.test."],
        (TARGET, "NS"): ["ns1.example-notreal.test."],
        (TARGET, "TXT"): ["v=spf1 include:_spf.example-notreal.test -all"],
        ("_dmarc." + TARGET, "TXT"): [],
        ("default._domainkey." + TARGET, "TXT"): ["v=DKIM1; p=AAA"],
    }
    _install(monkeypatch, {}, dns=dns)
    res = sp.run_subperm(TARGET)
    zone = [f for f in res["findings"] if "Zone apex DNS dump" in f["title"]]
    assert zone and zone[0]["verification"] == "info"
    assert "v=spf1" in zone[0]["evidence"]
    assert "MX" in zone[0]["evidence"] and "NS" in zone[0]["evidence"]
    email_sec = [f for f in res["findings"]
                 if "Email security records" in f["title"]]
    assert email_sec
    assert "SPF: True" in email_sec[0]["evidence"]
    assert "DKIM: True" in email_sec[0]["evidence"]
    dmarc_missing = [f for f in res["findings"] if "No DMARC record" in f["title"]]
    assert len(dmarc_missing) == 1
    assert dmarc_missing[0]["severity"] == "low"
    assert dmarc_missing[0]["verification"] == "candidate"
    assert dmarc_missing[0]["manual_check"] == "dig +short TXT _dmarc.%s   # empty = no DMARC" % TARGET


def test_dmarc_present_no_finding(monkeypatch):
    dns = {
        (TARGET, "MX"): ["10 mail.%s." % TARGET],
        (TARGET, "NS"): [],
        (TARGET, "TXT"): [],
        ("_dmarc." + TARGET, "TXT"): ["v=DMARC1; p=reject"],
        ("default._domainkey." + TARGET, "TXT"): [],
    }
    _install(monkeypatch, {}, dns=dns)
    res = sp.run_subperm(TARGET)
    assert not any("No DMARC record" in f["title"] for f in res["findings"])


# ---------------------------------------------------------------------------
# manual_check uses the real target, not placeholders
# ---------------------------------------------------------------------------

def test_manual_checks_reference_real_target(monkeypatch):
    mapping = {"db." + TARGET: "192.168.5.5"}
    dns = {(TARGET, "TXT"): ["v=spf1 -all"], ("_dmarc." + TARGET, "TXT"): []}
    _install(monkeypatch, mapping, dns=dns)
    res = sp.run_subperm(TARGET)
    assert res["findings"]
    for f in res["findings"]:
        assert "dig" in f["manual_check"]
        assert "<sub>" not in f["manual_check"]
        assert "example.com" not in f["manual_check"]
    assert any(TARGET in f["manual_check"] for f in res["findings"])


# ---------------------------------------------------------------------------
# Robustness: resolver exceptions never raise, degrade into skipped
# ---------------------------------------------------------------------------

def test_resolver_oserror_never_raises_and_records_skipped(monkeypatch):
    def always_raise(name):
        raise OSError("resolver down")

    monkeypatch.setattr(sp, "_resolve", always_raise)
    res = sp.run_subperm(TARGET)
    assert res["ran"] == ["subperm"]
    assert res["alive"] == []
    assert res["skipped"], "resolver failure must be recorded in skipped"


def test_resolver_failure_only_on_candidates(monkeypatch):
    # Probe + apex zone lookups work, candidate lookups raise.
    state = {"n": 0}

    def flaky(name):
        if name.startswith("omega-"):
            return None
        raise OSError("timeout")

    monkeypatch.setattr(sp, "_resolve", flaky)
    res = sp.run_subperm(TARGET)
    assert res["alive"] == []
    assert res["findings"]  # zone dump still produced


def test_invalid_target_skips(monkeypatch):
    _install(monkeypatch, {})
    res = sp.run_subperm("")
    assert res["skipped"]
    res2 = sp.run_subperm("not a domain/")
    assert res2["skipped"]


def test_result_shape(monkeypatch):
    _install(monkeypatch, {})
    res = sp.run_subperm(TARGET)
    for key in ("findings", "skipped", "requests_sent", "ran", "alive"):
        assert key in res
    assert res["ran"] == ["subperm"]
    for f in res["findings"]:
        for key in ("title", "severity", "confidence", "verification",
                    "manual_check", "location", "evidence", "source"):
            assert key in f
        assert f["source"] == "omega-subperm"
        assert len(f["evidence"]) <= 300
