"""Hermetic tests for omega.adapters.system_tools + brain/CLI wiring.

No real recon binaries are executed: every tool is a fake shell script
emitting canned nmap grepable / subfinder / nuclei / httpx / openssl /
jq output. No network, tmpdir-local, fully hermetic.
"""
import json
import os
import subprocess
import sys

import pytest

from omega import cli
from omega.adapters import system_tools as st
from omega.adapters.system_tools import (SYS_REGISTRY, jq_filter,
                                         run_system_suite)
from omega.brain import BrainState, default_registry


# ------------------------------------------------------------ fixtures

FAKE_BINARIES = {
    "nmap": "#!/bin/sh\n"
            "echo 'Host: example.com ()\tStatus: Up'\n"
            "echo 'Host: example.com ()\tPorts: 80/open/tcp//http///, "
            "443/open/tcp//https//nginx///'\n",
    "ffuf": "#!/bin/sh\n"
            "w=''; prev=''\n"
            "for a in \"$@\"; do [ \"$prev\" = \"-w\" ] && w=\"$a\"; "
            "prev=\"$a\"; done\n"
            "[ -f \"$w\" ] || { echo \"missing wordlist\" >&2; exit 1; }\n"
            "printf '%s' "
            "'{\"results\":[{\"url\":\"http://example.com/admin\","
            "\"status\":200,\"input\":{\"FUZZ\":\"admin\"}},"
            "{\"url\":\"http://example.com/login\","
            "\"status\":403,\"input\":{\"FUZZ\":\"login\"}}]}'\n",
    "nuclei": "#!/bin/sh\n"
              "echo '{\"template-id\":\"cve-2021-44228\",\"info\":"
              "{\"name\":\"log4j RCE (template match)\","
              "\"severity\":\"high\"},\"matched-at\":"
              "\"http://example.com/\"}'\n"
              "echo '{\"template-id\":\"exposed-git\",\"info\":"
              "{\"name\":\"exposed .git directory\",\"severity\":"
              "\"medium\"},\"matched-at\":\"http://example.com/.git/\"}'\n",
    "subfinder": "#!/bin/sh\nprintf 'www.example.com\\n*.example.com\\n"
                 "api.example.com\\n\\nother.invalid\\n'\n",
    "amass": "#!/bin/sh\nprintf 'cdn.example.com\\nmail.example.com\\n'\n",
    "httpx": "#!/bin/sh\n"
             "echo '{\"url\":\"http://example.com\",\"status_code\":200,"
             "\"title\":\"Example\",\"tech\":[\"nginx\"]}'\n"
             "echo '{\"url\":\"https://example.com\",\"status_code\":301,"
             "\"title\":\"\",\"tech\":[]}'\n",
    "openssl": "#!/bin/sh\n"
              "case \"$1\" in\n"
              "  s_client)\n"
              "    printf '%s\\n' 'CONNECTED' "
              "'-----BEGIN CERTIFICATE-----' 'AAAABBBB' "
              "'-----END CERTIFICATE-----' "
              "'-----BEGIN CERTIFICATE-----' 'CCCCDDDD' "
              "'-----END CERTIFICATE-----'\n"
              "    ;;\n"
              "  x509)\n"
              "    printf '%s\\n' 'subject=CN = cert.example.com' "
              "'issuer=CN = Fake CA'\n"
              "    ;;\n"
              "esac\n",
    "jq": "#!/bin/sh\ncat\n",   # emulates `jq .` passthrough
}

# canned-output fakes for the extended registry (parsers, stage mapping)
EXT_FAKE_BINARIES = {
    "whatweb": "#!/bin/sh\n"
               "printf '%s' "
               "'[{\"target\":\"http://example.com/\",\"plugins\":"
               "{\"HTTPServer\":{\"string\":[\"nginx\"],"
               "\"certainty\":[100]},\"Title\":{\"string\":"
               "[\"Example Domain\"],\"certainty\":[100]}}}]'\\n",
    "arjun": "#!/bin/sh\n"
             "echo '[+] Target URL: http://example.com/'\n"
             "echo '[+] Parameters found: '\n"
             "echo '    - id'\n"
             "echo '    - page'\n",
    "nikto": "#!/bin/sh\n"
             "echo '- Nikto v2.5.0'\n"
             "echo '+ Target IP:          93.184.216.34'\n"
             "echo '+ /admin/: Admin login page/section found.'\n"
             "echo '+ /robots.txt: contains 2 entries.'\n",
    "dalfox": "#!/bin/sh\n"
              "echo '[V] Triggered XSS Payload (found DOM Object): "
              "http://example.com/?q=<svg onload=alert(1)>'\n",
    "katana": "#!/bin/sh\n"
              "echo '{\"method\":\"GET\",\"url\":\"http://example.com/about\","
              "\"status\":200}'\n"
              "echo '{\"method\":\"GET\",\"url\":\"http://example.com/blog\","
              "\"status\":200}'\n",
    "gau": "#!/bin/sh\nprintf 'http://example.com/old-page\\n"
           "http://example.com/assets/app.js\\n'\n",
    "dnsx": "#!/bin/sh\n"
            "echo 'example.com [A] [93.184.216.34]'\n"
            "echo 'example.com [MX] [10 mail.example.com.]'\n",
    "massdns": "#!/bin/sh\necho 'example.com. A 93.184.216.34'\n",
    "mapcidr": "#!/bin/sh\nprintf '10.0.0.1\\n10.0.0.2\\n'\n",
    "naabu": "#!/bin/sh\n"
             "echo '{\"host\":\"example.com\",\"ip\":\"93.184.216.34\","
             "\"port\":443}'\n",
    "dirsearch": "#!/bin/sh\n"
                 "echo '200    1KB   http://example.com/admin/'\n",
    "feroxbuster": "#!/bin/sh\n"
                   "echo '{\"url\":\"http://example.com/uploads\","
                   "\"status\":200,\"method\":\"GET\"}'\n",
    "crlfuzz": "#!/bin/sh\n"
              "echo 'http://example.com/?q=1%0d%0aX-Injected: yes'\n",
    "graphw00f": "#!/bin/sh\n"
                 "echo '[+] Detected: Graphql Engine: Hasura'\n",
    "kxss": "#!/bin/sh\n"
            "echo 'http://example.com/?q=<INJ>'\n",
    "jwt_tool": "#!/bin/sh\n"
                "printf '%s\\n' '=====================' "
                "'Token header values:' '[+] alg = \"HS256\"' "
                "'[+] typ = \"JWT\"' '' 'Token payload values:' "
                "'[+] sub = \"1234567890\"' '[+] name = \"John Doe\"'\n",
    "trufflehog": "#!/bin/sh\n"
                  "echo '{\"SourceName\":\"git\",\"DetectorName\":\"AWS\","
                  "\"Verified\":false,\"Raw\":\"AKIAIOSFODNN7EXAMPLE\","
                  "\"SourceMetadata\":{\"Data\":{\"Git\":{\"file\":"
                  "\"config.py\"}}}}'\n",
    "gitleaks": "#!/bin/sh\n"
                "printf '%s' "
                "'[{\"RuleID\":\"aws-access-token\",\"File\":\"config.py\","
                "\"StartLine\":3,\"Secret\":\"AKIAIOSFODNN7EXAMPLE\","
                "\"Match\":\"key = AKIA...\"}]'\n",
    "jsluice": "#!/bin/sh\n"
               "echo '{\"type\":\"url\",\"url\":\"https://api.example.com/"
               "v2/users\",\"source\":\"app.js\"}'\n",
}



# arsenal-2 canned-output fakes (one per new registry binary; the fake
# "curl" is a composite whose output every curl-based parser reads)
EXT_FAKE_BINARIES.update({
    "curl": "#!/bin/sh\n"
            "printf '%s\\n' \\\n"
            " '{\"data\":{\"__schema\":{\"types\":[{\"name\":\"Query\"},"
            "{\"name\":\"User\"}]}}}' \\\n"
            " '<form><input type=\"password\" name=\"pw\"></form>' \\\n"
            " '/api/v1/users' \\\n"
            " 'Server: nginx/1.19' \\\n"
            " 'X-Powered-By: PHP/7.4' \\\n"
            " 'URL=http://example.com/.git/HEAD CODE=200' \\\n"
            " 'ref: refs/heads/main' \\\n"
            " 'URL=http://example.com/.svn/entries CODE=200' \\\n"
            " 'URL=http://example.com/.DS_Store CODE=200' \\\n"
            " 'URL=http://example.com/backup.zip CODE=200' \\\n"
            " 'URL=http://example.com/.well-known/security.txt CODE=200'\n",
    "testssl.sh": "#!/bin/sh\n"
                  "echo 'LOW  TLSv1.0 is deprecated'\n"
                  "echo 'INFO  HSTS header present'\n",
    "sslscan": "#!/bin/sh\n"
               "echo '  Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384'\n"
               "echo '  SSLv3     disabled'\n",
    "sslyze": "#!/bin/sh\necho '  * TLSv1.0: INSECURE - not supported'\n",
    "gobuster": "#!/bin/sh\n"
                "echo '/admin (Status: 200)'\n"
                "echo 'Found: dev.example.com (Status: 200)'\n",
    "wfuzz": "#!/bin/sh\n"
             "echo '000012:  C=200   45 L    111 W   1200 Ch    "
             "\"admin\"'\n",
    "dirb": "#!/bin/sh\n"
            "echo '+ http://example.com/admin/ (CODE:200|SIZE:1234)'\n",
    "halberd": "#!/bin/sh\necho 'Detected technologies: PHP, nginx'\n",
    "wapiti": "#!/bin/sh\necho 'Crawled http://example.com/ (level 1)'\n"
              "echo '[info] page title found'\n",
    "arachni": "#!/bin/sh\n"
               "echo 'xss_frame* check completed with 0 issues'\n",
    "skipfish": "#!/bin/sh\necho 'skipfish scan completed: 3 paths'\n",
    "dnsrecon": "#!/bin/sh\n"
                "echo '[*] A example.com 93.184.216.34'\n"
                "echo '[*] MX example.com 10 mail.example.com'\n",
    "dnsenum": "#!/bin/sh\necho \"Host's addresses\"\n"
               "echo 'example.com 93.184.216.34'\n",
    "sublist3r": "#!/bin/sh\necho '[+] www.example.com'\n"
                 "echo '[+] api.example.com'\n",
    "knockpy": "#!/bin/sh\necho 'www.example.com -> 93.184.216.34'\n",
    "theHarvester": "#!/bin/sh\necho 'hosts:'\n"
                    "echo 'www.example.com'\necho 'mail.example.com'\n",
    "sherlock": "#!/bin/sh\necho '[+] user: https://twitter.com/user'\n",
    "maigret": "#!/bin/sh\necho '[+] Found: https://github.com/user'\n",
    "photon": "#!/bin/sh\necho 'http://example.com/page1'\n",
    "spiderfoot": "#!/bin/sh\n"
                  "echo 'Found host api.example.com via passive source'\n",
    "hakrawler": "#!/bin/sh\necho 'http://example.com/contact'\n",
    "linkfinder": "#!/bin/sh\necho 'Found: /api/v1/login'\n"
                  "echo 'https://example.com/static/app.js'\n",
    "jsanalyze": "#!/bin/sh\n"
                 "echo '{\"url\":\"https://api.example.com/v3/data\"}'\n",
    "wpscan": "#!/bin/sh\n"
              "echo '[+] XML-RPC enabled'\n"
              "echo '[+] Warning: outdated plugin detected'\n",
    "droopescan": "#!/bin/sh\necho 'CMS detected: drupal'\n"
                  "echo 'Version: 9.2'\n",
    "joomscan": "#!/bin/sh\necho 'Joomla version found: 3.9'\n",
    "drupwn": "#!/bin/sh\necho 'Drupal modules found: 12'\n",
    "cmseek": "#!/bin/sh\n"
              "echo 'CMS: WordPress detected on http://example.com/'\n",
    "paramspider": "#!/bin/sh\necho 'http://example.com/index.php?q=1'\n",
    "kiterunner": "#!/bin/sh\necho '[300] [GET] /api/v1/users'\n",
    "s3scanner": "#!/bin/sh\necho 'aws,my-bucket,exists,public,10'\n",
    "cloud_enum": "#!/bin/sh\n"
                  "echo '[+] open: https://my-bucket.s3.amazonaws.com/'\n",
    "wafw00f": "#!/bin/sh\n"
               "echo 'example.com is behind Cloudflare (Cloudflare Inc.)'\n",
    "waybackurls": "#!/bin/sh\necho 'http://example.com/old'\n",
    "whois": "#!/bin/sh\necho 'Domain Name: EXAMPLE.COM'\n"
             "echo 'Registrar: Example, Inc.'\n",
    "dig": "#!/bin/sh\necho 'example.com 93.184.216.34'\n",
})


@pytest.fixture
def fake_bins(tmp_path):
    """Create fake recon binaries + which_fn pointing at them."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    names = []
    for name, body in FAKE_BINARIES.items():
        p = bin_dir / name
        p.write_text(body)
        p.chmod(0o755)
        names.append(name)
    known = set(names)

    def which_fn(binary):
        return str(bin_dir / binary) if binary in known else None

    return which_fn, str(bin_dir)


@pytest.fixture
def fake_bins_ext(tmp_path):
    """fake_bins plus the extended toolset binaries (merged which_fn)."""
    bin_dir = tmp_path / "bin_ext"
    bin_dir.mkdir()
    known = set(FAKE_BINARIES) | set(EXT_FAKE_BINARIES)
    for name, body in list(FAKE_BINARIES.items()) + \
            list(EXT_FAKE_BINARIES.items()):
        p = bin_dir / name
        p.write_text(body)
        p.chmod(0o755)
    return (lambda b: str(bin_dir / b) if b in known else None), \
        str(bin_dir)


@pytest.fixture
def ext_env(tmp_path, monkeypatch):
    """Operator-provided env inputs the extended arg builders require."""
    res = tmp_path / "resolvers.txt"
    res.write_text("1.1.1.1\n8.8.8.8\n")
    js = tmp_path / "app.js"
    js.write_text("var api = 'https://api.example.com/v2';\n")
    src = tmp_path / "repo"
    src.mkdir()
    monkeypatch.setenv("OMEGA_JWT",
                       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                       "eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4")
    monkeypatch.setenv("OMEGA_CIDR", "10.0.0.0/30")
    monkeypatch.setenv("OMEGA_MASSDNS_RESOLVERS", str(res))
    monkeypatch.setenv("OMEGA_JS_FILE", str(js))
    monkeypatch.setenv("OMEGA_GITLEAKS_SOURCE", str(src))
    kr = tmp_path / "kr.txt"
    kr.write_text("api/v1\\ngraphql\\n")
    buckets = tmp_path / "buckets.txt"
    buckets.write_text("my-bucket\\n")
    skip_out = tmp_path / "skipfish-out"
    skip_out.mkdir()
    monkeypatch.setenv("OMEGA_USERNAME", "user")
    monkeypatch.setenv("OMEGA_GITHUB_TOKEN", "ghp_fake")
    monkeypatch.setenv("OMEGA_INTELX_KEY", "fakekey")
    monkeypatch.setenv("OMEGA_JS_URL", "https://example.com/app.js")
    monkeypatch.setenv("OMEGA_TLS_PORT", "443")
    monkeypatch.setenv("OMEGA_KR_WORDLIST", str(kr))
    monkeypatch.setenv("OMEGA_BUCKET_FILE", str(buckets))
    monkeypatch.setenv("OMEGA_SKIPFISH_OUT", str(skip_out))
    monkeypatch.setenv("OMEGA_OSSF_REPO", "github.com/example/example")
    return {"resolvers": str(res), "js": str(js), "src": str(src)}


@pytest.fixture
def gate(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")


@pytest.fixture
def wordlist(tmp_path, monkeypatch):
    p = tmp_path / "wl.txt"
    p.write_text("admin\nlogin\nbackup\n")
    monkeypatch.setenv("OMEGA_FFUF_WORDLIST", str(p))
    return str(p)


@pytest.fixture
def x509_stub(monkeypatch, fake_bins):
    """Point the ssl_chain parser at the fake openssl for x509 calls."""
    _, bin_dir = fake_bins
    monkeypatch.setattr(st, "_X509_BIN", os.path.join(bin_dir, "openssl"))


# ------------------------------------------------------------- registry

# NOTE: "-S" is NOT flagged: dirb_slow uses the documented -S (slow)
# mode, which is a pacing option, not a decoy/spoof flag.
_DANGEROUS_FLAGS = ("-A", "--script", "--script-args", "-D", "--decoy",
                    "--datadir", "--excludefile", "--spoof")
_DANGEROUS_WORDS = ("exploit", "brute", "attack", "inject", "shell",
                    "payload", "intrusive", "hydra", "sqlmap", "-wF",
                    "-T5", "--fuzz")


def test_registry_shape_and_readonly_args(wordlist, ext_env):
    assert len(SYS_REGISTRY) >= 73
    for name, spec in SYS_REGISTRY.items():
        assert spec["name"] == name
        assert spec["stage"] in ("recon", "enum", "verify", "report")
        assert spec["safety"] in ("passive", "active-recon")
        assert callable(spec["parser"])
        assert 120 <= spec["timeout_s"] <= 600
        assert spec["arg_builder"] is None or callable(spec["arg_builder"])
        # reserved tools never produce runnable args (jq_probe,
        # interactsh_client)
        if spec.get("reserved"):
            assert spec["arg_builder"]("http://example.com") is None
            continue
        # env-gated tools are allowed to be None only without env inputs;
        # ext_env supplies every operator input, so they must build args
        args = spec["arg_builder"]("http://example.com")
        if spec.get("env_gated"):
            assert args is not None, name  # ext_env present
        else:
            assert args is not None, name
        args = spec["arg_builder"]("http://example.com")
        assert isinstance(args, list) and args, name
        lowered = [str(a).lower() for a in args]
        for flag in _DANGEROUS_FLAGS:
            assert flag not in args, (name, flag)
        for w in _DANGEROUS_WORDS:
            assert not any(w in a for a in lowered), (name, w)


def test_registry_jq_probe_is_reserved_and_never_auto_runs():
    spec = SYS_REGISTRY["jq_probe"]
    assert spec.get("reserved") is True
    assert spec["arg_builder"]("example.com") is None


def test_registry_safety_contract(wordlist):
    passive = {n for n, s in SYS_REGISTRY.items()
               if s["safety"] == "passive"}
    assert {"subfinder_passive", "amass_passive", "ssl_chain",
            "jq_probe"} <= passive
    # ffuf must carry an explicit rate limit
    assert "-rate-limit" in SYS_REGISTRY["ffuf_light"]["arg_builder"](
        "http://example.com")
    # nuclei must cap rate and severity, never passive-less aggressive
    n_args = SYS_REGISTRY["nuclei_scan"]["arg_builder"]("http://example.com")
    assert "-rl" in n_args and "low,medium,high" in n_args


# --------------------------------------------------------------- parsers

def test_parse_nmap_grepable():
    out = ("Host: example.com ()\tStatus: Up\n"
           "Host: example.com ()\tPorts: 80/open/tcp//http///, "
           "443/open/tcp//https//nginx///\n")
    findings, surface = st._parse_nmap(out, "")
    assert surface["hosts"] == ["example.com"]
    assert surface["ports"] == ["443", "80"]
    assert len(findings) == 2
    f = findings[0]
    assert f["source"] == "omega-sys/nmap_sv"
    assert f["confidence"] == "candidate"
    assert f["verification"] == "signature"
    assert f["manual_check"] is True
    assert "nmap -sV --top-ports 100 example.com" in f["verification_note"]


def test_parse_ffuf_json_and_text(monkeypatch):
    js = json.dumps({"results": [
        {"url": "http://example.com/admin", "status": 200}]})
    findings, surface = st._parse_ffuf(js, "")
    assert surface["urls"] == ["http://example.com/admin"]
    assert findings[0]["source"] == "omega-sys/ffuf_light"
    assert "curl -sI http://example.com/admin" in \
        findings[0]["verification_note"]
    findings2, surface2 = st._parse_ffuf(
        "http://example.com/old [Status=403, Size=12]", "")
    assert surface2["urls"] == ["http://example.com/old"]
    assert findings2[0]["title"].endswith("(HTTP 403)")


def test_parse_nuclei_jsonl():
    out = ('{"template-id":"cve-x","info":{"name":"bad thing","severity":'
           '"high"},"matched-at":"http://example.com/"}\nnot-json\n')
    findings, _ = st._parse_nuclei(out, "")
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "HIGH"
    assert f["location"] == "http://example.com/"
    assert f["source"] == "omega-sys/nuclei_scan"


def test_parse_subfinder_and_amass():
    f1, s1 = st._parse_subfinder(
        "www.example.com\n*.example.com\napi.example.com\n\n", "")
    assert s1["hosts"] == ["api.example.com", "example.com",
                           "www.example.com"]
    assert all(f["source"] == "omega-sys/subfinder_passive" for f in f1)
    f2, s2 = st._parse_amass("cdn.example.com\nmail.example.com\n", "")
    assert s2["hosts"] == ["cdn.example.com", "mail.example.com"]
    assert all(f["source"] == "omega-sys/amass_passive" for f in f2)


def test_parse_httpx_json():
    out = ('{"url":"http://example.com","status_code":200,"title":"Ex",'
           '"tech":["nginx"]}\n'
           '{"url":"https://example.com","status_code":301}\n')
    findings, surface = st._parse_httpx(out, "")
    assert surface["urls"] == ["http://example.com", "https://example.com"]
    assert surface["techs"] == ["nginx"]
    assert len(findings) == 2
    assert findings[0]["source"] == "omega-sys/httpx_json"


def test_parse_ssl_chain(x509_stub):
    out = ("CONNECTED\n"
           "-----BEGIN CERTIFICATE-----\nAAAABBBB\n"
           "-----END CERTIFICATE-----\n"
           "-----BEGIN CERTIFICATE-----\nCCCCDDDD\n"
           "-----END CERTIFICATE-----\n")
    findings, surface = st._parse_ssl_chain(out, "")
    assert len(surface["certs"]) == 2
    assert all("CN = cert.example.com" in c["subject"]
               for c in surface["certs"])
    assert findings and all(f["source"] == "omega-sys/ssl_chain"
                            for f in findings)


def test_parse_ssl_chain_no_certs_is_contained(x509_stub):
    findings, surface = st._parse_ssl_chain("no certs here", "some error")
    assert surface["certs"] == []
    assert findings and "no TLS certificate" in findings[0]["title"]


def test_evidence_truncated_to_300(monkeypatch):
    big = json.dumps({"results": [{"url": "http://example.com/" + "x" * 500,
                                   "status": 200}]})
    findings, _ = st._parse_ffuf(big, "")
    assert len(findings[0]["evidence"]) <= 301


# --------------------------------------------------------- jq helper

def test_jq_filter_with_fake_binary(fake_bins):
    which_fn, _ = fake_bins
    out = jq_filter('{"a": 1, "b": {"c": 2}}', which_fn=which_fn)
    assert out == {"a": 1, "b": {"c": 2}}
    err = jq_filter("not json", which_fn=which_fn)
    assert err.startswith("error:")


def test_jq_filter_missing_binary():
    out = jq_filter('{"a":1}', which_fn=lambda b: None)
    assert out == "error: jq binary not found"


# --------------------------------------------------------- suite runner

def test_gate_refusal_without_ptk_polyglot(monkeypatch, fake_bins):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    out = run_system_suite("http://example.com", which_fn=fake_bins[0])
    assert out["ran"] == []
    assert out["findings"] == []
    assert out["skipped"]
    assert all("PTK_POLYGLOT" in s["reason"] for s in out["skipped"])


def test_suite_runs_fake_binaries(gate, fake_bins_ext, wordlist, ext_env,
                                  x509_stub):
    which_fn, _ = fake_bins_ext
    out = run_system_suite("http://example.com", which_fn=which_fn)
    # original 7 still run first, in registry order
    assert out["ran"][:7] == ["nmap_sv", "ffuf_light", "nuclei_scan",
                              "subfinder_passive", "amass_passive",
                              "httpx_json", "ssl_chain"]
    # every extended (non-reserved) tool picked up via stage mapping
    assert set(out["ran"]) >= {
        "gau_urls", "dnsx_resolve", "massdns_resolve", "mapcidr_expand",
        "naabu_top100", "whatweb_fp", "arjun_get", "katana_crawl",
        "dirsearch_paths", "feroxbuster_light", "crlfuzz_scan",
        "graphw00f_fp", "dalfox_scan", "kxss_reflect", "nikto_info",
        "jwt_decode", "trufflehog_fs", "gitleaks_scan", "jsluice_urls"}
    # reserved tools are excluded by the stage filter: never auto-run
    assert "jq_probe" not in out["ran"]
    assert "interactsh_client" not in out["ran"]
    assert out["skipped"] == []
    sources = {f["source"] for f in out["findings"]}
    assert any(s.startswith("omega-sys/") for s in sources)
    assert "omega-sys/katana_crawl" in sources
    assert "omega-sys/jwt_decode" in sources
    assert "omega-sys/trufflehog_fs" in sources
    for f in out["findings"]:
        assert f["confidence"] == "candidate"
        assert f["verification"] == "signature"
        assert f["manual_check"] is True
        assert isinstance(f["verification_note"], str)
        assert f["verification_note"]
        assert len(f["evidence"]) <= 301
    # surface merged across tools
    assert "80" in out["surface"]["ports"]
    assert "api.example.com" in out["surface"]["hosts"]
    assert "http://example.com/admin" in out["surface"]["urls"]
    assert out["surface"]["techs"] == ["nginx"]
    assert "10.0.0.1" in out["surface"]["ips"]
    # ssl_chain parser yields one cert per PEM; the suite's surface
    # dedupe collapses identical x509 details (fake emits same subject)
    assert out["surface"]["certs"]


def test_missing_binary_is_skipped(gate, fake_bins, wordlist):
    which_fn, _ = fake_bins

    def partial(binary):
        return None if binary in ("subfinder", "amass") else which_fn(binary)

    out = run_system_suite("http://example.com",
                           stages=["recon"], which_fn=partial)
    assert "subfinder_passive" not in out["ran"]
    assert "amass_passive" not in out["ran"]
    assert "nmap_sv" in out["ran"]
    reasons = {s["tool"]: s["reason"] for s in out["skipped"]}
    assert reasons.get("subfinder_passive", "").startswith("binary not found")
    assert reasons.get("amass_passive", "").startswith("binary not found")


def test_ffuf_skipped_without_wordlist(gate, fake_bins, monkeypatch):
    monkeypatch.delenv("OMEGA_FFUF_WORDLIST", raising=False)
    which_fn, _ = fake_bins
    out = run_system_suite("http://example.com", stages=["enum"],
                           which_fn=which_fn)
    assert "ffuf_light" not in out["ran"]
    reasons = {s["tool"]: s["reason"] for s in out["skipped"]}
    assert reasons.get("ffuf_light") == ("not applicable for this "
                                         "target/environment")


def test_timeout_containment(gate, fake_bins, tmp_path, monkeypatch):
    which_fn, _ = fake_bins
    hang = tmp_path / "hang"
    hang.write_text("#!/bin/sh\nsleep 30\n")
    hang.chmod(0o755)
    # shrink the timeout so the test stays fast but still proves
    # subprocess.TimeoutExpired is contained, not raised
    reg_entry = dict(SYS_REGISTRY["nmap_sv"])
    reg_entry["timeout_s"] = 2
    monkeypatch.setitem(SYS_REGISTRY, "nmap_sv", reg_entry)
    out = run_system_suite("http://example.com", stages=["recon"],
                           allowlist=["nmap_sv"], which_fn=lambda b:
                           str(hang) if b == "nmap" else which_fn(b))
    assert out["ran"] == []
    reasons = {s["tool"]: s["reason"] for s in out["skipped"]}
    assert "timeout contained" in reasons.get("nmap_sv", "")


def test_budget_capping(gate, fake_bins, wordlist):
    which_fn, _ = fake_bins
    out = run_system_suite("http://example.com", budget=2,
                           which_fn=which_fn)
    assert len(out["ran"]) == 2
    cand = [s for s in SYS_REGISTRY.values()
            if s["stage"] in ("recon", "enum", "verify")]
    assert len(out["skipped"]) == len(cand) - 2
    assert all(s["reason"] == "budget exhausted"
               for s in out["skipped"])


def test_allowlist_restricts(gate, fake_bins, wordlist, x509_stub):
    which_fn, _ = fake_bins
    out = run_system_suite("http://example.com",
                           allowlist=["nmap_sv", "subfinder_passive"],
                           which_fn=which_fn)
    assert out["ran"] == ["nmap_sv", "subfinder_passive"]


def test_stage_filter(gate, fake_bins, wordlist):
    which_fn, _ = fake_bins
    out = run_system_suite("http://example.com", stages=["recon"],
                           which_fn=which_fn)
    assert set(out["ran"]) == {"nmap_sv", "subfinder_passive",
                               "amass_passive", "ssl_chain",
                               "openssl_sclient"}


def test_suite_never_raises_on_parser_blowup(gate, fake_bins,
                                             monkeypatch, wordlist):
    which_fn, _ = fake_bins

    def boom(stdout, stderr):
        raise RuntimeError("parser explosion")

    spec = dict(SYS_REGISTRY["nmap_sv"], parser=boom)
    monkeypatch.setitem(SYS_REGISTRY, "nmap_sv", spec)
    out = run_system_suite("http://example.com", allowlist=["nmap_sv"],
                           which_fn=which_fn)
    assert out["ran"] == []
    assert "explosion" in out["skipped"][0]["reason"]


# ------------------------------------------- extended registry: audit

def test_registry_has_at_least_73_entries_with_stage_mapping():
    assert len(SYS_REGISTRY) >= 73
    stages = {n: s["stage"] for n, s in SYS_REGISTRY.items()}
    assert {"subfinder_passive", "amass_passive", "gau_urls",
            "dnsx_resolve", "massdns_resolve", "mapcidr_expand",
            "naabu_top100", "ssl_chain"} <= {n for n, st in stages.items()
                                             if st == "recon"}
    assert {"ffuf_light", "httpx_json", "whatweb_fp", "arjun_get",
            "katana_crawl", "dirsearch_paths", "feroxbuster_light",
            "crlfuzz_scan", "graphw00f_fp"} <= {n for n, st in
                                                stages.items()
                                                if st == "enum"}
    assert {"nuclei_scan", "dalfox_scan", "kxss_reflect", "nikto_info",
            "jwt_decode", "trufflehog_fs", "gitleaks_scan",
            "jsluice_urls"} <= {n for n, st in stages.items()
                                if st == "verify"}


def test_reserved_tools_never_auto_run():
    for name in ("jq_probe", "interactsh_client"):
        spec = SYS_REGISTRY[name]
        assert spec.get("reserved") is True
        assert spec["stage"] not in st.DEFAULT_STAGES
        assert spec["arg_builder"]("http://example.com") is None


def test_registry_no_mutation_flags_anywhere(wordlist, ext_env):
    """Safety audit across ALL registry entries (incl. the 20 new)."""
    for name, spec in SYS_REGISTRY.items():
        if spec.get("reserved"):
            continue
        args = [str(a) for a in spec["arg_builder"]("http://example.com")]
        joined = " ".join(args)
        # no request-method mutation (POST/PUT/DELETE/PATCH data bodies);
        # an explicit "-X GET" (ffuf_light) is fine
        assert "POST" not in joined, name
        assert "PUT" not in joined, name
        assert "DELETE" not in joined, name
        assert "PATCH" not in joined, name
        # token-level for "--data": GET-based --data-urlencode is allowed
        for bad in ("--method", "tamper", "commix", "hydra", "sqlmap"):
            assert bad not in joined, (name, bad)
        assert "--data" not in args, name
        if "-X" in args:
            assert args[args.index("-X") + 1].upper() == "GET", name
        # no wordlist/write-to-file output flags that mutate state
        if spec["binary"] in ("gitleaks", "trufflehog"):
            assert "--no-banner" in args or "--json" in args, name
        if name == "nikto_info":
            tuning = args[args.index("-Tuning") + 1]
            assert set(tuning) <= set("123"), name  # informational only
        if name == "jwt_decode":
            # decode-only: token argument only, no tamper/crack modes
            assert len(args) == 1, name
            assert not any(a in ("-t", "-C", "-d", "-X", "-c")
                           for a in args), name
        if name == "dalfox_scan":
            assert "--no-color" in args and "--silence" in args
        if name == "crlfuzz_scan":
            assert "-X" not in args  # GET-only (default)
            assert "-o" in args and args[args.index("-o") + 1] == "-"
        if name == "whatweb_fp":
            assert "--aggression" in args and args[
                args.index("--aggression") + 1] in ("0", "1")


def test_rate_and_thread_caps_present(wordlist, ext_env):
    rates = {"feroxbuster_light": ("--rate-limit", "20"),
             "naabu_top100": ("-rate", "500"),
             "katana_crawl": ("-rl", "20"),
             "arjun_get": ("--rate-limit", "20"),
             "dnsx_resolve": ("-rl", "20")}
    for name, (flag, val) in rates.items():
        args = SYS_REGISTRY[name]["arg_builder"]("http://example.com")
        assert flag in args and args[args.index(flag) + 1] == val, name
    threads = {"gobuster_dir": ("-t", "5"),
               "gobuster_vhost": ("-t", "5"),
               "wfuzz_get": ("-t", "5"),
               "hakrawler_crawl": ("-t", "5"),
               "photon_crawl": ("--threads", "2"),
               "katana_crawl": ("-c", "10"), "arjun_get": ("-t", "5"),
               "dirsearch_paths": ("-t", "10"),
               "feroxbuster_light": ("-t", "5"),
               "crlfuzz_scan": ("-c", "10"), "gau_urls": ("--threads", "4"),
               "massdns_resolve": ("-s", "10"),
               "trufflehog_fs": ("--concurrency", "2")}
    for name, (flag, val) in threads.items():
        args = SYS_REGISTRY[name]["arg_builder"]("http://example.com")
        assert flag in args and args[args.index(flag) + 1] == val, name


def test_env_gated_tools_skip_contained_without_inputs(monkeypatch):
    for env in ("OMEGA_JWT", "OMEGA_CIDR", "OMEGA_MASSDNS_RESOLVERS",
                "OMEGA_JS_FILE", "OMEGA_JS_PATHS",
                "OMEGA_GITLEAKS_SOURCE"):
        monkeypatch.delenv(env, raising=False)
    for name in ("jwt_decode", "mapcidr_expand", "massdns_resolve",
                 "jsluice_urls", "gitleaks_scan", "sherlock_user",
                 "maigret_user", "github_dorks", "intelx_probe",
                 "relative_url_extract", "jsanalyze_urls",
                 "scorecard_ossf", "kiterunner_scan", "s3scanner_scan",
                 "skipfish_scan", "openssl_tls_sweep"):
        args = SYS_REGISTRY[name]["arg_builder"]("http://example.com")
        assert args is None, name


def test_stage_filter_ext_recon_enum_verify(gate, fake_bins_ext, wordlist,
                                            ext_env, x509_stub):
    which_fn, _ = fake_bins_ext

    def expected(stage):
        return {n for n, s in SYS_REGISTRY.items()
                if s["stage"] == stage and not s.get("reserved") and
                s["arg_builder"]("http://example.com") is not None}

    out = run_system_suite("http://example.com", stages=["recon"],
                           which_fn=which_fn)
    assert out["ran"] and set(out["ran"]) == expected("recon")
    assert {"nmap_sv", "subfinder_passive", "amass_passive", "ssl_chain",
            "gau_urls", "dnsx_resolve", "massdns_resolve",
            "mapcidr_expand", "naabu_top100", "testssl_sev",
            "sslscan_quiet", "sslyze_regular", "openssl_sclient",
            "crtsh_passive", "whois_lookup", "dig_query",
            "waybackurls_passive"} <= set(out["ran"])
    out2 = run_system_suite("http://example.com", stages=["enum"],
                            which_fn=which_fn)
    assert set(out2["ran"]) == expected("enum")
    assert {"ffuf_light", "httpx_json", "whatweb_fp", "arjun_get",
            "katana_crawl", "dirsearch_paths", "feroxbuster_light",
            "crlfuzz_scan", "graphw00f_fp", "gobuster_dir", "gobuster_vhost",
            "wfuzz_get", "dirb_slow", "hakrawler_crawl", "photon_crawl",
            "graphql_introspect"} <= set(out2["ran"])
    out3 = run_system_suite("http://example.com", stages=["verify"],
                            which_fn=which_fn)
    assert set(out3["ran"]) == expected("verify")
    assert {"nuclei_scan", "dalfox_scan", "kxss_reflect", "nikto_info",
            "jwt_decode", "trufflehog_fs", "gitleaks_scan",
            "jsluice_urls", "wpscan_enum", "cmseek_fp",
            "git_open_probe"} <= set(out3["ran"])
    out4 = run_system_suite("http://example.com", stages=["report"],
                            which_fn=which_fn)
    assert out4["ran"] == []  # report stage only has reserved helpers


# ------------------------------------------ extended parsers

def test_parse_whatweb_json_and_text():
    js = json.dumps([{"target": "http://example.com/",
                      "plugins": {"HTTPServer": {"string": ["nginx"],
                                                 "certainty": [100]},
                                  "Title": {"string": ["Example"],
                                            "certainty": [100]}}}])
    findings, surface = st._parse_whatweb(js, "")
    assert surface["urls"] == ["http://example.com/"]
    assert surface["techs"] == ["HTTPServer", "Title"]
    assert all(f["source"] == "omega-sys/whatweb_fp" for f in findings)
    findings2, surface2 = st._parse_whatweb(
        "http://example.com/ [200 OK] HTTPServer[nginx], IP[1.2.3.4]", "")
    assert surface2["urls"] == ["http://example.com/"]
    assert "HTTPServer" in surface2["techs"]


def test_parse_katana_jsonl():
    out = ('{"method":"GET","url":"http://example.com/about","status":200}\n'
           'not-json\n')
    findings, surface = st._parse_katana(out, "")
    assert surface["urls"] == ["http://example.com/about"]
    f = findings[0]
    assert f["source"] == "omega-sys/katana_crawl"
    assert f["confidence"] == "candidate"
    assert "curl -sI" in f["verification_note"]


def test_parse_dnsx_resp_only():
    out = ("example.com [A] [93.184.216.34]\n"
           "example.com [MX] [10 mail.example.com.]\n")
    findings, surface = st._parse_dnsx(out, "")
    assert surface["hosts"] == ["example.com"]
    assert "A 93.184.216.34 (example.com)" in surface["dns"]
    assert findings[0]["source"] == "omega-sys/dnsx_resolve"


def test_parse_jwt_tool_decode():
    out = ('=====================\nToken header values:\n'
           '[+] alg = "HS256"\n[+] typ = "JWT"\n\n'
           'Token payload values:\n[+] sub = "1234567890"\n'
           '[+] name = "John Doe"\n')
    findings, surface = st._parse_jwt_tool(out, "")
    assert surface["jwt_header"]["alg"] == "HS256"
    assert surface["jwt_claims"] == ["name", "sub"]
    assert all(f["source"] == "omega-sys/jwt_decode" for f in findings)
    # alg=none must escalate severity
    none_out = 'Token header values:\n[+] alg = "none"\n\n' \
               'Token payload values:\n[+] sub = "1"\n'
    findings2, _ = st._parse_jwt_tool(none_out, "")
    assert any(f["severity"] == "HIGH" and "alg=none" in f["title"]
               for f in findings2)


def test_parse_trufflehog_and_gitleaks():
    th = ('{"SourceName":"git","DetectorName":"AWS","Verified":false,'
          '"Raw":"AKIAIOSFODNN7EXAMPLE","SourceMetadata":{"Data":{"Git":'
          '{"file":"config.py"}}}}\n')
    findings, _ = st._parse_trufflehog(th, "")
    f = findings[0]
    assert f["severity"] == "HIGH"
    assert f["location"] == "config.py"
    assert "AKIAIOSFODNN7EXAMPLE" not in f["evidence"]  # masked
    assert "--no-verification" in f["verification_note"]
    gl = json.dumps([{"RuleID": "aws-access-token", "File": "config.py",
                      "StartLine": 3, "Secret": "AKIAIOSFODNN7EXAMPLE"}])
    findings2, _ = st._parse_gitleaks(gl, "")
    assert findings2[0]["severity"] == "HIGH"
    assert "AKIAIOSFODNN7EXAMPLE" not in findings2[0]["evidence"]


def test_parse_misc_extended_tools():
    f1, s1 = st._parse_naabu('{"host":"example.com","port":443}\n', "")
    assert s1["ports"] == ["443"] and f1[0]["source"] == \
        "omega-sys/naabu_top100"
    f2, s2 = st._parse_massdns("example.com. A 93.184.216.34\n", "")
    assert s2["hosts"] == ["example.com"]
    f3, s3 = st._parse_mapcidr("10.0.0.1\n10.0.0.2\nnot-an-ip\n", "")
    assert s3["ips"] == ["10.0.0.1", "10.0.0.2"] and len(f3) == 2
    f4, s4 = st._parse_dirsearch("200    1KB   http://example.com/admin\n",
                                 "")
    assert s4["urls"] == ["http://example.com/admin"]
    f5, s5 = st._parse_feroxbuster(
        '{"url":"http://example.com/uploads","status":200}\n', "")
    assert s5["urls"] == ["http://example.com/uploads"]
    f6, s6 = st._parse_crlfuzz("http://example.com/?q=1%0d%0aX\n", "")
    assert s6["urls"] and f6[0]["severity"] == "MEDIUM"
    f7, s7 = st._parse_graphw00f("[+] Detected: Graphql Engine: Hasura\n",
                                 "")
    assert s7["graphql"] and f7[0]["source"] == "omega-sys/graphw00f_fp"
    f8, s8 = st._parse_kxss("http://example.com/?q=<INJ>\n", "")
    assert s8["params"] == ["q"] and f8[0]["severity"] == "MEDIUM"
    f9, s9 = st._parse_nikto("+ /admin/: Admin login page/section found.\n"
                             "+ Target IP:          1.2.3.4\n", "")
    assert len(f9) == 1 and f9[0]["location"] == "/admin/"
    f10, s10 = st._parse_jsluice(
        '{"type":"url","url":"https://api.example.com/v2/users"}\n', "")
    assert s10["urls"] == ["https://api.example.com/v2/users"]
    f11, s11 = st._parse_gau("http://example.com/old-page\n", "")
    assert s11["urls"] == ["http://example.com/old-page"]
    f12, s12 = st._parse_arjun(
        "[+] Parameters found: \n    - id\n    - page\n", "")
    assert s12["params"] == ["id", "page"]
    f13, s13 = st._parse_dalfox(
        "[V] Triggered XSS Payload (found DOM Object): http://x/?q=<p>\n",
        "")
    assert f13[0]["severity"] == "HIGH"


def test_parse_whatweb_caps_urls_and_katana_caps_findings():
    many = ", ".join(f"http://h{i}.example.com" for i in range(40))
    args = SYS_REGISTRY["whatweb_fp"]["arg_builder"](many)
    assert len([a for a in args if a.startswith("http")]) <= 25
    big = "\n".join(json.dumps({"url": f"http://e.com/{i}", "status": 200})
                    for i in range(80))
    findings, surface = st._parse_katana(big, "")
    assert len(findings) == 50 and len(surface["urls"]) == 80


# ------------------------------------------------------- brain wiring

def test_brain_registry_audits_clean_with_new_capabilities():
    reg = default_registry()
    count, problems = reg.audit()
    assert count >= 22
    assert problems == []
    assert reg.get("recon.native_enum") is not None
    assert reg.get("enum.system_tools") is not None
    # risk classified + real costs + proper requires
    nat = reg.get("recon.native_enum")
    sys_cap = reg.get("enum.system_tools")
    assert nat.risk == "passive" and nat.cost >= 1
    assert sys_cap.risk == "active" and sys_cap.cost >= 1
    assert "has_dns" in nat.requires
    assert "has_dns" in sys_cap.requires
    # no chain-execution capability sneaks in
    assert all("execute" not in c.id for c in reg.all())


def test_new_capabilities_eligible_after_recon():
    reg = default_registry()
    st_state = BrainState("http://example.local")
    st_state.update_from_stage("recon", {"hosts": ["example.local"],
                                         "ports": ["443"]})
    facts = st_state.facts()
    assert reg.get("recon.native_enum").eligible(facts, 10)
    assert reg.get("enum.system_tools").eligible(facts, 10)
    # and unaffordable within a tiny budget
    assert not reg.get("enum.system_tools").eligible(facts, 1)


def test_brain_system_capability_gate_closed(monkeypatch):
    reg = default_registry()
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    state = BrainState("http://example.local")
    result = reg.get("enum.system_tools").fn(state) or {}
    assert "gate closed" in result.get("note", "")


def test_brain_native_capability_gate_closed(monkeypatch):
    reg = default_registry()
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    state = BrainState("http://example.local")
    result = reg.get("recon.native_enum").fn(state) or {}
    assert "gate closed" in result.get("note", "")


def test_brain_extended_system_capabilities():
    reg = default_registry()
    katana = reg.get("enum.katana_crawl")
    crlf = reg.get("enum.crlf_fuzz")
    jwt_cap = reg.get("verify.jwt")
    assert katana is not None and crlf is not None and jwt_cap is not None
    assert katana.cost == 2 and katana.risk == "active"
    assert crlf.cost == 2 and crlf.risk == "active"
    assert jwt_cap.cost == 1 and jwt_cap.risk == "passive"
    assert katana.requires == ("has_web",)
    assert crlf.requires == ("has_web",)
    assert jwt_cap.requires == ("has_jwt",)
    # guarded against duplicate registration
    count_before = len(reg.all())
    default_registry_into = default_registry()
    assert len(default_registry_into.all()) == count_before


def test_brain_extended_capabilities_eligibility():
    reg = default_registry()
    st_state = BrainState("http://example.local")
    st_state.update_from_stage("recon", {"hosts": ["example.local"],
                                         "urls": ["http://example.local"],
                                         "ports": ["443"]})
    facts = st_state.facts()
    assert facts["has_web"] is True
    assert facts["has_jwt"] is False
    assert reg.get("enum.katana_crawl").eligible(facts, 10)
    assert reg.get("enum.crlf_fuzz").eligible(facts, 10)
    assert not reg.get("verify.jwt").eligible(facts, 10)  # no jwt finding
    # once a finding references a JWT, verify.jwt becomes eligible
    st_state.findings.append({"title": "jwt token in response",
                              "severity": "INFO",
                              "location": "/api/jwt"})
    facts2 = st_state.facts()
    assert facts2["has_jwt"] is True
    assert reg.get("verify.jwt").eligible(facts2, 10)


def test_brain_extended_capability_gate_closed(monkeypatch):
    reg = default_registry()
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    state = BrainState("http://example.local")
    state.update_from_stage("recon", {"hosts": ["example.local"],
                                      "urls": ["http://example.local"]})
    for cap_id in ("enum.katana_crawl", "enum.crlf_fuzz", "verify.jwt"):
        result = reg.get(cap_id).fn(state) or {}
        assert "gate closed" in result.get("note", ""), cap_id


# ------------------------------------------------------------- CLI

def test_cli_polyglot_sets_env_engage(monkeypatch):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    monkeypatch.setenv("OMEGA_ENGINE_HOME", "/nonexistent-engine")
    rc = cli.main(["engage", "example.com", "--scope-ack", "--polyglot"])
    assert rc == 3  # engine-missing exit code preserved
    assert os.environ.get("PTK_POLYGLOT") == "1"


def test_cli_without_polyglot_clears_env(monkeypatch):
    monkeypatch.setenv("PTK_POLYGLOT", "1")
    monkeypatch.setenv("OMEGA_ENGINE_HOME", "/nonexistent-engine")
    rc = cli.main(["engage", "example.com", "--scope-ack"])
    assert rc == 3
    assert os.environ.get("PTK_POLYGLOT") is None


def test_cli_polyglot_reaches_brain_runner(monkeypatch):
    captured = {}

    def fake_run_brain(args):
        captured["polyglot"] = getattr(args, "polyglot", False)
        captured["env"] = os.environ.get("PTK_POLYGLOT")
        return 0

    monkeypatch.setattr(cli, "_run_brain", fake_run_brain)
    rc = cli.main(["brain", "example.com", "--scope-ack", "--polyglot"])
    assert rc == 0
    assert captured == {"polyglot": True, "env": "1"}


def test_cli_scope_gate_exit_code_preserved(monkeypatch):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
    rc = cli.main(["brain", "example.com", "--polyglot"])  # no --scope-ack
    assert rc == 2
    assert os.environ.get("PTK_POLYGLOT") is None  # gate checked first


def test_full_brain_run_smoke_with_polyglot_registry(monkeypatch):
    """End-to-end-ish: brain loop survives the new capabilities with the
    gate closed (both degrade to notes) and still renders a report."""
    from omega.brain import Brain
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)

    def stub_runner(target, mode="auto", scope_ack=None, budget=None,
                    cancel=None, log=None):
        return {"stages_planned": ["recon", "report"],
                "stage_results": {
                    "recon": {"hosts": ["example.local"],
                              "ports": ["443"]}},
                "chains_planned": [], "errors": []}

    b = Brain(engine_runner=stub_runner, budget=50)
    state, report = b.run("http://example.local", scope_ack=True)
    assert state.steps > 0
    assert "# OMEGA brain report" in report
    notes = [h for h in state.history
             if h["capability"] in ("recon.native_enum",
                                    "enum.system_tools")]
    assert notes, "new capabilities never considered by the loop"


# ------------------------------------------------- arsenal-2: stats

def test_registry_stats_summary():
    stats = st.registry_stats()
    assert stats["total"] == len(SYS_REGISTRY)
    assert stats["total"] >= 73
    assert sum(stats["by_stage"].values()) == stats["total"]
    assert sum(stats["by_safety"].values()) == stats["total"]
    assert set(stats["by_stage"]) <= {"recon", "enum", "verify", "report"}
    assert set(stats["by_safety"]) <= {"passive", "active-recon"}


def test_stats_cli_prints_arsenal_summary(monkeypatch, capsys):
    monkeypatch.setenv("OMEGA_ENGINE_HOME", "/nonexistent-engine")
    rc = cli.main(["stats"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "OMEGA arsenal stats" in out
    assert str(st.registry_stats()["total"]) in out
    assert "pytools" in out and "probes" in out and "deepchecks" in out
    assert "fusion" in out
    assert "TOTAL" in out


def test_credential_cracking_tools_refused_by_blocklist():
    """No credential-SUBMISSION / cracking tool may ever be registered."""
    for banned in st.REFUSED_BINARY_BLOCKLIST:
        assert banned not in {s["binary"] for s in SYS_REGISTRY.values()}
        assert banned not in SYS_REGISTRY
    # and the audit blocklist covers the canonical offenders
    assert {"hydra", "medusa", "mimikatz", "hashcat"} <= set(
        st.REFUSED_BINARY_BLOCKLIST)
    # auth_hints_fp is the read-only replacement: curl GET only
    args = SYS_REGISTRY["auth_hints_fp"]["arg_builder"]("http://example.com")
    assert args and args[0] in ("-sS",)  # curl, GET, no POST/data flags
    assert not any(a.upper() in ("POST", "--POST") for a in args)


# --------------------------------- arsenal-2: canned parser tests

def test_parse_testssl():
    out = ("LOW  TLSv1.0 is deprecated\n"
           "INFO  HSTS header present\n"
           "not-a-finding\n")
    findings, surface = st._parse_testssl(out, "")
    assert surface["tls_findings"][0] == "LOW  TLSv1.0 is deprecated"
    f = findings[0]
    assert f["severity"] == "LOW" and f["source"] == "omega-sys/testssl_sev"


def test_parse_sslscan():
    out = ("  Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384\n"
           "  SSLv3     enabled\n  SSLv3     disabled\n")
    findings, surface = st._parse_sslscan(out, "")
    assert any("ECDHE-RSA-AES256-GCM-SHA384" in f["title"]
               for f in findings)
    assert any("deprecated protocol enabled: SSLv3" in f["title"]
               for f in findings)
    assert surface["ciphers"]


def test_parse_wpscan():
    out = "[+] XML-RPC enabled\n[+] Warning: outdated plugin detected\n"
    findings, surface = st._parse_wpscan(out, "")
    assert surface["hits"][0] == "XML-RPC enabled"
    assert any(f["severity"] == "LOW" for f in findings)
    assert all(f["source"] == "omega-sys/wpscan_enum" for f in findings)


def test_parse_cmseek_via_cms_text():
    out = "CMS: WordPress detected on http://example.com/\n[i] skipped\n"
    findings, surface = st._parse_cms_text("cmseek_fp", out, "")
    assert surface["hits"] and "WordPress" in surface["hits"][0]
    assert findings[0]["source"] == "omega-sys/cmseek_fp"


def test_parse_photon_and_hakrawler_url_lines():
    f1, s1 = st._parse_photon("http://example.com/page1\nnoise\n", "")
    assert s1["urls"] == ["http://example.com/page1"]
    assert f1[0]["source"] == "omega-sys/photon_crawl"
    f2, s2 = st._parse_hakrawler("http://example.com/contact\n", "")
    assert s2["urls"] == ["http://example.com/contact"]
    assert f2[0]["source"] == "omega-sys/hakrawler_crawl"


def test_parse_paramspider():
    out = "http://example.com/index.php?q=1\nhttp://example.com/a?x=2\n"
    findings, surface = st._parse_params(out, "")
    assert surface["urls"] == ["http://example.com/a?x=2",
                               "http://example.com/index.php?q=1"]
    assert all(f["source"] == "omega-sys/paramspider_disc"
               for f in findings)


def test_parse_s3scanner():
    out = "aws,my-bucket,exists,public,10\naws,other,exists,priv,0\n"
    findings, surface = st._parse_s3scanner(out, "")
    assert surface["buckets"] == ["my-bucket", "other"]
    sev = {f["location"]: f["severity"] for f in findings}
    assert sev["my-bucket"] == "LOW" and sev["other"] == "INFO"


def test_parse_wafw00f():
    out = ("example.com is behind Cloudflare (Cloudflare Inc.)\n"
           "No WAF detected by generic detection\n")
    findings, surface = st._parse_wafw00f(out, "")
    assert "No WAF detected by generic detection" in surface["wafs"][1]
    assert len(findings) == 1
    assert findings[0]["source"] == "omega-sys/wafw00f_fp"


def test_parse_git_open_probe():
    out = ("http junk\n"
           "URL=http://example.com/.git/HEAD CODE=200\n"
           "ref: refs/heads/main\n"
           "URL=http://example.com/missing CODE=404\n"
           "some body\n")
    findings, surface = st._parse_git_open(out, "")
    assert surface["hits"] == ["http://example.com/.git/HEAD"]
    f = findings[0]
    assert f["severity"] == "LOW"
    assert f["source"] == "omega-sys/git_open_probe"
    assert "ref: refs/heads/main" in f["evidence"]
