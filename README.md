# <img src="docs/logo-icon.png" width="44" align="top" alt="OMEGA"/> OMEGA v1.0.0

<p align="center">
  <img src="docs/logo-banner.png" alt="OMEGA — the last pentest tool you'll ever need" width="720"/>
</p>

**Autonomous pentest engagement operator for the Hermes agent — headless,
deterministic, evidence-validated, multi-language.**

> **Why the name?** OMEGA (Ω) is the last letter of the Greek alphabet —
> *the last pentest tool you'll ever need*: recon, scanning, mobile,
> cloud, LLM, evasion, exploit-chains, and reporting, all in one place.

![version](https://img.shields.io/badge/version-1.0.0-blue)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![tests](https://img.shields.io/badge/tests-1572%20passed-brightgreen)
![suites](https://img.shields.io/badge/fusion%20suites-63-blue)
![capabilities](https://img.shields.io/badge/brain%20caps-106-blue)

## What is OMEGA?

OMEGA is a full security-testing brain that plugs into the
[Hermes agent](https://github.com/NousResearch/hermes-agent). You talk to it
in plain language from chat (Telegram, CLI, desktop — anywhere Hermes runs)
and it plans and executes an end-to-end penetration test autonomously:
surface recon, enumeration, evidence-based vulnerability verification,
triage, exploit-chain planning, evasion, and consultant-grade reporting.

- **Headless by design** — no web UI. You prompt, it works. Raw scanner
  output never floods the chat; you get summaries, evidence, and reports.
- **Deterministic scanners + AI orchestration.** The 63 fusion suites are
  deterministic tools; the AI decides what to run, interprets results,
  chains findings, and improvises. Scripts find, the AI thinks.
- **Anti-hallucination by construction.** The AI can never *claim* a
  vulnerability without reproducible evidence: the claim-validation gate
  (`omega validate` / `omega_validate`) re-fetches the claimed location
  live and refutes anything that does not reproduce. Self-declared
  "confirmed" statuses without evidence are demoted to candidate.
- **Honest severity.** Findings are `candidate` until verified; HIGH/CRIT
  claims that fail validation are demoted to LOW. False positives are
  designed out (baseline differentials, FP-guard fixtures, 0/10 on the
  clean-path benchmark).
- **Multi-domain.** Web, APIs, mobile (APK deep analysis + mobile backend
  APIs), cloud/K8s/CI-CD, LLM/AI systems, databases, DNS/infra — 63
  suites, 106 brain capabilities, 79 optional system binaries.
- **Multi-language reports.** 5 formats (markdown/HTML/JSON/DOCX/PDF)
  in 12 languages.
- **Safety gated.** Offensive tiers (`--offense`, `--exploit`,
  `--no-limits`) are never opened automatically — the operator flips
  them, and scope acknowledgment (`--scope-ack`) is required per target.

OMEGA uses the **engine** strictly as a library: resolved on disk at
runtime (never vendored, never modified), imported read-only from
`offensive.engagement` / `offensive.toolbridge`. A test asserts zero writes
back into the engine tree.

---

## Installation

### A. Core (CLI use, incl. Kali Linux)

```bash
unzip omega-v1.0.0-source.zip -d ~/source/omega && cd ~/source/omega
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # PyYAML — the only hard dependency
pip install reportlab python-docx        # optional: PDF/DOCX reports
python3 -m playwright install chromium   # optional: jsrender/browser suites
bash bin/omega --version                 # OMEGA v1.0.0
```

> **Kali Linux note:** Kali is PEP 668 externally-managed — plain `pip`
> refuses system-wide installs. Always use the venv as shown above.

### B. Hermes plugin (chat-driven use)

This is the recommended mode: it turns OMEGA into 8 callable tools inside
Hermes so the AI can scan, validate, follow up, plan chains, and report
directly from conversation.

```bash
# from the extracted OMEGA directory:
bash hermes-plugin/install.sh
#  -> copies the plugin to ~/.hermes/plugins/omega
#  -> pins THIS repo location into _omega_home.txt (no directory guessing)

# also install the companion skill (auto-triggers on security wording):
cp -r hermes-plugin/omega-engage ~/.hermes/skills/

# then RESTART Hermes (or start a new session) so the plugin loader
# picks it up. Verify with the plugin list — you should see 'omega'
# exposing 8 tools.
```

Install order matters: extract the source first, run `install.sh` from the
extracted location — the plugin records where OMEGA lives so tool calls
resolve deterministically. `OMEGA_HOME=/path/to/omega` overrides the pinned
path at any time.

### Requirements & optional components

Requirements: Python >= 3.11. Everything except PyYAML is standard library.
Optional external toolchains are detected at runtime and skipped gracefully
when missing: **Go** (native adapters, compiled on demand to
`~/.cache/omega/bin`), **Node**, **Perl**, **Ruby**, **C (gcc)**, **jq**,
and the **79 system security binaries** in the catalog (nmap, testssl.sh,
wpscan, gobuster, nuclei, ffuf, katana, …).

**The engagement engine ships bundled** in `engine/` inside this repo — it
is auto-detected at startup (zero configuration). On a host without it,
`omega engage` degrades gracefully; all scanner layers still work. Override
the location with `OMEGA_ENGINE_HOME` if needed.

---

## Usage

```bash
omega --version
omega engage  example.com --mode red-team --scope-ack
omega brain   example.com --scope-ack --max-steps 25
omega brain   example.com --scope-ack --aggressive     # MAXIMUM POWER
omega run     "bug bounty scan example.com lengkap saya berhak"
omega watch   example.com --scope-ack --interval 3600
omega sessions list
omega stats
omega dsl     example.com --scope-ack --file omega/dsl_default.yaml
omega matrix  example.com --scope-ack --param q
omega brute   example.com --scope-ack --wordlist ~/wl.txt
omega inject  example.com --scope-ack --param id
```

| Command | Purpose |
| --- | --- |
| `engage` | Bounded engagement via the engine (10 modes) |
| `brain` | Deterministic capability planner + executor (no LLM in the loop) |
| `run` | Free-form prompt → intent parse → plan preview → execute |
| `watch` | Periodic re-scan, diff against the last session, cron exit codes |
| `sessions` | `list` / `diff` stored engagement sessions |
| `stats` | Arsenal inventory (native tools, brain capabilities, toolbridge) |
| `dsl` | Operator-authored YAML checks |
| `matrix` | Payload encoding × placement matrix |
| `brute` | **Offense:** login-form brute force with an operator wordlist |
| `inject` | **Offense:** SQLi/CMDi/SSTI/XSS/traversal injection runner |

Exit codes: `0` success, `2` safety/refusal (missing scope ack, gate off,
unknown mode), `3` engine home missing, `4` watch drift detected.

## Modes

Ten engagement modes are supported: `auto`, `bug-bounty`, `red-team`,
`ctf`, `blue-team`, `offensive`, `grey-hat`, `forensic`,
`reverse-engineering`, `mobile-pentest`.

---

## Safety contract (enforced in code and tests)

- **Scope acknowledgment required.** No engagement runs without
  `--scope-ack` → exit 2 otherwise, before any network activity.
- **Hard budgets, operator-liftable.** Engine rounds: 25 stages / 150 HTTP
  requests; offense suite: 300 requests; per-module caps returned in
  `requests_sent`. Every cap is an operator override:
  `OMEGA_MAX_REQUESTS`, `OMEGA_FUSION_BUDGET`, `--max-steps` — or a single
  `--aggressive` flag lifts them all and enables every layer.
- **Chains are planning-only.** Attack chains are *plans*; OMEGA never
  executes them.
- **Layered gates.** `PTK_TOOLS=1` (`--with-tools`) external read-only
  bridge; `PTK_POLYGLOT=1` (`--polyglot`) native + system binaries;
  `PTK_OFFENSE=1` (`--offense`) brute force and injection payloads;
  `PTK_EXPLOIT=1` (`--exploit` / part of `--aggressive`) PoC exploitation
  of confirmed findings (SQLi data readback, RCE echo markers, SSRF
  internal capture, auth bypass, IDOR enumeration, JWT forgery) — each
  gate is a separate opt-in.
- **No-limits tier.** `--no-limits` (or `OMEGA_NO_LIMITS=1`, implies
  `--exploit`) unlocks the maximum-power exploit drivers: deep filesystem
  reads, file-write proofs, privilege-escalation enumeration, shell
  control PoCs, self-cleaning persistence PoCs and automatic exploit
  chaining. Still gated by `--scope-ack`; destructive PoCs are
  self-cleaning by design.
- **Exploitation is evidence-first.** Findings carry execution evidence
  (readback, echo markers, `id`/`uname` capture, generated reverse-shell
  one-liners for the operator) — never table drops or data destruction
  by default.
- **No destructive operations.** Allowlisted methods (GET/HEAD/OPTIONS;
  POST only for two documented GraphQL safe reads). Blocklisted patterns
  (`rm -rf`, `DROP TABLE`, masscan, hydra/medusa/mimikatz-class binaries)
  are rejected by audit tests.
- **No default credential list.** Brute force requires an operator-written
  wordlist (`--wordlist` / `OMEGA_WORDLIST`); the 20-entry fallback exists
  only behind `allow_default=True`.
- **Offline CVE reference only** — no exploit payload is fetched remotely.

## Honesty contract

Every finding carries `severity`, `confidence`, `verification`,
`evidence`, `location`, and a concrete `manual_check` command with the real
target.

- `verification` is `candidate` unless a **documented differential
  confirm** rule is fully satisfied (`confirmed`).
- Corroboration by ≥2 independent scanners raises `confidence` and sets
  `corroborated=True` — it **never** promotes `verification` to confirmed.
- Output of external tools is recorded as `signature` (unverified evidence).
- Unknowns say so: a blind OOB scan with no callback reports
  *"inconclusive, NOT secure"* rather than a clean bill of health.

---

## Architecture

```
omega/                  # repo root
├── bin/omega           # bash shim → python3 -m omega.core.cli
├── omega/              # the OMEGA package (see Architecture below)
│   ├── core/           # cli, brain, intent, session, watch, browser, auth, oob
│   ├── scanning/       # all scanner engines + fusion orchestrator
│   ├── offensive/      # offense (brute/inject) + exploit (PoC layer)
│   ├── reporting/      # report engine (5 formats)
│   └── adapters/       # Go/Node/Perl/jq/C/C++/Rust/PHP/awk/bash bridges + system catalog
├── engine/             # vendored engagement engine (auto-detected, read-only)
├── tests/              # hermetic pytest suite (822 tests)
├── hermes-plugin/      # Hermes integration
│   ├── omega/          # Hermes plugin (tools: omega_scan/sessions/report/stats)
│   ├── omega-engage/   # Hermes skill (auto-trigger on security prompts)
│   ├── install.sh
│   └── README.md
├── README.md · requirements.txt · pytest.ini · AGENTS.md · .gitignore
```

Top-level names like `omega.fusion` / `omega.brain` remain importable via
compatibility shims that alias the new subpackage locations.

The `omega/` package itself:

```
omega/
├── brain.py             106 capabilities, deterministic decide(), --max-steps loop
├── fusion.py            28 concurrent scanner suites + corroboration engine
├── intent.py            free-form prompt → structured intent
├── session.py           session persistence, diffing, watch state
│
├── pytools.py           pure-Python tool implementations
├── pytools_scan.py      async TCP port scanner
├── probes.py            10 differential HTTP probes
├── deepchecks.py        15 deep vulnerability checks
├── chaos.py             43 response mutators + wildcard-404 clustering
├── payloadmatrix.py     12 encodings × 8 placements, reflection survival
├── cvexref.py           offline CVE DB (60 entries / 83 CVEs)
├── dsl.py               YAML custom checks (dsl_default.yaml)
├── apiintel.py          OpenAPI/Swagger discovery, spec diffing
├── graphqldeep.py       field suggestion, depth, alias bulk, errors
├── racecheck.py         GET-only concurrency consistency (cap 20)
│
├── hyper.py             14 hyper-surface checks (artifacts, banners, CORS)
├── headerscan.py        11 deep header checks (CSP/HSTS/frames/cookies)
├── redirects.py         open redirect + chain auditor (differential confirm)
├── oobscan.py           blind OOB interaction + SSRF evidence confirm
├── jsrender.py          Chromium rendered-vs-static differential scan
├── subperm.py           DNS subdomain permutation + zone intel
├── sentinel.py          14 post-scan intelligence checks (JWT audit, secrets,
│                        takeover fingerprints, XXE safe probe, IDOR probe)
├── report.py            consultant-grade reporting: markdown / html / json /
│                        docx / pdf — executive summary, CWE + OWASP maps,
│                        evidence appendix, CONFIDENTIAL cover
├── browser.py           Playwright session engine
├── auth.py              session-aware authenticated scanning
├── oobchecks.py         local out-of-band callback server client
├── watch.py             periodic monitoring + drift detection
│
├── offense/             PTK_OFFENSE gate (--offense)
│   ├── __init__.py      gate + request budget (OMEGA_MAX_REQUESTS override)
│   ├── brute.py         form brute, HTTP basic, JWT alg=none forge
│   ├── payloadgen.py    8 payload classes with expect_signature
│   └── injection.py     differential confirm runner
├── exploit.py           PTK_EXPLOIT gate (--exploit / --aggressive): PoC
│                        exploitation of confirmed findings — SQLi readback,
│                        RCE echo markers, SSTI evaluation, LFI read,
│                        SSRF internal capture, auth bypass, IDOR enum,
│                        XSS PoC, JWT forgery; no-limits tier adds deep traversal, write proofs, privesc enum, shell PoC, persistence PoC, chaining)
│
└── adapters/
    ├── native.py        Go/Node adapters, compile-on-demand
    ├── system_tools.py  79-binary catalog + refuse-list + registry stats
    ├── go/              portspeed.go, htsweep.go, dirscan.go, dnssweep.go
    ├── node/            jsanalyze.mjs, hdrscore.mjs
    ├── jq/              validate.jq, diffstat.jq
    ├── gotools.py       Go runner (gated, contained)
    ├── node_hdr.py      Node header scorer bridge
    ├── jqdiff.py        jq differential bridge (fail-closed)
    ├── perltools.py     Perl regex mining bridge
    └── analyze.pl       endpoint/secret extraction
```

### Fusion suites (63)

`python-pytools`, `python-probes`, `python-deep`, `python-browser`,
`native`, `system`, `perl`, `python-chaos`, `python-api`,
`python-graphql-deep`, `python-offense`, `python-hyper`,
`python-headerscan`, `python-redirects`, `python-oobscan`,
`python-jsrender`, `python-subperm`, `go-dirscan`, `node-hdr`, `jq-diff`,
`python-sentinel`, `c-urlinfo`, `ruby-urlaudit`,
`cpp-hdrstruct`, `awk-urlmine`, `sh-methodcheck`, `rust-pathscope`,
`php-seriscan`
plus the post-collection `jq.validate` hygiene pass.

### Language coverage

Python (core logic) · Go (concurrent port/path/DNS scanning) · Node
(JS analysis, header scoring) · Perl (regex mining) · jq (normalization,
differential) · C (gcc, URL analysis) · Ruby (URL audit) · C++ (g++,
header structure classification) · awk (URL/secret mining) · bash (HTTP
method audit) · Rust (path-scope validation, optional toolchain) ·
PHP (unserialize/eval static scan, optional toolchain) ·
Chromium/Playwright (rendered-DOM scanning) · 79 external binaries.

---

## Hermes plugin

OMEGA ships as an installable Hermes plugin (`hermes-plugin/omega/`):
a `plugin.yaml` toolset + Python handlers that expose eight agent tools
to the AI — `omega_scan` (brain/run engagement), `omega_assault` (one-shot
scan + auto-report), `omega_validate` (AI-claim validation gate),
`omega_followup` (adaptive evidence probes), `omega_chains` (exploit
chain planning), `omega_sessions` (list/diff), `omega_report` (5
formats), `omega_stats`. With the plugin installed, the AI doesn't just
talk about security — it can actually drive OMEGA's scanners from chat,
and every offensive action still passes the same scope/claim gates as
the CLI.

```bash
bash hermes-plugin/install.sh   # copies to ~/.hermes/plugins/omega
```

Restart Hermes and the tools appear in the toolset `omega`. Authorization
is enforced per call: `omega_scan`/`omega_assault` only run when
`scope_ack=true` is passed explicitly — the plugin never injects it. The
repo location is resolved deterministically: `OMEGA_HOME` env, then the
path pinned by `hermes-plugin/install.sh` at install time, then an
`omega` shim on PATH — never by guessing directories.

### Using the plugin from chat

Example prompts to the assistant, and which tool they trigger:

| Prompt | Tool called |
|---|---|
| "Scan http://target — scope acknowledged" | `omega_scan` (brain scan) |
| "Pentest http://target, brutal, and give me a report" | `omega_assault` |
| "Validate these findings before reporting them" | `omega_validate` |
| "Follow up on the SQLi candidate with more probes" | `omega_followup` |
| "What exploit chains are possible on this session?" | `omega_chains` |
| "List my scan sessions / diff the last two" | `omega_sessions` |
| "Make a PDF report in Indonesian" | `omega_report` |
| "How big is the current arsenal?" | `omega_stats` |

CLI equivalents (outside chat): `omega brain/run/campaign TARGET
--scope-ack`, `omega validate claims.json --base URL`, `omega followup
findings.json`, `omega chains SESSION`, `omega report - --out report.pdf`.

---

## Reporting

Every session converts to a consultant-grade pentest report in five
formats:

```bash
omega report - --out report.pdf       # '-' = latest session by mtime
omega report <session-id> --out report.docx --format docx
```

Structure: CONFIDENTIAL cover, executive summary with overall risk rating,
scope & methodology, risk-rating methodology, numbered findings
(F-001…) with verification status, evidence, manual-check command,
CWE + OWASP mapping and remediation, evidence appendix, scanner-coverage
appendix. Formats: `markdown`, `html`, `json`, `docx` (python-docx),
`pdf` (reportlab) — docx/pdf are optional dependencies, the rest are
built in.

---

## False-positive guards

Accuracy is designed in, not asserted:

- **Baseline differential first.** Every HTTP check compares against a
  baseline response; identical (constant) responses produce **zero**
  findings — enforced by dedicated FP-guard fixtures.
- **Wildcard DNS detection** before subdomain enumeration; wildcard hits
  are tagged noise and never reported as internal exposure.
- **404/soft-404 clustering** for path scans; artifact probes require
  content-shape signatures (KEY=VALUE density, git refs, `[core]` sections),
  not bare status codes.
- **Fail-closed parsing.** jq validation quarantines malformed findings
  instead of passing them through.
- **Graceful degradation.** Missing toolchains produce documented `skipped`
  entries; they never fabricate results or crash the run.

---

## Report CLI examples

```bash
omega report -                       # markdown report of the latest session
omega report my-scan --format html
omega report my-scan --out report.pdf
omega report my-scan --out report.docx
```

`omega/report.py` produces consulting-grade deliverables in **markdown,
HTML (print-friendly), JSON, DOCX, and PDF** with the full pentest-report
structure: cover + CONFIDENTIAL classification banner, executive summary
with overall risk rating, scope & methodology, risk-rating methodology,
findings (sequential IDs, verification status, description, impact,
evidence, affected location, manual-verification steps, CWE-mapped
remediation recommendations with OWASP references), appendices (evidence
table + scanner coverage), and disclaimer. Findings are sanitized, deduped,
and enriched automatically; the PDF/DOCX branches require the optional
`python-docx` / `reportlab` packages.

### Accuracy benchmark

Two tooling layers measure OMEGA's detection accuracy — one against the
local ground-truth lab, one against a real-world vulnerable app. Neither
ever auto-confirms a finding: all matches are reported as *detected
signals* mapped to known challenge classes, and HIGH/CRIT findings that
match no known class are surfaced as FP suspects for manual review.

**Regression gate — `lab/regress.py`** (run before any release):

```bash
python3 lab/regress.py
```

It first runs `tests/test_deepchecks.py` + `tests/test_fusion.py`, then
starts the local lab app (`lab/vuln_app.py`, 10 planted vulns + 3 clean
FP traps) and runs the fusion flow against it. PASS requires:

- detection: >= 9/10 planted vulnerability classes produced >= 1 matching
  finding (token match over title/location/param/evidence);
- precision: 0 HIGH/CRIT findings located on the 3 clean paths
  (`/safe-param`, `/api/users`, `/health`).

Exit codes: 0 = PASS, 1 = FAIL (regression or prerequisite test failure).

**External benchmark — `lab/bench_ext.py`** (real vulnerable app):

```bash
python lab/bench_ext.py                                    # Juice Shop default
OMEGA_BENCH_TARGET=http://127.0.0.1:3000 python lab/bench_ext.py   # local instance
OMEGA_BENCH_BUDGET=900 python lab/bench_ext.py             # larger budget (default 600)
```

Scores findings against `lab/bench_catalog.json` (~20 known Juice Shop
challenge classes: SQLi, XSS variants, IDOR, path traversal, SSRF, JWT
forgery, sensitive data exposure, directory listing, missing headers,
open redirect, ...). The markdown report (saved to
`lab/bench_ext_report.md`) shows a coverage table (which classes emitted
a matching signal), a FP-suspect list, and timing. The public demo is
flaky: bounded retries are built in, and if the target is unreachable
the verdict is **TARGET UNREACHABLE** with exit code 3 — never a fake
0% score.

**Reading the numbers:** `Detected signal classes: N/M` means N of the M
known challenge classes produced at least one matching finding — an
indication of breadth, not a vulnerability count. Anything under "FP
suspects" needs manual triage before it can be called a true or false
positive.

### Adaptive follow-up loop

`omega/scanning/followup.py` adds a SECOND-depth probe per finding type
(`omega run --followup` or standalone `omega followup findings.json
--base URL [--json]`, budget: `OMEGA_FOLLOWUP_MAX`, default 12). A
script-guarded probe — blind-SQLi boolean differential (stable across 3
alternations), XSS script-tag echo with DOM-context detection, path
traversal deeper depths and alternate encodings, `.env` key-name parse
(values stay in verbatim evidence only), command-echo arithmetic
corroboration with different operands, open-redirect protocol-relative
and backslash variants, CSP weakness parse (unsafe-inline, missing
default-src) — turns each finding into a CLAIM that must pass the
claimcheck gate (`omega.scanning.claimcheck.validate_claim`). Only
gate-verified probe claims join the final findings (sources tagged
`omega-followup/<probe>`); everything the gate refutes is recorded
under `refuted` with `ai-claim:refuted`, and unknown finding types get
no probe and are reported in `skipped` with a reason. The loop never
raises and is offline-safe. In `fuse(followup=True)` the verified probe
claims are merged into the fusion result with refuted/skipped reported
under `result['followup']`.

### Exploit chain recommender

`omega/core/chainreco.py` turns collected session findings into
exploit-chain recommendations using deterministic keyword rules only —
no LLM, no network, and nothing is ever executed. Every chain step
cites the finding it is grounded in (`uses` + `evidence_ref`), so a
recommendation is only ever as strong as the recorded evidence.

```bash
omega chains SESSION_OR_FILE [--json]   # '-' picks the latest session
```

Rules: secret/env exposure + login/JWT → credential replay (offense
gate); version disclosure + local CVE index → CVE exploit path
(exploit gate); admin panel + upload → upload bypass; open redirect +
takeover hint → subdomain takeover; traversal + .env → secret
retrieval (explicit `--no-limits` only); anything unmatched falls back
to a per-finding verify-then-decide chain. Chains touching
`candidate`-verified findings are flagged `candidate-only chain:
verify first`. The brain exposes this passively as the
`ai.chainreco` capability (planning only).

### Adaptive evasion engine

`omega/offensive/evasion.py` detects the target's defenses from real
request evidence and mutates attack tactics accordingly. Four benign
marker probes (XSS marker, SQLi quote, traversal dots, oversized param)
reveal WAF block pages, differential 403/406/429 responses, vendor
fingerprints (Cloudflare/Sucuri/Akamai/...) and rate-limit headers.

```bash
omega evade TARGET --scope-ack --json   # planning only: probe defenses,
                                        # report the tactic plan, no attack
```

Tactic profiles: `direct` (no mutation), `encode-rotate`
(double-urlencode, unicode-escape, SQL keyword case-jitter, `/**/`
comment insertion), `slow-drip` (inter-request delay + jitter, serial
requests), `chunked` (Transfer-Encoding chunked body) and
`header-mimic` (realistic browser headers, X-Forwarded-For rotation).
`select_tactic()` is deterministic — no defense → direct, WAF →
encode-rotate then header-mimic, rate limit → slow-drip — and
`tactic_index` lets the AI loop step to the next profile when one
fails. `run_adaptive(fetch, base_url, attack_fn, max_attempts)` drives
the loop and returns per-attempt status plus the last successful
profile. All payloads are benign markers; the engine never raises.

### Attack playbooks

`omega/offensive/playbook.py` turns session findings into multi-stage
attack scenarios the AI executes stage-by-stage, each stage individually
gated and evidence-checked. Five playbooks ship: `auth-takeover`
(credential replay → session analysis → privilege escalation),
`upload-rce-path` (benign marker upload → retrieval → interpretation),
`ssrf-pivot` (open redirect → own-loopback internal canary),
`privesc-chain` (traversal → config leak → credential use) and
`session-weakness` (cookie flags → fixation probe → fixation test).

```bash
omega playbook list                              # what is available
omega playbook auth-takeover SESSION             # print the plan (stages,
                                                 # gates, abort conditions)
omega playbook auth-takeover SESSION --stage 0 --scope-ack [--json]
```

Prerequisites are matched against finding titles ONLY — nothing is ever
invented, and `candidate`-verified findings are flagged
`candidate-only: verify first`. Each stage names its gate (`none`,
`offense`, `exploit`, `no_limits`); a closed gate refuses the stage with
`executed: false` and is NEVER auto-opened. Every probe is benign and
marker-based (OMEGA-PB markers, tiny per-probe request budget,
self-cleaning after the claim gate has reproduced the evidence), and
each stage result is re-validated through `claimcheck.validate_claim`
against the live target. A REFUTED stage stops the playbook and records
the reason. The brain exposes this passively as the `offense.playbook`
capability (risk `offense`, cost 2) — plans and prereq checks only,
never execution.

## Tests

```bash
python3 -m pytest tests/ -q      # 1235 passed
```

Hermetic by design: `ThreadingHTTPServer` fixtures on `127.0.0.1`, fake
resolvers, canned adapter output. No internet, no DNS, no external service
is required for the suite to pass.

---

## Environment variables

| Variable | Purpose |
| --- | --- |
| `OMEGA_ENGINE_HOME` | engine location override (default: auto-detect the bundled `engine/` in the repo, then `~/workspace`, then `~/source`) |
| `OMEGA_SESSIONS_HOME` | Session storage directory |
| `OMEGA_WORDLIST` / `OMEGA_PASSLIST` | Operator wordlists for `omega brute` |
| `OMEGA_JWT` | Token for the JWT alg=none verifier |
| `OMEGA_CIDR` | CIDR scope hint |
| `OMEGA_OOB_BASE_URL` | OOB callback base URL exported to child suites |
| `PTK_TOOLS`, `PTK_POLYGLOT`, `PTK_OFFENSE` | Layer gates (off by default) |

---

## Hermes integration

The `omega-engage` skill drives OMEGA from the Hermes agent. Run tests with
the ENGINE venv interpreter:
`~/workspace/engine/.venv/bin/python -m pytest tests/ -q`.
