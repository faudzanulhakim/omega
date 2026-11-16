# OMEGA operations runbook — building & extending the agent

## Project conventions
- OMEGA repo location is wherever the operator deployed it (resolve via $OMEGA_HOME or the install.sh-pinned path, never a hardcoded directory).
  `rsync -a --delete ... --exclude __pycache__/ --exclude '*.pyc' --exclude
  .pytest_cache/ --exclude .git/`, then `git add -A && git commit --amend
  --no-edit`. The mirror keeps ONE rolling commit — set git user.email/name
  locally on first commit or amend fails.
- Tests always run with the engine's venv:
  `<omega-venv>/bin/python -m pytest tests/ -q` from
  Use the repo's own venv if present. Never /usr/bin/python3 (fresh servers strip its packages).
  VM resets ALSO strip pip-installed packages from the venv itself — when
  report tests fail with ModuleNotFoundError (reportlab/python-docx),
  reinstall them in the venv (`python -m pip install reportlab
  python-docx`) instead of suspecting the code.

## Package-layout shims (restructure safety)
- OMEGA's real code lives in omega/core|scanning|offensive|reporting|adapters;
  top-level omega/<name>.py files are compatibility ALIASES. A shim must be a
  sys.modules swap (`import sys; from omega.X import *; import omega.X as _m;
  sys.modules[__name__] = _m`), never a plain star-import re-export: a
  star-import shim is a SEPARATE module object, so tests that monkeypatch it
  patch the wrong module, and private/underscore names are silently missing.
- The CLI entrypoint executes under __main__: keep `bin/omega` pointing at
  `python3 -m omega.core.cli`. Running a shim module via -m never calls
  main(), so the command exits 0 with EMPTY output — symptom is '--scope-ack
  not in stdout' with returncode 0.
- OMEGA imports the engine read-only — never vendor it and never edit the
  engine checkout from an OMEGA task. Engine home resolution (omega/cli.py):
  OMEGA_ENGINE_HOME env → autodetect a ~/workspace checkout containing
  offensive/__init__.py → ~/workspace/engine default. The OMEGA source tree
  contains ZERO references to the engine project's name (user-owned rule) —
  keep new OMEGA code/docs/commit messages name-neutral ('engine').

## Vendoring the engine bundle (omega/engine/)
- The bundle carries ONLY the library: offensive/, engine/, tools/,
  requirements.txt. Strip every platform artifact from the source you copy:
  .dockerignore, .env.example, .gitignore, README.md, the engine's own
  cli.py, pytest.ini, conftest.py, tests/, scripts/. conftest.py is
  pytest-only (sys.path bootstrap) and is dead weight at runtime.
- Before deleting a directory from the bundle, grep the remaining code for
  its imports ("from <dir>", "import <dir>") — docstring/comment mentions
  are NOT imports and must not block removal.
- After stripping, verify `load_engine()` still resolves and run a fast
  test file, then rebuild the zip and re-grep its extracted content for the
  engine project's name AND for the stripped artifacts — the zip is the
  only channel that carries the bundle, so it is the gate.

## Hermes plugin integration
- Copy the plugin shape from REAL shipped examples (~/.hermes/hermes-agent/
  plugins/google_meet/__init__.py, disk-cleanup/plugin.yaml) before writing
  one: user plugins live in $HERMES_HOME/plugins/<name>/ with __init__.py
  whose register(ctx) calls ctx.register_tool(...), plus plugin.yaml
  declaring provides_tools. Do not guess the schema of register(ctx).
- Tool handlers that touch authorization (scan/exploit) must refuse when
  the operator-authorization flag is absent — return an error dict, never
  inject the flag. Test this with subprocess monkeypatched to raise so a
  silent call fails the test.

## Extending the stack (the working order)
1. Read the module you extend FIRST and match its exact entry shape
   (SYS_REGISTRY dict fields, brain capability fields incl. requires-facts
   and cost/risk). Capability ids must be unique — guard additions against
   duplicate-id collisions when a sibling may have added the same id.
2. Every new tool/probe: read-only args only, explicit rate/thread caps,
   finding shape candidate + verification 'signature' + manual_check with
   the REAL target substituted (never a placeholder), source=omega-*/<name>.
3. Gate everything optional behind its env (PTK_TOOLS, PTK_POLYGLOT);
   tests/conftest.py closes the gates by default so no test can fire real
   binaries.
4. Audit test: assert no mutation/exploit flags across the WHOLE registry
   (including old entries), not just the new ones.
5. Run the FULL suite (not just the new test file) before reporting —
   cross-module regressions hide outside your file.

## Parallel-agent dispatch on one tree
- Concurrent subagents editing the same repo produce false test failures
  (port collisions between fixture servers) — each agent's own file passes
  alone but the merged tree must be re-verified by the parent. Always run
  the full suite yourself after a parallel batch.
- Collection errors and failures naming symbols the dispatch is WIRING
  (e.g. a new fusion suite id) while a builder agent is still running are
  in-flight edits, not regressions — do not chase or re-run the suite;
  wait for the agent completion message, verify the agent's claimed test
  tail yourself, THEN run the full suite once.
- A sibling's write_file may be refused ('modified by sibling subagent') —
  check the file on disk before judging success; the survivor's content is
  usually the correct one.
- When dispatching parallel builders on one repo, give each agent an
  explicit non-overlapping file list and tell them which sibling owns what.
- After an interrupted subagent, the tree can be half-wired (argparse
  subcommand defined but its handler function missing -> NameError at
  runtime). Grep the CLI for add_parser vs the handler defs and smoke-run
  `bash bin/omega <subcommand> --help` before trusting the report; finish
  the missing handlers yourself.
- An interrupted agent also leaves SYNTAX-BROKEN stub test files (placeholder
  import lines like 'DEFAULT_REGISTRY if False else None') — a collection
  ERROR at pytest start means grep tests/ for 'placeholder' and fix the
  stub import to the module's real public names (inspect the module with
  dir() first), do not delete the file.
- Modules built by an agent whose report never arrived may still be complete
  and wired — verify on disk (py_compile, grep brain.py/fusion.py for the
  capability/suite id) before re-dispatching; half the work is often done.
- delegate_task goals must not contain unexpanded '<...>' template markers —
  the dispatcher rejects the whole call. Write concrete values or rewrite
  the sentence without the placeholder.

## Advanced layers (browser / auth / oob / watch)
- Playwright chromium installs into the ENGINE venv, not a system python:
  `<omega-venv>/bin/pip install playwright` then
  `python -m playwright install chromium`. browser_available() checks import
  AND executable-on-disk; every consumer treats missing-browser as a
  contained skip, never an error.
- Auth scanning: credentials come only from OMEGA_CREDS or explicit kwargs;
  the no-brute-force invariant (exactly ONE login POST per run) is asserted
  by a counting fixture — never add retry loops around login().
- OOB: each check uses a unique 32-hex token; CONFIRMED requires the exact
  token to receive a callback (cross-token isolation is tested). Blind RCE
  probes never execute commands — a hit yields 'candidate HIGH, manual
  verification required'.
- watch: diff direction is diff_sessions(older, newer); alert_exit_code
  returns 1 on new findings so cron can gate on it.

## Release & delivery
- The full suite takes ~7 minutes — launch it as a background process with
  notify from the start. A foreground run dies at the 420s timeout cap with
  no usable output, and the retry doubles the wait.
- After a source drop (zip for the user): reuse the rsync exclude list
  (`-x .venv/ __pycache__/ *.pyc .pytest_cache/ .git/ secrets.key .env
  toolkit.db* *.zip`), include the Hermes skill folder under its own
  top-level dir, then `grep -ri <engine-name>` the zip content as a final
  name-neutrality gate before sending.
- Project version lives ONLY in omega/__init__.py + the git tag
  (`omega --version` reads it). The skill's frontmatter version is internal
  skill metadata and is unrelated — never conflate the two when the user
  asks about 'the version'.

## Environment resets
- VM resets drop installed binaries (Go, Ruby, nmap/ffuf/... class) while
  the workspace tree survives. Before promising a tool-based feature, probe
  availability (`for t in go node perl nmap ...; do command -v $t; done`) —
  do not rely on what an earlier session found.
- Adapters must skip gracefully on missing binaries, so the suite stays
  green with skips — treat 'N passed, K skipped' as normal after a reset,
  not a regression.

- Capabilities registered at module-import tail (guarded `if DEFAULT_REGISTRY
  get(...) is None:` blocks) exist ONLY in DEFAULT_REGISTRY — a fresh
  `default_registry()` seed returns the pre-tail subset. Any stats/counter
  code must read DEFAULT_REGISTRY (as omega stats does), never a fresh
  seed, or it under-reports the arsenal.
- Offline intel DBs (cvexref.py) must never import network modules in the
  correlate path and must skip with 'no version' when a banner lacks an
  exact version — guessing from a versionless fingerprint is a false
  positive by construct.
- Report engine (omega/report.py): always sanitize+dedupe findings first
  (sanitize_findings), then write_report infers format from the extension
  (.md/.html/.json/.docx/.pdf); docx/pdf are BINARY formats that need
  --out (python-docx / reportlab, ImportError contained as ReportError).
  CLI: `omega report <session|-> --format F --out PATH` ('-' = latest
  session).

## Test-fixture pitfalls (hermetic HTTP/DNS tests)
- Assert finding `source` values with the EXACT slug the module emits — grep
  the module for the real source string (e.g. the boolean SQLi source is
  'omega-offense/sqli_boolean', not 'omega-offense/sqli') before writing the
  test filter. A guessed slug turns a working module into a failing test.
- Shape-scanning adapters (URL/payload pattern checks in Go/Ruby/Node/C) must
  URL-decode path+query BEFORE matching and run every check against the
  DECODED strings — payloads arrive percent-encoded (%27, %7B) and raw-string
  matching misses them entirely; an adapter that mixes raw `url` and decoded
  path/query silently skips half its checks.
- '//' inside a URL is NOT an open-redirect shape by itself — it is the
  scheme separator. Match scheme-relative redirects as path startswith('//')
  or '../' in the path; matching '//' anywhere in the raw URL false-positives
  on every http:// URL (a real FP that a real-toolchain test caught).
- Canned-binary fakes (monkeypatched subprocess.run) must replicate the real
  binary's semantics, not just its output shape — a fake that skips URL
  decoding passes the canned tests while the real-toolchain test fails.
  Always pair fakes with one real-binary integration test guarded by
  which(toolchain) skip; the toolchain is often present even after a reset.
- A fetch stub for tests must NOT follow redirects — build a urllib opener
  with HTTPRedirectHandler.redirect_request returning None. urllib.urlopen
  silently follows 3xx, so the final response loses the Set-Cookie/Location
  the success detector needs and every brute/redirect test fails with
  'exhausted' even when the module logic is correct.
- BaseHTTPRequestHandler injects its own 'Server:' header via send_response —
  override send_response in the fixture class when a test asserts banner
  headers, or the fixture's banner is doubled.
- Match fixture responses to the MODULE's real payload shapes: grep the
  payload constants first (e.g. boolean SQLi payloads are quote-based
  "' OR '1'='1", not numeric "1 AND 1=1") — a fixture built on guessed
  payload forms makes the differential never fire and looks like a module
  bug when it is a fixture bug.
- When adding fusion SUITES, grep tests/ for 'len(fz.SUITES) ==' and update
  the stale count assertion (test_deepchecks.py TestFusionIntegration) in the
  same change — otherwise the failure only surfaces in the final full-suite
  run, a 6+ minute cycle.
- Builder-dispatch convention: parallel agents create modules + tests ONLY;
  the parent does all brain/fusion/cli wiring afterwards in one pass. This
  avoids sibling write conflicts on shared files and guarantees the wiring
  happens exactly once.

## Fusion layer facts
- fusion.fuse() runs scanner suites CONCURRENTLY (ThreadPool, max 6 workers)
  and every suite is individually contained — one raising never kills the
  rest. New scanners plug in as additional suites, keeping the fuse()
  signature compatible.
- Corroboration rule: a finding seen by >= 2 DISTINCT source prefixes gets
  corroborated=True + confidence 'high' + note 'corroborated by: <sources>'.
  The verification LABEL is never upgraded to confirmed by corroboration —
  that is the honesty contract and is asserted in tests.
- jq hygiene pass (adapters/validate.jq) quarantines malformed findings into
  skipped; do not bypass it when adding scanners.
- Perl adapter pipes JSON lines through adapters/analyze.pl (JSON::PP, real
  perl run); check `perl -c analyze.pl` after editing it.

## Naming (user-owned)
- Never brand a project with a reference project's name (reference tools are
  inspiration credit at most, one docstring mention). Ask the user to pick
  names for new projects; they chose OMEGA (headless, no web UI) with
- Version bumps stay under user command — do not bump numbers unasked.

## Polyglot layer facts
- Go microtools compile on demand to ~/.cache/omega/bin (rebuild on source
  mtime change); Node scripts are plain .mjs run offline.
- Brain capabilities reference gates gracefully: gate closed = a history
  note, not an error.
