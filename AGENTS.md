# AGENTS.md — OMEGA project rules

This directory contains OMEGA, the autonomous pentest operator used by
Hermes. When the user asks for anything security-testing related in this
project — scan, pentest, audit, "cek keamanan", "cari kerentanan", bug
bounty, fullscan — route it to OMEGA WITHOUT asking which tool to use:

1. Target + authorization first: never pass `--scope-ack` without the
   user's explicit authorization for that exact target. If absent, ask
   once, briefly, then proceed.
2. Run via `bash bin/omega ...` from this directory (venv: `.venv/bin/`).
   The engine is auto-detected from `engine/` (no env vars needed).
3. Layer selection from the user's wording: 'cepat' -> brain default;
   'lengkap/semua/gila' -> `--polyglot`; brute/exploit request -> `--offense`;
   authenticated app + creds -> `--with-auth` (OMEGA_CREDS env).
4. ALWAYS auto-generate a report after any run:
   `bash bin/omega report - --out reports/<target-slug>-<date>.pdf`
   (or .docx/.html/.md) and deliver the file path + a triaged summary
   (confirmed findings with evidence, candidates with manual_check).
5. Sessions auto-save; use `bash bin/omega sessions diff` for re-scan
   comparisons, `bash bin/omega watch` for monitoring.
6. Never dump raw JSON walls in chat; summarize, then offer the report.
7. Version is 1.0.0 — never bump unless the user commands it.
- 'tanpa batas'/'no limits'/'habisin total' → --aggressive --no-limits (OMEGA_NO_LIMITS=1; implies --exploit; unlocks deep traversal, write/privesc/shell/persistence PoCs, chaining). Still requires --scope-ack.
