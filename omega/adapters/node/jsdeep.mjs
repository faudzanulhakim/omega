#!/usr/bin/env node
// jsdeep.mjs — deep static JS analysis for OMEGA (no network, no deps).
// Reads a JS bundle from stdin, emits NDJSON (one JSON object per line):
//   {"kind":"endpoint"|"secret"|"sourcemap"|"host"|"operation",
//    "value":str, "line_no":n, "evidence":str}
// Kinds:
//   endpoint   — absolute/relative API paths, fetch/axios/XHR calls,
//                template literals containing URLs
//   secret     — AWS AKIA keys, Google AIza keys, JWT-ish tokens, private
//                key headers, generic password/secret/token/key assignments
//                (non-test vars only)
//   sourcemap  — //# sourceMappingURL= references
//   host       — hardcoded hostnames
//   operation  — GraphQL/REST operation names (query/mutation/subscription)
// Caps output at 2000 records so a minified bundle cannot flood stdout.

import { readFileSync } from "node:fs";

const MAX_RECORDS = 2000;

const SECRET_PATTERNS = [
  { id: "aws_access_key", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: "google_api_key", re: /\bAIza[0-9A-Za-z_\-]{35}\b/g },
  { id: "private_key_header",
    re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g },
  { id: "jwt_token",
    re: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g },
  // Generic assignment: var named password/secret/token/key/api key holding
  // a non-trivial literal. Skip test/mock/example/placeholder vars.
  { id: "generic_assignment",
    re: /\b([A-Za-z_$][\w$]{0,60}(?:[Pp]assword|[Ss]ecret|[Tt]oken|API_?[Kk]ey|apiKey|[Aa]uth))\b["']?\s*[:=]\s*(["'`])([^"'`\n]{8,})\2/g,
    testVar: /test|mock|example|placeholder|sample|dummy|xxx|TODO|spec/i },
];

const ENDPOINT_PATTERNS = [
  { id: "absolute_url", re: /["'`](https?:\/\/[^\s"'`<>]{4,300})["'`]/g },
  { id: "fetch_call", re: /\bfetch\s*\(\s*["'`](\/[^\s"'`<>]{1,300})["'`]/g },
  { id: "axios_call",
    re: /\baxios(?:\s*\.\s*\w+)?\s*\(\s*["'`](\/[^\s"'`<>]{1,300})["'`]/g },
  { id: "xhr_open",
    re: /\.open\s*\(\s*["'`](?:GET|POST|PUT|DELETE|PATCH|HEAD)["'`]\s*,\s*["'`]([^"'`\s<>]{1,300})["'`]/gi },
  { id: "url_property",
    re: /\b(?:url|baseURL|endpoint)\s*[:=]\s*["'`](\/[^\s"'`<>]{2,300})["'`]/gi },
  { id: "template_url", re: /`(https?:\/\/[^`\n]{4,300})`/g },
  { id: "api_path_literal", re: /["'`](\/(?:api|v[1-9]|rest|service)\/[^\s"'`<>]{1,300})["'`]/gi },
];

const SOURCEMAP_RE = /\/\/[#@]\s*sourceMappingURL=([^\s*]+)/g;
const HOST_RE = /https?:\/\/([a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,})/g;
const OPERATION_RE = /\b(query|mutation|subscription)\s+([A-Za-z_]\w{1,80})/g;

function lineOf(js, idx) {
  let n = 1;
  for (let i = 0; i < idx && i < js.length; i++) {
    if (js.charCodeAt(i) === 10) n++;
  }
  return n;
}

function lineText(js, idx, max = 300) {
  let start = js.lastIndexOf("\n", idx - 1) + 1;
  let end = js.indexOf("\n", idx);
  if (end === -1) end = js.length;
  const line = js.slice(start, end).trim();
  return line.length > max ? line.slice(0, max - 3) + "..." : line;
}

function emit(out, kind, value, js, idx) {
  if (out.length >= MAX_RECORDS) return;
  out.push({
    kind,
    value: String(value).slice(0, 300),
    line_no: lineOf(js, idx),
    evidence: lineText(js, idx),
  });
}

function main() {
  let js = "";
  try {
    js = readFileSync(0, "utf8");
  } catch {
    process.exit(0);
  }
  const out = [];
  let m;

  for (const p of SECRET_PATTERNS) {
    SECRET_RE: while ((m = p.re.exec(js)) !== null) {
      if (p.testVar && p.testVar.test(m[1] || "")) continue SECRET_RE;
      emit(out, "secret", p.id + ":" + (m[0].length > 64
        ? m[0].slice(0, 64) + "…" : m[0]), js, m.index);
    }
  }
  for (const p of ENDPOINT_PATTERNS) {
    while ((m = p.re.exec(js)) !== null) {
      const v = m[1];
      if (!v || v.startsWith("//") || v.startsWith("data:")) continue;
      emit(out, "endpoint", v, js, m.index);
    }
  }
  while ((m = SOURCEMAP_RE.exec(js)) !== null) {
    emit(out, "sourcemap", m[1], js, m.index);
  }
  while ((m = HOST_RE.exec(js)) !== null) {
    emit(out, "host", m[1], js, m.index);
  }
  while ((m = OPERATION_RE.exec(js)) !== null) {
    emit(out, "operation", m[1] + " " + m[2], js, m.index);
  }

  for (const rec of out) process.stdout.write(JSON.stringify(rec) + "\n");
}

main();
