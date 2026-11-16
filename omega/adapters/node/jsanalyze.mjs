#!/usr/bin/env node
// jsanalyze.mjs — static JS analysis for OMEGA (no network).
// Usage: node jsanalyze.mjs <file.js>
// Prints JSON: {"endpoints":[],"secrets":[],"api_routes":[]}
//   endpoints  — fetch/axios URLs and string-literal path endpoints
//   secrets    — high-entropy candidates (>=20 chars, Shannon >= 3.5, cap 50)
//   api_routes — /api/... style paths
import { readFileSync } from "node:fs";

function shannon(s) {
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const c of freq.values()) h -= (c / s.length) * Math.log2(c / s.length);
  return h;
}

function main() {
  const out = { endpoints: [], secrets: [], api_routes: [] };
  const file = process.argv[2];
  if (!file) {
    console.log(JSON.stringify(out));
    return;
  }
  let js = "";
  try {
    js = readFileSync(file, "utf8");
  } catch {
    console.log(JSON.stringify(out));
    return;
  }

  const endpoints = new Set();
  const apiRoutes = new Set();

  // fetch("...") / fetch(`...`) / axios.get("...") / axios({url: "..."})
  const callPatterns = [
    /\bfetch\s*\(\s*["'`]([^"'`\s]+)["'`]/g,
    /\baxios(?:\.\w+)?\s*\(\s*(?:\{[^}]*url\s*:\s*)?["'`]([^"'`\s]+)["'`]/g,
    /\baxios\s*\.\s*(get|post|put|delete|patch|head)\s*\(\s*["'`]([^"'`\s]+)["'`]/g,
    /\burl\s*:\s*["'`](\/[^"'`\s]+)["'`]/g,
  ];
  for (const re of callPatterns) {
    let m;
    while ((m = re.exec(js)) !== null) {
      const u = m[2] !== undefined && m[1] !== undefined && m[0].startsWith("axios") ? m[2] : m[1];
      if (u && !u.startsWith("data:") && u.length <= 300) endpoints.add(u);
    }
  }
  // string-literal path endpoints
  const pathRe = /["'`](\/[A-Za-z0-9_\-./]{3,120})["'`]/g;
  let m;
  while ((m = pathRe.exec(js)) !== null) {
    const ep = m[1];
    if (ep.startsWith("//")) continue;
    if (/^\/[\w.\-]+(\/[\w.\-]+)*$/.test(ep)) endpoints.add(ep);
    if (/^\/api\b/i.test(ep)) apiRoutes.add(ep);
  }
  for (const e of endpoints) if (/\/api\b/i.test(e)) apiRoutes.add(e);

  // high-entropy secret candidates: quoted runs of token-ish chars
  const secrets = [];
  const tokRe = /["'`]([A-Za-z0-9+/=_\-]{20,})["'`]/g;
  while ((m = tokRe.exec(js)) !== null) {
    const tok = m[1];
    if (tok.length >= 20 && shannon(tok) >= 3.5) {
      secrets.push({ value: tok.slice(0, 32) + (tok.length > 32 ? "…" : ""), length: tok.length });
      if (secrets.length >= 50) break;
    }
  }

  out.endpoints = [...endpoints].sort().slice(0, 500);
  out.api_routes = [...apiRoutes].sort().slice(0, 200);
  out.secrets = secrets;
  console.log(JSON.stringify(out));
}

main();
