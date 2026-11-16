#!/usr/bin/env node
// hdrscore.mjs — HTTP header security scorer for OMEGA (pure Node, no deps,
// no network). Reads one JSON object on stdin:
//   {"headers": {"strict-transport-security": "...", ...},
//    "url": "https://example.com/"}
// and prints one JSON object on stdout:
//   {"score": 0-100, "grade": "A"-"F",
//    "issues": [{"id": "...", "severity": "info|low|medium|high",
//                "detail": "..."}]}
//
// Scoring rubric (start at 100, deduct per missing/misconfigured control):
//   strict-transport-security missing      -20  (skipped when url is http://)
//   content-security-policy missing        -20
//   content-security-policy unsafe
//     ('unsafe-inline'/'unsafe-eval'/'*')  -10  (not stacked with missing)
//   x-frame-options missing                -15
//   referrer-policy missing                -10
//   permissions-policy missing             -10
//   x-content-type-options missing         -10
//   set-cookie without Secure/HttpOnly/
//     SameSite flags on any cookie         -15
// Grade thresholds: A >= 90, B >= 75, C >= 60, D >= 40, else F.
// When url starts with http:// (not https), the HSTS deduction is skipped
// and the hsts-missing issue is emitted with severity "info" and a detail
// starting with "n-a" (not applicable to a plaintext endpoint).
import { readFileSync } from "node:fs";

function lowerKeys(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const lk = String(k).toLowerCase();
    const sv = String(v);
    if (Object.prototype.hasOwnProperty.call(out, lk)) {
      out[lk] = out[lk] + "\n" + sv;
    } else {
      out[lk] = sv;
    }
  }
  return out;
}

function score(input) {
  const headers = lowerKeys(input.headers);
  const url = String(input.url || "");
  const isHttps = url.toLowerCase().startsWith("https://");
  const issues = [];
  let deductions = 0;

  function add(id, severity, detail, points) {
    issues.push({ id, severity, detail });
    deductions += points;
  }

  // HSTS (only deducted on https endpoints)
  if (!headers["strict-transport-security"]) {
    if (isHttps) {
      add("hsts-missing", "high",
        "strict-transport-security header missing on https endpoint", 20);
    } else {
      issues.push({
        id: "hsts-missing",
        severity: "info",
        detail: "n-a: hsts not applicable to a plaintext http:// endpoint",
      });
    }
  }

  // CSP
  const csp = headers["content-security-policy"];
  if (!csp) {
    add("csp-missing", "high", "content-security-policy header missing", 20);
  } else if (/unsafe-inline|unsafe-eval/i.test(csp) || /\*/.test(csp)) {
    add("csp-unsafe", "medium",
      "content-security-policy present but permissive "
      + "(unsafe-inline/unsafe-eval/wildcard)", 10);
  }

  // Frame deny
  if (!headers["x-frame-options"]
      && !/frame-ancestors/i.test(csp || "")) {
    add("frame-deny-missing", "medium",
      "no x-frame-options and no CSP frame-ancestors (clickjacking risk)", 15);
  }

  // Referrer policy
  if (!headers["referrer-policy"]) {
    add("referrer-missing", "low",
      "referrer-policy header missing", 10);
  }

  // Permissions policy
  if (!headers["permissions-policy"]
      && !headers["feature-policy"]) {
    add("permissions-missing", "low",
      "permissions-policy (or legacy feature-policy) header missing", 10);
  }

  // XCTO
  if (!headers["x-content-type-options"]) {
    add("cto-missing", "low",
      "x-content-type-options: nosniff missing", 10);
  }

  // Cookie flags: every Set-Cookie should carry Secure, HttpOnly, SameSite
  const rawCookies = (headers["set-cookie"] || "").split("\n")
    .map((s) => s.trim()).filter(Boolean);
  if (rawCookies.length > 0) {
    const flagged = rawCookies.every((c) =>
      /secure/i.test(c) && /httponly/i.test(c) && /samesite=/i.test(c));
    if (!flagged) {
      add("cookie-flags", "medium",
        "set-cookie without complete Secure/HttpOnly/SameSite flags", 15);
    }
  }

  const score = Math.max(0, Math.min(100, 100 - deductions));
  let grade;
  if (score >= 90) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 60) grade = "C";
  else if (score >= 40) grade = "D";
  else grade = "F";

  return { score, grade, issues };
}

let raw = "";
try {
  raw = readFileSync(0, "utf8");
} catch {
  raw = "";
}
let input = {};
try {
  input = JSON.parse(raw || "{}");
} catch {
  input = {};
}
process.stdout.write(JSON.stringify(score(input)) + "\n");
