// pathscope.rs — OMEGA polyglot Rust adapter (compiled with rustc -O).
//
// Pure computation, NO network access. Reads candidate path strings
// (one per line) on stdin and emits one NDJSON object per path:
//   {"raw": "...", "normalized": "...", "traversal_risk": bool,
//    "encoded": bool, "score": u32, "escapes_root": bool}
//
// Normalization: percent-decode (%2e/%2f/%5c), backslash -> slash,
// collapse duplicate slashes, then resolve "." and ".." segments.
// A path whose normalization leaves leading ".." segments escapes the
// web root (traversal risk); the score ramps with escape depth
// (0 = clean, 100 = multi-level escape). Encoded traversal sequences
// (%2e%2e, ..%2f, %5c) are flagged separately for downstream triage.
use std::io::{self, BufRead, Write};

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| -> Option<u8> {
                match c {
                    b'0'..=b'9' => Some(c - b'0'),
                    b'a'..=b'f' => Some(c - b'a' + 10),
                    b'A'..=b'F' => Some(c - b'A' + 10),
                    _ => None,
                }
            };
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn normalize(raw: &str) -> (String, bool, bool, bool) {
    let encoded = raw.contains("%2e%2e")
        || raw.contains("%2E%2E")
        || raw.contains("..%2f")
        || raw.contains("..%2F")
        || raw.contains("%5c");
    // decode repeatedly (double-encoding resistance)
    let mut cur = raw.to_string();
    for _ in 0..3 {
        let dec = pct_decode(&cur);
        if dec == cur {
            break;
        }
        cur = dec;
    }
    let cur = cur.replace('\\', "/");
    let encoded = encoded || cur.contains('\\');
    // collapse duplicate slashes
    let mut collapsed = String::with_capacity(cur.len());
    let mut prev_slash = false;
    for c in cur.chars() {
        if c == '/' {
            if !prev_slash {
                collapsed.push(c);
            }
            prev_slash = true;
        } else {
            collapsed.push(c);
            prev_slash = false;
        }
    }
    // resolve . and ..
    let mut parts: Vec<&str> = Vec::new();
    let mut escapes = 0usize;
    for seg in collapsed.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.is_empty() {
                    escapes += 1;
                } else {
                    parts.pop();
                }
            }
            s => parts.push(s),
        }
    }
    let mut normalized = String::new();
    for _ in 0..escapes {
        normalized.push_str("../");
    }
    normalized.push_str(&parts.join("/"));
    let escapes_root = escapes > 0;
    (normalized, escapes_root, encoded, escapes)
}

fn score_for(escapes: usize, encoded: bool) -> u32 {
    let mut score = (escapes as u32) * 35;
    if encoded {
        score += 15;
    }
    if score > 100 {
        score = 100;
    }
    score
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut w = stdout.lock();
    for line in stdin.lock().lines() {
        let raw = match line {
            Ok(l) => l.trim().to_string(),
            Err(_) => continue,
        };
        if raw.is_empty() {
            continue;
        }
        let (normalized, escapes_root, encoded, escapes) = normalize(&raw);
        let traversal = escapes_root || (encoded && escapes_root);
        let score = score_for(escapes, encoded);
        let _ = writeln!(
            w,
            "{{\"raw\": \"{}\", \"normalized\": \"{}\", \"traversal_risk\": {}, \
             \"encoded\": {}, \"score\": {}, \"escapes_root\": {}}}",
            json_escape(&raw),
            json_escape(&normalized),
            traversal,
            encoded,
            score,
            escapes_root
        );
    }
}
