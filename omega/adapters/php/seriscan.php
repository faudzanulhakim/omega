<?php
/**
 * seriscan.php — OMEGA polyglot PHP adapter (php-cli, stdlib only).
 *
 * Static scan of a pasted PHP snippet for dangerous call patterns:
 * unserialize(), eval(), and system() family (system/shell_exec/
 * passthru/exec/proc_open/popen). Reads the snippet from stdin,
 * emits one JSON object on stdout:
 *   {"findings": [{"kind": ..., "line": N, "match": "..."}]}
 *
 * Comment lines (// # /* * and *) are IGNORED so commented-out calls
 * never produce findings (FP guard). Pure text processing: no
 * network access, no code execution, no filesystem access beyond
 * php://input.
 */

$raw = stream_get_contents(STDIN);
if ($raw === false || $raw === '') {
    echo json_encode(["findings" => []]);
    exit(0);
}

$lines = preg_split('/\r\n|\r|\n/', $raw);
$findings = [];

$patterns = [
    'unserialize' => '/\bunserialize\s*\(/i',
    'eval'        => '/\beval\s*\(/i',
    'system'      => '/\b(?:system|shell_exec|passthru|exec|proc_open|popen)\s*\(/i',
];

foreach ($lines as $i => $line) {
    $t = ltrim($line);
    // FP guard: skip comment lines (single-line, docblock, inline opener)
    if ($t === '' || $t[0] === '/' || $t[0] === '#' || $t[0] === '*') {
        continue;
    }
    $n = $i + 1;
    foreach ($patterns as $kind => $re) {
        if (preg_match($re, $line, $m)) {
            $findings[] = [
                'kind'  => $kind,
                'line'  => $n,
                'match' => mb_substr(trim($m[0]), 0, 120),
            ];
        }
    }
}

header('Content-Type: application/json');
echo json_encode(["findings" => $findings]);
