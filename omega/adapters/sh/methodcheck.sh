#!/usr/bin/env bash
# methodcheck.sh — OMEGA polyglot bash adapter.
#
# HTTP method audit for one URL: probes GET/HEAD/OPTIONS/POST (empty,
# body-safe POST) and TRACE with curl -X, reporting status + Allow
# header per method as NDJSON:
#   {"method": "GET", "status": 200, "allow": "GET, HEAD"}
#
# Read-only: no destructive payloads, no file writes, hard timeouts.
set -u

URL="${1:?usage: methodcheck.sh <url>}"
TIMEOUT="${OMEGA_METHOD_TIMEOUT:-8}"
CURL_BIN="${OMEGA_CURL:-curl}"

emit() {  # emit <method> <status> <allow>
    local m="$1" st="$2" al="$3"
    al="${al//\\/\\\\}"; al="${al//\"/\\\"}"
    printf '{"method": "%s", "status": %s, "allow": "%s"}\n' \
        "$m" "$st" "$al"
}

# probe <method> [extra curl args...]
probe() {
    local m="$1"; shift
    local out status allow
    out=$("$CURL_BIN" -s -o /dev/null -D - -X "$m" \
          --max-time "$TIMEOUT" "$@" "$URL" 2>/dev/null | tr -d '\r')
    status=$(printf '%s\n' "$out" | awk 'NR==1 && $1 ~ /^HTTP/ {print $2; exit}')
    allow=$(printf '%s\n' "$out" \
            | awk -F': ' 'tolower($1)=="allow" {print $2}' | tail -1)
    [ -z "$status" ] && status=0
    emit "$m" "$status" "${allow:-}"
}

probe GET
probe HEAD
probe OPTIONS
probe POST -d '' -H 'Content-Type: application/x-www-form-urlencoded'
probe TRACE
