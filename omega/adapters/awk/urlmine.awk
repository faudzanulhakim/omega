# urlmine.awk — OMEGA polyglot awk adapter.
#
# Mines URL/endpoint/secret candidates from arbitrary text (HTML, JS,
# config dumps). Reads raw text on stdin, emits NDJSON on stdout:
#   {"kind": "url"|"aws_key"|"jwt"|"api_key"|"private_ip", "value": "..."}
#
# Written for maximum portability: only POSIX ERE features are used
# (no {m,n} intervals, no \b word boundaries — mawk does not support
# them); candidate strings are post-filtered in awk instead.
# "url" matches are surface intel (NOT findings); the Python bridge
# only elevates secret/private-IP kinds to findings after an FP-safe
# baseline diff. Pure text processing: no network access.
function json_escape(s) {
    gsub(/\\/, "\\\\", s);
    gsub(/"/, "\\\"", s);
    gsub(/\t/, "\\t", s);
    return s;
}

function emit(kind, value) {
    printf "{\"kind\": \"%s\", \"value\": \"%s\"}\n", kind, json_escape(value);
}

# Repeatedly apply a regex to a line; for each match run the given
# post-filter function (by name) and emit only accepted matches.
# The filter receives the raw match; return 1 to emit, 0 to drop.
# AWK (POSIX) supports indirect function calls only via arrays in
# some implementations, so filters are dispatched by kind string.
function scan_all(line, re, kind,    rest, m, ok) {
    rest = line;
    while (match(rest, re)) {
        m = substr(rest, RSTART, RLENGTH);
        ok = filter(kind, m);
        if (ok) emit(kind, m);
        rest = substr(rest, RSTART + RLENGTH);
        if (length(rest) == 0) break;
    }
}

function filter(kind, m) {
    if (kind == "aws_key")  return aws_ok(m);
    if (kind == "api_key")  return api_key_ok(m);
    if (kind == "private_ip") return ipv4_private(m);
    return 1;  # url / jwt: accept as-is
}

# AWS access key id: AKIA prefix + exactly 20 chars of [0-9A-Z].
function aws_ok(v,    i, c) {
    if (length(v) != 20) return 0;
    if (substr(v, 1, 4) != "AKIA") return 0;
    for (i = 5; i <= 20; i++) {
        c = substr(v, i, 1);
        if (c !~ /[0-9A-Z]/) return 0;
    }
    return 1;
}

# API key: captured value part must be >= 16 chars. The match may be
# shorter than 16 overall because the assignment prefix consumes some
# characters; require the trailing run to be >= 16 by matching the
# tail directly.
function api_key_ok(v,    i, n, tail) {
    n = length(v);
    tail = "";
    for (i = n; i >= 1; i--) {
        c = substr(v, i, 1);
        if (c ~ /[A-Za-z0-9_-]/) tail = c tail;
        else break;
    }
    return (length(tail) >= 16);
}

# IPv4 address: four dotted octets, each 0-255, private ranges only
# (10/8, 127/8, 192.168/16, 172.16-31).
function ipv4_private(v,    n, i, o, o1, o2, oct) {
    n = split(v, oct, ".");
    if (n != 4) return 0;
    for (i = 1; i <= 4; i++) {
        o = oct[i] + 0;
        if (o < 0 || o > 255) return 0;
        # reject zero-padded forms like 010 (leading-zero octets)
        if (length(oct[i]) > 1 && substr(oct[i], 1, 1) == "0") return 0;
    }
    o1 = oct[1] + 0; o2 = oct[2] + 0;
    if (o1 == 10) return 1;
    if (o1 == 127) return 1;
    if (o1 == 192 && o2 == 168) return 1;
    if (o1 == 172 && o2 >= 16 && o2 <= 31) return 1;
    return 0;
}

{
    line = $0;
    # Dynamic (string) regexes: mawk does not support passing regex
    # literals as function arguments, so patterns live in strings.
    # POSIX ERE only (no intervals / no \b — see header note).
    aws_re    = "AKIA[0-9A-Z]+";
    jwt_re    = "eyJ[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+";
    api_re    = "([Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|Authorization: Bearer)['\\\":= ]+[A-Za-z0-9_-]+";
    ipv4_re   = "[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+";
    url_re    = "https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+";
    # AWS key candidates: AKIA + uppercase/digits, post-filtered to len 20
    scan_all(line, aws_re, "aws_key");
    # JWT three-segment shape (eyJ header . payload . signature)
    scan_all(line, jwt_re, "jwt");
    # API key assignment / Authorization bearer candidates
    scan_all(line, api_re, "api_key");
    # Dotted quads, post-filtered to private ranges (no \b in mawk)
    scan_all(line, ipv4_re, "private_ip");
    # URLs (surface intel)
    scan_all(line, url_re, "url");
}
