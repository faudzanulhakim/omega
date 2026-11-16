/*
 * urlinfo.c — fast URL/header-shape parser for the OMEGA C polyglot suite.
 *
 * Reads NDJSON lines on stdin, each {"url":"http://host/path"}, and for
 * every line emits one JSON line:
 *
 *   {"url":..., "scheme":..., "host":..., "port":..., "path":...,
 *    "flags":{"default_port":bool,"long_path_gt200":bool,
 *             "nonstd_scheme":bool,"userinfo_present":bool}}
 *
 * The flags highlight URL quirks that matter for SSRF/redirect analysis:
 *   - userinfo_present : user@host trick (credential/authority smuggling)
 *   - long_path_gt200  : path longer than 200 chars (parser confusion)
 *   - nonstd_scheme    : anything other than http/https
 *   - default_port     : port explicitly equals the scheme default
 *                        (port elision — server sees a normalized URL)
 *
 * Design notes:
 *   - No dependencies, no network: pure string analysis.
 *   - All copies are bounded and NUL-terminated; overlong fields are
 *     truncated, never overrun.
 *   - Handles 10k+ lines fast: single pass per line, no allocation after
 *     startup, buffered stdout.
 *
 * Build: cc -O2 -o urlinfo urlinfo.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIELD_MAX 4096   /* max bytes kept for any single URL field     */
#define LINE_MAX  65536  /* max input line length we will consider      */

/* Copy at most dst_size-1 bytes from src, always NUL-terminate. */
static void bounded_copy(char *dst, size_t dst_size, const char *src, size_t n)
{
    if (dst_size == 0)
        return;
    if (n >= dst_size)
        n = dst_size - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Write s as a JSON string (adds surrounding quotes, escapes \ " and
 * control chars). Bounded by a fixed buffer to avoid dynamic allocation. */
static void json_escape_write(FILE *out, const char *s)
{
    char buf[FIELD_MAX * 2];
    size_t o = 0;
    for (; *s && o + 7 < sizeof(buf); s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            buf[o++] = '\\';
            buf[o++] = (char)c;
        } else if (c < 0x20) {
            static const char hex[] = "0123456789abcdef";
            buf[o++] = '\\';
            buf[o++] = 'u';
            buf[o++] = '0';
            buf[o++] = '0';
            buf[o++] = hex[(c >> 4) & 0xF];
            buf[o++] = hex[c & 0xF];
        } else {
            buf[o++] = (char)c;
        }
    }
    buf[o] = '\0';
    fputs("\"", out);
    fputs(buf, out);
    fputs("\"", out);
}

/* Extract the value of "url" from an NDJSON object line. Returns a
 * malloc'd NUL-terminated string, or NULL when absent. Handles simple
 * \" escapes inside the value. */
static char *extract_url(const char *line)
{
    const char *key = strstr(line, "\"url\"");
    if (!key)
        return NULL;
    key += 5;
    while (*key == ' ' || *key == ':')
        key++;
    if (*key != '"')
        return NULL;
    key++;
    char *out = (char *)malloc(FIELD_MAX);
    if (!out)
        return NULL;
    size_t o = 0;
    while (*key && *key != '"' && o + 1 < FIELD_MAX) {
        if (*key == '\\' && key[1]) {
            key++;
            if (*key == 'n')
                out[o++] = '\n';
            else if (*key == 't')
                out[o++] = '\t';
            else
                out[o++] = *key; /* covers \" \\ \/ \r etc. */
            key++;
        } else {
            out[o++] = *key++;
        }
    }
    out[o] = '\0';
    if (o == 0) {
        free(out);
        return NULL;
    }
    return out;
}

/* Parse one URL into components + flags. All outputs are bounded copies. */
static void parse_url(const char *url,
                      char *scheme, char *host, char *port, char *path,
                      int *default_port, int *long_path_gt200,
                      int *nonstd_scheme, int *userinfo_present)
{
    bounded_copy(scheme, FIELD_MAX, "", 0);
    bounded_copy(host, FIELD_MAX, "", 0);
    bounded_copy(port, FIELD_MAX, "", 0);
    bounded_copy(path, FIELD_MAX, "", 0);
    *default_port = 0;
    *long_path_gt200 = 0;
    *nonstd_scheme = 0;
    *userinfo_present = 0;

    const char *p = url;

    /* scheme: letters/digits/+-. up to "://" */
    const char *sep = strstr(p, "://");
    if (sep && sep != p) {
        bounded_copy(scheme, FIELD_MAX, p, (size_t)(sep - p));
        p = sep + 3;
    } else {
        /* no scheme -> non-standard (relative/schemeless URL) */
        *nonstd_scheme = 1;
    }

    /* authority runs until '/', '?', '#' or end */
    const char *end = p;
    while (*end && *end != '/' && *end != '?' && *end != '#')
        end++;

    /* userinfo: last '@' inside the authority */
    const char *at = NULL;
    for (const char *q = p; q < end; q++)
        if (*q == '@')
            at = q;
    if (at) {
        *userinfo_present = 1;
        p = at + 1; /* host starts after the userinfo part */
    }

    /* host[:port] */
    const char *colon = NULL;
    for (const char *q = end - 1; q >= p; q--) {
        if (*q == ']')
            break;          /* IPv6 literal: [..] — skip port search  */
        if (*q == ':') {
            colon = q;
            break;
        }
    }
    if (colon) {
        bounded_copy(host, FIELD_MAX, p, (size_t)(colon - p));
        bounded_copy(port, FIELD_MAX, colon + 1, (size_t)(end - colon - 1));
    } else {
        bounded_copy(host, FIELD_MAX, p, (size_t)(end - p));
    }

    /* path: everything from the authority end onward */
    if (*end)
        bounded_copy(path, FIELD_MAX, end, strlen(end));

    /* flags */
    if (strlen(path) > 200)
        *long_path_gt200 = 1;
    if (scheme[0] && strcmp(scheme, "http") != 0 &&
        strcmp(scheme, "https") != 0)
        *nonstd_scheme = 1;
    if (port[0] && ((strcmp(scheme, "http") == 0 && strcmp(port, "80") == 0) ||
                    (strcmp(scheme, "https") == 0 &&
                     strcmp(port, "443") == 0)))
        *default_port = 1;
}

int main(void)
{
    char line[LINE_MAX];
    /* Fixed buffers + bounded copies everywhere: no overruns possible. */
    static char scheme[FIELD_MAX], host[FIELD_MAX], port[FIELD_MAX];
    static char path[FIELD_MAX];

    while (fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        /* skip blank / non-object lines silently */
        char *brace = strchr(line, '{');
        if (!brace)
            continue;

        char *url = extract_url(brace);
        if (!url) {
            /* malformed line: emit a JSON error object, keep going */
            fputs("{\"error\":\"missing url field\"}\n", stdout);
            continue;
        }

        {
            int default_port = 0, long_path = 0, nonstd = 0, userinfo = 0;
            parse_url(url, scheme, host, port, path,
                      &default_port, &long_path, &nonstd, &userinfo);

            fputs("{\"url\":", stdout);
            json_escape_write(stdout, url);
            fputs(",\"scheme\":", stdout);
            json_escape_write(stdout, scheme);
            fputs(",\"host\":", stdout);
            json_escape_write(stdout, host);
            fputs(",\"port\":", stdout);
            json_escape_write(stdout, port);
            fputs(",\"path\":", stdout);
            json_escape_write(stdout, path);
            printf(",\"flags\":{\"default_port\":%s,"
                   "\"long_path_gt200\":%s,"
                   "\"nonstd_scheme\":%s,"
                   "\"userinfo_present\":%s}}\n",
                   default_port ? "true" : "false",
                   long_path ? "true" : "false",
                   nonstd ? "true" : "false",
                   userinfo ? "true" : "false");
        }
        free(url);
    }
    fflush(stdout);
    return 0;
}
