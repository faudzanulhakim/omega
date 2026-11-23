// hdrstruct.cpp — OMEGA polyglot C++ adapter (compiled with g++ -O2).
//
// Reads NDJSON lines on stdin: {"url": "...", "headers": "<raw HTTP
// response head (status line + header block)>"}. For each line it
// parses the header block, classifies security-header presence and
// cookie flag completeness, and emits one NDJSON object:
//   {"url": ..., "flags": {has_csp, has_hsts, has_xcto, has_xfo,
//    has_referrer_policy, has_permissions_policy,
//    cookie_no_httponly, cookie_no_secure, server_with_version}}
//
// Pure text parsing: no network access, no filesystem access.
#include <iostream>
#include <string>
#include <sstream>
#include <map>

static std::string lower(const std::string &s) {
    std::string out = s;
    for (char &c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

static std::string trim(const std::string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static bool contains_ci(const std::string &hay, const std::string &needle) {
    return lower(hay).find(lower(needle)) != std::string::npos;
}

static std::string json_escape(const std::string &s) {
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (static_cast<unsigned char>(c) < 0x20) {
            std::ostringstream h;
            h << "\\u" << std::hex << static_cast<int>(c);
            out += h.str();
        } else out += c;
    }
    return out;
}

// Parse one raw response head into lowercase-name -> value map.
static void parse_headers(const std::string &head,
                          std::map<std::string, std::string> &hdrs) {
    std::istringstream in(head);
    std::string line;
    bool first = true;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty()) continue;
        if (first) { first = false; continue; }  // status line
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = lower(trim(line.substr(0, colon)));
        std::string value = trim(line.substr(colon + 1));
        // last occurrence wins (matches single-header expectations here)
        hdrs[name] = value;
    }
}

int main() {
    std::ios::sync_with_stdio(false);
    std::string line;
    while (std::getline(std::cin, line)) {
        line = trim(line);
        if (line.empty()) continue;
        // Extract "url" and "headers" values without a JSON parser:
        // both values are produced by the Python bridge with fixed key
        // order and JSON escaping, so simple prefix/suffix slicing is
        // safe and deterministic.
        std::string url, head;
        size_t u = line.find("\"url\": \"");
        if (u != std::string::npos) {
            size_t start = u + 8;
            size_t end = line.find("\", \"headers\": \"", start);
            if (end != std::string::npos) {
                url = line.substr(start, end - start);
                size_t hstart = end + 15;
                size_t hend = line.rfind('"');
                if (hend != std::string::npos && hend > hstart)
                    head = line.substr(hstart, hend - hstart);
            }
        }
        // Unescape the two escapes the bridge can emit.
        auto unesc = [](std::string s) {
            std::string out;
            for (size_t i = 0; i < s.size(); ++i) {
                if (s[i] == '\\' && i + 1 < s.size()) {
                    char n = s[++i];
                    if (n == 'n') out += '\n';
                    else if (n == 't') out += '\t';
                    else out += n;
                } else out += s[i];
            }
            return out;
        };
        url = unesc(url);
        head = unesc(head);

        std::map<std::string, std::string> hdrs;
        parse_headers(head, hdrs);

        bool cookie_flags_bad = false;
        bool cookie_no_secure = false;
        // set-cookie may repeat; the bridge folds duplicates, so we
        // scan the raw head text for every Set-Cookie line instead.
        {
            std::istringstream in(head);
            std::string hl;
            bool first2 = true;
            while (std::getline(in, hl)) {
                hl = trim(hl);
                if (first2) { first2 = false; continue; }
                size_t colon = hl.find(':');
                if (colon == std::string::npos) continue;
                std::string name = lower(trim(hl.substr(0, colon)));
                if (name != "set-cookie") continue;
                std::string value = trim(hl.substr(colon + 1));
                if (!contains_ci(value, "httponly")) cookie_flags_bad = true;
                if (!contains_ci(value, "secure")) cookie_no_secure = true;
            }
        }
        bool server_version = false;
        auto it = hdrs.find("server");
        if (it != hdrs.end()) {
            const std::string &v = it->second;
            for (char c : v) {
                if (c >= '0' && c <= '9') { server_version = true; break; }
            }
        }

        auto has = [&](const char *n) {
            return hdrs.find(n) != hdrs.end();
        };
        std::cout << "{\"url\": \"" << json_escape(url)
                  << "\", \"flags\": {"
                  << "\"has_csp\": " << (has("content-security-policy") ? "true" : "false")
                  << ", \"has_hsts\": " << (has("strict-transport-security") ? "true" : "false")
                  << ", \"has_xcto\": " << (has("x-content-type-options") ? "true" : "false")
                  << ", \"has_xfo\": " << (has("x-frame-options") ? "true" : "false")
                  << ", \"has_referrer_policy\": " << (has("referrer-policy") ? "true" : "false")
                  << ", \"has_permissions_policy\": " << (has("permissions-policy") ? "true" : "false")
                  << ", \"cookie_no_httponly\": " << (cookie_flags_bad ? "true" : "false")
                  << ", \"cookie_no_secure\": " << (cookie_no_secure ? "true" : "false")
                  << ", \"server_with_version\": " << (server_version ? "true" : "false")
                  << "}}\n";
    }
    return 0;
}
