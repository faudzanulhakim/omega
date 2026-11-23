// jsmine — OMEGA JavaScript bundle miner (Go core).
//
// Downloads the JS assets referenced by a page (plus any explicitly
// supplied URLs) and mines: API endpoints/paths, absolute internal
// URLs, secret patterns (AWS keys, JWTs, private tokens), debug flags.
// Read-only GETs only. Secrets are reported as TYPE + short prefix
// context, never the full value.
//
// Input (JSON stdin):
//   {"target":"http://h","js_urls":["/static/app.js"],"timeout_ms":3000}
//
// Output (JSON stdout):
//   {"endpoints":[...],"urls":[...],"secrets":[{"kind","hint","file"}],
//    "debug":{...},"files_scanned":N}
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type input struct {
	Target    string   `json:"target"`
	JsUrls    []string `json:"js_urls"`
	TimeoutMs int      `json:"timeout_ms"`
}

type secretHit struct {
	Kind string `json:"kind"`
	Hint string `json:"hint"`
	File string `json:"file"`
}

var (
	scriptRe = regexp.MustCompile(
		`(?:src)=["']([^"']+\.js[^"']*)["']`)
	endpointRe = regexp.MustCompile(
		`["']((?:/|~/)[a-zA-Z0-9_\-/.]{2,60})["']`)
	absUrlRe = regexp.MustCompile(
		`["']https?://[a-zA-Z0-9._-]+(?:\.[a-z]{2,})[^"']{0,80}["']`)
	secretRes = []struct {
		kind string
		re   *regexp.Regexp
	}{
		{"aws-access-key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}`)},
		{"github-token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)},
		{"slack-token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},
		{"google-api-key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{30,}`)},
		{"private-key-block", regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`)},
		{"bearer-secret", regexp.MustCompile(`(?i)(?:bearer|authorization)['":\s=]+[A-Za-z0-9_-]{20,}`)},
		{"api-key-assign", regexp.MustCompile(`(?i)api[_-]?key['":\s=]+['"][A-Za-z0-9_-]{16,}['"]`)},
		{"db-url", regexp.MustCompile(`(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'"<>]{6,80}`)},
	}
	debugRes = map[string]*regexp.Regexp{
		"debug-flag":  regexp.MustCompile(`(?i)(?:isDebug|DEBUG_MODE|debugEnabled)\s*[:=]\s*(?:true|1)`),
		"sourcemap":   regexp.MustCompile(`sourceMappingURL=`),
		"console-log": regexp.MustCompile(`console\.log\(`),
	}
)

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

func main() {
	raw, _ := io.ReadAll(bufio.NewReaderSize(os.Stdin, 1<<22))
	var in input
	if err := json.Unmarshal(raw, &in); err != nil || in.Target == "" {
		emit(map[string]interface{}{"error": "invalid input"})
		return
	}
	base := strings.TrimRight(in.Target, "/")
	if !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}
	timeout := 3 * time.Second
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	client := &http.Client{Timeout: timeout}
	get := func(url string) string {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return ""
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; browser)")
		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 6<<20))
		return string(body)
	}

	// collect JS urls: explicit + discovered from HTML
	urls := []string{}
	seen := map[string]bool{}
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	for _, u := range in.JsUrls {
		add(u)
	}
	html := get(base + "/")
	for _, m := range scriptRe.FindAllStringSubmatch(html, 12) {
		u := m[1]
		switch {
		case strings.HasPrefix(u, "http"):
			// cross-origin asset: keep only same-host to stay in scope
			if strings.HasPrefix(u, base) {
				add(strings.TrimPrefix(u, base))
			}
		case strings.HasPrefix(u, "//"):
			continue // protocol-relative, other host — out of scope
		default:
			add(u)
		}
	}
	if len(urls) > 30 {
		urls = urls[:30]
	}

	// mine concurrently
	endpoints := map[string]bool{}
	absUrls := map[string]bool{}
	secrets := []secretHit{}
	debug := map[string]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, u := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			body := get(base + u)
			if body == "" {
				return
			}
			var localEp, localAbs []string
			var localSec []secretHit
			localDbg := map[string]int{}
			for _, m := range endpointRe.FindAllStringSubmatch(body, 200) {
				p := m[1]
				if strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".css") ||
					strings.HasSuffix(p, ".png") || strings.HasSuffix(p, ".ico") ||
					strings.HasSuffix(p, ".svg") || strings.HasSuffix(p, ".woff") {
					continue
				}
				localEp = append(localEp, p)
			}
			for _, m := range absUrlRe.FindAllStringSubmatch(body, 60) {
				localAbs = append(localAbs,
					strings.Trim(m[0], `"'`))
			}
			for _, s := range secretRes {
				for _, m := range s.re.FindAllString(body, 3) {
					localSec = append(localSec, secretHit{
						Kind: s.kind,
						Hint: m[:min(len(m), 18)] + "…",
						File: u})
				}
			}
			for name, re := range debugRes {
				if n := len(re.FindAllString(body, 50)); n > 0 {
					localDbg[name] = n
				}
			}
			mu.Lock()
			defer mu.Unlock()
			for _, p := range localEp {
				endpoints[p] = true
			}
			for _, p := range localAbs {
				absUrls[p] = true
			}
			secrets = append(secrets, localSec...)
			for k, v := range localDbg {
				debug[k] += v
			}
		}(u)
	}
	wg.Wait()

	toList := func(m map[string]bool) []string {
		out := []string{}
		for k := range m {
			out = append(out, k)
		}
		return out
	}
	emit(map[string]interface{}{
		"target": in.Target, "files_scanned": len(urls),
		"endpoints": toList(endpoints), "urls": toList(absUrls),
		"secrets": secrets, "debug": debug,
	})
}
