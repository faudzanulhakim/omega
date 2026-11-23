// techprof — OMEGA technology stack profiler (Go core).
//
// Deep passive fingerprinting of a web target: meta generator, JS
// bundlers (webpack chunk hashes, sourceMappingURL), CDN edge
// signatures, service workers, asset-based framework hints, security
// headers. Read-only GETs only.
//
// Input (JSON stdin):
//   {"target":"http://h","timeout_ms":2500}
//
// Output (JSON stdout):
//   {"generator":..., "bundler":..., "cdn":..., "sw":..., "hints":[...],
//    "headers":{...}}
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
	Target    string `json:"target"`
	TimeoutMs int    `json:"timeout_ms"`
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

var (
	generatorRe = regexp.MustCompile(
		`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)`)
	webpackRe   = regexp.MustCompile(`[a-f0-9]{16,}\.chunk\.js|webpackChunk`)
	sourcemapRe = regexp.MustCompile(`sourceMappingURL=([^'"\s]+)`)
	wpContentRe = regexp.MustCompile(`/wp-content/(?:themes|plugins)/([a-z0-9_-]+)`)
	swpRe       = regexp.MustCompile(`serviceWorker\.register\(|/sw\.js`)
	assetRe     = regexp.MustCompile(`(?:src|href)=["']([^"']+\.(?:js|css))["']`)
)

var cdnHeaders = map[string]string{
	"cf-ray":             "cloudflare",
	"x-vercel-id":        "vercel",
	"x-amz-cf-id":        "cloudfront",
	"x-fastly-request":   "fastly",
	"x-served-by":        "varnish",
	"x-github-request-id": "github-pages",
	"akamai-grn":         "akamai",
	"x-cache":            "cdn-cache",
}

var securityHeaders = []string{
	"content-security-policy", "strict-transport-security",
	"x-frame-options", "x-content-type-options", "referrer-policy",
	"permissions-policy",
}

func main() {
	raw, _ := io.ReadAll(bufio.NewReaderSize(os.Stdin, 1<<20))
	var in input
	if err := json.Unmarshal(raw, &in); err != nil || in.Target == "" {
		emit(map[string]interface{}{"error": "invalid input"})
		return
	}
	base := strings.TrimRight(in.Target, "/")
	if !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}
	timeout := 2500 * time.Millisecond
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	client := &http.Client{Timeout: timeout}
	fetch := func(p string) (int, http.Header, string) {
		req, err := http.NewRequest("GET", base+p, nil)
		if err != nil {
			return 0, nil, ""
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; browser)")
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		return resp.StatusCode, resp.Header, string(body)
	}

	hints := map[string]interface{}{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	// root page analysis
	st, hdr, body := fetch("/")
	hints["root_status"] = st
	if m := generatorRe.FindStringSubmatch(body); m != nil {
		hints["generator"] = m[1]
	}
	if webpackRe.MatchString(body) {
		hints["bundler"] = "webpack"
	}
	if m := wpContentRe.FindStringSubmatch(body); m != nil {
		hints["wordpress_theme"] = m[1]
	}
	if swpRe.MatchString(body) {
		hints["service_worker"] = true
	}

	// CDN + security headers
	cdn := ""
	for h, name := range cdnHeaders {
		if hdr.Get(h) != "" {
			cdn = name
			break
		}
	}
	hints["cdn"] = cdn
	sec := map[string]string{}
	for _, h := range securityHeaders {
		sec[h] = hdr.Get(h)
	}
	hints["security_headers"] = sec
	hints["server"] = hdr.Get("Server")

	// service worker probe + first JS/CSS assets (concurrent)
	wg.Add(1)
	go func() {
		defer wg.Done()
		st2, _, b2 := fetch("/sw.js")
		if st2 == 200 && len(b2) > 0 &&
			!strings.Contains(b2[:min(200, len(b2))], "not found") {
			mu.Lock()
			hints["service_worker"] = true
			mu.Unlock()
		}
	}()
	assets := assetRe.FindAllStringSubmatch(body, 6)
	for _, a := range assets {
		url := a[1]
		if strings.HasPrefix(url, "/") {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				_, _, jsBody := fetch(u)
				if jsBody == "" {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if _, ok := hints["bundler"]; !ok && webpackRe.
					MatchString(jsBody) {
					hints["bundler"] = "webpack"
				}
				if m := sourcemapRe.FindStringSubmatch(jsBody); m != nil {
					hints["sourcemap"] = m[1]
				}
			}(url)
		}
	}
	wg.Wait()
	hints["assets"] = len(assets)
	emit(map[string]interface{}{"target": in.Target, "profile": hints})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
