// takeover — OMEGA subdomain takeover hunter (Go core).
//
// For each candidate hostname: resolve CNAME, classify the dangling
// target against provider fingerprints (S3, Azure, Heroku, GitHub
// Pages, Shopify, Fastly, Pantheon, Zendesk, Helpjuice). A matching
// signature on an unclaimed endpoint is candidate-grade evidence —
// never auto-confirmed; the operator validates DNS control manually.
//
// Input (JSON stdin):
//   {"hosts":["a.example.com","b.example.com"],"concurrency":50,
//    "timeout_ms":3000}
//
// Output (JSON stdout):
//   {"results":[{"host","cname","provider","signature","class"}]}
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type input struct {
	Hosts       []string `json:"hosts"`
	Concurrency int      `json:"concurrency"`
	TimeoutMs   int      `json:"timeout_ms"`
}

type row struct {
	Host      string `json:"host"`
	Cname     string `json:"cname"`
	Provider  string `json:"provider"`
	Signature string `json:"signature"`
	Class     string `json:"class"`
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

var fingerprints = []struct{ provider, marker string }{
	{"aws-s3", "NoSuchBucket"},
	{"aws-s3", "The specified bucket does not exist"},
	{"azure", "404 Web Site not found"},
	{"azure-cdn", "The request path is not found"},
	{"heroku", "No such app"},
	{"heroku", "There's nothing here, yet"},
	{"github-pages", "There isn't a GitHub Pages site here"},
	{"shopify", "Sorry, this shop is currently unavailable"},
	{"fastly", "Fastly error: unknown domain"},
	{"pantheon", "The gods are wise, but do not know of the site"},
	{"zendesk", "Help Center Closed"},
	{"helpjuice", "We could not find what you're looking for"},
	{"surge", "project not found"},
	{"bitbucket", "Repository not found"},
}

func classifyBody(body string) (string, string) {
	low := strings.ToLower(body)
	for _, fp := range fingerprints {
		if strings.Contains(low, strings.ToLower(fp.marker)) {
			return fp.provider, fp.marker
		}
	}
	return "", ""
}

func main() {
	in, _ := io.ReadAll(bufio.NewReader(io.LimitReader(os.Stdin, 1<<20)))
	var cfg input
	if err := json.Unmarshal(in, &cfg); err != nil {
		emit(map[string]string{"error": "bad json input: " + err.Error()})
		return
	}
	if len(cfg.Hosts) == 0 || len(cfg.Hosts) > 2048 {
		emit(map[string]string{"error": "1..2048 hosts required"})
		return
	}
	conc := cfg.Concurrency
	if conc <= 0 || conc > 100 {
		conc = 50
	}
	tm := cfg.TimeoutMs
	if tm <= 0 {
		tm = 3000
	}
	cl := &http.Client{Timeout: time.Duration(tm) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		}}

	results := []row{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)

	for _, h := range cfg.Hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			cname, err := net.LookupCNAME(host)
			if err != nil || cname == "" || cname == "." {
				return // no alias: not takeover-relevant here
			}
			cname = strings.TrimSuffix(cname, ".")
			if strings.EqualFold(cname, host) {
				return // self-alias: no external target
			}
			resp, err := cl.Get("http://" + cname)
			if err != nil {
				mu.Lock()
				results = append(results, row{host, cname, "", "",
					"dangling-cname-unreachable"})
				mu.Unlock()
				return
			}
			bd, _ := io.ReadAll(bufio.NewReader(io.LimitReader(resp.Body, 32768)))
			resp.Body.Close()
			prov, sig := classifyBody(string(bd))
			if prov != "" {
				mu.Lock()
				results = append(results, row{host, cname, prov, sig,
					"takeover-candidate"})
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	emit(map[string]interface{}{"results": results, "hosts": len(cfg.Hosts)})
}
