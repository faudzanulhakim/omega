// decoy — OMEGA traffic-blending noise mixer (Go core).
//
// Sends a short burst of BENIGN requests (favicon, robots.txt, static
// assets, common pages) to the target so the scan traffic pattern
// blends in with normal browsing instead of standing out to
// anomaly-based WAFs. Read-only: GET only, nothing modified.
//
// Input (JSON on stdin):
//   {"target":"http://host:port","bursts":2,"cookie":"sess=..."}
//
// Output (JSON on stdout):
//   {"sent": 14, "results":[{"path","status","ms"}]}
//
// Pure stdlib, concurrent pool 4, per-request timeout 3s.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	pool       = 4
	reqTimeout = 3 * time.Second
	maxBursts  = 10
)

var decoyPaths = []string{
	"/favicon.ico", "/robots.txt", "/sitemap.xml", "/apple-touch-icon.png",
	"/static/", "/assets/", "/css/", "/js/", "/img/", "/logo.png",
	"/manifest.json", "/humans.txt", "/security.txt", "/.well-known/",
	"/terms", "/about", "/contact",
}

type input struct {
	Target string `json:"target"`
	Bursts int    `json:"bursts"`
	Cookie string `json:"cookie"`
}

type result struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
	Ms     int64  `json:"ms"`
}

func main() {
	var in input
	r := bufio.NewReader(os.Stdin)
	raw, _ := io.ReadAll(io.LimitReader(r, 1<<20))
	if err := json.Unmarshal(raw, &in); err != nil || in.Target == "" {
		emit(map[string]interface{}{"error": "invalid input"})
		return
	}
	bursts := in.Bursts
	if bursts <= 0 {
		bursts = 2
	}
	if bursts > maxBursts {
		bursts = maxBursts
	}
	base := strings.TrimRight(in.Target, "/")
	if !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}
	client := &http.Client{Timeout: reqTimeout}
	paths := decoyPaths
	if bursts > 1 {
		// repeat the round-robin list for the extra bursts
		rep := make([]string, 0, len(decoyPaths)*bursts)
		for i := 0; i < bursts; i++ {
			rep = append(rep, decoyPaths...)
		}
		paths = rep
	}
	jobs := make(chan string)
	results := make(chan result, len(paths))
	var wg sync.WaitGroup
	for i := 0; i < pool; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				t0 := time.Now()
				st := 0
				func() {
					req, err := http.NewRequest("GET", base+p, nil)
					if err != nil {
						return
					}
					req.Header.Set("User-Agent",
						"Mozilla/5.0 (compatible; browser)")
					req.Header.Set("Accept",
						"text/html,application/xhtml+xml,image/*,*/*;q=0.8")
					if in.Cookie != "" {
						req.Header.Set("Cookie", in.Cookie)
					}
					resp, err := client.Do(req)
					if err != nil {
						return
					}
					defer resp.Body.Close()
					_, _ = io.Copy(io.Discard,
						io.LimitReader(resp.Body, 4096))
					st = resp.StatusCode
				}()
				results <- result{p, st,
					time.Since(t0).Milliseconds()}
			}
		}()
	}
	for _, p := range paths {
		jobs <- p
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()
	sent := 0
	out := []result{}
	for r := range results {
		sent++
		out = append(out, r)
	}
	emit(map[string]interface{}{"sent": sent, "results": out})
}

func emit(v map[string]interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}
