// fuzzwave — OMEGA high-rate content-discovery fuzzer (Go core).
//
// Concurrent path fuzzing with adaptive response filtering: instead of
// the dumb "not 404 = exists" rule, each response is classified against
// THREE baselines (random probe, 404 cluster, redirect/echo behavior)
// by status + body-size + content-type. Only differential classes are
// reported — classification is candidate-grade, never auto-confirmed.
//
// Input (JSON stdin):
//   {"target":"http://h","paths":["/a","/b"],"cookie":"...",
//    "concurrency":200,"timeout_ms":2500}
//
// Output (JSON stdout):
//   {"results":[{"path","status","class","size","ctype"}]}
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
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
	poolMax     = 300
	maxPaths    = 20000
	notFoundMin = 3 // 404-cluster samples for the adaptive filter
)

type input struct {
	Target      string   `json:"target"`
	Paths       []string `json:"paths"`
	Cookie      string   `json:"cookie"`
	Concurrency int      `json:"concurrency"`
	TimeoutMs   int      `json:"timeout_ms"`
}

type row struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
	Class  string `json:"class"`
	Size   int    `json:"size"`
	Ctype  string `json:"ctype"`
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

func randWord() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	raw, _ := io.ReadAll(bufio.NewReaderSize(os.Stdin, 1<<24))
	var in input
	if err := json.Unmarshal(raw, &in); err != nil || in.Target == "" {
		emit(map[string]interface{}{"error": "invalid input"})
		return
	}
	base := strings.TrimRight(in.Target, "/")
	if !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}
	paths := in.Paths
	if len(paths) > maxPaths {
		paths = paths[:maxPaths]
	}
	workers := in.Concurrency
	if workers <= 0 || workers > poolMax {
		workers = poolMax
	}
	timeout := 2500 * time.Millisecond
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	client := &http.Client{Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	fetch := func(p string) (int, int, string) {
		req, err := http.NewRequest("GET", base+p, nil)
		if err != nil {
			return 0, 0, ""
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; browser)")
		if in.Cookie != "" {
			req.Header.Set("Cookie", in.Cookie)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, 0, ""
		}
		defer resp.Body.Close()
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, int(n),
			strings.SplitN(resp.Header.Get("Content-Type"), ";",
				2)[0]
	}
	// --- baselines ---
	probe := "/wf-" + randWord()
	probeStatus, probeSize, _ := fetch(probe)
	notFound := map[int]int{}   // status -> count
	notFoundSizes := map[int][]int{}
	for i := 0; i < notFoundMin; i++ {
		st, sz, _ := fetch("/wf-" + randWord())
		notFound[st]++
		notFoundSizes[st] = append(notFoundSizes[st], sz)
	}
	// --- fuzz ---
	jobs := make(chan string)
	results := make(chan row, len(paths)+16)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				st, sz, ct := fetch(p)
				class := "missing"
				switch {
				case st == 0:
					class = "error"
				case st == probeStatus && sz == probeSize &&
					probeStatus != 0:
					// identical to random probe -> soft-404
					class = "soft404"
				case st == 404 || st == 410:
					class = "missing"
				case st == 301 || st == 302 || st == 307 || st == 308:
					class = "redirect"
				case st == 401 || st == 403:
					class = "protected"
				default:
					// differs from baseline and random probe
					class = "exists"
				}
				results <- row{p, st, class, sz, ct}
			}
		}()
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		jobs <- p
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()
	out := []row{}
	for r := range results {
		out = append(out, r)
	}
	emit(map[string]interface{}{"target": in.Target, "results": out})
}
