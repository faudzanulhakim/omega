// dirscan — fast differential path scanner for OMEGA (read-only recon).
//
// Input (JSON on stdin):
//   {"target": "http://host:port", "paths": ["/admin", "/backup.sql"],
//    "probe": "/omega-<random-hex>"}   // probe optional
//
// Behaviour: concurrent GETs (worker pool 16, per-request 4s timeout,
// hard cap 120 paths). One probe request first establishes the site's
// "not found" baseline body. Each path is then classified:
//   exists    — HTTP 200 AND body differs from the baseline by > 40 chars
//   protected — HTTP 403
//   missing   — HTTP 404, or 200 whose body matches the baseline
//               (length delta <= 40 AND <= 40 differing bytes)
//   other     — any other status
// For every path the Content-Type and the first 200 chars of the body
// are captured.
//
// Output (JSON on stdout):
//   {"results": [{"path","status","class","ctype","snippet"}]}
//
// Pure stdlib. GET only; nothing is modified on the target.

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const (
	workers     = 16
	reqTimeout  = 4 * time.Second
	maxPaths    = 120
	snippetLen  = 200
	diffPercent = 40 // "differs by more than N chars"
)

type scanInput struct {
	Target string   `json:"target"`
	Paths  []string `json:"paths"`
	Probe  string   `json:"probe"`
}

type scanResult struct {
	Path    string `json:"path"`
	Status  int    `json:"status"`
	Class   string `json:"class"`
	Ctype   string `json:"ctype"`
	Snippet string `json:"snippet"`
}

type scanOutput struct {
	Results []scanResult `json:"results"`
}

// fetchURL performs a single GET with the shared client.
func fetchURL(client *http.Client, url string) (int, string, []byte) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, "", nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap 1 MiB
	ctype := resp.Header.Get("Content-Type")
	return resp.StatusCode, ctype, body
}

// bodyDiffCount returns how many bytes differ between two bodies when
// compared positionally up to the shorter length, plus the length delta.
// Total "difference" = positional diffs + length delta. Keeping it simple
// and allocation-free: for the common case (custom 404 page vs real page)
// the length delta alone dominates.
func bodyDiffCount(a, b []byte) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	// positional differences over the overlap
	overlap := len(a)
	if len(b) < overlap {
		overlap = len(b)
	}
	pos := 0
	for i := 0; i < overlap; i++ {
		if a[i] != b[i] {
			pos++
		}
	}
	return pos + (n - overlap)
}

// classify maps a response to its class using the baseline body.
func classify(status int, body, baseline []byte) string {
	switch status {
	case 403:
		return "protected"
	case 404:
		return "missing"
	case 200:
		if bodyDiffCount(body, baseline) > diffPercent {
			return "exists"
		}
		return "missing" // 200 but identical to the fallback page
	default:
		return "other"
	}
}

func main() {
	var in scanInput
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		json.NewEncoder(os.Stdout).Encode(scanOutput{Results: []scanResult{}})
		return
	}
	if len(in.Paths) > maxPaths {
		in.Paths = in.Paths[:maxPaths]
	}
	probe := in.Probe
	if probe == "" {
		// random probe path when the caller did not supply one
		h := make([]byte, 8)
		_, _ = rand.Read(h)
		probe = "/omega-" + hex.EncodeToString(h)
	}

	client := &http.Client{Timeout: reqTimeout}

	// baseline: what a definitely-nonexistent path returns
	_, _, baseline := fetchURL(client, in.Target+probe)
	if baseline == nil {
		baseline = []byte{}
	}

	out := scanOutput{Results: []scanResult{}}
	jobs := make(chan string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for p := range jobs {
			st, ctype, body := fetchURL(client, in.Target+p)
			snippet := ""
			if len(body) > snippetLen {
				snippet = string(body[:snippetLen])
			} else {
				snippet = string(body)
			}
			mu.Lock()
			out.Results = append(out.Results, scanResult{
				Path:    p,
				Status:  st,
				Class:   classify(st, body, baseline),
				Ctype:   ctype,
				Snippet: snippet,
			})
			mu.Unlock()
		}
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}
	for _, p := range in.Paths {
		jobs <- p
	}
	close(jobs)
	wg.Wait()

	_ = json.NewEncoder(os.Stdout).Encode(out)
}
