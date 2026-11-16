package main

// htsweep — fast HTTP liveness sweep.
// Flags: -targets-file (one URL per line), -concurrency (default 50),
//        -timeout (ms, default 5000).
// JSON to stdout: {"alive":[{"url","status","title","server"}]}
// One GET per target; TLS certificates are NOT verified (skip-verify).

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type aliveEntry struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Title  string `json:"title"`
	Server string `json:"server"`
}

type sweepResult struct {
	Alive []aliveEntry `json:"alive"`
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func pageTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	s := string(m[1])
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func main() {
	targetsFile := ""
	concurrency := 50
	timeoutMS := 5000

	fs := os.Args[1:]
	for i := 0; i < len(fs); i++ {
		switch fs[i] {
		case "-targets-file":
			i++
			targetsFile = fs[i]
		case "-concurrency":
			i++
			concurrency = atoiOr(fs[i], 50)
		case "-timeout":
			i++
			timeoutMS = atoiOr(fs[i], 5000)
		}
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if timeoutMS < 1 {
		timeoutMS = 1
	}
	timeout := time.Duration(timeoutMS) * time.Millisecond

	raw, err := os.ReadFile(targetsFile)
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(sweepResult{Alive: []aliveEntry{}})
		return
	}
	var targets []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // nolint: gosec — recon sweep, skip-verify by design
		},
	}

	var mu sync.Mutex
	alive := []aliveEntry{}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			url := t
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				url = "http://" + url
			}
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "omega-htsweep/1.0 (read-only liveness sweep)")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			resp.Body.Close()
			entry := aliveEntry{
				URL:    url,
				Status: resp.StatusCode,
				Title:  pageTitle(body),
				Server: resp.Header.Get("Server"),
			}
			mu.Lock()
			alive = append(alive, entry)
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.Encode(sweepResult{Alive: alive})
}

func atoiOr(s string, def int) int {
	n := 0
	if s == "" {
		return def
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return def
	}
	return n
}
