// swarm — OMEGA distributed scan coordinator (Go core).
//
// Splits a target list across worker nodes over plain HTTP: the
// coordinator POSTs small JSON jobs ({"target":...}) to each worker's
// /job endpoint and collects back their JSON results. Workers run an
// embedded minimal engine: HTTP liveness + title + server header per
// assigned target (read-only). With zero workers, everything runs
// locally with the same engine (single-node mode).
//
// Input (JSON stdin):
//   {"targets":["http://a","http://b"],"workers":["http://w1:9999"],
//    "timeout_ms":3000}
//
// Output (JSON stdout):
//   {"results":[{"target","status","title","server","via_worker"}]}
package main

import (
	"bufio"
	"bytes"
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
	Targets   []string `json:"targets"`
	Workers   []string `json:"workers"`
	TimeoutMs int      `json:"timeout_ms"`
}

type resultRow struct {
	Target    string `json:"target"`
	Status    int    `json:"status"`
	Title     string `json:"title"`
	Server    string `json:"server"`
	ViaWorker string `json:"via_worker"`
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// localEngine: the per-target probe every worker runs (HTTP GET,
// status/title/server only). Read-only.
func localEngine(client *http.Client, target string) resultRow {
	row := resultRow{Target: target}
	base := strings.TrimRight(target, "/")
	if !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}
	req, err := http.NewRequest("GET", base+"/", nil)
	if err != nil {
		return row
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; browser)")
	resp, err := client.Do(req)
	if err != nil {
		return row
	}
	defer resp.Body.Close()
	row.Status = resp.StatusCode
	row.Server = resp.Header.Get("Server")
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if m := titleRe.FindSubmatch(body); m != nil {
		row.Title = strings.TrimSpace(string(m[1]))[:minCap(
			len(strings.TrimSpace(string(m[1]))), 200)]
	}
	return row
}

func minCap(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func remoteProbe(client *http.Client, worker, target string,
	timeout time.Duration) (resultRow, bool) {
	jobURL := strings.TrimRight(worker, "/") + "/job"
	payload, _ := json.Marshal(map[string]string{"target": target})
	req, err := http.NewRequest("POST", jobURL, bytes.NewReader(payload))
	if err != nil {
		return resultRow{}, false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return resultRow{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var row resultRow
	if json.Unmarshal(body, &row) != nil {
		return resultRow{}, false
	}
	return row, true
}

func main() {
	raw, _ := io.ReadAll(bufio.NewReaderSize(os.Stdin, 1<<24))
	var in input
	if err := json.Unmarshal(raw, &in); err != nil || len(in.Targets) == 0 {
		emit(map[string]interface{}{"error": "invalid input"})
		return
	}
	timeout := 3 * time.Second
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	client := &http.Client{Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	results := make([]resultRow, len(in.Targets))
	var wg sync.WaitGroup
	for i, t := range in.Targets {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			// round-robin workers by index
			if len(in.Workers) > 0 {
				w := in.Workers[i%len(in.Workers)]
				if row, ok := remoteProbe(client, w, t, timeout); ok {
					row.ViaWorker = w
					results[i] = row
					return
				}
				// worker failed -> fall back to local engine
			}
			row := localEngine(client, t)
			if len(in.Workers) > 0 {
				row.ViaWorker = "local-fallback"
			}
			results[i] = row
		}(i, t)
	}
	wg.Wait()
	emit(map[string]interface{}{"results": results})
}
