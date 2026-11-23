// racehunter — OMEGA race-condition / TOCTOU hunter (Go core).
//
// Fires N copies of one request simultaneously (goroutine barrier for
// near-simultaneous dispatch) and compares the outcomes. A race
// vulnerability shows as MULTIPLE success outcomes for an action that
// must be one-time (double withdraw, voucher reuse, vote stuffing).
// OFFENSE-GATED at the Python layer (PTK_OFFENSE). CANDIDATE grade:
// the operator replays the race manually to confirm.
//
// Input (JSON stdin):
//   {"target":"http://h/withdraw","method":"POST","body":"acct=1&amt=1",
//    "race_n":20,"success_marker":"success","cookie":"","timeout_ms":3000}
//
// Output (JSON stdout):
//   {"outcomes":{"200":20},"success_count":18,"total":20,
//    "distinct_bodies":3,"results":[{"status","flagged"}]}
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

type input struct {
	Target        string `json:"target"`
	Method        string `json:"method"`
	Body          string `json:"body"`
	ContentType   string `json:"content_type"`
	Cookie        string `json:"cookie"`
	Headers       map[string]string `json:"headers"`
	RaceN         int    `json:"race_n"`
	SuccessMarker string `json:"success_marker"`
	TimeoutMs     int    `json:"timeout_ms"`
}

type row struct {
	Status  int    `json:"status"`
	Flagged bool   `json:"flagged"`
	Shape   string `json:"shape"`
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

func main() {
	in, _ := io.ReadAll(bufio.NewReader(io.LimitReader(os.Stdin, 1<<20)))
	var cfg input
	if err := json.Unmarshal(in, &cfg); err != nil {
		emit(map[string]string{"error": "bad json input: " + err.Error()})
		return
	}
	if cfg.Target == "" || cfg.RaceN < 2 || cfg.RaceN > 200 {
		emit(map[string]string{"error":
		"target and race_n in 2..200 required"})
		return
	}
	n := cfg.RaceN
	tm := cfg.TimeoutMs
	if tm <= 0 {
		tm = 3000
	}
	tr := &http.Transport{MaxIdleConnsPerHost: n + 10}
	cl := &http.Client{Timeout: time.Duration(tm) * time.Millisecond,
		Transport: tr}

	// barrier: all goroutines wait, then fire together
	start := make(chan struct{})
	results := make([]row, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var body io.Reader
			if cfg.Body != "" {
				body = strings.NewReader(cfg.Body)
			}
			req, err := http.NewRequest(strings.ToUpper(cfg.Method),
				cfg.Target, body)
			if err != nil {
				return
			}
			ct := cfg.ContentType
			if ct == "" && cfg.Body != "" {
				ct = "application/x-www-form-urlencoded"
			}
			if ct != "" {
				req.Header.Set("Content-Type", ct)
			}
			if cfg.Cookie != "" {
				req.Header.Set("Cookie", cfg.Cookie)
			}
			for k, v := range cfg.Headers {
				req.Header.Set(k, v)
			}
			req.Header.Set("User-Agent", "omegarace/1.0")
			<-start
			resp, err := cl.Do(req)
			if err != nil {
				results[idx] = row{Status: 0, Shape: "transport-error"}
				return
			}
			sb := new(strings.Builder)
			sc := bufio.NewScanner(io.LimitReader(resp.Body, 16384))
			sc.Buffer(make([]byte, 16384), 16384)
			for sc.Scan() && sb.Len() < 8192 {
				sb.WriteString(sc.Text())
			}
			resp.Body.Close()
			shape := fmt.Sprintf("%d/%d", resp.StatusCode,
				len(sb.String()))
			flagged := cfg.SuccessMarker != "" &&
				strings.Contains(strings.ToLower(sb.String()),
					strings.ToLower(cfg.SuccessMarker))
			results[idx] = row{Status: resp.StatusCode,
				Flagged: flagged, Shape: shape}
		}(i)
	}
	close(start)
	wg.Wait()

	outcomes := map[string]int{}
	successCount := 0
	shapes := map[string]bool{}
	for _, r := range results {
		if r.Status == 0 && r.Shape == "" {
			continue
		}
		outcomes[fmt.Sprintf("%d", r.Status)]++
		if r.Flagged {
			successCount++
		}
		if r.Shape != "" {
			shapes[r.Shape] = true
		}
	}
	emit(map[string]interface{}{
		"outcomes": outcomes, "success_count": successCount,
		"total": n, "distinct_bodies": len(shapes),
		"results": results})
}
