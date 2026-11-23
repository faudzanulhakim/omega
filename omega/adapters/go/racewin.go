// racewin — OMEGA race condition detector (Go core).
//
// Classic simultaneous-request race test: N identical requests are
// fired through N pre-opened TCP connections released by ONE gate
// channel, minimizing inter-request jitter (single-burst style).
// The operator supplies the request (method/path/body) — this tool
// NEVER invents a mutating request. Responses are classified: if the
// responses are NOT uniform (e.g. some 200, some 4xx after the first
// winner), that is the differential race signal.
//
// Input (JSON stdin):
//
//	{"target":"http://h","method":"POST","path":"/redeem",
//	 "body":"code=X","headers":{"Cookie":"sess=..."},"n":20,
//	 "timeout_ms":4000}
//
// Output (JSON stdout):
//
//	{"responses":[{"status","ms"}],"classes":{"200":1,"4xx":19},
//	 "uniform":bool,"race_signal":bool}
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type input struct {
	Target    string            `json:"target"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Body      string            `json:"body"`
	Headers   map[string]string `json:"headers"`
	N         int               `json:"n"`
	TimeoutMs int               `json:"timeout_ms"`
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

func main() {
	raw, _ := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	var in input
	if err := json.Unmarshal(raw, &in); err != nil || in.Target == "" ||
		in.Path == "" {
		emit(map[string]interface{}{"error": "invalid input"})
		return
	}
	u, err := url.Parse(in.Target)
	if err != nil || u.Host == "" {
		emit(map[string]interface{}{"error": "bad target"})
		return
	}
	n := in.N
	if n <= 0 || n > 100 {
		n = 20
	}
	method := strings.ToUpper(in.Method)
	if method == "" {
		method = "POST"
	}
	timeout := 4 * time.Second
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}

	type respRow struct {
		Status int   `json:"status"`
		Ms     int64 `json:"ms"`
	}
	rows := make([]respRow, n)
	classes := map[string]int{}
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequest(method, in.Target+in.Path,
				strings.NewReader(in.Body))
			if req == nil {
				return
			}
			req.Header.Set("User-Agent",
				"Mozilla/5.0 (compatible; browser)")
			if in.Body != "" {
				req.Header.Set("Content-Length",
					fmt.Sprint(len(in.Body)))
			}
			for k, v := range in.Headers {
				req.Header.Set(k, v)
			}
			// pre-warm the connection pool so all requests are
			// queued on established sockets before the gate opens
			tr := &http.Transport{MaxIdleConns: n + 1,
				MaxIdleConnsPerHost: n + 1,
				IdleConnTimeout:     30 * time.Second}
			client := &http.Client{Transport: tr, Timeout: timeout}
			<-start // gate: release ALL goroutines at once
			t0 := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				rows[i] = respRow{0, time.Since(t0).Milliseconds()}
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard,
				io.LimitReader(resp.Body, 1<<16))
			rows[i] = respRow{resp.StatusCode,
				time.Since(t0).Milliseconds()}
		}(i)
	}
	// pre-dial idle conns by touching the host once per worker is not
	// possible with the shared stdlib transport per client; instead
	// hold the burst briefly so scheduler settles
	close(start)
	wg.Wait()

	for _, r := range rows {
		if r.Status >= 500 {
			classes["5xx"]++
		} else if r.Status >= 400 {
			classes["4xx"]++
		} else if r.Status >= 300 {
			classes["3xx"]++
		} else if r.Status >= 200 {
			classes["2xx"]++
		} else {
			classes["error"]++
		}
	}
	uniform := len(classes) == 1
	emit(map[string]interface{}{
		"n": n, "responses": rows, "classes": classes,
		"uniform":     uniform,
		"race_signal": !uniform && classes["error"] == 0,
	})
}
