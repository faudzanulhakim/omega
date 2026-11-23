// diffscan — OMEGA snapshot/diff regression scanner (Go core).
//
// Mode "save": crawl a target (given paths + discovered links) and
// emit a content snapshot (per-path status, size, ctype, server,
// title hash). Mode "diff": compare a fresh snapshot against a
// baseline passed in the input; emit churn: new/changed/removed
// endpoints, header deltas, technology changes.
//
// Input (JSON stdin):
//   {"target":"http://h","mode":"save","paths":["/a","/b"]}
//   {"target":"http://h","mode":"diff","paths":["/a","/b"],
//    "baseline":{"http://h/a":{"status":200,"size":120,...}}}
//
// Output (JSON stdout):
//   save: {"snapshot":{...}}
//   diff: {"snapshot":{...},"churn":{"new":[...],"changed":[...],
//          "removed":[...]}}
package main

import (
	"bufio"
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
	Target   string            `json:"target"`
	Mode     string            `json:"mode"`
	Paths    []string          `json:"paths"`
	Baseline map[string]map[string]interface{} `json:"baseline"`
}

type row struct {
	Status int    `json:"status"`
	Size   int    `json:"size"`
	Ctype  string `json:"ctype"`
	Server string `json:"server"`
	Title  string `json:"title"`
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var linkRe = regexp.MustCompile(`(?:href|src)=["'](/[^"'#\?]{1,80})["']`)

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
	timeout := 2500 * time.Millisecond
	client := &http.Client{Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	fetch := func(p string) row {
		req, err := http.NewRequest("GET", base+p, nil)
		if err != nil {
			return row{}
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; browser)")
		resp, err := client.Do(req)
		if err != nil {
			return row{}
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		r := row{Status: resp.StatusCode, Size: len(body),
			Ctype: resp.Header.Get("Content-Type"),
			Server: resp.Header.Get("Server")}
		if m := titleRe.FindSubmatch(body); m != nil {
			r.Title = strings.TrimSpace(string(m[1]))
		}
		return r
	}

	paths := in.Paths
	if len(paths) == 0 {
		paths = []string{"/"}
	}
	if len(paths) > 2000 {
		paths = paths[:2000]
	}
	snapshot := map[string]row{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)
	newPaths := []string{}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := fetch(p)
			mu.Lock()
			snapshot[p] = r
			// discover same-host links from 200 pages
			if r.Status == 200 {
				mu.Unlock()
				return
			}
			mu.Unlock()
		}(p)
	}
	// root page link discovery feeds extra paths (single pass)
	root := fetch("/")
	mu.Lock()
	snapshot["/"] = root
	mu.Unlock()
	if root.Status == 200 {
		// fetch root body again for links
		resp, err := client.Get(base + "/")
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			for _, m := range linkRe.FindAllStringSubmatch(string(body), 40) {
				p := m[1]
				if !strings.HasSuffix(p, ".css") &&
					!strings.HasSuffix(p, ".png") &&
					!strings.HasSuffix(p, ".ico") &&
					!strings.HasSuffix(p, ".svg") &&
					!strings.HasSuffix(p, ".woff2") {
					newPaths = append(newPaths, p)
				}
			}
		}
	}
	for _, p := range newPaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := fetch(p)
			mu.Lock()
			if _, dup := snapshot[p]; !dup {
				snapshot[p] = r
			}
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	out := map[string]interface{}{}
	snapJson := map[string]map[string]interface{}{}
	for p, r := range snapshot {
		b, _ := json.Marshal(r)
		m := map[string]interface{}{}
		json.Unmarshal(b, &m)
		snapJson[p] = m
	}
	out["snapshot"] = snapJson

	if in.Mode == "diff" && in.Baseline != nil {
		newList, changed, removed := []string{}, []string{}, []string{}
		for p, r := range snapJson {
			old, ok := in.Baseline[p]
			if !ok {
				newList = append(newList, p)
				continue
			}
			if old["status"] != r["status"] ||
				old["size"] != r["size"] ||
				old["server"] != r["server"] ||
				old["title"] != r["title"] {
				changed = append(changed, p)
			}
		}
		for p := range in.Baseline {
			if _, ok := snapJson[p]; !ok {
				removed = append(removed, p)
			}
		}
		out["churn"] = map[string]interface{}{
			"new": newList, "changed": changed, "removed": removed}
	}
	emit(out)
}
