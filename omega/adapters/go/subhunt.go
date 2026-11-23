// subhunt — OMEGA concurrent subdomain + vhost enumerator (Go core).
//
// Three read-only techniques, all differential (wildcard-safe):
//   1. DNS brute via net.Resolver against a candidate list
//   2. Certificate Transparency lookup (crt.sh JSON, best effort)
//   3. VHost fuzz via Host-header on the target web server, comparing
//      response size against a random-baseline Host (wildcard filter).
//
// Input (JSON stdin):
//   {"domain":"example.com","words":["www","api"],"target":"http://10.0.0.1",
//    "do_ct":true,"timeout_ms":2000}
//
// Output (JSON stdout):
//   {"dns":[{"host","ip"}],"ct":["sub.example.com"],"vhost":[{"host","status","size"}]}
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	dnsPool   = 200
	maxWords  = 5000
	vhPool    = 16
	baselineN = 2
)

type input struct {
	Domain    string   `json:"domain"`
	Words     []string `json:"words"`
	Target    string   `json:"target"`
	DoCT      bool     `json:"do_ct"`
	TimeoutMs int      `json:"timeout_ms"`
}

type dnsHit struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
}

type vhostHit struct {
	Host   string `json:"host"`
	Status int    `json:"status"`
	Size   int    `json:"size"`
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

func dnsBrute(domain string, words []string, timeout time.Duration) []dnsHit {
	r := &net.Resolver{}
	ctx := context.Background()
	jobs := make(chan string)
	hits := make([]dnsHit, 0, 16)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < dnsPool; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range jobs {
				host := w + "." + domain
				cctx, cancel := context.WithTimeout(ctx, timeout)
				addrs, err := r.LookupHost(cctx, host)
				cancel()
				if err == nil && len(addrs) > 0 {
					mu.Lock()
					hits = append(hits, dnsHit{host, addrs[0]})
					mu.Unlock()
				}
			}
		}()
	}
	for _, w := range words {
		jobs <- strings.ToLower(strings.TrimSpace(w))
	}
	close(jobs)
	wg.Wait()
	return hits
}

func ctLookup(domain string, timeout time.Duration) []string {
	client := &http.Client{Timeout: timeout}
	url := "https://crt.sh/?q=%." + domain + "&output=json"
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil
	}
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if json.Unmarshal(body, &entries) != nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, e := range entries {
		for _, n := range strings.Split(e.NameValue, "\n") {
			n = strings.TrimSpace(strings.ToLower(n))
			if n != "" && strings.HasSuffix(n, domain) && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}

func vhostFuzz(target string, words []string, domain string,
	timeout time.Duration) []vhostHit {
	base := strings.TrimRight(target, "/")
	if base == "" {
		return nil
	}
	client := &http.Client{Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	fetch := func(host string) (int, int) {
		req, err := http.NewRequest("GET", base+"/", nil)
		if err != nil {
			return 0, 0
		}
		req.Host = host
		req.Header.Set("Host", host)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; browser)")
		resp, err := client.Do(req)
		if err != nil {
			return 0, 0
		}
		defer resp.Body.Close()
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, int(n)
	}
	// wildcard baseline: two random hosts should produce identical size
	rnd := map[int]int{}
	for i := 0; i < baselineN; i++ {
		h := fmt.Sprintf("ow%x%d.%s", time.Now().UnixNano(), i, domain)
		_, sz := fetch(h)
		rnd[sz]++
	}
	wildSize := 0
	for sz, cnt := range rnd {
		if cnt > 1 {
			wildSize = sz
		}
	}
	jobs := make(chan string)
	hits := make([]vhostHit, 0, 8)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < vhPool; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range jobs {
				host := w + "." + domain
				st, sz := fetch(host)
				if st == 0 {
					continue
				}
				// differ from wildcard response => real vhost
				if wildSize == 0 || sz != wildSize {
					mu.Lock()
					hits = append(hits, vhostHit{host, st, sz})
					mu.Unlock()
				}
			}
		}()
	}
	for _, w := range words {
		jobs <- strings.ToLower(strings.TrimSpace(w))
	}
	close(jobs)
	wg.Wait()
	return hits
}

func main() {
	raw, _ := io.ReadAll(bufio.NewReaderSize(os.Stdin, 1<<22))
	var in input
	if err := json.Unmarshal(raw, &in); err != nil || in.Domain == "" {
		emit(map[string]interface{}{"error": "invalid input"})
		return
	}
	words := in.Words
	if len(words) == 0 {
		words = []string{"www", "api", "dev", "staging", "test", "mail",
			"admin", "portal", "app", "vpn"}
	}
	if len(words) > maxWords {
		words = words[:maxWords]
	}
	timeout := 2 * time.Second
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	out := map[string]interface{}{"domain": in.Domain}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		d := dnsBrute(in.Domain, words, timeout)
		mu.Lock()
		out["dns"] = d
		mu.Unlock()
	}()
	if in.DoCT {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ct := ctLookup(in.Domain, 5*time.Second)
			mu.Lock()
			out["ct"] = ct
			mu.Unlock()
		}()
	}
	if in.Target != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vh := vhostFuzz(in.Target, words, in.Domain, timeout)
			mu.Lock()
			out["vhost"] = vh
			mu.Unlock()
		}()
	}
	wg.Wait()
	emit(out)
}
