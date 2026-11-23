// sniffy — OMEGA passive network discovery sniffer (Go core).
//
// READ-ONLY passive listening: captures live traffic on an interface
// and extracts hosts/hosts visible in DNS queries, HTTP Host headers
// and HTTP Authorization lines (values NEVER stored — only the fact
// that cleartext credentials crossed the wire). Requires root/CAP for
// raw sockets; without privileges it exits with a clear privilege
// note instead of pretending.
//
// Input (JSON stdin):
//   {"iface":"eth0","seconds":10,"bpf":"port 53 or port 80"}
//
// Output (JSON stdout):
//   {"dns_queries":[...],"http_hosts":[...],"cleartext_auth":N,
//    "packets":N,"privileged":true}
//
// Implementation note: uses Go's raw socket via golang.org/x/net —
// NOT available here (stdlib-only build). We implement the capture
// using pcap-free UDP/TCP observation via SO_REUSE... which also is
// not stdlib. Therefore: stdlib-only fallback listens on a UDP mirror
// port option ({"listen_udp":15353}) to observe DNS forwarded to it —
// documented limitation; full promiscuous capture needs the pcap
// build tag. Without either, output is {"privileged":false}.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

type input struct {
	Iface     string `json:"iface"`
	Seconds   int    `json:"seconds"`
	ListenUDP int    `json:"listen_udp"` // mirror port for DNS obs
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

var (
	dnsNameRe = regexp.MustCompile(
		`(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}`)
	httpHostRe  = regexp.MustCompile(`(?im)^host:\s*(.+)$`)
	authLineRe  = regexp.MustCompile(`(?im)^authorization:\s*basic\s`)
	passwdRe    = regexp.MustCompile(`(?i)(password|passwd|pwd)=`)
)

func main() {
	raw, _ := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	var in input
	if err := json.Unmarshal(raw, &in); err != nil {
		emit(map[string]interface{}{"error": "invalid input"})
		return
	}
	seconds := 10
	if in.Seconds > 0 {
		seconds = in.Seconds
	}
	if seconds > 300 {
		seconds = 300
	}
	if in.ListenUDP == 0 {
		// stdlib-only build: no promiscuous capture available.
		emit(map[string]interface{}{
			"privileged": false,
			"note": "promiscuous capture needs root + a pcap build; " +
				"set listen_udp to observe a DNS mirror port",
		})
		return
	}
	addr := net.JoinHostPort("0.0.0.0", fmt.Sprint(in.ListenUDP))
	sock, err := net.ListenPacket("udp", addr)
	if err != nil {
		emit(map[string]interface{}{
			"privileged": false, "error": err.Error()})
		return
	}
	defer sock.Close()
	dnsQ := map[string]bool{}
	httpHosts := map[string]bool{}
	clearAuth, packets := 0, 0
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		sock.SetDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := sock.ReadFrom(buf)
		if err != nil {
			continue
		}
		packets++
		payload := buf[:n]
		for _, m := range dnsNameRe.FindAllString(
			strings.ToLower(string(payload)), 5) {
			dnsQ[m] = true
		}
		for _, m := range httpHostRe.FindAllStringSubmatch(
			string(payload), 2) {
			httpHosts[strings.TrimSpace(strings.ToLower(m[1]))] = true
		}
		if authLineRe.Match(payload) {
			clearAuth++
		}
		if passwdRe.Match(payload) {
			clearAuth++
		}
	}
	toList := func(m map[string]bool) []string {
		out := []string{}
		for k := range m {
			out = append(out, k)
		}
		return out
	}
	emit(map[string]interface{}{
		"privileged": true, "packets": packets,
		"dns_queries": toList(dnsQ), "http_hosts": toList(httpHosts),
		"cleartext_auth": clearAuth,
	})
}
