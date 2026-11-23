// udpsweep — OMEGA UDP service prober (Go core).
//
// Sends protocol-correct UDP probe payloads and waits for a response
// signature. Pure discovery/read-only. Services: DNS, SNMP, NTP,
// memcached, SSDP.
//
// Input (JSON stdin):
//   {"host":"10.0.0.1","ports":[53,161,123,11211,1900],"timeout_ms":1500}
//   ports omitted -> all five defaults
//
// Output (JSON stdout):
//   {"open":[{"port":53,"service":"dns","reply_len":42,"note":"..."}]}
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

type input struct {
	Host      string `json:"host"`
	Ports     []int  `json:"ports"`
	TimeoutMs int    `json:"timeout_ms"`
}

type probeDef struct {
	port    int
	service string
	payload []byte
	match   func([]byte) bool
}

func buildProbes() []probeDef {
	return []probeDef{
		{53, "dns", []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
			0x04, 'b', 'i', 'n', 'd',
			0x00, 0x00, 0x10, 0x00, 0x03},
			func(b []byte) bool { return len(b) > 12 && b[3]&0x80 != 0 }},
		{161, "snmp", []byte{
			0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 'p', 'u', 'b',
			'l', 'i', 'c', 0xa0, 0x19, 0x02, 0x04, 0x55, 0x1f, 0x7c,
			0xd3, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b,
			0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,
			0x05, 0x00},
			func(b []byte) bool { return len(b) > 6 && b[0] == 0x30 }},
		{123, "ntp", []byte{
			0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			func(b []byte) bool { return len(b) >= 48 }},
		{11211, "memcached", []byte("version\r\n"),
			func(b []byte) bool {
				return strings.HasPrefix(strings.ToLower(string(b)),
					"version")
			}},
		{1900, "ssdp", []byte("M-SEARCH * HTTP/1.1\r\nHost: 239.255.255" +
			".250:1900\r\nMan: \"ssdp:discover\"\r\nMX: 1\r\nST: " +
			"ssdp:all\r\n\r\n"),
			func(b []byte) bool {
				return strings.Contains(strings.ToUpper(string(b)),
					"HTTP")
			}},
	}
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

func main() {
	raw, _ := io.ReadAll(bufio.NewReaderSize(os.Stdin, 1<<20))
	var in input
	if err := json.Unmarshal(raw, &in); err != nil || in.Host == "" {
		emit(map[string]interface{}{"error": "invalid input"})
		return
	}
	probes := buildProbes()
	if len(in.Ports) > 0 {
		want := map[int]bool{}
		for _, p := range in.Ports {
			want[p] = true
		}
		f := []probeDef{}
		for _, pd := range probes {
			if want[pd.port] {
				f = append(f, pd)
			}
		}
		probes = f
	}
	timeout := 1500 * time.Millisecond
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	open := []map[string]interface{}{}
	for _, pd := range probes {
		raddr := net.JoinHostPort(in.Host, fmt.Sprint(pd.port))
		conn, err := net.DialTimeout("udp", raddr, timeout)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(timeout))
		conn.Write(pd.payload)
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil || n == 0 {
			continue
		}
		resp := buf[:n]
		if pd.match(resp) {
			open = append(open, map[string]interface{}{
				"port": pd.port, "service": pd.service,
				"reply_len": n,
				"note":      string(resp[:min(n, 120)]),
			})
		}
	}
	emit(map[string]interface{}{"host": in.Host, "open": open})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
