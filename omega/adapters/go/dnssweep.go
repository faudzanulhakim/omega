// dnssweep — concurrent DNS subdomain resolver for OMEGA (read-only recon).
//
// Input (JSON on stdin):
//   {"domain": "example.com", "names": ["www", "mail"],
//    "servers": ["8.8.8.8"]}          // servers optional
//
// Behaviour: 20 workers, 2s per-query timeout, A queries sent as raw DNS
// packets over UDP built by hand (no external DNS library). Multiple
// servers: the first server that answers for a name wins.
//
// Output (JSON on stdout):
//   {"alive": [{"name": "www.example.com", "ip": "1.2.3.4"}],
//    "errors": 2}
//
// Pure stdlib.

package main

import (
	"encoding/binary"
	"encoding/json"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"
)

const (
	workers     = 20
	queryTimeout = 2 * time.Second
	udpBufSize  = 1500
)

type sweepInput struct {
	Domain  string   `json:"domain"`
	Names   []string `json:"names"`
	Servers []string `json:"servers"`
}

type aliveHost struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

type sweepOutput struct {
	Alive  []aliveHost `json:"alive"`
	Errors int         `json:"errors"`
}

// ------------------------------------------------------------- packet builder

// buildQuery builds a raw DNS A-query packet for name.domain.
//
// Wire format (RFC 1035):
//   header (12 bytes): ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
//   question:          QNAME (length-prefixed labels) + QTYPE + QCLASS
// All multi-byte integers are big-endian (network byte order).
func buildQuery(id uint16, fqdn string) []byte {
	buf := make([]byte, 0, 512)

	// --- header ---
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)  // ID: random, matched in reply
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // flags: RD (recursion desired)
	binary.BigEndian.PutUint16(hdr[4:6], 1)   // QDCOUNT = 1 question
	// ANCOUNT/NSCOUNT/ARCOUNT stay 0
	buf = append(buf, hdr...)

	// --- QNAME: each label prefixed by its byte length, 0 terminates ---
	for _, label := range splitLabels(fqdn) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00) // root label terminator

	// --- question trailer ---
	buf = append(buf, 0x00, 0x01) // QTYPE  = 1 (A)
	buf = append(buf, 0x00, 0x01) // QCLASS = 1 (IN)
	return buf
}

// splitLabels splits "www.example.com" into ["www", "example", "com"].
func splitLabels(fqdn string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(fqdn); i++ {
		if i == len(fqdn) || fqdn[i] == '.' {
			if i > start {
				out = append(out, fqdn[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// ------------------------------------------------------------- parser

// parseARecord scans a DNS reply and returns the first A-record IPv4
// address for the question name, or "" when none is present. Message
// compression pointers (0xC0) in answer owner names are skipped without
// following them (we do not need the name, just the A record).
func parseARecord(resp []byte) string {
	if len(resp) < 12 {
		return ""
	}
	qd := binary.BigEndian.Uint16(resp[4:6])
	an := binary.BigEndian.Uint16(resp[6:8])
	pos := 12

	// skip the question section
	for i := 0; i < int(qd) && pos < len(resp); i++ {
		pos = skipName(resp, pos)
		pos += 4 // QTYPE + QCLASS
	}
	// scan answer records
	for i := 0; i < int(an) && pos < len(resp); i++ {
		pos = skipName(resp, pos)
		if pos+10 > len(resp) {
			return ""
		}
		rectype := binary.BigEndian.Uint16(resp[pos : pos+2])
		rdlen := binary.BigEndian.Uint16(resp[pos+8 : pos+10])
		pos += 10
		if pos+int(rdlen) > len(resp) {
			return ""
		}
		if rectype == 1 && rdlen == 4 { // A record, IPv4
			return net.IP(resp[pos : pos+4]).String()
		}
		pos += int(rdlen)
	}
	return ""
}

// skipName advances pos past a (possibly compressed) domain name.
func skipName(msg []byte, pos int) int {
	for pos < len(msg) {
		l := int(msg[pos])
		if l == 0 {
			return pos + 1
		}
		if l&0xC0 == 0xC0 { // compression pointer: 2 bytes, done
			return pos + 2
		}
		pos += 1 + l
	}
	return pos
}

// ------------------------------------------------------------- querying

// resolveA sends one hand-built A query over UDP and returns the IP or "".
func resolveA(server, fqdn string) (string, bool) {
	id := uint16(rand.Intn(0xFFFF) + 1)
	query := buildQuery(id, fqdn)

	conn, err := net.DialTimeout("udp", server+":53", queryTimeout)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(queryTimeout))

	if _, err := conn.Write(query); err != nil {
		return "", false
	}
	buf := make([]byte, udpBufSize)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return "", false
	}
	// sanity: reply ID must match our query ID (simple forgery/nat check)
	if binary.BigEndian.Uint16(buf[0:2]) != id {
		return "", false
	}
	ip := parseARecord(buf[:n])
	return ip, ip != ""
}

func main() {
	var in sweepInput
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		json.NewEncoder(os.Stdout).Encode(sweepOutput{Alive: []aliveHost{}})
		return
	}
	servers := in.Servers
	if len(servers) == 0 {
		servers = []string{"8.8.8.8", "1.1.1.1"}
	}

	out := sweepOutput{Alive: []aliveHost{}}
	jobs := make(chan string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for name := range jobs {
			fqdn := name + "." + in.Domain
			found := ""
			for _, srv := range servers {
				ip, ok := resolveA(srv, fqdn)
				if ok {
					found = ip
					break // first server to answer wins
				}
			}
			mu.Lock()
			if found != "" {
				out.Alive = append(out.Alive, aliveHost{Name: fqdn, IP: found})
			} else {
				out.Errors++
			}
			mu.Unlock()
		}
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}
	for _, n := range in.Names {
		jobs <- n
	}
	close(jobs)
	wg.Wait()

	_ = json.NewEncoder(os.Stdout).Encode(out)
}
