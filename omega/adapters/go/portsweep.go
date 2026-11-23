// portsweep — OMEGA concurrent port + service fingerprinter (Go core).
//
// Raw TCP connect sweep across a port range with a large goroutine
// pool; open ports get a short banner grab (HTTP HEAD / TLS ClientHello
// / recv-then-close) and a protocol guess. Read-only.
//
// Input (JSON stdin):
//   {"host":"10.0.0.1","ports":[80,443,8080],"timeout_ms":1500}
//   ports may be omitted -> defaults (top 40 common ports)
//
// Output (JSON stdout):
//   {"open":[{"port":443,"service":"https","banner":"...","ms":12}]}
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	poolDefault     = 500
	defaultTimeout  = 1500 * time.Millisecond
	maxPorts        = 4096
	bannerReadLimit = 256
)

var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 9200,
	11211, 27017, 5000, 8000, 8008, 8081, 8181, 3000, 5001, 7001, 4848,
	10000, 161, 389,
}

type input struct {
	Host      string `json:"host"`
	Ports     []int  `json:"ports"`
	TimeoutMs int    `json:"timeout_ms"`
}

type openPort struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
	Ms      int64  `json:"ms"`
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

func guessService(port int, banner string, spokeTLS bool) string {
	b := strings.ToLower(banner)
	switch {
	case spokeTLS:
		return "tls"
	case strings.Contains(b, "ssh-"):
		return "ssh"
	case strings.Contains(b, "http/"):
		return "http"
	case strings.Contains(b, "ftp"):
		return "ftp"
	case strings.Contains(b, "smtp"):
		return "smtp"
	case strings.Contains(b, "redis"):
		return "redis"
	case strings.Contains(b, "mysql"):
		return "mysql"
	case port == 443 || port == 8443:
		return "https"
	case port == 80 || port == 8080:
		return "http"
	case port == 22:
		return "ssh"
	case port == 21:
		return "ftp"
	case port == 3306:
		return "mysql"
	case port == 6379:
		return "redis"
	}
	return "tcp"
}

func probe(host string, port int, timeout time.Duration) (openPort, bool) {
	t0 := time.Now()
	res := openPort{Port: port}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host,
		strconv.Itoa(port)), timeout)
	if err != nil {
		return res, false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	spokeTLS := false
	if port == 443 || port == 8443 || port == 465 || port == 993 ||
		port == 995 {
		tconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if err := tconn.Handshake(); err == nil {
			spokeTLS = true
			res.Banner = "tls/" + tls.VersionName(
				tconn.ConnectionState().Version)
			conn = tconn
		}
	}
	// send a probe that coaxes a banner from most services
	conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	buf := make([]byte, bannerReadLimit)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, err := conn.Read(buf); err == nil || n > 0 {
		res.Banner = strings.TrimSpace(
			strings.ReplaceAll(string(buf[:n]), "\r\n", " | "))
	}
	res.Service = guessService(port, res.Banner, spokeTLS)
	res.Ms = time.Since(t0).Milliseconds()
	return res, true
}

func main() {
	raw, _ := io.ReadAll(bufio.NewReaderSize(os.Stdin, 1<<20))
	var in input
	if err := json.Unmarshal(raw, &in); err != nil || in.Host == "" {
		emit(map[string]interface{}{"error": "invalid input"})
		return
	}
	timeout := defaultTimeout
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	ports := in.Ports
	if len(ports) == 0 {
		ports = commonPorts
	}
	if len(ports) > maxPorts {
		ports = ports[:maxPorts]
	}
	jobs := make(chan int)
	results := make(chan openPort, len(ports))
	var wg sync.WaitGroup
	for i := 0; i < poolDefault; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if r, open := probe(in.Host, p, timeout); open {
					results <- r
				}
			}
		}()
	}
	for _, p := range ports {
		jobs <- p
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()
	open := []openPort{}
	for r := range results {
		open = append(open, r)
	}
	emit(map[string]interface{}{"host": in.Host, "open": open})
}
