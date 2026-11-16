package main

// portspeed — high-concurrency TCP port scanner.
// Flags: -host, -ports (comma/range, e.g. "80,443,8000-8100"),
//        -concurrency (default 1000), -timeout (ms, default 800).
// JSON to stdout: {"open":[{"port":N,"banner":"..."}]}
// Banner is a short recv best-effort after connect.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type openPort struct {
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

type scanResult struct {
	Open []openPort `json:"open"`
}

func parsePorts(spec string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	add := func(p int) {
		if p > 0 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, e1 := strconv.Atoi(strings.TrimSpace(lo))
			h, e2 := strconv.Atoi(strings.TrimSpace(hi))
			if e1 != nil || e2 != nil || l > h {
				return nil, fmt.Errorf("bad range %q", part)
			}
			for p := l; p <= h && p-l < 65536; p++ {
				add(p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("bad port %q", part)
			}
			add(p)
		}
	}
	return out, nil
}

func main() {
	host := ""
	portSpec := ""
	concurrency := 1000
	timeoutMS := 800

	fs := os.Args[1:]
	for i := 0; i < len(fs); i++ {
		switch fs[i] {
		case "-host":
			i++
			host = fs[i]
		case "-ports":
			i++
			portSpec = fs[i]
		case "-concurrency":
			i++
			concurrency, _ = strconv.Atoi(fs[i])
		case "-timeout":
			i++
			timeoutMS, _ = strconv.Atoi(fs[i])
		}
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if timeoutMS < 1 {
		timeoutMS = 1
	}
	timeout := time.Duration(timeoutMS) * time.Millisecond

	ports, err := parsePorts(portSpec)
	if err != nil || host == "" || len(ports) == 0 {
		json.NewEncoder(os.Stdout).Encode(scanResult{Open: []openPort{}})
		return
	}

	var mu sync.Mutex
	open := []openPort{}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, p := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(p)), timeout)
			if err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(timeout))
			banner := make([]byte, 256)
			n, _ := conn.Read(banner)
			conn.Close()
			mu.Lock()
			open = append(open, openPort{Port: p, Banner: string(banner[:n])})
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.Encode(scanResult{Open: open})
}
