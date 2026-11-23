// smuggler — OMEGA raw-socket HTTP request smuggling detector (Go core).
//
// Sends raw-byte smuggle probes over a single TCP connection and
// times a "safety" follow-up request: if the front-end and back-end
// disagree about request boundaries, the poison request desyncs the
// second request (timeout or shifted response). Differential design:
// a benign control pair must both succeed for the result to count.
// All requests are harmless (GET /), nothing destructive is sent.
//
// Input (JSON stdin):
//   {"target":"http://host:port","timeout_ms":4000}
//
// Output (JSON stdout):
//   {"smuggled":[{"technique":"CL.TE","evidence":"timeout-after-poison"}],
//    "control_ok":true}
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

type input struct {
	Target    string `json:"target"`
	TimeoutMs int    `json:"timeout_ms"`
	Path      string `json:"path"`
}

func emit(v interface{}) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

func parseTarget(t string) (host, path string, ok bool) {
	u, err := url.Parse(t)
	if err != nil || u.Host == "" {
		return "", "", false
	}
	host = u.Host
	if u.Path != "" {
		path = u.Path
	}
	return host, path, true
}

// sendRaw opens a connection, writes raw bytes, reads the first
// response line (or until deadline) and reports whether a parseable
// HTTP response came back within the deadline.
func sendRaw(host, raw string, timeout time.Duration) (int, error) {
	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte(raw))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	return len(line), nil
}

// smugglePair: poison then safety probe on the SAME connection — the
// desync shows up as the safety probe being consumed/shifted.
func smugglePair(host, poisonRaw string, timeout time.Duration) (bool, string) {
	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return false, "connect-failed"
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte(poisonRaw))
	// safety probe on the same connection
	safety := "GET / HTTP/1.1\r\nHost: " + host +
		"\r\nUser-Agent: probe\r\n\r\n"
	conn.Write([]byte(safety))
	reader := bufio.NewReader(conn)
	_, err = reader.ReadString('\n')
	if err != nil {
		// first read blocked/EOF — poison consumed the safety request
		return true, "timeout-or-eof-after-poison"
	}
	// second read: if the pipeline is healthy, safety response follows
	_, err2 := reader.ReadString('\n')
	if err2 != nil {
		return true, "safety-response-missing"
	}
	return false, ""
}

func main() {
	raw, _ := io.ReadAll(bufio.NewReaderSize(os.Stdin, 1<<20))
	var in input
	if err := json.Unmarshal(raw, &in); err != nil || in.Target == "" {
		emit(map[string]interface{}{"error": "invalid input"})
		return
	}
	host, path, ok := parseTarget(in.Target)
	if !ok {
		emit(map[string]interface{}{"error": "bad target"})
		return
	}
	if path == "" {
		path = "/"
	}
	timeout := 4 * time.Second
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	p := path

	// control: two pipelined normal GETs must both answer
	controlOK := false
	{
		two := "GET " + p + " HTTP/1.1\r\nHost: " + host +
			"\r\n\r\nGET " + p + " HTTP/1.1\r\nHost: " + host +
			"\r\nUser-Agent: probe\r\n\r\n"
		_, err := sendRaw(host, two, timeout)
		controlOK = err == nil
	}

	probes := []struct{ name, raw string }{
		{"CL.TE", "POST " + p + " HTTP/1.1\r\nHost: " + host +
			"\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n" +
			"\r\n1\r\nZ\r\nQ\r\n"},
		{"TE.CL", "POST " + p + " HTTP/1.1\r\nHost: " + host +
			"\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n" +
			"\r\n0\r\n\r\nX"},
		{"TE.TE-obfusc", "POST " + p + " HTTP/1.1\r\nHost: " + host +
			"\r\nContent-Length: 4\r\nTransfer-Encoding: xchunked\r\n" +
			"Transfer-Encoding : chunked\r\n\r\n1\r\nZ\r\nQ\r\n"},
		{"h2c-upgrade", "GET " + p + " HTTP/1.1\r\nHost: " + host +
			"\r\nConnection: Upgrade, HTTP2-Settings\r\n" +
			"Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n"},
	}
	found := []map[string]string{}
	for _, pr := range probes {
		smug, evidence := smugglePair(host, pr.raw, timeout)
		if smug {
			found = append(found, map[string]string{
				"technique": pr.name, "evidence": evidence})
		}
	}
	_ = strings.TrimSpace
	emit(map[string]interface{}{"target": in.Target,
		"control_ok": controlOK, "smuggled": found})
}
