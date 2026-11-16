package main

// smsweep — raw-socket HTTP request-smuggling differential prober.
//
// Reads one JSON object on stdin:
//   {"target": {"host": "127.0.0.1", "port": 8080},
//    "timeout_ms": 2000,
//    "cases": [{"name": "cl_te", "raw_b64": "<base64 raw request bytes>"}]}
//
// For every case it opens ONE raw TCP connection to the target, writes
// the request bytes EXACTLY as provided (no normalization — precise
// byte control is the whole point), reads until deadline or a complete
// response, and reports status/elapsed/size.
//
// JSON to stdout:
//   {"results": [{"name","status","elapsed_ms","size","error"}]}
//
// The binary never smuggles a second request by itself: the caller
// (omega.scanning.smuggle) only ever hands it safe-read probe requests
// (conflicting framing headers + an ordinary body). Errors are reported
// per case, never fatal.
import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func ioReadAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}

type targetSpec struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type caseSpec struct {
	Name   string `json:"name"`
	RawB64 string `json:"raw_b64"`
}

type inputSpec struct {
	Target    targetSpec `json:"target"`
	TimeoutMS int        `json:"timeout_ms"`
	Cases     []caseSpec `json:"cases"`
}

type caseResult struct {
	Name      string `json:"name"`
	Status    int    `json:"status"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Size      int    `json:"size"`
	Error     string `json:"error"`
}

type outputSpec struct {
	Results []caseResult `json:"results"`
}

func readResponse(conn net.Conn, deadline time.Time) (int, int, error) {
	// Read headers (find \r\n\r\n), then honor Content-Length when a
	// body is declared; otherwise read until the peer closes or the
	// deadline expires.
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 8*1024)
	headerEnd := -1
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(deadline)
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if headerEnd < 0 {
				if i := indexCRLF(buf); i >= 0 {
					headerEnd = i
				}
			}
			if headerEnd >= 0 {
				if cl := contentLength(buf[:headerEnd]); cl >= 0 {
					if len(buf) >= headerEnd+4+cl {
						break // complete response
					}
				}
			}
		}
		if err != nil {
			break // closed or deadline — return what we have
		}
	}
	status := 0
	if headerEnd >= 0 && len(buf) >= 12 {
		fmt.Sscanf(string(buf[9:12]), "%d", &status)
	}
	return status, len(buf), nil
}

func indexCRLF(b []byte) int {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return i
		}
	}
	return -1
}

func contentLength(header []byte) int {
	for _, line := range splitLines(header) {
		if len(line) > 15 && equalFold(string(line[:15]), "content-length:") {
			n := 0
			for _, c := range string(line[15:]) {
				if c >= '0' && c <= '9' {
					n = n*10 + int(c-'0')
				}
			}
			return n
		}
	}
	return -1
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			end := i
			if end > start && b[end-1] == '\r' {
				end--
			}
			out = append(out, b[start:end])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func runCase(spec targetSpec, c caseSpec, timeout time.Duration) caseResult {
	res := caseResult{Name: c.Name}
	raw, err := base64.StdEncoding.DecodeString(c.RawB64)
	if err != nil {
		res.Error = "bad base64: " + err.Error()
		return res
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp",
		net.JoinHostPort(spec.Host, fmt.Sprint(spec.Port)), timeout)
	if err != nil {
		res.Error = "dial: " + err.Error()
		res.ElapsedMS = time.Since(start).Milliseconds()
		return res
	}
	defer conn.Close()
	deadline := start.Add(timeout)
	conn.SetWriteDeadline(deadline)
	if _, err := conn.Write(raw); err != nil {
		res.Error = "write: " + err.Error()
		res.ElapsedMS = time.Since(start).Milliseconds()
		return res
	}
	status, size, _ := readResponse(conn, deadline)
	res.Status = status
	res.Size = size
	res.ElapsedMS = time.Since(start).Milliseconds()
	return res
}

func main() {
	in := inputSpec{TimeoutMS: 2000}
	raw, err := ioReadAll(os.Stdin)
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(outputSpec{Results: []caseResult{}})
		return
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		json.NewEncoder(os.Stdout).Encode(outputSpec{Results: []caseResult{}})
		return
	}
	timeout := time.Duration(in.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	out := outputSpec{Results: []caseResult{}}
	for _, c := range in.Cases {
		out.Results = append(out.Results, runCase(in.Target, c, timeout))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.Encode(out)
}
