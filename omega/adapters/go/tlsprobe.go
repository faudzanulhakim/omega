// tlsprobe — OMEGA TLS/SSL configuration analyzer (Go core).
//
// Read-only audit of one host:port using crypto/tls: protocol version
// support, weak ciphers, certificate expiry / SAN / self-signed /
// hostname mismatch. Produces findings-grade JSON.
//
// Input (JSON stdin):
//   {"host":"example.com","port":443,"timeout_ms":5000}
//
// Output (JSON stdout):
//   {"host","port","cert":{"subject","issuer","not_after","san":[...],
//    "self_signed","hostname_ok","days_left"},
//    "versions":{"tls1.0":true,...},"ciphers":[...],"weak":{...}}
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

type input struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	TimeoutMs int    `json:"timeout_ms"`
}

var versionNames = map[uint16]string{
	tls.VersionSSL30: "ssl3.0",
	tls.VersionTLS10: "tls1.0",
	tls.VersionTLS11: "tls1.1",
	tls.VersionTLS12: "tls1.2",
	tls.VersionTLS13: "tls1.3",
}

var weakSuites = map[string]string{
	"TLS_RSA_WITH_RC4_128_SHA":                "rc4",
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           "3des",
	"TLS_RSA_WITH_AES_128_CBC_SHA256":         "cbc-sha256",
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     "3des",
	"TLS_RSA_WITH_AES_128_CBC_SHA":            "cbc",
	"TLS_RSA_WITH_AES_256_CBC_SHA":            "cbc",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      "cbc",
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      "cbc",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    "cbc",
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    "cbc",
	"TLS_RSA_EXPORT_WITH_RC4_40_MD5":          "export-rc4",
	"TLS_RSA_WITH_DES_CBC_SHA":                "des",
	"TLS_DH_anon_WITH_AES_128_CBC_SHA":        "anon",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   "", // strong
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   "", // strong
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    "", // strong
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "", // strong
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "", // strong
	"TLS_AES_128_GCM_SHA256":                  "", // tls1.3
	"TLS_AES_256_GCM_SHA384":                  "", // tls1.3
	"TLS_CHACHA20_POLY1305_SHA256":            "", // tls1.3
}

type certInfo struct {
	Subject    string   `json:"subject"`
	Issuer     string   `json:"issuer"`
	NotAfter   string   `json:"not_after"`
	NotBefore  string   `json:"not_before"`
	SAN        []string `json:"san"`
	SelfSigned bool     `json:"self_signed"`
	HostnameOK bool     `json:"hostname_ok"`
	DaysLeft   int      `json:"days_left"`
	Expired    bool     `json:"expired"`
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
	port := in.Port
	if port == 0 {
		port = 443
	}
	timeout := 5 * time.Second
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	hostport := fmt.Sprintf("%s:%d", in.Host, port)

	dialer := &net.Dialer{Timeout: timeout}
	cfg := &tls.Config{InsecureSkipVerify: true,
		ServerName: in.Host}
	versions := map[string]bool{}
	ciphers := []string{}
	var leaf *x509.Certificate

	// enumerate supported versions: pin Min/Max per attempt
	for _, v := range []uint16{tls.VersionTLS13, tls.VersionTLS12,
		tls.VersionTLS11, tls.VersionTLS10, tls.VersionSSL30} {
		cfgV := cfg.Clone()
		cfgV.MinVersion = v
		cfgV.MaxVersion = v
		conn, err := tls.DialWithDialer(dialer, "tcp", hostport, cfgV)
		name := versionNames[v]
		if err != nil {
			versions[name] = false
			continue
		}
		versions[name] = true
		cs := conn.ConnectionState()
		if leaf == nil && len(cs.PeerCertificates) > 0 {
			leaf = cs.PeerCertificates[0]
		}
		conn.Close()
	}

	// enumerate cipher suites (TLS<=1.2): pin one suite per attempt
	suiteIDs := []uint16{}
	for _, s := range tls.CipherSuites() {
		suiteIDs = append(suiteIDs, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		suiteIDs = append(suiteIDs, s.ID)
	}
	for _, id := range suiteIDs {
		cfgC := cfg.Clone()
		cfgC.MinVersion = tls.VersionTLS10
		cfgC.MaxVersion = tls.VersionTLS12
		cfgC.CipherSuites = []uint16{id}
		conn, err := tls.DialWithDialer(dialer, "tcp", hostport, cfgC)
		if err == nil {
			ciphers = append(ciphers, tls.CipherSuiteName(id))
			conn.Close()
		}
	}
	if versions["tls1.3"] {
		ciphers = append(ciphers, "TLS_AES_128_GCM_SHA256",
			"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256")
	}

	cert := map[string]interface{}{}
	if leaf != nil {
		san := []string{}
		san = append(san, leaf.DNSNames...)
		for _, ip := range leaf.IPAddresses {
			san = append(san, ip.String())
		}
		selfSigned := len(leaf.AuthorityKeyId) == 0 ||
			string(leaf.AuthorityKeyId) == string(leaf.SubjectKeyId)
		hostnameOK := leaf.VerifyHostname(in.Host) == nil
		days := int(time.Until(leaf.NotAfter).Hours() / 24)
		cert = map[string]interface{}{
			"subject":     leaf.Subject.String(),
			"issuer":      leaf.Issuer.String(),
			"not_after":   leaf.NotAfter.UTC().Format(time.RFC3339),
			"not_before":  leaf.NotBefore.UTC().Format(time.RFC3339),
			"san":         san,
			"self_signed": selfSigned,
			"hostname_ok": hostnameOK,
			"days_left":   days,
			"expired":     time.Now().After(leaf.NotAfter),
		}
	}

	weak := map[string]string{}
	for _, c := range ciphers {
		if why, ok := weakSuites[c]; ok && why != "" {
			weak[c] = why
		}
	}
	// protocol weaknesses
	if versions["ssl3.0"] || versions["tls1.0"] || versions["tls1.1"] {
		weak["__protocol"] = "legacy-version-supported"
	}
	emit(map[string]interface{}{
		"host": in.Host, "port": port,
		"versions": versions, "ciphers": ciphers,
		"weak": weak, "cert": cert,
	})
}
