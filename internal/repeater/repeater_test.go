package repeater

import (
	"net"
	"strings"
	"testing"
)

func TestParseRequest_AbsoluteURI(t *testing.T) {
	raw := "GET https://example.com/api/v1/users?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
	pr, err := ParseRequest(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pr.Method != "GET" {
		t.Errorf("method = %q, want GET", pr.Method)
	}
	if pr.URL.Hostname() != "example.com" {
		t.Errorf("host = %q, want example.com", pr.URL.Hostname())
	}
	if pr.URL.Path != "/api/v1/users" {
		t.Errorf("path = %q, want /api/v1/users", pr.URL.Path)
	}
	if q := pr.URL.Query().Get("x"); q != "1" {
		t.Errorf("query x = %q, want 1", q)
	}
	if pr.Body != "" {
		t.Errorf("body = %q, want empty", pr.Body)
	}
	// Raw should be rebuilt with CRLF line endings.
	if !strings.Contains(pr.Raw, "GET /api/v1/users?x=1 HTTP/1.1\r\n") {
		t.Errorf("raw request line not normalized: %q", pr.Raw)
	}
}

func TestParseRequest_RelativePathWithHost(t *testing.T) {
	raw := "POST /api/login HTTP/1.1\r\nHost: target.local:8443\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}"
	pr, err := ParseRequest(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pr.Method != "POST" {
		t.Errorf("method = %q, want POST", pr.Method)
	}
	// Port 8443 is not in the http-port list → defaults to https.
	if pr.URL.Scheme != "https" {
		t.Errorf("scheme = %q, want https", pr.URL.Scheme)
	}
	if pr.URL.Hostname() != "target.local" {
		t.Errorf("host = %q, want target.local", pr.URL.Hostname())
	}
	if pr.URL.Port() != "8443" {
		t.Errorf("port = %q, want 8443", pr.URL.Port())
	}
	if pr.Body != `{"user":"admin"}` {
		t.Errorf("body = %q", pr.Body)
	}
	// Content-Length should be recomputed to match the body.
	if !strings.Contains(pr.Raw, "Content-Length: 16\r\n") {
		t.Errorf("Content-Length not recomputed: %q", pr.Raw)
	}
}

func TestParseRequest_BareLF(t *testing.T) {
	// Requests pasted from a terminal often use bare LF instead of CRLF.
	raw := "GET / HTTP/1.1\nHost: example.com\n\n"
	pr, err := ParseRequest(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pr.URL.Hostname() != "example.com" {
		t.Errorf("host = %q", pr.URL.Hostname())
	}
}

func TestParseRequest_HTTPPortScheme(t *testing.T) {
	// Port 8080 → http scheme for relative-path requests.
	raw := "GET /foo HTTP/1.1\r\nHost: target.local:8080\r\n\r\n"
	pr, err := ParseRequest(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pr.URL.Scheme != "http" {
		t.Errorf("scheme = %q, want http", pr.URL.Scheme)
	}
}

func TestParseRequest_MissingHost(t *testing.T) {
	raw := "GET /path HTTP/1.1\r\nUser-Agent: test\r\n\r\n"
	_, err := ParseRequest(raw)
	if err == nil {
		t.Fatal("expected error for relative path without Host header")
	}
}

func TestParseRequest_Empty(t *testing.T) {
	if _, err := ParseRequest(""); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseRequest_MalformedRequestLine(t *testing.T) {
	if _, err := ParseRequest("GARBAGE\r\n\r\n"); err == nil {
		t.Fatal("expected error for malformed request line")
	}
}

func TestURLBuilder_GET(t *testing.T) {
	ub := URLBuilder{}
	raw, err := ub.BuildRawRequest("https://example.com/api?x=1", "GET", map[string]string{"y": "2"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.HasPrefix(raw, "GET /api?x=1&y=2 HTTP/1.1\r\n") {
		t.Errorf("request line missing expected query: %q", raw)
	}
	if !strings.Contains(raw, "Host: example.com\r\n") {
		t.Errorf("Host header missing: %q", raw)
	}
}

func TestURLBuilder_POSTBody(t *testing.T) {
	ub := URLBuilder{}
	raw, err := ub.BuildRawRequest("https://example.com/api", "POST", map[string]string{"user": "admin", "pass": "x"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Body params are url-encoded; order is non-deterministic so check both.
	if !strings.Contains(raw, "user=admin") || !strings.Contains(raw, "pass=x") {
		t.Errorf("body params missing: %q", raw)
	}
	if !strings.Contains(raw, "Content-Type: application/x-www-form-urlencoded\r\n") {
		t.Errorf("Content-Type missing: %q", raw)
	}
}

func TestURLBuilder_AddsScheme(t *testing.T) {
	ub := URLBuilder{}
	raw, err := ub.BuildRawRequest("example.com/path", "GET", nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(raw, "Host: example.com\r\n") {
		t.Errorf("Host missing: %q", raw)
	}
}

// TestURLBuilder_BrowserHeaders verifies the seed request is minimal and
// realistic: a browser User-Agent + Accept, and crucially NO Accept-Encoding
// (so Go's http.Transport adds gzip itself and transparently decompresses
// the response — otherwise the Repeater would show garbled compressed bytes).
func TestURLBuilder_BrowserHeaders(t *testing.T) {
	ub := URLBuilder{}
	raw, err := ub.BuildRawRequest("https://apistagingnew.globe.gov/", "GET", nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Must NOT carry the old bot User-Agent.
	if strings.Contains(raw, "Dark-Recon-Repeater") {
		t.Errorf("request still uses bot User-Agent: %q", raw)
	}
	// Must carry the Chrome browser User-Agent.
	if !strings.Contains(raw, "User-Agent: "+BrowserUserAgent+"\r\n") {
		t.Errorf("browser User-Agent missing: %q", raw)
	}
	// Must include a browser-style Accept.
	if !strings.Contains(raw, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n") {
		t.Errorf("Accept header missing: %q", raw)
	}
	// Must NOT set Accept-Encoding explicitly — Go's Transport must own it so
	// the response is auto-decompressed.
	if strings.Contains(raw, "Accept-Encoding:") {
		t.Errorf("Accept-Encoding must not be set explicitly (breaks auto-decompress): %q", raw)
	}
	// No Accept-Language / Connection / Upgrade-Insecure-Requests padding —
	// the seed should be minimal, not a hardcoded browser header dump.
	for _, h := range []string{"Accept-Language:", "Connection:", "Upgrade-Insecure-Requests:"} {
		if strings.Contains(raw, h) {
			t.Errorf("unnecessary header %q in minimal seed: %q", h, raw)
		}
	}
}

func TestCheckIP_BlocksLoopback(t *testing.T) {
	if err := checkIP(net.ParseIP("127.0.0.1"), "localhost", false); err == nil {
		t.Fatal("expected 127.0.0.1 to be blocked")
	}
	if err := checkIP(net.ParseIP("127.0.0.1"), "localhost", true); err != nil {
		t.Fatalf("expected 127.0.0.1 allowed with AllowInternal: %v", err)
	}
}

func TestCheckIP_BlocksPrivate(t *testing.T) {
	if err := checkIP(net.ParseIP("10.0.0.1"), "internal", false); err == nil {
		t.Fatal("expected 10.0.0.1 to be blocked")
	}
	if err := checkIP(net.ParseIP("192.168.1.1"), "internal", false); err == nil {
		t.Fatal("expected 192.168.1.1 to be blocked")
	}
	if err := checkIP(net.ParseIP("169.254.169.254"), "metadata", false); err == nil {
		t.Fatal("expected 169.254.169.254 (AWS metadata) to be blocked")
	}
}

func TestCheckIP_AllowsPublic(t *testing.T) {
	if err := checkIP(net.ParseIP("93.184.216.34"), "example.com", false); err != nil {
		t.Fatalf("expected public IP allowed: %v", err)
	}
}
