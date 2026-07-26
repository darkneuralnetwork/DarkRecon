// Package repeater implements the Dark-Recon Repeater: a Burp-Repeater-style
// manual HTTP request editor. The user sends a raw HTTP request string; the
// forwarder parses it, enforces the scan scope and SSRF guards, executes the
// request, and returns the raw response.
//
// This is NOT an intercepting proxy. There is no CONNECT handler, no Mitm CA,
// and no browser integration. The Repeater is a deliberate, request-by-request
// forwarder fed by URLs/findings discovered during recon — the manual-testing
// companion to the automated Phase-2 modules.
package repeater

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ParsedRequest is the result of splitting a raw HTTP request string into its
// method, target URL, headers and body. The Raw field preserves the original
// text (with Content-Length normalized) so it can be echoed back to the UI and
// persisted verbatim.
type ParsedRequest struct {
	Method  string
	URL     *url.URL
	Host    string
	Headers http.Header
	Body    string
	Raw     string
}

// ParseRequest parses a raw HTTP/1.1 request string into a ParsedRequest.
//
// The request line may use an absolute URI ("GET https://host/path HTTP/1.1")
// or an origin-form path ("GET /path HTTP/1.1"); in the latter case the Host
// header supplies the scheme and authority. The body is everything after the
// first blank line. CRLF and bare-LF line endings are both accepted.
//
// ParseRequest does no scope or SSRF checking — that is the forwarder's job.
func ParseRequest(raw string) (*ParsedRequest, error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	// Split headers from body on the first blank line.
	var headerBlock, body string
	if idx := strings.Index(raw, "\n\n"); idx >= 0 {
		headerBlock = raw[:idx]
		body = raw[idx+2:]
	} else {
		headerBlock = raw
		body = ""
	}

	lines := strings.Split(headerBlock, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, fmt.Errorf("empty request")
	}

	// Request line: METHOD REQUEST-URI HTTP/1.1
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed request line: %q", lines[0])
	}
	method := parts[0]
	requestURI := parts[1]

	// Parse header lines (skip the request line).
	headers := http.Header{}
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		if key != "" {
			headers.Add(key, val)
		}
	}

	host := headers.Get("Host")
	var target *url.URL

	switch {
	case strings.HasPrefix(requestURI, "http://") || strings.HasPrefix(requestURI, "https://"):
		// Absolute URI (proxy-style request line). Parse directly.
		u, err := url.Parse(requestURI)
		if err != nil {
			return nil, fmt.Errorf("invalid absolute URI %q: %w", requestURI, err)
		}
		target = u
		if target.Host == "" && host != "" {
			target.Host = host
		}
		if host == "" {
			host = target.Host
		}
	default:
		// Origin-form path (e.g. "/api/foo?x=1"). Need the Host header to
		// build the full URL; default scheme to https.
		if host == "" {
			return nil, fmt.Errorf("relative request URI %q requires a Host header", requestURI)
		}
		scheme := schemeForHost(host)
		u, err := url.Parse(scheme + "://" + host + requestURI)
		if err != nil {
			return nil, fmt.Errorf("invalid request URI %q: %w", requestURI, err)
		}
		target = u
	}

	if target.Host == "" {
		return nil, fmt.Errorf("could not determine target host")
	}

	pr := &ParsedRequest{
		Method:  method,
		URL:     target,
		Host:    target.Host,
		Headers: headers,
		Body:    body,
	}

	// Normalize Content-Length to match the actual body so the server doesn't
	// hang waiting for more bytes (or reject the request). We rewrite the raw
	// text so the persisted version matches what was actually sent.
	pr.Raw = rebuildRaw(pr, body)
	return pr, nil
}

// schemeForHost picks http vs https for an origin-form request. If the Host
// header carries a port commonly associated with plaintext HTTP, use http;
// otherwise default to https (the modern norm).
func schemeForHost(host string) string {
	if _, port, err := net.SplitHostPort(host); err == nil {
		switch port {
		case "80", "8080", "8000", "8008", "3000", "5000", "9000":
			return "http"
		}
	}
	return "https"
}

// rebuildRaw reconstructs the canonical raw request text from the parsed
// components, with a corrected Content-Length header. Header order from the
// original is preserved (Host first, then the rest in original order); any
// pre-existing Content-Length is replaced.
func rebuildRaw(pr *ParsedRequest, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", pr.Method, pr.URL.RequestURI())
	fmt.Fprintf(&b, "Host: %s\r\n", pr.Host)

	wroteContentLength := false
	for key, vals := range pr.Headers {
		if strings.EqualFold(key, "Host") {
			continue
		}
		if strings.EqualFold(key, "Content-Length") {
			wroteContentLength = true
			fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", key, v)
		}
	}
	if !wroteContentLength && body != "" {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}
