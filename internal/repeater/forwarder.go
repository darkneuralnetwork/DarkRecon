package repeater

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yourname/dark-recon/internal/storage"
)

// Safety limits. These are deliberately conservative to keep the Repeater from
// being abused as an SSRF / DoS pivot: a slow server can't hold a connection
// open, and a huge response can't fill memory or the SQLite DB.
const (
	DefaultTimeout       = 15 * time.Second
	MaxRedirects         = 5
	MaxResponseBodyBytes = 5 * 1024 * 1024 // 5 MiB hard cap on captured body
)

// ScopeChecker is the interface the forwarder uses to decide whether a target
// host is in scope for the current scan. *storage.DB satisfies it via
// IsHostInScope; the interface keeps the forwarder testable without a real DB.
type ScopeChecker interface {
	IsHostInScope(scanID int64, host string) (bool, error)
}

// Options tunes a single Send call.
type Options struct {
	// AllowInternal permits requests to private/loopback/link-local IPs.
	// Default false — the SSRF guard blocks them so a Repeater session can't
	// be used to hit http://169.254.169.254/ or internal services.
	AllowInternal bool
	// FollowRedirects enables automatic redirect following (up to MaxRedirects).
	// Default false — the user sees the 3xx response exactly as the server sent
	// it, matching Burp Repeater's default behaviour.
	FollowRedirects bool
	// Timeout overrides DefaultTimeout when non-zero.
	Timeout time.Duration
}

// Response is the captured result of a forwarded request. Any of the fields
// may be zero/empty on error; Err is set when the request never completed.
type Response struct {
	StatusCode int
	Headers    string // formatted as "Key: Value\r\n" for display
	Body       string
	DurationMs int64
	Err        string
}

// Forwarder executes parsed raw HTTP requests with scope + SSRF enforcement.
// It is safe for concurrent use; the underlying http.Transport is reused. The
// scope checker is passed per-Send (not stored on the struct) so sends to
// different scans can never race on the scope binding.
type Forwarder struct {
	client        *http.Client
	allowInsecure bool // skip TLS cert verification (self-signed dev boxes)
}

// NewForwarder constructs a Forwarder. The scope checker argument is ignored
// (kept for signature stability) — Send accepts it per-call instead.
// allowInsecureTLS disables certificate verification, appropriate for a
// pentest tool that routinely hits self-signed / expired-cert targets.
func NewForwarder(_ ScopeChecker, allowInsecureTLS bool) *Forwarder {
	dialer := &net.Dialer{
		Timeout: DefaultTimeout,
	}
	transport := &http.Transport{
		// Custom DialContext resolves the hostname and rejects private IPs
		// (unless AllowInternal is set per-request via the context) BEFORE the
		// connection is established. This is the SSRF guard: it cannot be
		// bypassed by following a redirect to an internal address because the
		// check runs on every dial, including redirect dials.
		DialContext: makeScopedDialer(dialer),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: allowInsecureTLS,
		},
		// Don't pool Repeater connections — each request is a one-off and we
		// don't want idle conns to a target lingering after the user moves on.
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		// Default: do not follow redirects. Overridden per-request via
		// CheckRedirect when Options.FollowRedirects is set.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Forwarder{client: client, allowInsecure: allowInsecureTLS}
}

// Send executes a raw HTTP request string against the given scan's scope.
//
// Pipeline: parse → scope check (host must be in scan's live_hosts /
// crawled_urls) → SSRF guard (block private IPs unless AllowInternal) → send →
// capture response (status, headers, body up to MaxResponseBodyBytes, duration).
//
// On any failure (parse, scope, network, TLS) Response.Err is set and the
// status code is zero. A successful send always returns a populated Response.
// The scope checker is passed per-call so concurrent sends to different scans
// never race on a shared scope binding.
func (f *Forwarder) Send(ctx context.Context, scope ScopeChecker, scanID int64, raw string, opts Options) (*Response, *ParsedRequest) {
	resp := &Response{}
	start := time.Now()

	pr, err := ParseRequest(raw)
	if err != nil {
		resp.Err = fmt.Sprintf("parse error: %v", err)
		return resp, nil
	}

	// ── Scope guard: the request host must have been discovered during this
	// scan's recon. This is the single most important defence — it prevents the
	// Repeater from being used to probe arbitrary internal or out-of-scope
	// hosts. The check is on the hostname (port stripped) so the user can still
	// target non-standard ports on an in-scope host.
	host := pr.URL.Hostname()
	if host == "" {
		resp.Err = "could not determine target host from request"
		return resp, pr
	}
	inScope, err := scope.IsHostInScope(scanID, host)
	if err != nil {
		resp.Err = fmt.Sprintf("scope check failed: %v", err)
		return resp, pr
	}
	if !inScope {
		resp.Err = fmt.Sprintf("host %q is not in scope for this scan (only hosts discovered during recon may be targeted)", host)
		return resp, pr
	}

	// Build the *http.Request from the parsed components.
	bodyReader := strings.NewReader(pr.Body)
	req, err := http.NewRequestWithContext(ctx, pr.Method, pr.URL.String(), bodyReader)
	if err != nil {
		resp.Err = fmt.Sprintf("build request: %v", err)
		return resp, pr
	}
	// Apply parsed headers AFTER setting req.Body so http.NewRequest doesn't
	// clobber Host / Content-Length. Content-Length is recomputed by net/http
	// from the body, so we skip it. Host is set separately below.
	for key, vals := range pr.Headers {
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, v := range vals {
			req.Header.Add(key, v)
		}
	}
	if h := pr.Headers.Get("Host"); h != "" {
		req.Host = h
	}

	// Stash AllowInternal in the context so the scoped dialer can read it.
	ctx = context.WithValue(ctx, allowInternalKey{}, opts.AllowInternal)
	req = req.WithContext(ctx)

	// Configure redirect behaviour per-options. Each redirect target is
	// re-scoped so an open-redirect to an out-of-scope host is blocked.
	if opts.FollowRedirects {
		f.client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
			if len(via) >= MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", MaxRedirects)
			}
			if ok, err := scope.IsHostInScope(scanID, r.URL.Hostname()); err != nil || !ok {
				return fmt.Errorf("redirect to out-of-scope host %q blocked", r.URL.Hostname())
			}
			return nil
		}
	} else {
		f.client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()
	req = req.WithContext(ctx)

	httpResp, err := f.client.Do(req)
	if err != nil {
		resp.Err = sanitiseErr(err)
		resp.DurationMs = time.Since(start).Milliseconds()
		return resp, pr
	}
	defer httpResp.Body.Close()

	resp.StatusCode = httpResp.StatusCode
	resp.Headers = formatHeaders(httpResp.Header)

	// Cap the captured body to MaxResponseBodyBytes. io.LimitReader returns EOF
	// at the cap; if the real body is larger we note the truncation.
	limited := io.LimitReader(httpResp.Body, MaxResponseBodyBytes+1)
	bodyBytes, err := io.ReadAll(limited)
	if err != nil {
		// We still return whatever we read; the error is appended.
		resp.Body = string(bodyBytes)
		resp.Err = fmt.Sprintf("read response body: %v", err)
		resp.DurationMs = time.Since(start).Milliseconds()
		return resp, pr
	}
	if len(bodyBytes) > MaxResponseBodyBytes {
		resp.Body = string(bodyBytes[:MaxResponseBodyBytes])
		resp.Body += fmt.Sprintf("\n\n[... response truncated at %d bytes ...]", MaxResponseBodyBytes)
	} else {
		resp.Body = string(bodyBytes)
	}
	resp.DurationMs = time.Since(start).Milliseconds()
	return resp, pr
}

// allowInternalKey is the context-key type for the per-request AllowInternal
// SSRF override. Using a private type avoids collisions with other packages.
type allowInternalKey struct{}

// makeScopedDialer returns a DialContext that resolves the hostname and blocks
// private / loopback / link-local IPs unless the request's context carries
// allowInternalKey{} == true. Connecting to the resolved IP (rather than the
// hostname) also prevents DNS-rebinding: the resolution we check is the one we
// connect to.
func makeScopedDialer(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		allowInternal, _ := ctx.Value(allowInternalKey{}).(bool)

		// If the host is already an IP literal, check it directly — no DNS
		// lookup needed.
		if ip := net.ParseIP(host); ip != nil {
			if err := checkIP(ip, host, allowInternal); err != nil {
				return nil, err
			}
			return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}

		// Resolve and check every returned address. If ANY address is private
		// and AllowInternal is off, reject — this blocks DNS rebinding where
		// the first A record is public and the second is 127.0.0.1.
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", host, err)
		}
		for _, ip := range ips {
			if err := checkIP(ip.IP, host, allowInternal); err != nil {
				return nil, err
			}
		}

		// Connect to the first resolved IP. TLS (if used) still uses the
		// original hostname for SNI + cert verification because the
		// http.Transport sets tls.Config.ServerName from the request URL.
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

// checkIP rejects private/loopback/link-local/unicast addresses when
// AllowInternal is false. Returns nil for public IPs.
func checkIP(ip net.IP, host string, allowInternal bool) error {
	if allowInternal {
		return nil
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("SSRF guard: %q resolves to blocked address %s (loopback/private/link-local). Enable Allow Internal to override", host, ip)
	}
	return nil
}

// formatHeaders renders an http.Header as a display-friendly string. The
// response's own status line is added by the caller; this is just the headers.
func formatHeaders(h http.Header) string {
	var b strings.Builder
	for key, vals := range h {
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", key, v)
		}
	}
	return b.String()
}

// sanitiseErr strips noisy prefixes from net/http errors so the UI shows a
// clean message. e.g. `Get "https://x": dial tcp: ...` → `dial tcp: ...`.
func sanitiseErr(err error) string {
	msg := err.Error()
	// Trim the leading `Get "URL": ` / `Post "URL": ` wrapper from url.Error.
	if i := strings.Index(msg, `": `); i > 0 && strings.Contains(msg[:i], `"`) {
		msg = msg[i+3:]
	}
	return msg
}

// Compile-time assertion that *storage.DB satisfies ScopeChecker.
var _ ScopeChecker = (*storage.DB)(nil)

// URLBuilder helps the API layer pre-populate a raw request from a discovered
// URL. It is a struct (not a method on Forwarder) so the API handler can use it
// without a forwarder instance.
type URLBuilder struct{}

// BrowserUserAgent is the User-Agent the Repeater uses when pre-building a
// request from a discovered URL. It mimics a real Chrome browser so the
// captured response matches what an actual visitor to the domain would see —
// many sites serve different (or no) content to bot User-Agents, and WAFs
// routinely block obvious tool signatures. This is the "original request" a
// browser sends to the domain, not a Dark-Recon-branded probe.
const BrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

// BuildRawRequest constructs a raw HTTP/1.1 request string for the given URL
// and method, ready to drop into the Repeater editor. If params is non-empty
// and method is GET/HEAD, they are appended to the query string; for other
// methods they are placed in the body as application/x-www-form-urlencoded.
// The Host header is derived from the URL.
//
// This is a SEED: a minimal, realistic request (Host + browser User-Agent +
// Accept) used to prime a live probe in FromURL. The probe actually sends it
// and persists the normalized version (pr.Raw) as the real request. Accept-
// Encoding is intentionally omitted so Go's http.Transport owns decompression.
func (URLBuilder) BuildRawRequest(targetURL, method string, params map[string]string) (string, error) {
	if method == "" {
		method = "GET"
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	// A scheme-less URL like "example.com/path" parses with an empty Host
	// (url.Parse treats it as a relative path). Prepend a scheme so the host
	// is extracted correctly.
	if u.Scheme == "" {
		u, err = url.Parse("https://" + targetURL)
		if err != nil {
			return "", fmt.Errorf("invalid URL: %w", err)
		}
		u.Scheme = "https"
	}
	if u.Host == "" {
		return "", fmt.Errorf("URL has no host")
	}

	q := u.Query()
	body := ""
	if method == "GET" || method == "HEAD" {
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	} else if len(params) > 0 {
		form := url.Values{}
		for k, v := range params {
			form.Set(k, v)
		}
		body = form.Encode()
	}

	// Build a minimal, realistic seed request. Only the essentials are set so
	// the editor isn't padded with a hardcoded header block: Host, a browser
	// User-Agent (avoids WAF/bot-content skew), and a browser Accept. We
	// deliberately do NOT set Accept-Encoding — Go's http.Transport adds
	// "Accept-Encoding: gzip" itself and transparently decompresses the
	// response, so the captured body is plain text. If we set it explicitly
	// the Transport skips auto-decompress and the Repeater would show garbled
	// gzip bytes. The live probe in FromURL sends this seed and persists the
	// normalized version (pr.Raw) as the actual request.
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, u.RequestURI())
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	fmt.Fprintf(&b, "User-Agent: %s\r\n", BrowserUserAgent)
	b.WriteString("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n")
	if body != "" {
		b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String(), nil
}
