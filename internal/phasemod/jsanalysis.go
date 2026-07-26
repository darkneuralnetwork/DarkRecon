package phasemod

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/pkg/logger"
)

// jsPattern defines one extraction rule for JS analysis.
type jsPattern struct {
	name    string
	pattern *regexp.Regexp
	typ     string // endpoint | secret
}

// jsPatterns covers common API paths, internal IPs, and well-known secret
// formats. Implemented in pure Go (no binary dependency).
var jsPatterns = []jsPattern{
	{"api_path", regexp.MustCompile(`["'](/api/[a-zA-Z0-9/_\-\.]+)["']`), "endpoint"},
	{"relative_path", regexp.MustCompile(`["'](/[a-zA-Z0-9/_\-\.]{3,50})["']`), "endpoint"},
	{"full_url", regexp.MustCompile(`["'](https?://[a-zA-Z0-9/_\-\.:\?=&%#@]+)["']`), "endpoint"},
	{"internal_ip", regexp.MustCompile(`["'](10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)["']`), "endpoint"},
	{"aws_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "secret"},
	{"github_token", regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), "secret"},
	{"google_api", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), "secret"},
	{"slack_token", regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{20,}`), "secret"},
	{"stripe_key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{20,}`), "secret"},
	{"jwt", regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`), "secret"},
	{"private_key", regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`), "secret"},
	{"generic_token", regexp.MustCompile(`(?i)(token|secret|password|apikey|api_key)\s*[:=]\s*['"'][a-zA-Z0-9_\-\.]{16,}['"']`), "secret"},
	{"bearer", regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}`), "secret"},
}

// RunJSAnalysis fetches every .js URL discovered by Katana (from crawled_urls)
// and applies regex extraction for endpoints and secrets. JS bodies are also
// saved to <rawdir>/js/ so trufflehog/gitleaks can scan them afterwards.
func (r *Runner) RunJSAnalysis(ctx context.Context) {
	if !r.cfg.Phase1.JSAnalysis {
		return
	}
	r.emit(map[string]any{"phase": "js_analysis", "status": "running", "message": "JS analysis on crawled .js URLs"})
	logger.Phase("Phase 1+ — JS Analysis: %s", r.target)

	urls, err := r.db.GetCrawledURLs(r.scanID)
	if err != nil || len(urls) == 0 {
		// No crawled URLs (Katana didn't run / no prior crawl data to reuse).
		// Fall back to discovering JS URLs directly from the live hosts'
		// homepages so a standalone "only js_analysis" scan still produces
		// results instead of a blank section.
		discovered := r.discoverJSFromLiveHosts(ctx)
		if discovered == 0 {
			r.emit(map[string]any{"phase": "js_analysis", "status": "completed", "count": 0, "message": "JS analysis complete: no crawled URLs and no live hosts to probe"})
			return
		}
		urls, err = r.db.GetCrawledURLs(r.scanID)
		if err != nil || len(urls) == 0 {
			r.emit(map[string]any{"phase": "js_analysis", "status": "completed", "count": 0, "message": "JS analysis complete: no JS files found on live hosts"})
			return
		}
	}
	var jsURLs []struct {
		id  int64
		sub string
		url string
	}
	for _, u := range urls {
		lu := strings.ToLower(u.URL)
		if strings.Contains(lu, ".js") {
			jsURLs = append(jsURLs, struct {
				id  int64
				sub string
				url string
			}{u.ID, u.Subdomain, u.URL})
		}
	}
	if len(jsURLs) == 0 {
		r.emit(map[string]any{"phase": "js_analysis", "status": "completed", "count": 0, "message": "JS analysis complete: no JS files found"})
		return
	}

	sem := make(chan struct{}, maxWorkers(r.cfg.Phase1.JSAnalysisWorkers, 30))
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 10 * time.Second}

	totalFindings := 0
	var mu sync.Mutex

	for _, ju := range jsURLs {
		wg.Add(1)
		go func(ju struct {
			id  int64
			sub string
			url string
		}) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := http.NewRequestWithContext(ctx, "GET", ju.url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Dark-Recon/1.0)")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			// Limit to 512KB per file.
			body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			if err != nil || len(body) == 0 {
				return
			}
			content := string(body)

			// Persist JS file record + raw body for secret scanners.
			sizeBytes := len(body)
			jsFileID, _ := r.db.InsertP1JSFile(r.scanID, storage.P1JSFile{
				Subdomain: ju.sub, URL: ju.url, SizeBytes: &sizeBytes,
			})
			_ = r.saveRawJS(ju.sub, ju.url, body)

			seen := make(map[string]bool)
			for _, pat := range jsPatterns {
				matches := pat.pattern.FindAllStringSubmatch(content, -1)
				for _, m := range matches {
					val := m[0]
					if len(m) > 1 {
						val = m[1]
					}
					key := pat.typ + ":" + val
					if seen[key] {
						continue
					}
					seen[key] = true

					context := extractContext(content, m[0], 50)
					var jsFileIDVal *int64
					if jsFileID > 0 {
						v := jsFileID
						jsFileIDVal = &v
					}
					_ = r.db.InsertP1JSFinding(r.scanID, storage.P1JSFinding{
						JsFileID: jsFileIDVal, Subdomain: ju.sub, Type: pat.typ,
						Pattern: pat.name, Value: val, Context: context,
					})

					if pat.typ == "secret" {
						name := fmt.Sprintf("Secret in JS: %s", pat.name)
						ev := val
						desc := fmt.Sprintf("Found in %s", ju.url)
						_ = r.db.InsertP1Finding(r.scanID, storage.P1Finding{
							Subdomain: ju.sub, Tool: "js_analysis", Severity: "high",
							Name: name, Description: &desc, Evidence: &ev,
						})
						_ = r.db.InsertP1Secret(r.scanID, storage.P1Secret{
							Subdomain: &ju.sub, SourceURL: &ju.url, SecretType: pat.name,
							RawMatch: val, Tool: "js_analysis",
						})
						r.emitFinding(ju.sub, "js_analysis", "high", name, "")
						mu.Lock()
						totalFindings++
						mu.Unlock()
					}
					r.emit(map[string]any{
						"phase": "js_analysis", "status": "finding",
						"message": fmt.Sprintf("%s: %s (%s)", ju.sub, pat.name, pat.typ),
					})
				}
			}
		}(ju)
	}
	wg.Wait()

	// Update per-host JS endpoint counts.
	r.recountJSFindings()

	r.emit(map[string]any{"phase": "js_analysis", "status": "completed", "count": totalFindings, "message": fmt.Sprintf("JS analysis complete: %d findings", totalFindings)})
	logger.Success("JS analysis: %d secret findings", totalFindings)
}

// extractContext returns up to `radius` chars on each side of the match,
// newlines collapsed to spaces, capped at 200 chars total (per spec).
func extractContext(content, match string, radius int) string {
	idx := strings.Index(content, match)
	if idx < 0 {
		return ""
	}
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + radius
	if end > len(content) {
		end = len(content)
	}
	snippet := strings.ReplaceAll(content[start:end], "\n", " ")
	if len(snippet) > 200 {
		snippet = snippet[:200]
	}
	return snippet
}

// recountJSFindings recomputes per-host JS-endpoint counts into p1_host_intel.
func (r *Runner) recountJSFindings() {
	rows, err := r.db.Conn().Query(
		`SELECT subdomain, COUNT(*) FROM p1_js_findings WHERE scan_id = ? AND type = 'endpoint' GROUP BY subdomain`, r.scanID)
	if err != nil {
		return
	}
	defer rows.Close()
	type pc struct {
		host  string
		count int
	}
	var counts []pc
	for rows.Next() {
		var p pc
		if err := rows.Scan(&p.host, &p.count); err != nil {
			continue
		}
		counts = append(counts, p)
	}
	for _, c := range counts {
		_ = r.db.UpsertP1HostIntel(r.scanID, storage.P1HostIntel{
			Subdomain: c.host, JSEndpointCount: c.count, HasJSEndpoints: c.count > 0,
		})
	}
}

// scriptSrcRE extracts the URL from <script src="..."> tags in an HTML page.
var scriptSrcRE = regexp.MustCompile(`(?i)<script[^>]+\ssrc\s*=\s*["']([^"']+)["']`)

// discoverJSFromLiveHosts is the standalone fallback for JS analysis: when
// there are no crawled URLs (Katana didn't run and nothing was reused from a
// prior scan), it fetches each live host's homepage, parses <script src>
// tags, resolves relative URLs, and inserts the .js URLs into crawled_urls so
// the normal JS-analysis loop can process them. Returns the number of JS URLs
// discovered. Capped at maxHosts hosts to stay bounded.
func (r *Runner) discoverJSFromLiveHosts(ctx context.Context) int {
	hosts := r.resolveLiveHosts(ctx)
	if len(hosts) == 0 {
		return 0
	}
	if len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}
	r.emit(map[string]any{"phase": "js_analysis", "status": "info", "message": fmt.Sprintf("No crawled URLs — discovering JS files from %d live hosts", len(hosts))})
	logger.Phase("Phase 1+ — JS Analysis: discovering JS from %d live hosts (no crawl data)", len(hosts))

	sem := make(chan struct{}, maxWorkers(r.cfg.Phase1.JSAnalysisWorkers, 30))
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 10 * time.Second}
	var mu sync.Mutex
	var discovered int

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Try https first, fall back to http.
			pageURL := ""
			var body []byte
			for _, scheme := range []string{"https://", "http://"} {
				u := scheme + h
				req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Dark-Recon/1.0)")
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				body, err = io.ReadAll(io.LimitReader(resp.Body, 512*1024))
				resp.Body.Close()
				if err != nil || len(body) == 0 {
					continue
				}
				pageURL = resp.Request.URL.String() // follow redirects → base for resolving
				break
			}
			if pageURL == "" {
				return
			}

			base, err := url.Parse(pageURL)
			if err != nil {
				return
			}
			matches := scriptSrcRE.FindAllStringSubmatch(string(body), -1)
			for _, m := range matches {
				raw := m[1]
				if !strings.Contains(strings.ToLower(raw), ".js") {
					continue
				}
				ref, err := url.Parse(raw)
				if err != nil {
					continue
				}
				resolved := base.ResolveReference(ref).String()
				_ = r.db.InsertCrawledURL(r.scanID, storage.CrawledURL{
					URL: resolved, Subdomain: h, Source: "js_discovery",
				})
				mu.Lock()
				discovered++
				mu.Unlock()
			}
		}(host)
	}
	wg.Wait()

	if discovered > 0 {
		r.emit(map[string]any{"phase": "js_analysis", "status": "info", "message": fmt.Sprintf("Discovered %d JS files from live hosts", discovered), "count": discovered})
		logger.Success("JS discovery: found %d JS files from live hosts", discovered)
	}
	return discovered
}
