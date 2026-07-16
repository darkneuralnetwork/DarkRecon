package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yourname/dark-recon/internal/config"
	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/pkg/executor"
	"github.com/yourname/dark-recon/pkg/logger"
	"github.com/yourname/dark-recon/pkg/parser"
)

// KatanaCrawler crawls live hosts using Katana.
// CRITICAL: This runs AFTER live host discovery and BEFORE Nuclei.
// The URLs it discovers are fed into Nuclei as additional input.
type KatanaCrawler struct {
	cfg    *config.Config
	db     *storage.DB
	scanID int64
}

// NewKatanaCrawler creates a new Katana crawler.
func NewKatanaCrawler(cfg *config.Config, db *storage.DB, scanID int64) *KatanaCrawler {
	return &KatanaCrawler{cfg: cfg, db: db, scanID: scanID}
}

// KatanaResult holds the crawling output.
type KatanaResult struct {
	AllURLs       []CrawledURL
	URLsWithParams []CrawledURL
}

// CrawledURL represents a URL discovered by Katana.
type CrawledURL struct {
	URL        string   `json:"url"`
	Subdomain  string   `json:"subdomain"`
	HasParams  bool     `json:"has_params"`
	ParamNames []string `json:"param_names,omitempty"`
	ParamCount int      `json:"param_count"`
}

// Run crawls all live hosts in parallel using Katana.
// Unlike the Python version which crawled only top-N subdomains AFTER priority scoring,
// the Go version crawls ALL live hosts BEFORE Nuclei, per the new pipeline.
func (k *KatanaCrawler) Run(ctx context.Context, liveHosts []LiveHost) (*KatanaResult, error) {
	logger.Phase("Phase 4 — Deep Crawling (Katana): %s", k.cfg.Target)

	if len(liveHosts) == 0 {
		logger.Warn("No live hosts to crawl. Skipping Katana.")
		return &KatanaResult{}, nil
	}

	logger.Tool("katana", "Crawling %d live hosts in parallel...", len(liveHosts))

	var allURLs []CrawledURL
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrency to avoid overwhelming the target
	maxConcurrency := k.cfg.Katana.Concurrency
	if maxConcurrency > k.cfg.Threads {
		maxConcurrency = k.cfg.Threads
	}
	if maxConcurrency > len(liveHosts) {
		maxConcurrency = len(liveHosts)
	}
	sem := make(chan struct{}, maxConcurrency)

	// NOTE: `break` inside `select` exits the select only, not this loop, so a
	// cancelled context would otherwise keep spawning crawl goroutines. Check
	// ctx.Err() at the loop top instead.
	for _, host := range liveHosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(host LiveHost) {
			defer wg.Done()
			defer func() { <-sem }()
			urls := k.runKatanaSingle(ctx, host)
			mu.Lock()
			allURLs = append(allURLs, urls...)
			mu.Unlock()
			logger.Tool("katana", "%s: Found %d URLs", host.Subdomain, len(urls))
		}(host)
	}
	wg.Wait()

	// Deduplicate URLs
	seen := make(map[string]bool)
	var deduped []CrawledURL
	var urlsWithParams []CrawledURL
	for _, u := range allURLs {
		if seen[u.URL] {
			continue
		}
		seen[u.URL] = true
		deduped = append(deduped, u)
		if u.HasParams {
			urlsWithParams = append(urlsWithParams, u)
		}
	}

	// Store in DB
	for _, u := range deduped {
		paramJSON, _ := json.Marshal(u.ParamNames)
		_ = k.db.InsertCrawledURL(k.scanID, storage.CrawledURL{
			URL:        u.URL,
			Subdomain:  u.Subdomain,
			HasParams:  u.HasParams,
			ParamNames: string(paramJSON),
			ParamCount: u.ParamCount,
			Source:     "katana",
		})
	}

	// Write all URLs to file for Nuclei to consume
	allURLsFile := filepath.Join(k.cfg.ParsedDir(k.cfg.Target), "all_urls.txt")
	var urlStrs []string
	for _, u := range deduped {
		urlStrs = append(urlStrs, u.URL)
	}
	os.WriteFile(allURLsFile, []byte(strings.Join(urlStrs, "\n")), 0644)

	// Write param URLs separately
	paramURLsFile := filepath.Join(k.cfg.ParsedDir(k.cfg.Target), "param_urls.txt")
	var paramStrs []string
	for _, u := range urlsWithParams {
		paramStrs = append(paramStrs, u.URL)
	}
	os.WriteFile(paramURLsFile, []byte(strings.Join(paramStrs, "\n")), 0644)

	logger.Success("Total URLs crawled: %d (params: %d)", len(deduped), len(urlsWithParams))
	logger.Result("URLs crawled", len(deduped))
	logger.Result("URLs with parameters", len(urlsWithParams))

	return &KatanaResult{
		AllURLs:        deduped,
		URLsWithParams: urlsWithParams,
	}, nil
}

// runKatanaSingle runs Katana on a single host.
// FIX: Python used -t (concurrency flag is -c in katana, -t is timeout).
// Go version uses -c for concurrency.
func (k *KatanaCrawler) runKatanaSingle(ctx context.Context, host LiveHost) []CrawledURL {
	concurrency := k.cfg.Katana.Concurrency
	if concurrency > k.cfg.Threads {
		concurrency = k.cfg.Threads
	}

	args := []string{
		"katana",
		"-u", host.URL,
		"-j",  // JSON output — includes response.status_code so we can filter 404/5xx
		"-aff",      // auto-fill forms
		"-d", fmt.Sprintf("%d", k.cfg.Katana.Depth), // crawl depth
		"-c", fmt.Sprintf("%d", concurrency),
		"-kf", "all", // include all known file types
		"-strategy", "breadth-first", // breadth-first avoids diving deep on huge sites (prevents 10m timeouts)
		"-silent",
		"-no-color",
		"-timeout", fmt.Sprintf("%d", k.cfg.Timeout),
		// Exclude 404 + 5xx error responses at the source so they never enter
		// the crawled URL list (saves time + avoids feeding dead URLs to Nuclei).
		"-fdc", "status_code != 404 && status_code < 500",
	}

	// Active headless crawling for JS-rendered content
	if k.cfg.Katana.Headless {
		args = append(args, "-hl")
	}
	// Parse and crawl JS endpoints
	if k.cfg.Katana.JSParse {
		args = append(args, "-js-crawl")
	}

	result := executor.Run(ctx, executor.Config{
		Args:    args,
		Timeout: 10 * time.Minute,
	})

	// Surface katana failures (e.g. timeouts) per-host instead of silently
	// dropping them. Partial stdout is still parsed below.
	if result.ReturnCode != 0 {
		if result.Stderr != "" {
			logger.Warn("katana %s: %s", host.Subdomain, executor.TruncateLog(result.Stderr, 160))
		} else if result.Stdout == "" {
			logger.Warn("katana %s: failed (rc=%d)", host.Subdomain, result.ReturnCode)
		}
	}
	if result.ReturnCode != 0 && result.Stdout == "" {
		return nil
	}

	// Save raw output per subdomain (sanitized filename)
	safeName := strings.ReplaceAll(host.Subdomain, ".", "_")
	rawPath := filepath.Join(k.cfg.RawDir(k.cfg.Target), fmt.Sprintf("katana_%s.txt", safeName))
	os.WriteFile(rawPath, []byte(result.Stdout), 0644)

	// Parse Katana output. With -j, every line is a JSON object containing
	// request.endpoint (the URL) and response.status_code. We skip 404 and 5xx
	// responses so dead/error URLs never reach Nuclei or the DB.
	var urls []CrawledURL
	var filtered404, filtered5xx int
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var urlStr string
		statusCode := 0

		if strings.HasPrefix(line, "{") {
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				continue
			}
			if req, ok := obj["request"].(map[string]any); ok {
				if endpoint, ok := req["endpoint"].(string); ok {
					urlStr = endpoint
				}
			}
			if resp, ok := obj["response"].(map[string]any); ok {
				if sc, ok := resp["status_code"].(float64); ok {
					statusCode = int(sc)
				}
			}
		} else {
			// Fallback for plain-URL lines (non-JSON output)
			urlStr = line
		}

		// Ensure it's a URL
		if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
			continue
		}

		// Filter out 404 and 5xx error responses
		if statusCode == 404 {
			filtered404++
			continue
		}
		if statusCode >= 500 && statusCode < 600 {
			filtered5xx++
			continue
		}

		hasParams, paramNames, paramCount := parser.ExtractParamsFromURL(urlStr)
		subdomain := parser.ExtractHostname(urlStr)

		urls = append(urls, CrawledURL{
			URL:        urlStr,
			Subdomain:  subdomain,
			HasParams:  hasParams,
			ParamNames: paramNames,
			ParamCount: paramCount,
		})
	}

	if filtered404 > 0 || filtered5xx > 0 {
		logger.Tool("katana", "%s: filtered %d 404s + %d 5xx errors", host.Subdomain, filtered404, filtered5xx)
	}

	return urls
}
