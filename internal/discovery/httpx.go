package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourname/dark-recon/internal/config"
	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/pkg/executor"
	"github.com/yourname/dark-recon/pkg/logger"
	"github.com/yourname/dark-recon/pkg/parser"
)

// HttpxChecker checks which subdomains are live using httpx.
type HttpxChecker struct {
	cfg    *config.Config
	db     *storage.DB
	scanID int64
}

// NewHttpxChecker creates a new httpx checker.
func NewHttpxChecker(cfg *config.Config, db *storage.DB, scanID int64) *HttpxChecker {
	return &HttpxChecker{cfg: cfg, db: db, scanID: scanID}
}

// LiveHost represents a live subdomain.
type LiveHost struct {
	URL           string   `json:"url"`
	Subdomain     string   `json:"subdomain"`
	StatusCode    int      `json:"status_code"`
	Title         *string  `json:"title,omitempty"`
	ContentLength *int     `json:"content_length,omitempty"`
	Webserver     *string  `json:"webserver,omitempty"`
	CDN           *string  `json:"cdn,omitempty"`
	RedirectURL   *string  `json:"redirect_url,omitempty"`
	Technologies  []string `json:"technologies,omitempty"`
}

// Result holds the live check output.
type LiveResult struct {
	LiveHosts []LiveHost
	DeadSubs  []string
}

// Run runs httpx on the subdomain list.
func (h *HttpxChecker) Run(ctx context.Context, subdomains []string) (*LiveResult, error) {
	logger.Phase("Phase 2 — Live Host Detection: %s", h.cfg.Target)

	if len(subdomains) == 0 {
		logger.Warn("No subdomains to check. Skipping live check.")
		return &LiveResult{}, nil
	}

	// Write subdomains to temp file for httpx -l. Always (over)write: on a
	// rescan the in-memory `subdomains` slice is authoritative, and reusing a
	// stale subdomains.txt from a prior run would probe the wrong host set.
	subsFile := filepath.Join(h.cfg.ParsedDir(h.cfg.Target), "subdomains.txt")
	os.WriteFile(subsFile, []byte(strings.Join(subdomains, "\n")), 0644)

	logger.Tool("httpx", "Checking %d subdomains...", len(subdomains))

	result := executor.Run(ctx, executor.Config{
		Args: []string{
			"httpx",
			"-l", subsFile,
			"-status-code",
			"-title",
			"-tech-detect",
			"-follow-redirects",
			"-silent",
			"-json",
			"-t", fmt.Sprintf("%d", h.cfg.Threads),
			"-timeout", fmt.Sprintf("%d", h.cfg.Timeout),
		},
		Timeout: 10 * time.Minute,
	})

	// Save raw output
	rawPath := filepath.Join(h.cfg.RawDir(h.cfg.Target), "httpx.json")
	os.WriteFile(rawPath, []byte(result.Stdout), 0644)

	if result.ReturnCode != 0 && result.Stdout == "" {
		logger.Warn("httpx error: %s", truncate(result.Stderr, 200))
		return &LiveResult{}, nil
	}

	// Parse httpx JSON output
	httpxResults := parser.ParseJSONLines(result.Stdout)
	var liveHosts []LiveHost
	liveHostnames := make(map[string]bool)

	// Hosts that respond with 404 (nothing there) or 5xx (server error) are not
	// useful attack-surface targets — they're excluded from the live list so
	// downstream phases (tech detect / crawl / nuclei / priority) don't waste
	// effort on dead or broken endpoints, and the UI live list stays clean.
	var skipped404, skipped5xx int

	for _, entry := range httpxResults {
		url, _ := entry["url"].(string)
		hostname, _ := entry["host"].(string)
		if url == "" {
			continue
		}
		if hostname == "" {
			hostname = parser.ExtractHostname(url)
		}
		hostname = strings.ToLower(hostname)

		statusCode := 0
		if sc, ok := entry["status_code"].(float64); ok {
			statusCode = int(sc)
		}

		// Filter out 404 (not found) and 5xx (server error) responses. These
		// are not actionable live hosts; counting them as dead is fine since a
		// 404/500 page offers no attack surface to enumerate.
		if statusCode == 404 {
			skipped404++
			continue
		}
		if statusCode >= 500 && statusCode < 600 {
			skipped5xx++
			continue
		}

		liveHostnames[hostname] = true

		var title *string
		if t, ok := entry["title"].(string); ok && t != "" {
			title = &t
		}
		var webserver *string
		if ws, ok := entry["webserver"].(string); ok && ws != "" {
			webserver = &ws
		}
		var cdn *string
		if c, ok := entry["cdn"].(string); ok && c != "" {
			cdn = &c
		}
		var redirectURL *string
		if r, ok := entry["redirect_url"].(string); ok && r != "" {
			redirectURL = &r
		}
		var contentLength *int
		if cl, ok := entry["content_length"].(float64); ok {
			clInt := int(cl)
			contentLength = &clInt
		}

		var technologies []string
		if tech, ok := entry["tech"].([]any); ok {
			for _, t := range tech {
				if s, ok := t.(string); ok {
					technologies = append(technologies, s)
				}
			}
		}

		host := LiveHost{
			URL:           url,
			Subdomain:     hostname,
			StatusCode:    statusCode,
			Title:         title,
			ContentLength: contentLength,
			Webserver:     webserver,
			CDN:           cdn,
			RedirectURL:   redirectURL,
			Technologies:  technologies,
		}
		liveHosts = append(liveHosts, host)

		// Store in DB
		techJSON, _ := json.Marshal(technologies)
		_ = h.db.InsertLiveHost(h.scanID, storage.LiveHost{
			URL:          url,
			Subdomain:    hostname,
			StatusCode:   statusCode,
			Title:        title,
			ContentLength: contentLength,
			Webserver:    webserver,
			CDN:          cdn,
			RedirectURL:  redirectURL,
			TechDetected: string(techJSON),
		})
	}

	// Determine dead subdomains
	var deadSubs []string
	for _, sub := range subdomains {
		if !liveHostnames[strings.ToLower(sub)] {
			deadSubs = append(deadSubs, sub)
		}
	}

	// Write live subdomains file for downstream modules
	liveFile := filepath.Join(h.cfg.ParsedDir(h.cfg.Target), "live_subdomains.txt")
	var liveURLs []string
	for _, lh := range liveHosts {
		liveURLs = append(liveURLs, lh.URL)
	}
	os.WriteFile(liveFile, []byte(strings.Join(liveURLs, "\n")), 0644)

	if skipped404 > 0 || skipped5xx > 0 {
		logger.Tool("httpx", "filtered %d 404 + %d 5xx responses from live list", skipped404, skipped5xx)
	}
	logger.Success("Found %d live subdomains", len(liveHosts))
	logger.Result("live hosts", len(liveHosts))
	logger.Result("dead / unresponsive", len(deadSubs))

	return &LiveResult{
		LiveHosts: liveHosts,
		DeadSubs:  deadSubs,
	}, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
