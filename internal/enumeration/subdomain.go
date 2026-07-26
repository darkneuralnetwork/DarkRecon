package enumeration

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yourname/dark-recon/internal/config"
	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/pkg/executor"
	"github.com/yourname/dark-recon/pkg/logger"
	"github.com/yourname/dark-recon/pkg/parser"
)

// DNS brute-force prefixes (ported from Python's DNS_BRUTE_PREFIXES).
var dnsBrutePrefixes = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
	"dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "dev", "staging",
	"test", "admin", "portal", "vpn", "remote", "blog", "shop", "app",
	"cdn", "static", "media", "images", "img", "assets", "css", "js",
	"login", "sso", "auth", "oauth", "secure", "panel", "cpanel",
	"webmin", "server", "db", "database", "mysql", "postgres", "redis",
	"mongo", "elastic", "es", "grafana", "prometheus", "kibana",
	"jenkins", "ci", "git", "gitlab", "github", "bitbucket", "jira",
	"confluence", "wiki", "docs", "api-docs", "swagger", "status",
	"monitor", "health", "ping", "trace", "debug", "internal", "intranet",
	"extranet", "backup", "old", "new", "beta", "alpha", "demo", "sandbox",
	"uat", "preprod", "prod", "production", "stage", "dev1", "dev2",
	"test1", "test2", "qa", "load", "perf", "proxy", "nginx", "apache",
	"node", "python", "java", "ruby", "go", "php", "react", "vue",
	"angular", "next", "nuxt", "gatsby", "wordpress", "wp", "drupal",
	"joomla", "magento", "shopify", "woocommerce", "store", "checkout",
	"payment", "billing", "invoice", "account", "user", "profile",
	"dashboard", "console", "manage", "control", "hub", "gateway",
	"router", "switch", "firewall", "ipsec", "openvpn",
	"cloud", "aws", "azure", "gcp", "digitalocean", "heroku",
	"kubernetes", "k8s", "docker", "container", "registry",
	"analytics", "tracking", "pixel", "ads", "marketing", "email",
	"newsletter", "notification", "push", "websocket", "socket",
	"realtime", "stream", "video", "audio", "download", "upload",
	"file", "storage", "s3", "bucket", "cdn1", "cdn2", "edge",
	"origin", "cache", "memcached", "varnish", "fastly",
	"cloudfront", "akamai", "incapsula", "sucuri", "cloudflare",
}

// Enumerator discovers subdomains using multiple techniques.
type Enumerator struct {
	cfg     *config.Config
	db      *storage.DB
	scanID  int64
}

// New creates a new subdomain enumerator.
func New(cfg *config.Config, db *storage.DB, scanID int64) *Enumerator {
	return &Enumerator{cfg: cfg, db: db, scanID: scanID}
}

// Result holds the enumeration output.
type Result struct {
	Subdomains []string
	BySource   map[string][]string
}

// Run executes subdomain enumeration with 3 parallel goroutines:
// subfinder, ffuf DNS brute, and Go-native DNS resolution.
func (e *Enumerator) Run(ctx context.Context) (*Result, error) {
	logger.Phase("Phase 1 — Subdomain Enumeration: %s", e.cfg.Target)

	var mu sync.Mutex
	allSubs := make(map[string][]string) // subdomain -> sources
	bySource := make(map[string][]string)

	var wg sync.WaitGroup
	wg.Add(3)

	// Goroutine 1: subfinder
	go func() {
		defer wg.Done()
		subs := e.runSubfinder(ctx)
		mu.Lock()
		bySource["subfinder"] = subs
		for _, s := range subs {
			allSubs[s] = append(allSubs[s], "subfinder")
		}
		mu.Unlock()
		logger.Tool("subfinder", "Found %d subdomains", len(subs))
	}()

	// Goroutine 2: ffuf DNS brute
	go func() {
		defer wg.Done()
		subs := e.runFfufDNS(ctx)
		mu.Lock()
		bySource["ffuf"] = subs
		for _, s := range subs {
			allSubs[s] = append(allSubs[s], "ffuf")
		}
		mu.Unlock()
		logger.Tool("ffuf", "Found %d subdomains via DNS brute", len(subs))
	}()

	// Goroutine 3: Go-native DNS resolution (replaces dnspython)
	go func() {
		defer wg.Done()
		subs := e.runDNSBrute(ctx)
		mu.Lock()
		bySource["dns_enum"] = subs
		for _, s := range subs {
			allSubs[s] = append(allSubs[s], "dns_enum")
		}
		mu.Unlock()
		logger.Tool("dns_enum", "Resolved %d subdomains via DNS", len(subs))
	}()

	wg.Wait()

	// Deduplicate and sort
	finalSubs := make([]string, 0, len(allSubs))
	for sub := range allSubs {
		finalSubs = append(finalSubs, sub)
	}
	finalSubs = parser.Deduplicate(finalSubs)
	sort.Strings(finalSubs)

	// Store in database
	for _, sub := range finalSubs {
		sources := allSubs[sub]
		source := strings.Join(sources, ",")
		_ = e.db.InsertSubdomain(e.scanID, sub, source)
	}

	// Write subdomains.txt for downstream modules
	subsFile := filepath.Join(e.cfg.ParsedDir(e.cfg.Target), "subdomains.txt")
	os.WriteFile(subsFile, []byte(strings.Join(finalSubs, "\n")), 0644)

	logger.Success("Total unique subdomains: %d", len(finalSubs))
	logger.Result("subdomains discovered", len(finalSubs))
	logger.Result("sources", strings.Join(sortedKeys(bySource), ", "))

	return &Result{
		Subdomains: finalSubs,
		BySource:   bySource,
	}, nil
}

// runSubfinder runs subfinder for passive subdomain enumeration.
func (e *Enumerator) runSubfinder(ctx context.Context) []string {
	result := executor.Run(ctx, executor.Config{
		Args: []string{
			"subfinder", "-d", e.cfg.Target,
			"-silent",
			"-t", fmt.Sprintf("%d", e.cfg.Threads),
		},
		Timeout: 5 * time.Minute,
	})

	// Save raw output
	rawPath := filepath.Join(e.cfg.RawDir(e.cfg.Target), "subfinder.txt")
	os.WriteFile(rawPath, []byte(result.Stdout), 0644)

	if result.ReturnCode != 0 {
		logger.Warn("subfinder error: %s", truncate(result.Stderr, 200))
		return []string{}
	}

	return parser.ParseSubfinderOutput(result.Stdout)
}

// runFfufDNS runs ffuf DNS brute force. It does NOT fall back to runDNSBrute
// when the wordlist is missing: the dedicated DNS-brute goroutine in Run
// already calls runDNSBrute, so a fallback here would just duplicate that
// work (same built-in prefixes, same resolutions) and double the DNS load.
// Instead we skip ffuf and let goroutine 3 own DNS brute in that case.
func (e *Enumerator) runFfufDNS(ctx context.Context) []string {
	wordlist := e.cfg.SecLists.DNSWordlist
	if wordlist == "" {
		logger.Warn("no DNS wordlist configured; skipping ffuf DNS brute (Go DNS brute still runs)")
		return []string{}
	}
	if _, err := os.Stat(wordlist); err != nil {
		logger.Warn("seclists DNS wordlist not found: %s, skipping ffuf DNS brute (Go DNS brute still runs)", wordlist)
		return []string{}
	}

	result := executor.Run(ctx, executor.Config{
		Args: []string{
			"ffuf",
			"-u", fmt.Sprintf("https://FUZZ.%s", e.cfg.Target),
			"-w", wordlist,
			"-mc", "all",
			"-fc", "400,502",
			"-t", fmt.Sprintf("%d", e.cfg.Threads),
			"-timeout", fmt.Sprintf("%d", e.cfg.Timeout),
		},
		Timeout: 10 * time.Minute,
	})

	rawPath := filepath.Join(e.cfg.RawDir(e.cfg.Target), "ffuf_dns.txt")
	os.WriteFile(rawPath, []byte(result.Stdout), 0644)

	if result.ReturnCode != 0 {
		logger.Warn("ffuf DNS error: %s", truncate(result.Stderr, 200))
		return []string{}
	}

	// Parse ffuf output - extract subdomains from URLs
	var subdomains []string
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "http") {
			continue
		}
		hostname := parser.ExtractHostname(line)
		if strings.HasSuffix(hostname, "."+e.cfg.Target) {
			subdomains = append(subdomains, strings.ToLower(hostname))
		}
	}

	return parser.Deduplicate(subdomains)
}

// runDNSBrute runs Go-native DNS resolution (replaces dnspython).
func (e *Enumerator) runDNSBrute(ctx context.Context) []string {
	prefixes := dnsBrutePrefixes

	// Load extra prefixes from wordlist if available
	if e.cfg.SecLists.DNSWordlist != "" {
		if data, err := os.ReadFile(e.cfg.SecLists.DNSWordlist); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					prefixes = append(prefixes, line)
				}
			}
		}
	}

	logger.Tool("dns_enum", "Resolving %d DNS entries...", len(prefixes))

	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, "8.8.8.8:53")
		},
	}

	var subdomains []string
	var mu sync.Mutex
	sem := make(chan struct{}, e.cfg.Threads) // concurrency limit
	var wg sync.WaitGroup

	// NOTE: a `break` inside `select` only exits the select, not this loop,
	// so a plain `select { case <-ctx.Done(): break }` would keep spawning
	// goroutines after cancellation. Check ctx.Err() at the loop top instead.
	for _, prefix := range prefixes {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(prefix string) {
			defer wg.Done()
			defer func() { <-sem }()
			fqdn := fmt.Sprintf("%s.%s", prefix, e.cfg.Target)
			lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			_, err := resolver.LookupHost(lookupCtx, fqdn)
			if err == nil {
				mu.Lock()
				subdomains = append(subdomains, strings.ToLower(fqdn))
				mu.Unlock()
			}
		}(prefix)
	}
	wg.Wait()

	subdomains = parser.Deduplicate(subdomains)

	// Save raw output
	rawPath := filepath.Join(e.cfg.RawDir(e.cfg.Target), "dns_enum.txt")
	os.WriteFile(rawPath, []byte(strings.Join(subdomains, "\n")), 0644)

	return subdomains
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// sortedKeys returns the keys of m sorted alphabetically.
func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
