package phasemod

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/pkg/executor"
	"github.com/yourname/dark-recon/pkg/logger"
)

// RunPassiveRecon enumerates subdomains from passive HTTP sources (crt.sh,
// HackerTarget, AlienVault OTX) and optionally the chaos binary when an API
// key is configured. All sources run concurrently. Results are written to
// p1_passive_recon and also fed into the existing subdomains table so the
// live-check pipeline can pick them up.
func (r *Runner) RunPassiveRecon(ctx context.Context) {
	if !r.cfg.Phase1.PassiveRecon {
		return
	}
	r.emit(map[string]any{"phase": "passive_recon", "status": "running", "message": "Passive recon (crt.sh, HackerTarget, AlienVault, chaos)"})
	logger.Phase("Phase 1+ — Passive Recon: %s", r.target)

	sem := make(chan struct{}, maxWorkers(r.cfg.Phase1.PassiveReconWorkers, 5))
	var wg sync.WaitGroup

	type source struct {
		name string
		fn   func(context.Context) []string
	}
	sources := []source{
		{"crtsh", r.fetchCRTSh},
		{"hackertarget", r.fetchHackerTarget},
		{"alienvault", r.fetchAlienVault},
	}
	if r.cfg.Phase1.ChaosAPIKey != "" && toolAvailable("chaos", "-version") {
		sources = append(sources, source{"chaos", r.runChaos})
	} else if r.cfg.Phase1.ChaosAPIKey != "" {
		logger.Warn("chaos: API key set but binary not found/usable, skipping")
	}

	var mu sync.Mutex
	totalSubs := 0
	for _, src := range sources {
		wg.Add(1)
		go func(s source) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			subs := safeSource(ctx, s)
			logger.Tool(s.name, "passive: found %d subdomains", len(subs))

			for _, sub := range subs {
				sub = strings.ToLower(strings.TrimSpace(sub))
				if sub == "" || !strings.HasSuffix(sub, "."+r.target) {
					continue
				}
				_ = r.db.InsertP1PassiveRecon(r.scanID, storage.P1PassiveRecon{
					Subdomain: sub, Source: s.name, DataType: "subdomain", Value: sub,
				})
				// Also seed the existing subdomains table so httpx/live-check picks it up.
				_ = r.db.InsertSubdomain(r.scanID, sub, s.name)
				r.emit(map[string]any{
					"phase": "passive_recon", "status": "subdomain",
					"message": fmt.Sprintf("%s: %s", s.name, sub),
				})
			}
			mu.Lock()
			totalSubs += len(subs)
			mu.Unlock()
		}(src)
	}
	wg.Wait()

	r.emit(map[string]any{"phase": "passive_recon", "status": "completed", "count": totalSubs, "message": fmt.Sprintf("Passive recon complete: %d subdomain candidates", totalSubs)})
	logger.Success("Passive recon: %d subdomain candidates", totalSubs)
}

// safeSource runs a source function, recovering from panics so one bad
// source never aborts the whole recon step.
func safeSource(ctx context.Context, s struct {
	name string
	fn   func(context.Context) []string
}) []string {
	defer func() {
		if rec := recover(); rec != nil {
			logger.Warn("%s: panicked: %v", s.name, rec)
		}
	}()
	return s.fn(ctx)
}

func httpGet(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Dark-Recon/1.0)")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
}

// fetchCRTSh queries the crt.sh certificate-transparency JSON API.
func (r *Runner) fetchCRTSh(ctx context.Context) []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", r.target)
	data, err := httpGet(ctx, url, 20*time.Second)
	if err != nil {
		logger.Warn("crtsh: %v", err)
		return nil
	}
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		// crt.sh occasionally returns nested-JSON or HTML on rate-limit; bail.
		logger.Warn("crtsh: parse error: %v", err)
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, row := range rows {
		for _, line := range strings.Split(row.NameValue, "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "*."))
			if line != "" && strings.HasSuffix(line, r.target) && !seen[line] {
				seen[line] = true
				out = append(out, line)
			}
		}
	}
	return out
}

// fetchHackerTarget uses the free hostsearch API.
func (r *Runner) fetchHackerTarget(ctx context.Context) []string {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", r.target)
	data, err := httpGet(ctx, url, 20*time.Second)
	if err != nil {
		logger.Warn("hackertarget: %v", err)
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		// format: subdomain,ip
		if idx := strings.Index(line, ","); idx > 0 {
			host := strings.TrimSpace(line[:idx])
			if host != "" {
				out = append(out, host)
			}
		}
	}
	return out
}

// fetchAlienVault queries the OTX passive DNS endpoint.
func (r *Runner) fetchAlienVault(ctx context.Context) []string {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", r.target)
	data, err := httpGet(ctx, url, 20*time.Second)
	if err != nil {
		logger.Warn("alienvault: %v", err)
		return nil
	}
	var resp struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		logger.Warn("alienvault: parse error: %v", err)
		return nil
	}
	var out []string
	for _, e := range resp.PassiveDNS {
		if e.Hostname != "" {
			out = append(out, e.Hostname)
		}
	}
	return out
}

// runChaos runs the projectdiscovery chaos binary (needs PDCP_API_KEY env).
func (r *Runner) runChaos(ctx context.Context) []string {
	result := executor.Run(ctx, executor.Config{
		Args:    []string{"chaos", "-d", r.target, "-silent"},
		Timeout: 2 * time.Minute,
		Env:     map[string]string{"PDCP_API_KEY": r.cfg.Phase1.ChaosAPIKey},
	})
	if result.ReturnCode != 0 && result.Stdout == "" {
		logger.Warn("chaos: %s", executor.TruncateLog(result.Stderr, 160))
		return nil
	}
	var out []string
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func maxWorkers(n, fallback int) int {
	if n <= 0 {
		return fallback
	}
	return n
}
