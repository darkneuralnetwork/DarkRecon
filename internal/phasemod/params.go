package phasemod

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/pkg/executor"
	"github.com/yourname/dark-recon/pkg/logger"
)

// RunParamDiscovery runs arjun against high-priority URLs (those on hosts with
// status 200 from the live check) to discover hidden GET/POST parameters.
// arjun is slow per URL, so concurrency is deliberately low.
func (r *Runner) RunParamDiscovery(ctx context.Context) {
	if !r.cfg.Phase1.ParamDiscovery {
		return
	}
	if !toolAvailable("arjun", "--version") {
		r.emit(map[string]any{"phase": "param_discovery", "status": "skipped", "message": "arjun not found, skipping param discovery"})
		logger.Warn("arjun not found, skipping param discovery")
		return
	}

	// Pick high-signal URLs: 200-OK crawled URLs, capped to keep runtime sane.
	urls, err := r.db.GetCrawledURLs(r.scanID)
	if err != nil || len(urls) == 0 {
		return
	}
	type target struct {
		url string
		sub string
	}
	var targets []target
	seen := make(map[string]bool)
	for _, u := range urls {
		// arjun needs a bare URL without fragment; keep param-free base URL.
		base := stripQuery(u.URL)
		if seen[base] {
			continue
		}
		seen[base] = true
		targets = append(targets, target{base, u.Subdomain})
		if len(targets) >= 50 {
			break
		}
	}
	if len(targets) == 0 {
		return
	}

	r.emit(map[string]any{"phase": "param_discovery", "status": "running", "message": fmt.Sprintf("arjun on %d URLs", len(targets))})
	logger.Phase("Phase 1+ — Parameter Discovery (arjun): %d URLs", len(targets))

	sem := make(chan struct{}, maxWorkers(r.cfg.Phase1.ParamDiscoveryWorkers, 5))
	var wg sync.WaitGroup
	totalParams := 0
	var mu sync.Mutex

	for _, t := range targets {
		wg.Add(1)
		go func(t target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			params := r.arjunURL(ctx, t.url)
			for method, list := range params {
				for _, p := range list {
					_ = r.db.InsertP1Param(r.scanID, storage.P1Param{
						Subdomain: t.sub, URL: t.url, ParamName: p,
						ParamType: strings.ToLower(method), Source: "arjun",
					})
					r.emit(map[string]any{
						"phase": "param_discovery", "status": "param",
						"message": fmt.Sprintf("%s: %s (%s)", t.sub, p, method),
					})
				}
			}
			mu.Lock()
			for _, list := range params {
				totalParams += len(list)
			}
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	// Recompute per-host param counts.
	r.recountParams()

	r.emit(map[string]any{"phase": "param_discovery", "status": "completed", "count": totalParams, "message": fmt.Sprintf("Param discovery complete: %d params", totalParams)})
	logger.Success("arjun: %d parameters discovered", totalParams)
}

// arjunURL runs arjun on one URL and returns params grouped by HTTP method.
func (r *Runner) arjunURL(ctx context.Context, urlStr string) map[string][]string {
	tmp, err := os.CreateTemp("", "arjun-*.json")
	if err != nil {
		return nil
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	cmdCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	result := executor.Run(cmdCtx, executor.Config{
		Args:    []string{"arjun", "-u", urlStr, "-oJ", tmpPath, "--stable", "-q"},
		Timeout: 90 * time.Second,
	})
	_ = result

	data, err := os.ReadFile(tmpPath)
	if err != nil || len(data) == 0 {
		return nil
	}
	var out struct {
		URL    string              `json:"url"`
		Params map[string][]string `json:"params"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out.Params
}

func stripQuery(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}

func (r *Runner) recountParams() {
	rows, err := r.db.Conn().Query(
		`SELECT subdomain, COUNT(DISTINCT param_name) FROM p1_params WHERE scan_id = ? GROUP BY subdomain`, r.scanID)
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
			Subdomain: c.host, ParamCount: c.count, HasParams: c.count > 0,
		})
	}
}
