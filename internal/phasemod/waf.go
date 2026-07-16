package phasemod

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/pkg/executor"
	"github.com/yourname/dark-recon/pkg/logger"
)

// RunWAFDetection runs wafw00f against every live host concurrently. The WAF
// name is stored on p1_host_intel.waf and a WAF detection is also logged as
// an info-severity finding in p1_findings.
//
// wafw00f writes JSON only to a -o file (not stdout), so each goroutine uses
// its own temp file.
func (r *Runner) RunWAFDetection(ctx context.Context, hosts []string) {
	if !r.cfg.Phase1.WAFDetect {
		return
	}
	if !toolAvailable("wafw00f", "-V") {
		r.emit(map[string]any{"phase": "waf_detect", "status": "skipped", "message": "wafw00f not found, skipping WAF detection"})
		logger.Warn("wafw00f not found, skipping WAF detection")
		return
	}
	if len(hosts) == 0 {
		return
	}
	if len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}

	r.emit(map[string]any{"phase": "waf_detect", "status": "running", "message": fmt.Sprintf("wafw00f on %d hosts", len(hosts))})
	logger.Phase("Phase 1+ — WAF Detection (wafw00f): %d hosts", len(hosts))

	sem := make(chan struct{}, maxWorkers(r.cfg.Phase1.WAFWorkers, 20))
	var wg sync.WaitGroup

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			wafName, manufacturer, detected := r.wafw00fHost(ctx, h)
			if wafName == "" && !detected {
				return // tool erro out, skip
			}
			_ = r.db.UpdateP1HostWAF(r.scanID, h, wafName, manufacturer)
			r.emit(map[string]any{
				"phase": "waf_detect", "status": "waf",
				"message": fmt.Sprintf("%s: %s", h, wafName),
				"finding": map[string]any{"host": h, "waf": wafName, "detected": detected},
			})
			if detected {
				desc := fmt.Sprintf("WAF detected: %s (%s)", wafName, manufacturer)
				_ = r.db.InsertP1Finding(r.scanID, storage.P1Finding{
					Subdomain: h, Tool: "wafw00f", Severity: "info",
					Name: "WAF Detected", Description: &desc,
				})
				r.emitFinding(h, "wafw00f", "info", "WAF: "+wafName, wafName)
			}
		}(host)
	}
	wg.Wait()

	r.emit(map[string]any{"phase": "waf_detect", "status": "completed", "message": fmt.Sprintf("WAF detection complete: %d hosts", len(hosts))})
	logger.Success("wafw00f: scanned %d hosts", len(hosts))
}

// wafw00fHost runs wafw00f on a single host and returns (wafName, manufacturer, detected).
func (r *Runner) wafw00fHost(ctx context.Context, host string) (string, string, bool) {
	tmp, err := os.CreateTemp("", "wafw00f-*.json")
	if err != nil {
		return "", "", false
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	cmdCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "wafw00f", "-a", "https://"+host, "-o", tmpPath, "-f", "json")
	cmd.Env = append(os.Environ(), "PATH="+executor.ToolPath("wafw00f")+":"+os.Getenv("PATH"))
	_ = cmd.Run() // wafw00f returns non-zero sometimes even on success

	data, err := os.ReadFile(tmpPath)
	if err != nil || len(data) == 0 {
		return "none", "", false
	}
	var results []struct {
		URL          string `json:"url"`
		Detected     bool   `json:"detected"`
		Firewall     string `json:"firewall"`
		Manufacturer string `json:"manufacturer"`
	}
	if err := json.Unmarshal(data, &results); err != nil || len(results) == 0 {
		return "none", "", false
	}
	first := results[0]
	wafName := "none"
	if first.Detected && first.Firewall != "" && first.Firewall != "None" {
		wafName = first.Firewall
	}
	manu := first.Manufacturer
	if manu == "None" {
		manu = ""
	}
	return wafName, manu, first.Detected
}

// saveRawJS persists a downloaded JS body for later secret scanning, returning
// the on-disk path. Used by JSAnalysis and consumed by SecretScan.
func (r *Runner) saveRawJS(subdomain, urlStr string, body []byte) string {
	dir := filepath.Join(r.cfg.RawDir(r.target), "js")
	_ = os.MkdirAll(dir, 0755)
	// Sanitize a stable filename from host + url hash-ish.
	safe := strings.NewReplacer("://", "_", "/", "_", "?", "_", "&", "_", "=", "_").Replace(urlStr)
	if len(safe) > 120 {
		safe = safe[:120]
	}
	path := filepath.Join(dir, subdomain+"__"+safe+".js")
	_ = os.WriteFile(path, body, 0644)
	return path
}
