// Package phasemod implements the new Phase-1 advanced modules:
// PassiveRecon, PortScan (nmap), WAFDetection (wafw00f), JSAnalysis
// (pure Go), ParamDiscovery (arjun) and SecretScan (trufflehog + gitleaks).
//
// Every module follows the existing project conventions:
//   - exec.CommandContext + timeout (never shell=True)
//   - semaphore worker-pool for per-item concurrency
//   - results written via the existing *storage.DB single-writer
//   - progress reported through the shared ProgressCallback
//
// All modules are additive: they never modify existing tool invocations,
// tables, or signatures. Missing tools are skipped gracefully.
package phasemod

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/yourname/dark-recon/internal/config"
	"github.com/yourname/dark-recon/internal/storage"
)

// ProgressFn is the existing pipeline progress callback signature.
type ProgressFn func(data map[string]any)

// Runner holds shared state for all phase-1 modules.
type Runner struct {
	cfg     *config.Config
	db      *storage.DB
	scanID  int64
	target  string
	progress ProgressFn
	// jsURLMap maps an on-disk crawled-JS file path back to its original
	// accessible web URL. Built once at the start of RunSecretScan and only
	// read afterwards, so it is safe to consult from the concurrent scanner
	// goroutines. Lets secret findings report a clickable source URL instead
	// of a local filesystem path.
	jsURLMap map[string]string
}

// NewRunner creates a Runner bound to a scan.
func NewRunner(cfg *config.Config, db *storage.DB, scanID int64, target string, progress ProgressFn) *Runner {
	return &Runner{cfg: cfg, db: db, scanID: scanID, target: target, progress: progress}
}

func (r *Runner) emit(data map[string]any) {
	if r.progress != nil {
		r.progress(data)
	}
}

// emitFinding broadcasts a unified finding event to the live progress feed.
// This is the WebSocket-equivalent of the doc's BroadcastEvent("finding_added").
func (r *Runner) emitFinding(host, tool, severity, name, waf string) {
	r.emit(map[string]any{
		"phase":    "phase1_findings",
		"status":   "finding",
		"message":  name,
		"finding":  map[string]any{"host": host, "tool": tool, "severity": severity, "name": name, "waf": waf},
	})
}

// toolAvailable reports whether a binary is both on PATH and actually
// executable — it runs `<bin> <versionArg>` and requires non-empty stdout.
// This guards against broken/zero-byte binaries (e.g. a half-installed
// naabu) that would otherwise pass a plain LookPath check.
func toolAvailable(bin string, versionArg ...string) bool {
	p, err := exec.LookPath(bin)
	if err != nil || p == "" {
		return false
	}
	args := versionArg
	if len(args) == 0 {
		args = []string{"--version"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

// toolPath returns the resolved binary path or empty string.
func toolPath(bin string) string {
	p, err := exec.LookPath(bin)
	if err != nil {
		return ""
	}
	return p
}

// MaxHosts caps the number of live hosts a module will process, to keep
// scans bounded on huge target footprints. 0 = no cap (caller pre-trims).
const maxHosts = 500

// resolveLiveHosts reads the live hosts for this scan from the DB and returns
// their subdomain names (deduplicated, lowercased).
func (r *Runner) resolveLiveHosts(ctx context.Context) []string {
	hosts, err := r.db.GetLiveHosts(r.scanID)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool, len(hosts))
	var out []string
	for _, h := range hosts {
		s := h.Subdomain
		if s == "" {
			continue
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
