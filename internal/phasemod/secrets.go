package phasemod

import (
	"bufio"
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

// RunSecretScan scans the target's stored raw output directory (which includes
// downloaded JS files, crawled content, and any tool raw output) for leaked
// secrets. Both trufflehog and gitleaks run CONCURRENTLY when installed,
// maximising coverage; findings are merged into p1_secrets + p1_findings.
func (r *Runner) RunSecretScan(ctx context.Context) {
	if !r.cfg.Phase1.SecretScan {
		return
	}
	hasTruffle := toolAvailable("trufflehog", "--version")
	hasGitleaks := toolAvailable("gitleaks", "version")
	if !hasTruffle && !hasGitleaks {
		r.emit(map[string]any{"phase": "secret_scan", "status": "skipped", "message": "no secret scanner found (trufflehog/gitleaks)"})
		logger.Warn("no secret scanner found, skipping secret scan")
		return
	}

	scanDir := r.cfg.RawDir(r.target)
	// Ensure the js subdir (written by JSAnalysis) is included even if empty.
	jsDir := filepath.Join(scanDir, "js")
	_ = os.MkdirAll(jsDir, 0755)

	// Build a map from each crawled JS file's on-disk path back to its original
	// web URL, so secret findings store an accessible source URL rather than a
	// local filesystem path. Built before the scanners start; only read after.
	r.jsURLMap = r.buildJSURLMap()

	r.emit(map[string]any{"phase": "secret_scan", "status": "running", "message": fmt.Sprintf("secret scan (%s) on %s", toolsLabel(hasTruffle, hasGitleaks), scanDir)})
	logger.Phase("Phase 1+ — Secret Scan: %s", toolsLabel(hasTruffle, hasGitleaks))

	var wg sync.WaitGroup
	var mu sync.Mutex
	totalSecrets := 0

	if hasTruffle {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := r.runTrufflehog(ctx, scanDir)
			mu.Lock()
			totalSecrets += n
			mu.Unlock()
		}()
	}
	if hasGitleaks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := r.runGitleaks(ctx, scanDir)
			mu.Lock()
			totalSecrets += n
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Recompute per-host secret counts.
	r.recountSecrets()

	r.emit(map[string]any{"phase": "secret_scan", "status": "completed", "count": totalSecrets, "message": fmt.Sprintf("Secret scan complete: %d secrets", totalSecrets)})
	logger.Success("secret scan: %d secrets found", totalSecrets)
}

func toolsLabel(t, g bool) string {
	var parts []string
	if t {
		parts = append(parts, "trufflehog")
	}
	if g {
		parts = append(parts, "gitleaks")
	}
	return strings.Join(parts, " + ")
}

// runTrufflehog scans scanDir with `trufflehog filesystem --json` and parses
// newline-delimited JSON findings. Returns the count of stored secrets.
func (r *Runner) runTrufflehog(ctx context.Context, scanDir string) int {
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "trufflehog", "filesystem", "--json", "--no-update", "--no-verification", scanDir)
	cmd.Env = append(os.Environ(), "PATH="+executor.ToolPath("trufflehog")+":"+os.Getenv("PATH"))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0
	}
	if err := cmd.Start(); err != nil {
		return 0
	}

	count := 0
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var f struct {
			DetectorName string  `json:"DetectorName"`
			Raw          string  `json:"Raw"`
			RawV2        string  `json:"RawV2"`
			Verified     bool    `json:"Verified"`
			SourceMetadata struct {
				Data struct {
					Filesystem struct {
						File string `json:"file"`
					} `json:"Filesystem"`
				} `json:"Data"`
			} `json:"SourceMetadata"`
		}
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			continue
		}
		raw := f.Raw
		if raw == "" {
			raw = f.RawV2
		}
		if raw == "" {
			continue
		}
		if len(raw) > 500 {
			raw = raw[:500] + "..."
		}
		filePath := f.SourceMetadata.Data.Filesystem.File
		host := r.hostFromPath(filePath)
		var hostPtr *string
		if host != "" {
			hostPtr = &host
		}
		srcURL := r.resolveSourceURL(filePath)
		var urlPtr *string
		if srcURL != "" {
			urlPtr = &srcURL
		}
		_ = r.db.InsertP1Secret(r.scanID, storage.P1Secret{
			Subdomain: hostPtr, SourceURL: urlPtr, SecretType: f.DetectorName,
			RawMatch: raw, Tool: "trufflehog",
		})
		severity := "high"
		if f.Verified {
			severity = "critical"
		}
		name := fmt.Sprintf("Secret: %s", f.DetectorName)
		desc := "Leaked credential found by trufflehog"
		ev := raw
		_ = r.db.InsertP1Finding(r.scanID, storage.P1Finding{
			Subdomain: host, Tool: "trufflehog", Severity: severity,
			Name: name, Description: &desc, Evidence: &ev, Verified: f.Verified,
		})
		r.emitFinding(host, "trufflehog", severity, name, "")
		count++
	}
	_ = cmd.Wait()
	return count
}

// runGitleaks scans scanDir with `gitleaks detect --no-git` writing a JSON
// array report to a temp file. Returns the count of stored secrets.
func (r *Runner) runGitleaks(ctx context.Context, scanDir string) int {
	tmp, err := os.CreateTemp("", "gitleaks-*.json")
	if err != nil {
		return 0
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "gitleaks", "detect",
		"--source", scanDir, "--no-git",
		"--report-format", "json", "--report-path", tmpPath, "--no-banner")
	cmd.Env = append(os.Environ(), "PATH="+executor.ToolPath("gitleaks")+":"+os.Getenv("PATH"))
	_ = cmd.Run() // gitleaks exits 1 when leaks are found

	data, err := os.ReadFile(tmpPath)
	if err != nil || len(data) == 0 {
		return 0
	}
	var findings []struct {
		Description string  `json:"Description"`
		Match       string  `json:"Match"`
		Secret      string  `json:"Secret"`
		File        string  `json:"File"`
		Entropy     float64 `json:"Entropy"`
		RuleID      string  `json:"RuleID"`
	}
	if err := json.Unmarshal(data, &findings); err != nil {
		return 0
	}

	count := 0
	for _, f := range findings {
		raw := f.Secret
		if raw == "" {
			raw = f.Match
		}
		if raw == "" {
			continue
		}
		if len(raw) > 500 {
			raw = raw[:500] + "..."
		}
		host := r.hostFromPath(f.File)
		var hostPtr *string
		if host != "" {
			hostPtr = &host
		}
		srcURL := r.resolveSourceURL(f.File)
		var urlPtr *string
		if srcURL != "" {
			urlPtr = &srcURL
		}
		secretType := f.Description
		if secretType == "" {
			secretType = f.RuleID
		}
		_ = r.db.InsertP1Secret(r.scanID, storage.P1Secret{
			Subdomain: hostPtr, SourceURL: urlPtr, SecretType: secretType,
			RawMatch: raw, Tool: "gitleaks",
		})
		name := fmt.Sprintf("Secret: %s", secretType)
		desc := "Leaked credential found by gitleaks"
		ev := raw
		_ = r.db.InsertP1Finding(r.scanID, storage.P1Finding{
			Subdomain: host, Tool: "gitleaks", Severity: "high",
			Name: name, Description: &desc, Evidence: &ev,
		})
		r.emitFinding(host, "gitleaks", "high", name, "")
		count++
	}
	return count
}

// hostFromPath tries to recover the subdomain from a stored file path written
// by JSAnalysis, which names files "<subdomain>__<sanitized-url>.js".
func (r *Runner) hostFromPath(path string) string {
	if path == "" {
		return ""
	}
	base := filepath.Base(path)
	if idx := strings.Index(base, "__"); idx > 0 {
		return base[:idx]
	}
	return ""
}

// buildJSURLMap reconstructs the on-disk path for every crawled JS file (using
// the exact same naming scheme as saveRawJS) and maps it back to the original
// accessible web URL. Both the cleaned full path and the basename are keyed so
// the lookup succeeds regardless of whether the scanner reports an absolute or
// relative file path.
func (r *Runner) buildJSURLMap() map[string]string {
	m := make(map[string]string)
	files, err := r.db.GetP1JSFiles(r.scanID)
	if err != nil {
		return m
	}
	dir := filepath.Join(r.cfg.RawDir(r.target), "js")
	repl := strings.NewReplacer("://", "_", "/", "_", "?", "_", "&", "_", "=", "_")
	for _, f := range files {
		if f.URL == "" {
			continue
		}
		safe := repl.Replace(f.URL)
		if len(safe) > 120 {
			safe = safe[:120]
		}
		name := f.Subdomain + "__" + safe + ".js"
		full := filepath.Clean(filepath.Join(dir, name))
		m[full] = f.URL
		m[name] = f.URL
	}
	return m
}

// resolveSourceURL maps a scanner-reported filesystem path back to the original
// web URL when the file is a crawled JS file; otherwise it returns the path
// unchanged (no accessible web URL exists for raw tool-output files). This is
// what gets stored as the secret's source_url so the UI can show a clickable,
// complete URL.
func (r *Runner) resolveSourceURL(filePath string) string {
	if filePath == "" {
		return ""
	}
	if r.jsURLMap == nil {
		return filePath
	}
	if u, ok := r.jsURLMap[filepath.Clean(filePath)]; ok {
		return u
	}
	if u, ok := r.jsURLMap[filepath.Base(filePath)]; ok {
		return u
	}
	return filePath
}

func (r *Runner) recountSecrets() {
	rows, err := r.db.Conn().Query(
		`SELECT subdomain, COUNT(*) FROM p1_secrets WHERE scan_id = ? AND subdomain IS NOT NULL GROUP BY subdomain`, r.scanID)
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
			Subdomain: c.host, SecretCount: c.count, HasSecrets: c.count > 0,
		})
	}
}
