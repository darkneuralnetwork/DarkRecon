package nuclei

import (
	"context"
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

// Scanner runs Nuclei vulnerability scanning.
// CRITICAL: Katana-crawled URLs are fed into Nuclei as additional input targets.
type Scanner struct {
	cfg    *config.Config
	db     *storage.DB
	scanID int64
}

// New creates a new Nuclei scanner.
func New(cfg *config.Config, db *storage.DB, scanID int64) *Scanner {
	return &Scanner{cfg: cfg, db: db, scanID: scanID}
}

// VulnResult represents a single vulnerability finding.
type VulnResult struct {
	TemplateID      *string  `json:"template_id,omitempty"`
	Name            string   `json:"name"`
	Severity        string   `json:"severity"`
	URL             string   `json:"url"`
	Subdomain       string   `json:"subdomain"`
	CVEIDs          []string `json:"cve_ids,omitempty"`
	Description     *string  `json:"description,omitempty"`
	MatcherName     *string  `json:"matcher_name,omitempty"`
	ExtractedResults []string `json:"extracted_results,omitempty"`
	References      []string `json:"reference,omitempty"`
	Type            string   `json:"type"`
}

// ScanResult holds the scan output.
type ScanResult struct {
	Vulnerabilities []VulnResult
	BySeverity      map[string]int
}

// Run runs Nuclei on live hosts AND crawled URLs.
// The target list is: live_subdomains.txt + all_urls.txt (from Katana).
func (s *Scanner) Run(ctx context.Context) (*ScanResult, error) {
	logger.Phase("Phase 5 — Vulnerability Scanning (Nuclei): %s", s.cfg.Target)

	// Build the target list: live hosts + crawled URLs
	targetFile := filepath.Join(s.cfg.ParsedDir(s.cfg.Target), "nuclei_targets.txt")
	if err := s.buildTargetList(targetFile); err != nil {
		logger.Warn("Could not build nuclei target list: %v", err)
		return &ScanResult{}, nil
	}

	// Check if target file has content
	info, err := os.Stat(targetFile)
	if err != nil || info.Size() == 0 {
		logger.Warn("No targets for nuclei. Skipping.")
		return &ScanResult{}, nil
	}

	severityStr := strings.Join(s.cfg.Nuclei.Severity, ",")

	args := []string{
		"nuclei",
		"-l", targetFile,
		"-severity", severityStr,
		"-rl", fmt.Sprintf("%d", s.cfg.Nuclei.Rate),
		"-c", fmt.Sprintf("%d", s.cfg.Nuclei.Concurrent),
		"-bs", fmt.Sprintf("%d", s.cfg.Nuclei.BulkSize),
		"-j",        // JSON output
		"-silent",
		"-no-color",
		// NOTE: "-uc" (auto template update) removed — it adds a startup
		// delay to every scan. Run `nuclei -update-templates` manually instead.
	}

	// Add templates directory if specified
	if s.cfg.Nuclei.Templates != "" {
		if _, err := os.Stat(s.cfg.Nuclei.Templates); err == nil {
			args = append(args, "-t", s.cfg.Nuclei.Templates)
		}
	}

	// FIX: Python used -mhe (max-host-error) incorrectly for CVSS filtering.
	// The correct approach is to filter by severity, which we already do.
	// If CVSS filtering is needed, we post-filter results.

	result := executor.Run(ctx, executor.Config{
		Args:    args,
		Timeout: time.Duration(s.cfg.Nuclei.Timeout) * time.Minute,
	})

	// Save raw output
	rawPath := filepath.Join(s.cfg.RawDir(s.cfg.Target), "nuclei.json")
	os.WriteFile(rawPath, []byte(result.Stdout), 0644)

	if result.ReturnCode != 0 && result.Stdout == "" {
		logger.Warn("nuclei error: %s", executor.TruncateLog(result.Stderr, 200))
	}

	// Parse nuclei JSON output
	nucleiResults := parser.ParseJSONLines(result.Stdout)
	var vulns []VulnResult
	bySeverity := make(map[string]int)

	for _, entry := range nucleiResults {
		info, _ := entry["info"].(map[string]any)
		name, _ := info["name"].(string)
		if name == "" {
			name = "Unknown"
		}
		severity, _ := info["severity"].(string)
		severity = strings.ToLower(severity)
		if severity == "" {
			severity = "info"
		}

		templateID, _ := entry["template-id"].(string)
		if templateID == "" {
			templateID, _ = entry["templateID"].(string)
		}

		matched, _ := entry["matched-at"].(string)
		if matched == "" {
			matched, _ = entry["matched"].(string)
		}
		if matched == "" {
			matched, _ = entry["host"].(string)
		}

		subdomain := parser.ExtractHostname(matched)

		// Extract CVE IDs
		var cveIDs []string
		if class, ok := info["classification"].(map[string]any); ok {
			if cves, ok := class["cve-id"].([]any); ok {
				for _, c := range cves {
					if s, ok := c.(string); ok {
						cveIDs = append(cveIDs, s)
					}
				}
			} else if cve, ok := class["cve-id"].(string); ok {
				cveIDs = append(cveIDs, cve)
			}
		}

		// Extract references
		var references []string
		if refs, ok := info["reference"].([]any); ok {
			for _, r := range refs {
				if s, ok := r.(string); ok {
					references = append(references, s)
				}
			}
		}

		// Extract matcher name
		var matcherName *string
		if typeData, ok := entry["type"].(map[string]any); ok {
			if mn, ok := typeData["matcher-name"].(string); ok && mn != "" {
				matcherName = &mn
			}
		}

		// Extract description
		var description *string
		if desc, ok := info["description"].(string); ok && desc != "" {
			description = &desc
		}

		// Extracted results
		var extractedResults []string
		if er, ok := entry["extracted-results"].([]any); ok {
			for _, e := range er {
				if s, ok := e.(string); ok {
					extractedResults = append(extractedResults, s)
				}
			}
		}

		// CVSS filtering
		if s.cfg.Nuclei.CVSSMin > 0 {
			if class, ok := info["classification"].(map[string]any); ok {
				if cvss, ok := class["cvss-score"].(float64); ok && cvss < s.cfg.Nuclei.CVSSMin {
					continue // Skip low CVSS
				}
			}
		}

		var tid *string
		if templateID != "" {
			tid = &templateID
		}

		vuln := VulnResult{
			TemplateID:      tid,
			Name:            name,
			Severity:        severity,
			URL:             matched,
			Subdomain:       subdomain,
			CVEIDs:          cveIDs,
			Description:     description,
			MatcherName:     matcherName,
			ExtractedResults: extractedResults,
			References:      references,
			Type:            "nuclei",
		}
		vulns = append(vulns, vuln)
		bySeverity[severity]++

		// Store in DB
		_ = s.db.InsertVulnerability(s.scanID, storage.Vulnerability{
			TemplateID:      tid,
			Name:            name,
			Severity:        severity,
			URL:             matched,
			Subdomain:       subdomain,
			CVEIDs:          parser.MarshalArray(cveIDs),
			Description:     description,
			MatcherName:     matcherName,
			ExtractedResults: parser.MarshalArray(extractedResults),
			References:      parser.MarshalArray(references),
			Type:            "nuclei",
		})
	}

	logger.Success("Nuclei found %d vulnerabilities", len(vulns))
	logger.Result("vulnerabilities", len(vulns))
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c := bySeverity[sev]; c > 0 {
			logger.Result("  "+sev, c)
		}
	}

	return &ScanResult{
		Vulnerabilities: vulns,
		BySeverity:      bySeverity,
	}, nil
}

// buildTargetList creates the nuclei target list file.
// It combines live_subdomains.txt + high-signal crawled URLs from Katana.
//
// To keep the target list small (and the scan fast + WAF-friendly), static
// assets (.css/.js/.png/.svg/fonts/...) are stripped from crawled URLs.
// URLs with parameters are always kept (highest signal for injection tests).
func (s *Scanner) buildTargetList(targetFile string) error {
	var targets []string
	keptFromURLs := 0
	droppedAssets := 0

	// Load live subdomains (always included)
	liveFile := filepath.Join(s.cfg.ParsedDir(s.cfg.Target), "live_subdomains.txt")
	if data, err := os.ReadFile(liveFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				targets = append(targets, line)
			}
		}
	}

	// Load crawled URLs from Katana — but drop static assets.
	// Param URLs (param_urls.txt) are highest-signal, load them first.
	urlFiles := []string{
		filepath.Join(s.cfg.ParsedDir(s.cfg.Target), "param_urls.txt"),
		filepath.Join(s.cfg.ParsedDir(s.cfg.Target), "all_urls.txt"),
	}
	for _, urlsFile := range urlFiles {
		data, err := os.ReadFile(urlsFile)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if parser.IsStaticAsset(line) {
				droppedAssets++
				continue
			}
			targets = append(targets, line)
			keptFromURLs++
		}
	}

	// Deduplicate
	targets = parser.Deduplicate(targets)

	logger.Success("Nuclei targets: %d (URLs kept: %d, static assets dropped: %d)",
		len(targets), keptFromURLs, droppedAssets)

	return os.WriteFile(targetFile, []byte(strings.Join(targets, "\n")), 0644)
}
