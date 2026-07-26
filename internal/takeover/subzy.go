package takeover

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yourname/dark-recon/internal/config"
	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/pkg/executor"
	"github.com/yourname/dark-recon/pkg/logger"
)

// Checker checks for subdomain takeover using subzy.
type Checker struct {
	cfg    *config.Config
	db     *storage.DB
	scanID int64
}

// New creates a new subdomain takeover checker.
func New(cfg *config.Config, db *storage.DB, scanID int64) *Checker {
	return &Checker{cfg: cfg, db: db, scanID: scanID}
}

// TakeoverFinding represents a takeover result.
type TakeoverFinding struct {
	Subdomain   string  `json:"subdomain"`
	Vulnerable  bool    `json:"vulnerable"`
	Service     *string `json:"service,omitempty"`
	Fingerprint *string `json:"fingerprint,omitempty"`
}

// Run runs subzy on the live subdomains list.
func (c *Checker) Run(ctx context.Context) ([]TakeoverFinding, error) {
	logger.Phase("Phase 5b — Subdomain Takeover (subzy): %s", c.cfg.Target)

	subsFile := filepath.Join(c.cfg.ParsedDir(c.cfg.Target), "live_subdomains.txt")
	if _, err := os.Stat(subsFile); err != nil {
		logger.Warn("No live subdomains file found. Skipping subzy.")
		return nil, nil
	}

	// FIX: Python used --version which should be 'version' for subzy.
	// The run subcommand is correct: subzy run --targets <file>
	result := executor.Run(ctx, executor.Config{
		Args: []string{
			"subzy", "run",
			"--targets", subsFile,
			"--hide_fails",
			"--timeout", subzyTimeout(c.cfg.Timeout),
		},
		Timeout: 10 * time.Minute,
	})

	// Save raw output
	rawPath := filepath.Join(c.cfg.RawDir(c.cfg.Target), "subzy.txt")
	os.WriteFile(rawPath, []byte(result.Stdout), 0644)

	var findings []TakeoverFinding

	if result.ReturnCode != 0 && result.Stdout == "" {
		logger.Warn("subzy error: %s", executor.TruncateLog(result.Stderr, 200))
		return findings, nil
	}

	// Parse subzy output
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip INF lines
		if strings.Contains(line, "[INF]") {
			continue
		}

		upper := strings.ToUpper(line)
		if strings.Contains(upper, "VULNERABLE") && !strings.Contains(upper, "NOT VULNERABLE") {
			parts := strings.Fields(line)
			subdomain := ""
			service := ""
			for _, part := range parts {
				if strings.Contains(part, ".") && !strings.HasPrefix(part, "[") {
					subdomain = strings.Trim(part, "()[]")
				}
				if strings.Contains(part, "(") {
					service = strings.Trim(part, "()")
				}
			}
			var svcPtr *string
			if service != "" {
				svcPtr = &service
			}
			fp := line
			findings = append(findings, TakeoverFinding{
				Subdomain:   subdomain,
				Vulnerable:  true,
				Service:     svcPtr,
				Fingerprint: &fp,
			})

			// Store in DB
			_ = c.db.InsertTakeover(c.scanID, storage.TakeoverResult{
				Subdomain:   subdomain,
				Vulnerable:  true,
				Service:     svcPtr,
				Fingerprint: &fp,
			})

			// Also insert as a vulnerability
			name := "Subdomain Takeover"
			if service != "" {
				name = "Subdomain Takeover - " + service
			}
			desc := "Vulnerable to subdomain takeover"
			if service != "" {
				desc = "Vulnerable to subdomain takeover via " + service
			}
			_ = c.db.InsertVulnerability(c.scanID, storage.Vulnerability{
				Name:        name,
				Severity:    "high",
				URL:         subdomain,
				Subdomain:   subdomain,
				Description: &desc,
				Type:        "subzy",
				CVEIDs:      "[]",
				ExtractedResults: "[]",
				References:  "[]",
			})
		}
	}

	vulnCount := 0
	for _, f := range findings {
		if f.Vulnerable {
			vulnCount++
		}
	}

	logger.Success("subzy: %d vulnerable, %d checked", vulnCount, len(findings))
	logger.Result("takeover vulnerable", vulnCount)
	logger.Result("hosts checked", len(findings))
	return findings, nil
}

// subzyTimeout renders the --timeout flag value (seconds) for subzy. The flag
// expects a plain integer; subzy itself caps/scales it internally. A
// non-positive config value falls back to 10s so we never pass an empty/
// negative arg.
func subzyTimeout(n int) string {
	if n <= 0 {
		return "10"
	}
	return strconv.Itoa(n)
}
