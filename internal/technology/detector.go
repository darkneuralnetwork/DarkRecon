package technology

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourname/dark-recon/internal/config"
	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/pkg/executor"
	"github.com/yourname/dark-recon/pkg/logger"
)

// Detector detects technologies using webanalyze + HTTP header analysis.
// This merges the old Python header_analyzer.py functionality.
type Detector struct {
	cfg    *config.Config
	db     *storage.DB
	scanID int64
}

// New creates a new technology detector.
func New(cfg *config.Config, db *storage.DB, scanID int64) *Detector {
	return &Detector{cfg: cfg, db: db, scanID: scanID}
}

// TechInfo represents a detected technology.
type TechInfo struct {
	Name       string  `json:"name"`
	Version    *string `json:"version,omitempty"`
	Category   string  `json:"category"`
	Confidence string  `json:"confidence"`
}

// HeaderResult holds header analysis output.
type HeaderResult struct {
	URL                    string     `json:"url"`
	StatusCode             int        `json:"status_code"`
	Headers                map[string]string `json:"headers"`
	DetectedTech           []TechInfo `json:"detected_tech"`
	Frameworks             []string   `json:"frameworks"`
	Server                 *string    `json:"server,omitempty"`
	MissingSecurityHeaders []string   `json:"missing_security_headers"`
}

// Run runs technology detection on the main target.
func (d *Detector) Run(ctx context.Context, target string) (*HeaderResult, error) {
	logger.Phase("Phase 3 — Technology Detection: %s", target)

	// Grab headers
	headers, statusCode, url := d.grabHeaders(target)

	// Save raw headers
	headersJSON, _ := json.MarshalIndent(headers, "", "  ")
	rawPath := filepath.Join(d.cfg.RawDir(d.cfg.Target), "headers_raw.txt")
	os.WriteFile(rawPath, headersJSON, 0644)

	// Built-in tech detection from headers
	detectedTech := d.detectTechFromHeaders(headers)

	// Run webanalyze for additional tech detection
	webanalyzeTech := d.runWebanalyze(ctx, url)
	detectedTech = append(detectedTech, webanalyzeTech...)

	// Deduplicate
	detectedTech = dedupTech(detectedTech)

	// Extract frameworks and server
	var frameworks []string
	var server *string
	for _, t := range detectedTech {
		if t.Category == "Web Framework" || t.Category == "Programming Language" {
			frameworks = append(frameworks, t.Name)
		}
		if t.Category == "Web Server" && server == nil {
			s := t.Name
			server = &s
		}
	}
	if server == nil {
		if s, ok := headers["server"]; ok {
			server = &s
		}
	}

	// Check missing security headers
	missingHeaders := checkMissingSecurityHeaders(headers)

	// Store tech detections in DB
	for _, t := range detectedTech {
		_ = d.db.InsertTechDetection(d.scanID, storage.TechDetection{
			Subdomain:  target,
			Name:       t.Name,
			Version:    t.Version,
			Category:   t.Category,
			Confidence: t.Confidence,
		})
	}

	// Store header result in DB
	headersStr, _ := json.Marshal(headers)
	techStr, _ := json.Marshal(detectedTech)
	frameworksStr, _ := json.Marshal(frameworks)
	missingStr, _ := json.Marshal(missingHeaders)

	_ = d.db.InsertHeaderResult(d.scanID, storage.HeaderResult{
		URL:                   url,
		StatusCode:            statusCode,
		Headers:               string(headersStr),
		DetectedTech:          string(techStr),
		Frameworks:            string(frameworksStr),
		Server:                server,
		MissingSecurityHeaders: string(missingStr),
	})

	result := &HeaderResult{
		URL:                    url,
		StatusCode:             statusCode,
		Headers:                headers,
		DetectedTech:           detectedTech,
		Frameworks:             frameworks,
		Server:                 server,
		MissingSecurityHeaders: missingHeaders,
	}

	// Save parsed results
	parsedPath := filepath.Join(d.cfg.ParsedDir(d.cfg.Target), "headers.json")
	data, _ := json.MarshalIndent(result, "", "  ")
	os.WriteFile(parsedPath, data, 0644)

	missingPath := filepath.Join(d.cfg.ParsedDir(d.cfg.Target), "missing_headers.json")
	missingData, _ := json.MarshalIndent(missingHeaders, "", "  ")
	os.WriteFile(missingPath, missingData, 0644)

	logger.Success("Detected %d technologies, %d missing security headers", len(detectedTech), len(missingHeaders))
	logger.Result("technologies", len(detectedTech))
	logger.Result("missing security headers", len(missingHeaders))

	return result, nil
}

// grabHeaders fetches HTTP headers from the target.
func (d *Detector) grabHeaders(target string) (map[string]string, int, string) {
	client := &http.Client{
		Timeout: time.Duration(d.cfg.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, target)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Dark-Recon/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		headers := make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				headers[strings.ToLower(k)] = v[0]
			}
		}

		return headers, resp.StatusCode, resp.Request.URL.String()
	}

	logger.Err("Could not connect to %s", target)
	return map[string]string{}, 0, fmt.Sprintf("https://%s", target)
}

// runWebanalyze runs webanalyze for technology detection.
func (d *Detector) runWebanalyze(ctx context.Context, url string) []TechInfo {
	result := executor.Run(ctx, executor.Config{
		Args: []string{
			"webanalyze",
			"-host", url,
			"-silent",
			"-output", "json",
		},
		Timeout: 30 * time.Second,
	})

	rawPath := filepath.Join(d.cfg.RawDir(d.cfg.Target), "webanalyze.txt")
	os.WriteFile(rawPath, []byte(result.Stdout), 0644)

	if result.ReturnCode != 0 {
		logger.Warn("webanalyze failed: %s", executor.TruncateLog(result.Stderr, 200))
		return nil
	}

	var techs []TechInfo
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var data map[string]any
		if err := json.Unmarshal([]byte(line), &data); err != nil {
			continue
		}
		matches, _ := data["matches"].([]any)
		for _, m := range matches {
			match, _ := m.(map[string]any)
			name, _ := match["match"].(string)
			category, _ := match["category"].(string)
			var version *string
			if v, ok := match["version"].(string); ok && v != "" {
				version = &v
			}
			confidence := "medium"
			if mt, ok := match["match_type"].(string); ok && mt == "header" {
				confidence = "high"
			}
			if name != "" {
				techs = append(techs, TechInfo{
					Name:       name,
					Version:    version,
					Category:   category,
					Confidence: confidence,
				})
			}
		}
	}

	return techs
}

// detectTechFromHeaders detects technologies from HTTP headers.
func (d *Detector) detectTechFromHeaders(headers map[string]string) []TechInfo {
	var techs []TechInfo

	if server := headers["server"]; server != "" {
		techs = append(techs, TechInfo{
			Name:       server,
			Category:   "Web Server",
			Confidence: "high",
		})
	}

	if poweredBy := headers["x-powered-by"]; poweredBy != "" {
		techs = append(techs, TechInfo{
			Name:       poweredBy,
			Category:   "Programming Language",
			Confidence: "high",
		})
	}

	if xaspnet := headers["x-aspnet-version"]; xaspnet != "" {
		v := xaspnet
		techs = append(techs, TechInfo{
			Name:       "ASP.NET",
			Version:    &v,
			Category:   "Web Framework",
			Confidence: "high",
		})
	}

	if setCookie := headers["set-cookie"]; setCookie != "" {
		if strings.Contains(strings.ToLower(setCookie), "phpsessid") {
			techs = append(techs, TechInfo{Name: "PHP", Category: "Programming Language", Confidence: "high"})
		}
		if strings.Contains(strings.ToLower(setCookie), "jsessionid") {
			techs = append(techs, TechInfo{Name: "Java", Category: "Programming Language", Confidence: "high"})
		}
		if strings.Contains(strings.ToLower(setCookie), "asp.net") || strings.Contains(strings.ToLower(setCookie), "aspnetsession") {
			techs = append(techs, TechInfo{Name: "ASP.NET", Category: "Web Framework", Confidence: "high"})
		}
	}

	if via := headers["via"]; via != "" {
		techs = append(techs, TechInfo{
			Name:       via,
			Category:   "Proxy",
			Confidence: "high",
		})
	}

	return techs
}

// checkMissingSecurityHeaders identifies missing security headers.
func checkMissingSecurityHeaders(headers map[string]string) []string {
	required := []string{
		"strict-transport-security",
		"content-security-policy",
		"x-frame-options",
		"x-content-type-options",
		"x-xss-protection",
		"referrer-policy",
		"permissions-policy",
	}

	var missing []string
	displayNames := map[string]string{
		"strict-transport-security": "Strict-Transport-Security",
		"content-security-policy":   "Content-Security-Policy",
		"x-frame-options":           "X-Frame-Options",
		"x-content-type-options":    "X-Content-Type-Options",
		"x-xss-protection":          "X-XSS-Protection",
		"referrer-policy":           "Referrer-Policy",
		"permissions-policy":        "Permissions-Policy",
	}

	for _, h := range required {
		if _, ok := headers[h]; !ok {
			missing = append(missing, displayNames[h])
		}
	}

	return missing
}

func dedupTech(techs []TechInfo) []TechInfo {
	seen := make(map[string]bool)
	var result []TechInfo
	for _, t := range techs {
		key := fmt.Sprintf("%s:%v", t.Name, t.Version)
		if !seen[key] {
			seen[key] = true
			result = append(result, t)
		}
	}
	return result
}
