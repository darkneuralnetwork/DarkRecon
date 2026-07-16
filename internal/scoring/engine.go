package scoring

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yourname/dark-recon/internal/config"
	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/pkg/logger"
	"github.com/yourname/dark-recon/pkg/parser"
)

// maxRawScore is the theoretical maximum sum of all scoring factors. It is
// the denominator for the 0–100 normalization, so it MUST equal the sum of the
// per-factor caps below; otherwise every priority score is systematically
// skewed. Keep this in sync when adding/removing a factor.
//
// Factor caps:
//   1. subdomain_name keywords .... 30
//   2. vulnerability severity ..... 35 (capped)
//   3. subdomain takeover ......... 25
//   4. exposed sensitive paths ... 20 (capped)
//   5. missing security headers ... 15 (capped)
//   6. tech stack risk ............ 12
//   7. parameter-rich URLs ........ 10
//   8. phase-1 intel (ports/params/ 10
//      secrets/waf/js)
//                            total 157
const maxRawScore = 157.0

// Keyword scoring for subdomain names (ported from Python).
var keywordScores = map[string]int{
	"admin": 30, "console": 25, "manage": 20, "internal": 25,
	"vpn": 25, "auth": 25, "login": 20, "dashboard": 20,
	"api": 25, "staging": 20,
	"dev": 15, "test": 10, "uat": 15, "beta": 12,
	"app": 12, "portal": 15, "gateway": 15, "control": 18,
	"panel": 18, "cpanel": 20, "root": 20,
	"backup": 15, "old": 10, "debug": 12, "config": 15,
	"db": 15, "database": 15, "mysql": 12, "phpmyadmin": 18,
	"server": 10, "remote": 12, "secure": 10,
}

// Vulnerability severity scores.
var vulnSeverityScores = map[string]int{
	"critical": 35,
	"high":     25,
	"medium":   15,
	"low":      5,
	"info":     0,
}

// Known vulnerable/EOL tech patterns.
var knownVulnPatterns = map[string]int{
	"php 5.": 8, "php 7.0": 8, "php 7.1": 8, "php 7.2": 5, "php 7.3": 5, "php 7.4": 5,
	"apache 2.4.49": 12, "apache 2.4.50": 12,
	"openssh 7.": 5, "openssh 6.": 8,
	"struts 2": 12, "django 1.": 5, "rails 3": 5,
	"iis 6": 12, "iis 7": 8,
	"openssl 1.0": 8,
}

// PriorityReason represents a single scoring reason.
type PriorityReason struct {
	Factor string `json:"factor"`
	Detail string `json:"detail"`
	Weight int    `json:"weight"`
}

// PriorityEntry represents a scored subdomain.
type PriorityEntry struct {
	Rank              int            `json:"rank"`
	Subdomain         string         `json:"subdomain"`
	URL               string         `json:"url"`
	PriorityScore     float64        `json:"priority_score"`
	PriorityTier      string         `json:"priority"`
	Reasons           []PriorityReason `json:"reasons,omitempty"`
	TechStack         []string       `json:"tech_stack,omitempty"`
	Vulnerabilities   []string       `json:"vulnerabilities,omitempty"`
	URLsWithParams    []string       `json:"urls_with_params,omitempty"`
	ExposedDirs       []string       `json:"exposed_dirs,omitempty"`
	MissingHeaders    []string       `json:"missing_headers,omitempty"`
	TakeoverVulnerable bool          `json:"takeover_vulnerable"`
	SuggestedTests    []string       `json:"suggested_manual_tests,omitempty"`
}

// Scorer scores and ranks subdomains by attack priority.
type Scorer struct {
	cfg     *config.Config
	db      *storage.DB
	scanID  int64
	liveHosts []storage.LiveHost
	vulns     []storage.Vulnerability
	takeovers []storage.TakeoverResult
	crawledURLs []storage.CrawledURL
	dirs      []storage.DiscoveredDir
	headers   *storage.HeaderResult
	// headerHost is the lowercased hostname the HeaderResult.URL was fetched
	// from (empty if none). headerHostLive is true when that host is itself one
	// of the scored live subdomains, meaning its missing-header score can be
	// attributed precisely; otherwise we fall back to apex-inference.
	headerHost     string
	headerHostLive bool
	// Phase-1 advanced module intel
	hostIntel   map[string]storage.P1HostIntel
	p1Findings  []storage.P1Finding
}

// New creates a new priority scorer.
func New(cfg *config.Config, db *storage.DB, scanID int64) *Scorer {
	s := &Scorer{cfg: cfg, db: db, scanID: scanID}
	s.loadData()
	return s
}

// loadData loads all scan data from the database.
func (s *Scorer) loadData() {
	s.liveHosts, _ = s.db.GetLiveHosts(s.scanID)
	s.vulns, _ = s.db.GetVulnerabilities(s.scanID)
	s.crawledURLs, _ = s.db.GetCrawledURLs(s.scanID)
	s.dirs, _ = s.db.GetDiscoveredDirs(s.scanID)
	s.headers, _ = s.db.GetHeaderResult(s.scanID)
	s.headerHost = strings.ToLower(hostnameOf(headerResultURL(s.headers)))
	for _, h := range s.liveHosts {
		if s.headerHost != "" && strings.ToLower(h.Subdomain) == s.headerHost {
			s.headerHostLive = true
			break
		}
	}

	// Load takeovers
	// We stored takeover results as vulnerabilities with type="subzy"
	// Also load from takeover_results table if available

	// Phase-1 advanced module intel (port/waf/param/secret/js counts per host).
	s.hostIntel = make(map[string]storage.P1HostIntel)
	if intel, err := s.db.GetP1HostIntel(s.scanID); err == nil {
		for _, h := range intel {
			s.hostIntel[strings.ToLower(h.Subdomain)] = h
		}
	}
	s.p1Findings, _ = s.db.GetP1Findings(s.scanID)
}

// Run scores all subdomains and creates a priority ranking.
func (s *Scorer) Run(ctx context.Context) ([]PriorityEntry, error) {
	logger.Phase("Phase 6 — Priority Scoring: %s", s.cfg.Target)

	if len(s.liveHosts) == 0 {
		logger.Warn("No live subdomains to score.")
		return nil, nil
	}

	var entries []PriorityEntry
	for _, host := range s.liveHosts {
		score, reasons := s.scoreSubdomain(host.Subdomain, host.URL)

		entry := PriorityEntry{
			Rank:              0,
			Subdomain:         host.Subdomain,
			URL:               host.URL,
			PriorityScore:     score,
			Reasons:           reasons,
			TechStack:         s.getSubTech(host),
			Vulnerabilities:   s.getSubVulns(host.Subdomain),
			URLsWithParams:    s.getSubParamURLs(host.Subdomain),
			ExposedDirs:       s.getSubDirs(host.Subdomain),
			MissingHeaders:    s.getMissingHeaders(),
			TakeoverVulnerable: s.isTakeoverVulnerable(host.Subdomain),
			SuggestedTests:    s.suggestManualTests(host.Subdomain, score, reasons),
		}
		entries = append(entries, entry)
	}

	// Sort by score descending
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].PriorityScore > entries[j].PriorityScore
	})

	// Assign ranks and tiers
	for i := range entries {
		entries[i].Rank = i + 1
		entries[i].PriorityTier = scoreToTier(entries[i].PriorityScore)
	}

	// Store in DB
	for _, entry := range entries {
		_ = s.db.InsertPriorityEntry(s.scanID, storage.PriorityEntry{
			Rank:              entry.Rank,
			Subdomain:         entry.Subdomain,
			URL:               entry.URL,
			PriorityScore:     entry.PriorityScore,
			PriorityTier:      entry.PriorityTier,
			Reasons:           parser.MarshalArray(entry.Reasons),
			TechStack:         parser.MarshalArray(entry.TechStack),
			Vulnerabilities:   parser.MarshalArray(entry.Vulnerabilities),
			URLsWithParams:    parser.MarshalArray(entry.URLsWithParams),
			ExposedDirs:       parser.MarshalArray(entry.ExposedDirs),
			MissingHeaders:    parser.MarshalArray(entry.MissingHeaders),
			TakeoverVulnerable: entry.TakeoverVulnerable,
			SuggestedTests:    parser.MarshalArray(entry.SuggestedTests),
		})
	}

	// Save JSON export
	priorityPath := filepath.Join(s.cfg.PriorityDir(s.cfg.Target), "priority_ranking.json")
	result := map[string]any{
		"target":         s.cfg.Target,
		"total_scored":   len(entries),
		"by_priority_tier": s.countByTier(entries),
		"priority_list":  entries,
	}
	data, _ := json.MarshalIndent(result, "", "  ")
	os.WriteFile(priorityPath, data, 0644)

	// Generate handoff file
	s.generateHandoff(entries)

	logger.Success("Scored %d subdomains", len(entries))
	logger.Result("subdomains scored", len(entries))

	return entries, nil
}

// scoreSubdomain scores a single subdomain based on all factors.
func (s *Scorer) scoreSubdomain(subdomain, url string) (float64, []PriorityReason) {
	var reasons []PriorityReason
	rawScore := 0.0

	// Factor 1: Subdomain name keywords (0-30)
	kwScore, kwReasons := s.scoreKeywords(subdomain)
	rawScore += kwScore
	reasons = append(reasons, kwReasons...)

	// Factor 2: Vulnerability severity (0-35, capped)
	vulnScore, vulnReasons := s.scoreVulnerabilities(subdomain)
	if vulnScore > 35 {
		vulnScore = 35
	}
	rawScore += vulnScore
	reasons = append(reasons, vulnReasons...)

	// Factor 3: Subdomain takeover risk (0-25)
	takeoverScore, takeoverReasons := s.scoreTakeover(subdomain)
	rawScore += takeoverScore
	reasons = append(reasons, takeoverReasons...)

	// Factor 4: Exposed sensitive paths (0-20, capped)
	pathScore, pathReasons := s.scoreExposedPaths(subdomain)
	if pathScore > 20 {
		pathScore = 20
	}
	rawScore += pathScore
	reasons = append(reasons, pathReasons...)

	// Factor 5: Missing security headers (0-15). Headers are only grabbed for a
	// single host (the apex domain, see technology.Detector.Run), so applying
	// that result to every subdomain would mis-credit e.g. blog.x.com with
	// www.x.com's header posture. Attribution rules:
	//   - this subdomain IS the measured host → score it (precise).
	//   - the measured host is NOT among the live subdomains (apex wasn't live)
	//     → fall back to apex-inference for everyone, with a reason noting it.
	//   - otherwise (measured host is a different live subdomain) → skip, to
	//     avoid mis-attribution.
	var headerScore float64
	var headerReasons []PriorityReason
	switch {
	case s.headerHost != "" && strings.ToLower(subdomain) == s.headerHost:
		headerScore, headerReasons = s.scoreMissingHeaders()
	case s.headerHost != "" && !s.headerHostLive:
		headerScore, headerReasons = s.scoreMissingHeaders()
		if headerScore > 0 {
			headerReasons = append(headerReasons, PriorityReason{
				Factor: "missing_headers",
				Detail: fmt.Sprintf("inferred from apex %s (headers not grabbed per-host)", s.headerHost),
			})
		}
	}
	rawScore += headerScore
	reasons = append(reasons, headerReasons...)

	// Factor 6: Tech stack risk (0-12)
	techScore, techReasons := s.scoreTechRisk(subdomain)
	rawScore += techScore
	reasons = append(reasons, techReasons...)

	// Factor 7: Parameter-rich URLs (0-10)
	paramScore, paramReasons := s.scoreParamURLs(subdomain)
	rawScore += paramScore
	reasons = append(reasons, paramReasons...)

	// Factor 8: Phase-1 advanced signals (open ports, params, secrets, WAF, JS)
	p1Score, p1Reasons := s.scorePhase1Intel(subdomain)
	rawScore += p1Score
	reasons = append(reasons, p1Reasons...)

	// Normalize to 0-100
	normalized := (rawScore / maxRawScore) * 100
	if normalized > 100 {
		normalized = 100
	}

	// Round to 1 decimal
	normalized = float64(int(normalized*10)) / 10

	return normalized, reasons
}

func (s *Scorer) scoreKeywords(subdomain string) (float64, []PriorityReason) {
	var reasons []PriorityReason
	maxScore := 0
	subLower := strings.ToLower(subdomain)

	for keyword, score := range keywordScores {
		if strings.Contains(subLower, keyword) {
			if score > maxScore {
				maxScore = score
			}
			reasons = append(reasons, PriorityReason{
				Factor: "subdomain_name",
				Detail: fmt.Sprintf("Contains keyword '%s'", keyword),
				Weight: score,
			})
		}
	}

	// Check custom priority keywords from config
	for tier, keywords := range s.cfg.PriorityKeywords {
		for _, keyword := range keywords {
			if strings.Contains(subLower, keyword) {
				if _, exists := keywordScores[keyword]; !exists {
					tierScore := 10
					switch tier {
					case "critical":
						tierScore = 30
					case "high":
						tierScore = 20
					case "medium":
						tierScore = 10
					}
					if tierScore > maxScore {
						maxScore = tierScore
					}
					reasons = append(reasons, PriorityReason{
						Factor: "subdomain_name",
						Detail: fmt.Sprintf("Contains '%s' keyword '%s'", tier, keyword),
						Weight: tierScore,
					})
				}
			}
		}
	}

	// Keep only the highest scoring reason
	if len(reasons) > 0 {
		best := reasons[0]
		for _, r := range reasons[1:] {
			if r.Weight > best.Weight {
				best = r
			}
		}
		reasons = []PriorityReason{best}
	}

	return float64(maxScore), reasons
}

func (s *Scorer) scoreVulnerabilities(subdomain string) (float64, []PriorityReason) {
	var reasons []PriorityReason
	total := 0

	subLower := strings.ToLower(subdomain)
	for _, v := range s.vulns {
		if strings.ToLower(v.Subdomain) == subLower {
			severity := strings.ToLower(v.Severity)
			score := vulnSeverityScores[severity]
			total += score

			detail := v.Name
			var cveIDs []string
			_ = json.Unmarshal([]byte(v.CVEIDs), &cveIDs)
			if len(cveIDs) > 0 {
				detail += fmt.Sprintf(" (%s)", strings.Join(cveIDs, ", "))
			}
			detail += fmt.Sprintf(" [%s]", severity)

			factor := "vulnerability"
			if severity == "critical" || severity == "high" {
				factor = "critical_vuln"
			}
			reasons = append(reasons, PriorityReason{
				Factor: factor,
				Detail: detail,
				Weight: score,
			})
		}
	}

	return float64(total), reasons
}

func (s *Scorer) scoreTakeover(subdomain string) (float64, []PriorityReason) {
	subLower := strings.ToLower(subdomain)
	for _, v := range s.vulns {
		if v.Type == "subzy" && strings.ToLower(v.Subdomain) == subLower {
			return 25, []PriorityReason{{
				Factor: "subdomain_takeover",
				Detail: "Vulnerable to subdomain takeover",
				Weight: 25,
			}}
		}
	}
	return 0, nil
}

func (s *Scorer) scoreExposedPaths(subdomain string) (float64, []PriorityReason) {
	var reasons []PriorityReason
	total := 0

	subLower := strings.ToLower(subdomain)
	for _, d := range s.dirs {
		if strings.ToLower(d.Subdomain) == subLower {
			path := strings.ToLower(d.Path)
			for sensitivePath, score := range s.cfg.ExposedPathScores {
				if strings.Contains(path, strings.ToLower(sensitivePath)) {
					total += score
					reasons = append(reasons, PriorityReason{
						Factor: "exposed_path",
						Detail: fmt.Sprintf("Sensitive path exposed: %s", path),
						Weight: score,
					})
					break
				}
			}
		}
	}

	return float64(total), reasons
}

func (s *Scorer) scoreMissingHeaders() (float64, []PriorityReason) {
	missing := s.getMissingHeaders()
	if len(missing) == 0 {
		return 0, nil
	}
	score := len(missing) * 3
	if score > 15 {
		score = 15
	}
	return float64(score), []PriorityReason{{
		Factor: "missing_headers",
		Detail: fmt.Sprintf("Missing %d security headers: %s", len(missing), strings.Join(missing[:min(5, len(missing))], ", ")),
		Weight: score,
	}}
}

func (s *Scorer) scoreTechRisk(subdomain string) (float64, []PriorityReason) {
	var reasons []PriorityReason
	maxScore := 0

	techStack := s.getSubTechByName(subdomain)
	for _, techName := range techStack {
		techLower := strings.ToLower(techName)
		for pattern, score := range knownVulnPatterns {
			if strings.Contains(techLower, pattern) {
				if score > maxScore {
					maxScore = score
				}
				reasons = append(reasons, PriorityReason{
					Factor: "tech_stack_risk",
					Detail: fmt.Sprintf("Potentially vulnerable tech: %s", techName),
					Weight: score,
				})
				break
			}
		}
	}

	if len(reasons) > 0 {
		best := reasons[0]
		for _, r := range reasons[1:] {
			if r.Weight > best.Weight {
				best = r
			}
		}
		reasons = []PriorityReason{best}
	}

	return float64(maxScore), reasons
}

func (s *Scorer) scoreParamURLs(subdomain string) (float64, []PriorityReason) {
	paramURLs := s.getSubParamURLs(subdomain)
	count := len(paramURLs)

	var score int
	switch {
	case count >= 5:
		score = 10
	case count >= 3:
		score = 7
	case count >= 1:
		score = 3
	default:
		return 0, nil
	}

	return float64(score), []PriorityReason{{
		Factor: "param_urls",
		Detail: fmt.Sprintf("%d URLs with parameters (potential injection points)", count),
		Weight: score,
	}}
}

// scorePhase1Intel adds the new Phase-1 advanced-module signals:
// +2 if open ports found, +2 if params discovered, +3 if secrets found,
// +1 if WAF detected (useful intel), +2 if JS endpoints found. These come
// from the p1_host_intel table populated by the phasemod modules.
func (s *Scorer) scorePhase1Intel(subdomain string) (float64, []PriorityReason) {
	intel, ok := s.hostIntel[strings.ToLower(subdomain)]
	if !ok {
		return 0, nil
	}
	var reasons []PriorityReason
	total := 0
	if intel.HasOpenPorts {
		total += 2
		reasons = append(reasons, PriorityReason{Factor: "open_ports", Detail: fmt.Sprintf("%d open ports (service exposure)", intel.OpenPortCount), Weight: 2})
	}
	if intel.HasParams {
		total += 2
		reasons = append(reasons, PriorityReason{Factor: "hidden_params", Detail: fmt.Sprintf("%d hidden parameters discovered (arjun)", intel.ParamCount), Weight: 2})
	}
	if intel.HasSecrets {
		total += 3
		reasons = append(reasons, PriorityReason{Factor: "leaked_secrets", Detail: fmt.Sprintf("%d leaked secrets found", intel.SecretCount), Weight: 3})
	}
	if intel.WAF != nil && *intel.WAF != "" && *intel.WAF != "none" {
		total += 1
		reasons = append(reasons, PriorityReason{Factor: "waf_detected", Detail: fmt.Sprintf("WAF: %s (useful intel for payload selection)", *intel.WAF), Weight: 1})
	}
	if intel.HasJSEndpoints {
		total += 2
		reasons = append(reasons, PriorityReason{Factor: "js_endpoints", Detail: fmt.Sprintf("%d endpoints extracted from JS", intel.JSEndpointCount), Weight: 2})
	}
	return float64(total), reasons
}

// ── Data extractors ────────────────────────────────────────────────

func (s *Scorer) getSubTech(host storage.LiveHost) []string {
	var techs []string
	if host.TechDetected != "" && host.TechDetected != "[]" {
		_ = json.Unmarshal([]byte(host.TechDetected), &techs)
	}
	if host.Webserver != nil {
		techs = append(techs, *host.Webserver)
	}
	// Deduplicate
	seen := make(map[string]bool)
	var result []string
	for _, t := range techs {
		if t != "" && !seen[t] {
			seen[t] = true
			result = append(result, t)
		}
	}
	return result
}

func (s *Scorer) getSubTechByName(subdomain string) []string {
	subLower := strings.ToLower(subdomain)
	for _, host := range s.liveHosts {
		if strings.ToLower(host.Subdomain) == subLower {
			return s.getSubTech(host)
		}
	}
	return nil
}

func (s *Scorer) getSubVulns(subdomain string) []string {
	var vulnNames []string
	subLower := strings.ToLower(subdomain)
	for _, v := range s.vulns {
		if strings.ToLower(v.Subdomain) == subLower {
			vulnNames = append(vulnNames, fmt.Sprintf("%s [%s]", v.Name, v.Severity))
		}
	}
	return vulnNames
}

func (s *Scorer) getSubParamURLs(subdomain string) []string {
	var urls []string
	subLower := strings.ToLower(subdomain)
	for _, u := range s.crawledURLs {
		if strings.ToLower(u.Subdomain) == subLower && u.HasParams {
			urls = append(urls, u.URL)
		}
	}
	return urls
}

func (s *Scorer) getSubDirs(subdomain string) []string {
	var dirs []string
	subLower := strings.ToLower(subdomain)
	for _, d := range s.dirs {
		if strings.ToLower(d.Subdomain) == subLower {
			dirs = append(dirs, d.Path)
		}
	}
	return dirs
}

func (s *Scorer) getMissingHeaders() []string {
	if s.headers == nil {
		return nil
	}
	var missing []string
	_ = json.Unmarshal([]byte(s.headers.MissingSecurityHeaders), &missing)
	return missing
}

// headerResultURL returns the URL the header result was fetched from, or "".
func headerResultURL(h *storage.HeaderResult) string {
	if h == nil {
		return ""
	}
	return h.URL
}

// hostnameOf extracts the host part of a URL string, tolerating schemes and
// paths. It is intentionally simple (no net/url) to avoid allocations and to
// handle inputs like "example.com" as well as "https://example.com/path".
func hostnameOf(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// strip userinfo
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	// strip port
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

func (s *Scorer) isTakeoverVulnerable(subdomain string) bool {
	subLower := strings.ToLower(subdomain)
	for _, v := range s.vulns {
		if v.Type == "subzy" && strings.ToLower(v.Subdomain) == subLower {
			return true
		}
	}
	return false
}

// ── Suggestions ────────────────────────────────────────────────────

func (s *Scorer) suggestManualTests(subdomain string, score float64, reasons []PriorityReason) []string {
	var suggestions []string

	subLower := strings.ToLower(subdomain)
	for _, v := range s.vulns {
		if strings.ToLower(v.Subdomain) != subLower {
			continue
		}
		name := strings.ToLower(v.Name)
		severity := strings.ToLower(v.Severity)

		if strings.Contains(name, "sql") {
			suggestions = append(suggestions, "SQL injection: Test all parameter endpoints with SQLi payloads")
		}
		if strings.Contains(name, "xss") {
			suggestions = append(suggestions, "XSS: Test reflected/stored XSS on all input fields")
		}
		if strings.Contains(name, "ssrf") {
			suggestions = append(suggestions, "SSRF: Test URL parameters for internal resource access")
		}
		if strings.Contains(name, "rce") || strings.Contains(name, "command") {
			suggestions = append(suggestions, "RCE: Test command injection on all input fields")
		}
		if strings.Contains(name, "auth") {
			suggestions = append(suggestions, "Authentication: Test for auth bypass and privilege escalation")
		}
		if strings.Contains(name, "redirect") {
			suggestions = append(suggestions, "Open Redirect: Test redirect parameters for phishing vectors")
		}
		if severity == "critical" {
			suggestions = append(suggestions, fmt.Sprintf("Critical vuln detected: %s - Verify and exploit", v.Name))
		}
	}

	// Based on exposed paths
	for _, path := range s.getSubDirs(subdomain) {
		pathLower := strings.ToLower(path)
		if strings.Contains(pathLower, ".env") {
			suggestions = append(suggestions, "Check .env file for exposed credentials and API keys")
		}
		if strings.Contains(pathLower, ".git") {
			suggestions = append(suggestions, "Check .git directory for source code leakage")
		}
		if strings.Contains(pathLower, "admin") {
			suggestions = append(suggestions, "Test admin panel for default credentials and auth bypass")
		}
	}

	// Based on parameters
	paramURLs := s.getSubParamURLs(subdomain)
	if len(paramURLs) > 0 {
		suggestions = append(suggestions, fmt.Sprintf("Test %d parameter-rich URLs for injection vulnerabilities", len(paramURLs)))
	}

	// Based on missing headers
	missing := s.getMissingHeaders()
	for _, h := range missing {
		switch h {
		case "Content-Security-Policy":
			suggestions = append(suggestions, "No CSP: Test for XSS and data injection vectors")
		case "Strict-Transport-Security":
			suggestions = append(suggestions, "No HSTS: Test for MITM and protocol downgrade attacks")
		case "X-Frame-Options":
			suggestions = append(suggestions, "No XFO: Test for clickjacking on authenticated pages")
		}
	}

	// Based on takeover
	if s.isTakeoverVulnerable(subdomain) {
		suggestions = append(suggestions, "Subdomain takeover confirmed - Attempt takeover and verify")
	}

	// Generic high-priority suggestions
	if score >= 70 {
		suggestions = append(suggestions, "High-priority target: Perform comprehensive manual testing")
		suggestions = append(suggestions, "Check for business logic vulnerabilities")
		suggestions = append(suggestions, "Test for IDOR on all CRUD endpoints")
	}

	// Deduplicate and cap at 15
	seen := make(map[string]bool)
	var result []string
	for _, s := range suggestions {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	if len(result) > 15 {
		result = result[:15]
	}
	return result
}

// ── Helpers ────────────────────────────────────────────────────────

func scoreToTier(score float64) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 45:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

func (s *Scorer) countByTier(entries []PriorityEntry) map[string]int {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, e := range entries {
		counts[e.PriorityTier]++
	}
	return counts
}

func (s *Scorer) generateHandoff(entries []PriorityEntry) {
	bySeverity := map[string][]storage.Vulnerability{
		"critical": {}, "high": {}, "medium": {}, "low": {}, "info": {},
	}
	for _, v := range s.vulns {
		sev := strings.ToLower(v.Severity)
		if _, ok := bySeverity[sev]; ok {
			bySeverity[sev] = append(bySeverity[sev], v)
		}
	}

	var allParamURLs []map[string]any
	for _, u := range s.crawledURLs {
		if u.HasParams {
			var params []string
			_ = json.Unmarshal([]byte(u.ParamNames), &params)
			allParamURLs = append(allParamURLs, map[string]any{
				"url":       u.URL,
				"subdomain": u.Subdomain,
				"params":    params,
			})
		}
	}

	handoff := map[string]any{
		"target":           s.cfg.Target,
		"scan_date":        time.Now().Format(time.RFC3339),
		"total_subdomains": len(s.liveHosts),
		"live_subdomains":  len(s.liveHosts),
		"total_vulnerabilities": len(s.vulns),
		"critical_vulnerabilities": len(bySeverity["critical"]),
		"priority_targets": entries,
		"all_urls_with_params": allParamURLs,
	}

	handoffPath := filepath.Join(s.cfg.PriorityDir(s.cfg.Target), "phase2_handoff.json")
	data, _ := json.MarshalIndent(handoff, "", "  ")
	os.WriteFile(handoffPath, data, 0644)

	logger.Success("Phase 2 handoff file generated")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
