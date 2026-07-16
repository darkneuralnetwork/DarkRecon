package storage

import "time"

// ScanMeta holds metadata for a scan session.
type ScanMeta struct {
	ID              int64     `json:"id"`
	Target          string    `json:"target"`
	StartTime       time.Time `json:"start_time"`
	EndTime         *time.Time `json:"end_time,omitempty"`
	DurationSeconds *float64  `json:"duration_seconds,omitempty"`
	Status          string    `json:"status"` // running, completed, failed
	PhasesCompleted string    `json:"phases_completed"` // JSON array as string
	Error           *string   `json:"error,omitempty"`
}

// Subdomain represents a discovered subdomain.
type Subdomain struct {
	ID       int64  `json:"id"`
	ScanID   int64  `json:"scan_id"`
	Subdomain string `json:"subdomain"`
	Source   string `json:"source"` // subfinder, ffuf, dns_enum
}

// LiveHost represents a live subdomain detected by httpx.
type LiveHost struct {
	ID           int64    `json:"id"`
	ScanID       int64    `json:"scan_id"`
	URL          string   `json:"url"`
	Subdomain    string   `json:"subdomain"`
	StatusCode   int      `json:"status_code"`
	Title        *string  `json:"title,omitempty"`
	ContentLength *int    `json:"content_length,omitempty"`
	Webserver    *string  `json:"webserver,omitempty"`
	CDN          *string  `json:"cdn,omitempty"`
	RedirectURL  *string  `json:"redirect_url,omitempty"`
	TechDetected string   `json:"tech_detected,omitempty"` // JSON array
}

// TechDetection represents a detected technology.
type TechDetection struct {
	ID         int64    `json:"id"`
	ScanID     int64    `json:"scan_id"`
	Subdomain  string   `json:"subdomain"`
	Name       string   `json:"name"`
	Version    *string  `json:"version,omitempty"`
	Category   string   `json:"category"`
	Confidence string   `json:"confidence"`
}

// CrawledURL represents a URL discovered by Katana.
type CrawledURL struct {
	ID        int64    `json:"id"`
	ScanID    int64    `json:"scan_id"`
	URL       string   `json:"url"`
	Subdomain string   `json:"subdomain"`
	HasParams bool     `json:"has_params"`
	ParamNames string  `json:"param_names,omitempty"` // JSON array
	ParamCount int     `json:"param_count"`
	Source    string   `json:"source"` // katana, ffuf
}

// DiscoveredDir represents a directory/endpoint found by ffuf.
type DiscoveredDir struct {
	ID            int64   `json:"id"`
	ScanID        int64   `json:"scan_id"`
	URL           string  `json:"url"`
	Subdomain     string  `json:"subdomain"`
	Path          string  `json:"path"`
	StatusCode    int     `json:"status_code"`
	ContentLength *int    `json:"content_length,omitempty"`
	WordlistUsed  string  `json:"wordlist_used"`
}

// Vulnerability represents a finding from nuclei or subzy.
type Vulnerability struct {
	ID              int64    `json:"id"`
	ScanID          int64    `json:"scan_id"`
	TemplateID      *string  `json:"template_id,omitempty"`
	Name            string   `json:"name"`
	Severity        string   `json:"severity"`
	URL             string   `json:"url"`
	Subdomain       string   `json:"subdomain"`
	CVEIDs          string   `json:"cve_ids,omitempty"` // JSON array
	Description     *string  `json:"description,omitempty"`
	MatcherName     *string  `json:"matcher_name,omitempty"`
	ExtractedResults string  `json:"extracted_results,omitempty"` // JSON array
	References      string   `json:"reference,omitempty"` // JSON array
	Type            string   `json:"type"` // nuclei, subzy
}

// TakeoverResult represents a subdomain takeover finding.
type TakeoverResult struct {
	ID          int64   `json:"id"`
	ScanID      int64   `json:"scan_id"`
	Subdomain   string  `json:"subdomain"`
	Vulnerable  bool    `json:"vulnerable"`
	Service     *string `json:"service,omitempty"`
	Fingerprint *string `json:"fingerprint,omitempty"`
}

// PriorityEntry represents a scored subdomain.
type PriorityEntry struct {
	ID                int64    `json:"id"`
	ScanID            int64    `json:"scan_id"`
	Rank              int      `json:"rank"`
	Subdomain         string   `json:"subdomain"`
	URL               string   `json:"url"`
	PriorityScore     float64  `json:"priority_score"`
	PriorityTier      string   `json:"priority"` // Critical, High, Medium, Low
	Reasons           string   `json:"reasons,omitempty"` // JSON array
	TechStack         string   `json:"tech_stack,omitempty"` // JSON array
	Vulnerabilities   string   `json:"vulnerabilities,omitempty"` // JSON array
	URLsWithParams    string   `json:"urls_with_params,omitempty"` // JSON array
	ExposedDirs       string   `json:"exposed_dirs,omitempty"` // JSON array
	MissingHeaders    string   `json:"missing_headers,omitempty"` // JSON array
	TakeoverVulnerable bool    `json:"takeover_vulnerable"`
	SuggestedTests    string   `json:"suggested_manual_tests,omitempty"` // JSON array
}

// HeaderResult stores HTTP header analysis results.
type HeaderResult struct {
	ID                  int64   `json:"id"`
	ScanID              int64   `json:"scan_id"`
	URL                 string  `json:"url"`
	StatusCode          int     `json:"status_code"`
	Headers             string  `json:"headers"` // JSON object
	DetectedTech        string  `json:"detected_tech,omitempty"` // JSON array
	Frameworks          string  `json:"frameworks,omitempty"` // JSON array
	Server              *string `json:"server,omitempty"`
	MissingSecurityHeaders string `json:"missing_security_headers,omitempty"` // JSON array
}

// ── Phase 1 advanced module models (p1_ prefixed tables) ─────────

// P1PassiveRecon holds a passive recon result row.
type P1PassiveRecon struct {
	ID        int64  `json:"id"`
	ScanID    int64  `json:"scan_id"`
	Subdomain string `json:"subdomain"`
	Source    string `json:"source"`   // crtsh | hackertarget | alienvault | chaos
	DataType  string `json:"data_type"` // subdomain | ip | asn | port | tech
	Value     string `json:"value"`
	Raw       string `json:"raw,omitempty"`
}

// P1Port holds an open port row.
type P1Port struct {
	ID        int64   `json:"id"`
	ScanID    int64   `json:"scan_id"`
	Subdomain string  `json:"subdomain"`
	Port      int     `json:"port"`
	Protocol  string  `json:"protocol"`
	Service   *string `json:"service,omitempty"`
	Banner    *string `json:"banner,omitempty"`
}

// P1JSFile holds a discovered JS file row.
type P1JSFile struct {
	ID        int64  `json:"id"`
	ScanID    int64  `json:"scan_id"`
	Subdomain string `json:"subdomain"`
	URL       string `json:"url"`
	SizeBytes *int   `json:"size_bytes,omitempty"`
}

// P1JSFinding holds a JS analysis result row.
type P1JSFinding struct {
	ID        int64  `json:"id"`
	ScanID    int64  `json:"scan_id"`
	JsFileID  *int64 `json:"js_file_id,omitempty"`
	Subdomain string `json:"subdomain"`
	Type      string `json:"type"`   // endpoint | secret
	Pattern   string `json:"pattern,omitempty"`
	Value     string `json:"value"`
	Context   string `json:"context,omitempty"`
}

// P1Param holds a discovered parameter row.
type P1Param struct {
	ID        int64  `json:"id"`
	ScanID    int64  `json:"scan_id"`
	Subdomain string `json:"subdomain"`
	URL       string `json:"url"`
	ParamName string `json:"param_name"`
	ParamType string `json:"param_type,omitempty"` // query | body | path | header
	Source    string `json:"source,omitempty"`     // arjun | katana
}

// P1Secret holds a leaked secret row.
type P1Secret struct {
	ID         int64   `json:"id"`
	ScanID     int64   `json:"scan_id"`
	Subdomain  *string `json:"subdomain,omitempty"`
	SourceURL  *string `json:"source_url,omitempty"`
	SecretType string  `json:"secret_type"`
	RawMatch   string  `json:"raw_match"`
	Entropy    *float64 `json:"entropy,omitempty"`
	Tool       string  `json:"tool"` // trufflehog | gitleaks | js_analysis | manual
}

// P1Finding holds a unified finding from the new phase-1 tools.
type P1Finding struct {
	ID          int64   `json:"id"`
	ScanID      int64   `json:"scan_id"`
	Subdomain   string  `json:"subdomain"`
	Tool        string  `json:"tool"`        // nmap | wafw00f | js_analysis | trufflehog | gitleaks
	TemplateID  *string `json:"template_id,omitempty"`
	Severity    string  `json:"severity"`    // critical | high | medium | low | info
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Evidence    *string `json:"evidence,omitempty"`
	Verified    bool    `json:"verified"`
	FalsePos    bool    `json:"false_pos"`
}

// P1HostIntel holds per-host intel aggregated by the new modules.
type P1HostIntel struct {
	ID              int64   `json:"id"`
	ScanID          int64   `json:"scan_id"`
	Subdomain       string  `json:"subdomain"`
	WAF             *string `json:"waf,omitempty"`
	WAFManufacturer *string `json:"waf_manufacturer,omitempty"`
	OpenPortCount   int     `json:"open_port_count"`
	ParamCount      int     `json:"param_count"`
	SecretCount     int     `json:"secret_count"`
	JSEndpointCount int     `json:"js_endpoint_count"`
	HasOpenPorts    bool    `json:"has_open_ports"`
	HasParams       bool    `json:"has_params"`
	HasSecrets      bool    `json:"has_secrets"`
	HasJSEndpoints  bool    `json:"has_js_endpoints"`
}
