package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for Dark-Recon.
type Config struct {
	Target                     string                 `yaml:"target"`
	OutputDir                  string                 `yaml:"output_dir"`
	Threads                    int                    `yaml:"threads"`
	Timeout                    int                    `yaml:"timeout"`
	AutoInstall                bool                   `yaml:"auto_install"`
	TopSubdomainsForScanning   int                    `yaml:"top_subdomains_for_scanning"`
	SkipPhases                 []int                  `yaml:"skip_phases"`
	RunPhases                  map[string]bool        `yaml:"run_phases"` // opt-in phase selection; empty = run all
	SecLists                   SecListsConfig         `yaml:"seclists"`
	Nuclei                     NucleiConfig           `yaml:"nuclei"`
	Katana                     KatanaConfig           `yaml:"katana"`
	PriorityKeywords           map[string][]string    `yaml:"priority_keywords"`
	ExposedPathScores          map[string]int         `yaml:"exposed_path_scores"`
	Phase1                     Phase1Config           `yaml:"phase1"`
}

type SecListsConfig struct {
	BaseDir       string `yaml:"base_dir"`
	DNSWordlist   string `yaml:"dns_wordlist"`
	DirCommon     string `yaml:"dir_common"`
	DirBig        string `yaml:"dir_big"`
	DirMedium     string `yaml:"dir_medium"`
	APIEndpoints  string `yaml:"api_endpoints"`
}

type NucleiConfig struct {
	Templates  string   `yaml:"templates"`
	Severity   []string `yaml:"severity"`
	Rate       int      `yaml:"rate"`
	Concurrent int      `yaml:"concurrent"`
	CVSSMin    float64  `yaml:"cvss_min"`
	Timeout    int      `yaml:"timeout"`    // max scan duration in minutes
	BulkSize   int      `yaml:"bulk_size"`  // number of hosts per batch
}

type KatanaConfig struct {
	Depth       int  `yaml:"depth"`
	Concurrency int  `yaml:"concurrency"`
	Headless    bool `yaml:"headless"`    // active browser-based crawling
	JSParse     bool `yaml:"js_parse"`    // parse and crawl JS endpoints
}

// Phase1Config toggles and tunes the new Phase-1 advanced modules.
// Every module defaults to OFF (JS analysis ON) — the user opts in per scan.
type Phase1Config struct {
	PassiveRecon         bool   `yaml:"passive_recon"`
	PortScan             bool   `yaml:"port_scan"`
	WAFDetect            bool   `yaml:"waf_detect"`
	JSAnalysis           bool   `yaml:"js_analysis"`
	ParamDiscovery       bool   `yaml:"param_discovery"`
	SecretScan           bool   `yaml:"secret_scan"`
	ChaosAPIKey          string `yaml:"chaos_api_key"`
	PassiveReconWorkers  int    `yaml:"passive_recon_workers"`
	PortScanWorkers      int    `yaml:"port_scan_workers"`
	WAFWorkers           int    `yaml:"waf_workers"`
	JSAnalysisWorkers    int    `yaml:"js_analysis_workers"`
	ParamDiscoveryWorkers int   `yaml:"param_discovery_workers"`
	SecretScanWorkers    int    `yaml:"secret_scan_workers"`
}

// Phase name constants — the canonical ids used in RunPhases and by the
// pipeline engine's shouldRun predicate. Centralised here so the UI, API,
// config and engine never drift apart on naming.
const (
	PhaseSubdomainEnum   = "subdomain_enum"
	PhasePassiveRecon    = "passive_recon"
	PhaseLiveCheck       = "live_check"
	PhaseTechDetection   = "tech_detection"
	PhaseEarlyCrawling   = "early_crawling"
	PhaseVulnScan        = "vuln_scan"
	PhaseTakeover        = "takeover"
	PhaseWAFDetect       = "waf_detect"
	PhasePortScan        = "port_scan"
	PhaseJSAnalysis      = "js_analysis"
	PhaseParamDiscovery  = "param_discovery"
	PhaseSecretScan      = "secret_scan"
	PhasePriorityScoring = "priority_scoring"
)

// IsPhaseEnabled reports whether `name` should run. When RunPhases is empty
// (no opt-in selection) every phase is enabled (legacy "run all" behaviour).
// Otherwise only phases explicitly set true in RunPhases are enabled.
func (c *Config) IsPhaseEnabled(name string) bool {
	if len(c.RunPhases) == 0 {
		return true
	}
	return c.RunPhases[name]
}

// DefaultConfigPath returns the default config.yaml location.
func DefaultConfigPath() string {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	// Try current working directory first
	if _, err := os.Stat("config.yaml"); err == nil {
		abs, _ := filepath.Abs("config.yaml")
		return abs
	}
	// Try relative to executable
	p := filepath.Join(dir, "config.yaml")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return "config.yaml"
}

// DefaultBaseDir returns ~/dark_recon_results.
func DefaultBaseDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "dark_recon_results")
}

// Load reads config from a YAML file and applies overrides.
func Load(path string, overrides map[string]any) (*Config, error) {
	cfg := &Config{
		OutputDir:                DefaultBaseDir(),
		Threads:                  50,
		Timeout:                  10,
		AutoInstall:              true,
		TopSubdomainsForScanning: 10,
		Nuclei: NucleiConfig{
			Templates:  filepath.Join(os.Getenv("HOME"), "nuclei-templates"),
			Severity:   []string{"critical", "high"},
			Rate:       250,
			Concurrent: 50,
			CVSSMin:    6.5,
			Timeout:    90,
			BulkSize:   50,
		},
		Katana: KatanaConfig{
			Depth:       3,
			Concurrency: 50,
			Headless:    true,
			JSParse:     true,
		},
		Phase1: Phase1Config{
			JSAnalysis:            true, // on by default per spec
			PassiveReconWorkers:   5,
			PortScanWorkers:       50,
			WAFWorkers:            20,
			JSAnalysisWorkers:     30,
			ParamDiscoveryWorkers: 5,
			SecretScanWorkers:     10,
		},
		SecLists: SecListsConfig{
			BaseDir: "/usr/share/wordlists/seclists",
		},
		PriorityKeywords: map[string][]string{
			"critical": {"admin", "api", "staging", "internal", "vpn", "auth", "login", "dashboard", "console", "manage"},
			"high":     {"dev", "test", "uat", "beta", "app", "portal", "gateway", "control", "panel", "root"},
			"medium":   {"www", "mail", "cdn", "static", "blog"},
		},
		ExposedPathScores: map[string]int{
			".env": 20, ".git": 15, "/admin": 10,
			"/api/docs": 10, "/config": 8, "/backup": 8,
			"/.htaccess": 6, "/debug": 6, "/phpmyadmin": 12,
			"/wp-admin": 10, "/actuator": 10, "/swagger": 10,
			"/graphql": 8, "/.svn": 12, "/wp-config.php": 15,
			"/server-status": 8, "/server-info": 8,
		},
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, err
			}
		}
	}

	// Apply overrides. Values may arrive from JSON (numbers as float64,
	// arrays as []any) or from native Go callers (int, []int), so every
	// accessor coerces defensively instead of panic-asserting.
	if overrides != nil {
		applyStr := func(key string, dst *string) {
			if v, ok := overrides[key]; ok {
				if s, ok := v.(string); ok {
					*dst = s
				}
			}
		}
		applyInt := func(key string, dst *int) {
			if v, ok := overrides[key]; ok {
				if n, ok := asInt(v); ok {
					*dst = n
				}
			}
		}
		applyFloat := func(key string, dst *float64) {
			if v, ok := overrides[key]; ok {
				if f, ok := asFloat(v); ok {
					*dst = f
				}
			}
		}
		applyBool := func(key string, dst *bool) {
			if v, ok := overrides[key]; ok {
				if b, ok := v.(bool); ok {
					*dst = b
				}
			}
		}

		// General
		applyStr("target", &cfg.Target)
		applyStr("output_dir", &cfg.OutputDir)
		applyInt("threads", &cfg.Threads)
		applyInt("timeout", &cfg.Timeout)
		applyBool("auto_install", &cfg.AutoInstall)
		applyInt("top_subdomains_for_scanning", &cfg.TopSubdomainsForScanning)
		if v, ok := overrides["skip_phases"]; ok {
			if ints, ok := asInts(v); ok {
				cfg.SkipPhases = ints
			}
		}
		// Opt-in phase selection (UI "Select Scanning Phases"). Accepts a list
		// of phase names ([]string / []any) or a map[string]bool. When set,
		// the pipeline runs ONLY the listed phases (plus any auto-resolved
		// prerequisites loaded from prior scans). Empty/unset = run all.
		if v, ok := overrides["run_phases"]; ok {
			cfg.RunPhases = asStringSet(v)
		}

		// Nuclei configuration (Settings page)
		applyStr("nuclei_templates_dir", &cfg.Nuclei.Templates)
		applyInt("nuclei_rate", &cfg.Nuclei.Rate)
		applyInt("nuclei_concurrent", &cfg.Nuclei.Concurrent)
		applyFloat("nuclei_cvss_min", &cfg.Nuclei.CVSSMin)
		if v, ok := overrides["nuclei_severity"]; ok {
			if ss, ok := asStrings(v); ok {
				cfg.Nuclei.Severity = ss
			}
		}

		// SecLists / wordlists (Settings page)
		applyStr("seclists_base_dir", &cfg.SecLists.BaseDir)
		applyStr("dns_wordlist", &cfg.SecLists.DNSWordlist)
		applyStr("dir_common_wordlist", &cfg.SecLists.DirCommon)
		applyStr("dir_big_wordlist", &cfg.SecLists.DirBig)
		applyStr("dir_medium_wordlist", &cfg.SecLists.DirMedium)
		applyStr("api_endpoints_wordlist", &cfg.SecLists.APIEndpoints)

		// Phase-1 advanced module toggles (per-scan opt-in)
		applyBool("passive_recon", &cfg.Phase1.PassiveRecon)
		applyBool("port_scan", &cfg.Phase1.PortScan)
		applyBool("waf_detect", &cfg.Phase1.WAFDetect)
		applyBool("js_analysis", &cfg.Phase1.JSAnalysis)
		applyBool("param_discovery", &cfg.Phase1.ParamDiscovery)
		applyBool("secret_scan", &cfg.Phase1.SecretScan)
		applyStr("chaos_api_key", &cfg.Phase1.ChaosAPIKey)

		// Fall back to env var if not provided in overrides/config
		if cfg.Phase1.ChaosAPIKey == "" {
			cfg.Phase1.ChaosAPIKey = os.Getenv("PDCP_API_KEY")
		}
	}

	// When an opt-in phase selection is provided, derive the Phase-1 module
	// toggles from it so every gate (engine + module-internal checks) agrees.
	// This keeps the phasemod functions (which consult cfg.Phase1.PortScan etc.)
	// consistent with the RunPhases set without touching each module.
	if len(cfg.RunPhases) > 0 {
		cfg.Phase1.PassiveRecon = cfg.RunPhases[PhasePassiveRecon]
		cfg.Phase1.PortScan = cfg.RunPhases[PhasePortScan]
		cfg.Phase1.WAFDetect = cfg.RunPhases[PhaseWAFDetect]
		cfg.Phase1.JSAnalysis = cfg.RunPhases[PhaseJSAnalysis]
		cfg.Phase1.ParamDiscovery = cfg.RunPhases[PhaseParamDiscovery]
		cfg.Phase1.SecretScan = cfg.RunPhases[PhaseSecretScan]
	}

	// Expand ~ in paths
	cfg.OutputDir = expandHome(cfg.OutputDir)
	cfg.Nuclei.Templates = expandHome(cfg.Nuclei.Templates)
	cfg.SecLists.BaseDir = expandHome(cfg.SecLists.BaseDir)
	cfg.SecLists.DNSWordlist = expandHome(cfg.SecLists.DNSWordlist)
	cfg.SecLists.DirCommon = expandHome(cfg.SecLists.DirCommon)
	cfg.SecLists.DirBig = expandHome(cfg.SecLists.DirBig)
	cfg.SecLists.DirMedium = expandHome(cfg.SecLists.DirMedium)
	cfg.SecLists.APIEndpoints = expandHome(cfg.SecLists.APIEndpoints)

	// Set default seclists paths if not set
	if cfg.SecLists.DNSWordlist == "" && cfg.SecLists.BaseDir != "" {
		cfg.SecLists.DNSWordlist = filepath.Join(cfg.SecLists.BaseDir, "Discovery/DNS/subdomains-top1million-5000.txt")
	}
	if cfg.SecLists.DirCommon == "" && cfg.SecLists.BaseDir != "" {
		cfg.SecLists.DirCommon = filepath.Join(cfg.SecLists.BaseDir, "Discovery/Web-Content/common.txt")
	}
	if cfg.SecLists.DirBig == "" && cfg.SecLists.BaseDir != "" {
		cfg.SecLists.DirBig = filepath.Join(cfg.SecLists.BaseDir, "Discovery/Web-Content/big.txt")
	}
	if cfg.SecLists.DirMedium == "" && cfg.SecLists.BaseDir != "" {
		cfg.SecLists.DirMedium = filepath.Join(cfg.SecLists.BaseDir, "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt")
	}
	if cfg.SecLists.APIEndpoints == "" && cfg.SecLists.BaseDir != "" {
		cfg.SecLists.APIEndpoints = filepath.Join(cfg.SecLists.BaseDir, "Discovery/Web-Content/api/api-endpoints.txt")
	}

	return cfg, nil
}

// TargetDir returns the output directory for a specific target.
//
// The target name is sanitized to prevent path traversal: only hostname-safe
// characters (letters, digits, dots, hyphens, underscores) are retained. Any
// path separators or ../ sequences are stripped, keeping the result within
// OutputDir. This is defense-in-depth — the API layer also validates input.
func (c *Config) TargetDir(target string) string {
	return filepath.Join(c.OutputDir, sanitizeTargetName(target))
}

// sanitizeTargetName strips every character that is not safe in a hostname
// or directory name. This prevents path-traversal attacks where a malicious
// {target_name} path parameter (e.g. "../../etc") could escape OutputDir.
func sanitizeTargetName(target string) string {
	var b strings.Builder
	for _, c := range target {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '-', c == '_':
			b.WriteRune(c)
		}
	}
	return b.String()
}

// RawDir returns the raw output directory.
func (c *Config) RawDir(target string) string {
	return filepath.Join(c.TargetDir(target), "raw")
}

// ParsedDir returns the parsed output directory.
func (c *Config) ParsedDir(target string) string {
	return filepath.Join(c.TargetDir(target), "parsed")
}

// PriorityDir returns the priority output directory.
func (c *Config) PriorityDir(target string) string {
	return filepath.Join(c.TargetDir(target), "priority")
}

// ReportsDir returns the reports output directory.
func (c *Config) ReportsDir(target string) string {
	return filepath.Join(c.TargetDir(target), "reports")
}

// ToMap returns a map representation for the API.
func (c *Config) ToMap() map[string]any {
	return map[string]any{
		"output_dir":                  c.OutputDir,
		"threads":                     c.Threads,
		"timeout":                     c.Timeout,
		"auto_install":                c.AutoInstall,
		"top_subdomains_for_scanning": c.TopSubdomainsForScanning,
		"skip_phases":                 c.SkipPhases,
		"run_phases":                  c.RunPhases,
		"nuclei_templates_dir":        c.Nuclei.Templates,
		"nuclei_severity":             c.Nuclei.Severity,
		"nuclei_rate":                 c.Nuclei.Rate,
		"nuclei_concurrent":           c.Nuclei.Concurrent,
		"nuclei_cvss_min":             c.Nuclei.CVSSMin,
		"nuclei_timeout":              c.Nuclei.Timeout,
		"nuclei_bulk_size":            c.Nuclei.BulkSize,
		"katana_depth":                c.Katana.Depth,
		"katana_concurrency":          c.Katana.Concurrency,
		"katana_headless":             c.Katana.Headless,
		"katana_js_parse":             c.Katana.JSParse,
		"seclists_base_dir":           c.SecLists.BaseDir,
		"dns_wordlist":                c.SecLists.DNSWordlist,
		"dir_common_wordlist":         c.SecLists.DirCommon,
		"dir_big_wordlist":            c.SecLists.DirBig,
		"dir_medium_wordlist":         c.SecLists.DirMedium,
		"api_endpoints_wordlist":      c.SecLists.APIEndpoints,
		"target":                      c.Target,
		"phase1": map[string]any{
			"passive_recon":          c.Phase1.PassiveRecon,
			"port_scan":              c.Phase1.PortScan,
			"waf_detect":             c.Phase1.WAFDetect,
			"js_analysis":            c.Phase1.JSAnalysis,
			"param_discovery":        c.Phase1.ParamDiscovery,
			"secret_scan":            c.Phase1.SecretScan,
			"passive_recon_workers":  c.Phase1.PassiveReconWorkers,
			"port_scan_workers":      c.Phase1.PortScanWorkers,
			"waf_workers":            c.Phase1.WAFWorkers,
			"js_analysis_workers":    c.Phase1.JSAnalysisWorkers,
			"param_discovery_workers": c.Phase1.ParamDiscoveryWorkers,
			"secret_scan_workers":    c.Phase1.SecretScanWorkers,
		},
	}
}

// Save writes the config back to YAML.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func expandHome(path string) string {
	if path == "" {
		return path
	}
	if path[0] == '~' {
		home, _ := os.UserHomeDir()
		if len(path) == 1 {
			return home
		}
		if path[1] == '/' {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// ── override value coercion helpers ────────────────────────────────
// JSON-decoded config values arrive as float64 / []any, while native Go
// callers pass int / []int. These helpers normalise both without panicking.

// asInt coerces numeric values (JSON float64 / native int/int64) into an int.
func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

// asFloat coerces numeric values (JSON float64 / native int) into float64.
func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// asStrings coerces a JSON array of strings ([]any) or a native []string
// into []string. Non-string elements are skipped.
func asStrings(v any) ([]string, bool) {
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out, true
	}
	return nil, false
}

// asInts coerces a JSON array ([]any of numbers) or native []int into []int.
func asInts(v any) ([]int, bool) {
	switch s := v.(type) {
	case []int:
		return s, true
	case []any:
		out := make([]int, 0, len(s))
		for _, e := range s {
			if n, ok := asInt(e); ok {
				out = append(out, n)
			}
		}
		return out, true
	}
	return nil, false
}

// asStringSet coerces a JSON array of strings ([]any / []string) or a
// map[string]bool (or map[string]any) into a set used for opt-in phase
// selection. For map values, truthy means enabled; for arrays, presence means
// enabled. Returns a non-nil map only when the input was a recognised shape.
func asStringSet(v any) map[string]bool {
	switch s := v.(type) {
	case map[string]bool:
		return s
	case map[string]any:
		out := make(map[string]bool, len(s))
		for k, val := range s {
			if b, ok := val.(bool); ok {
				out[k] = b
			} else {
				out[k] = true
			}
		}
		return out
	case []string:
		out := make(map[string]bool, len(s))
		for _, e := range s {
			if e != "" {
				out[e] = true
			}
		}
		return out
	case []any:
		out := make(map[string]bool, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok && str != "" {
				out[str] = true
			}
		}
		return out
	}
	return nil
}
