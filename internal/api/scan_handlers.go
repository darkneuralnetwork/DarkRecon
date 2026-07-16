package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/yourname/dark-recon/internal/config"
	"github.com/yourname/dark-recon/internal/scanmgr"
	"github.com/yourname/dark-recon/internal/storage"
)

// Handlers holds all HTTP handler dependencies.
type Handlers struct {
	cfg        *config.Config
	configPath string
	scanMgr    *scanmgr.Manager
	// dbCache pools open per-target SQLite handles for the read-heavy API so
	// each GET doesn't re-open + re-migrate the DB. See storage.DBCache.
	dbCache    *storage.DBCache
	// priorityMu serializes on-demand priority generation (see ensurePriority)
	// so two concurrent reads of a scan missing priority_entries can't
	// double-insert. It only ever locks the rare fallback path, never the
	// normal read flow.
	priorityMu sync.Mutex
}

// New creates a new API handlers instance.
func New(cfg *config.Config, configPath string, sm *scanmgr.Manager) *Handlers {
	return &Handlers{
		cfg:        cfg,
		configPath: configPath,
		scanMgr:    sm,
		dbCache:    storage.NewDBCache(),
	}
}

// ScanRequest represents a scan launch request.
type ScanRequest struct {
	Domain        string `json:"domain"`
	Threads       int    `json:"threads"`
	Timeout       int    `json:"timeout"`
	TopSubdomains int    `json:"top_subdomains"`
	SkipPhases    []int  `json:"skip_phases"`
	Resume        bool   `json:"resume"`

	// Phases is the opt-in selection of scan phases/modules to run
	// (e.g. ["subdomain_enum","port_scan"]). When non-empty the pipeline runs
	// ONLY these; missing prerequisites are loaded from prior scans of the
	// target. Mutually independent of the legacy skip_phases (opt-out).
	Phases         []string `json:"phases,omitempty"`

	// Phase-1 advanced module toggles (per-scan, legacy). Each is a *bool so we
	// can distinguish "not sent" (use config default) from "explicitly off".
	// Superseded by Phases when Phases is set.
	PassiveRecon    *bool `json:"passive_recon,omitempty"`
	PortScan        *bool `json:"port_scan,omitempty"`
	WAFDetect       *bool `json:"waf_detect,omitempty"`
	JSAnalysis      *bool `json:"js_analysis,omitempty"`
	ParamDiscovery  *bool `json:"param_discovery,omitempty"`
	SecretScan      *bool `json:"secret_scan,omitempty"`
	ChaosAPIKey     string `json:"chaos_api_key,omitempty"`
}

func (h *Handlers) LaunchScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "Invalid request body")
		return
	}

	target := strings.TrimSpace(req.Domain)
	if target == "" {
		writeError(w, 400, "Domain is required")
		return
	}

	overrides := map[string]any{
		"target": target,
	}
	if req.Threads > 0 {
		overrides["threads"] = req.Threads
	}
	if req.Timeout > 0 {
		overrides["timeout"] = req.Timeout
	}
	// Only override when the caller actually sent a value; otherwise the zero
	// value (0) would clobber the config default (10) via applyInt, silently
	// disabling top-subdomain selection.
	if req.TopSubdomains > 0 {
		overrides["top_subdomains_for_scanning"] = req.TopSubdomains
	}
	if len(req.SkipPhases) > 0 {
		overrides["skip_phases"] = req.SkipPhases
	}
	if len(req.Phases) > 0 {
		overrides["run_phases"] = req.Phases
	}

	// Phase-1 advanced module per-scan overrides (only forwarded when set).
	if req.PassiveRecon != nil {
		overrides["passive_recon"] = *req.PassiveRecon
	}
	if req.PortScan != nil {
		overrides["port_scan"] = *req.PortScan
	}
	if req.WAFDetect != nil {
		overrides["waf_detect"] = *req.WAFDetect
	}
	if req.JSAnalysis != nil {
		overrides["js_analysis"] = *req.JSAnalysis
	}
	if req.ParamDiscovery != nil {
		overrides["param_discovery"] = *req.ParamDiscovery
	}
	if req.SecretScan != nil {
		overrides["secret_scan"] = *req.SecretScan
	}
	if req.ChaosAPIKey != "" {
		overrides["chaos_api_key"] = req.ChaosAPIKey
	}

	success := h.scanMgr.LaunchScan(target, overrides, h.configPath)
	if !success {
		writeError(w, 409, "A scan is already running for this target")
		return
	}

	writeJSON(w, 200, map[string]string{"status": "launched", "target": target})
}

func (h *Handlers) StopScan(w http.ResponseWriter, r *http.Request) {
	target, ok := requireTarget(w, r)
	if !ok {
		return
	}
	success := h.scanMgr.StopScan(target)
	if !success {
		writeError(w, 404, "No running scan for this target")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "stopping", "target": target})
}

func (h *Handlers) ScanStatus(w http.ResponseWriter, r *http.Request) {
	target, ok := requireTarget(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, h.scanMgr.GetStatus(target))
}

func (h *Handlers) ScanLogs(w http.ResponseWriter, r *http.Request) {
	target, ok := requireTarget(w, r)
	if !ok {
		return
	}
	logs := h.scanMgr.GetProgressLog(target)
	writeJSON(w, 200, map[string]any{"target": target, "logs": logs, "count": len(logs)})
}

func (h *Handlers) ActiveScans(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"scans": h.scanMgr.GetAllActiveScans()})
}
