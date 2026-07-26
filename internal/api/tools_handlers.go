package api

import (
	"encoding/json"
	"net/http"

	"github.com/yourname/dark-recon/internal/config"
	"github.com/yourname/dark-recon/internal/installer"
)

func (h *Handlers) GetTools(w http.ResponseWriter, r *http.Request) {
	inst := installer.New(false)
	// Each tool is verified on the filesystem (PATH + ~/go/bin) inside
	// GetAllToolsStatus before its installed/missing state is reported.
	writeJSON(w, 200, map[string]any{"tools": inst.GetAllToolsStatus()})
}

func (h *Handlers) RefreshTools(w http.ResponseWriter, r *http.Request) {
	inst := installer.New(false)
	writeJSON(w, 200, map[string]any{"tools": inst.GetAllToolsStatus()})
}

func (h *Handlers) GetTool(w http.ResponseWriter, r *http.Request) {
	toolName := r.PathValue("tool_name")
	inst := installer.New(false)
	result := inst.GetToolDetail(toolName)
	if result == nil {
		writeError(w, 404, "Tool not found")
		return
	}
	writeJSON(w, 200, result)
}

func (h *Handlers) InstallTool(w http.ResponseWriter, r *http.Request) {
	toolName := r.PathValue("tool_name")
	inst := installer.New(true)
	success, msg := inst.InstallTool(toolName)
	if success {
		writeJSON(w, 200, map[string]string{"status": "installed", "tool": toolName, "message": msg})
		return
	}
	writeError(w, 500, "Failed to install "+toolName+": "+msg)
}

func (h *Handlers) UninstallTool(w http.ResponseWriter, r *http.Request) {
	toolName := r.PathValue("tool_name")
	inst := installer.New(false)
	success, msg := inst.UninstallTool(toolName)
	if success {
		writeJSON(w, 200, map[string]string{"status": "uninstalled", "tool": toolName, "message": msg})
		return
	}
	writeError(w, 500, "Failed to uninstall "+toolName+": "+msg)
}

func (h *Handlers) CheckTool(w http.ResponseWriter, r *http.Request) {
	toolName := r.PathValue("tool_name")
	inst := installer.New(false)
	result := inst.GetToolDetail(toolName)
	if result == nil {
		writeError(w, 404, "Tool not found")
		return
	}
	writeJSON(w, 200, result)
}

func (h *Handlers) ToggleTool(w http.ResponseWriter, r *http.Request) {
	toolName := r.PathValue("tool_name")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "Invalid request body")
		return
	}
	// Tools are always enabled in the Go version; acknowledge the toggle
	writeJSON(w, 200, map[string]any{
		"tool":    toolName,
		"enabled": req.Enabled,
	})
}

func (h *Handlers) ListPhases(w http.ResponseWriter, r *http.Request) {
	// Canonical opt-in phase list — the single source of truth the UI contract
	// reads, mirroring config.Phase* constants and the pipeline engine's
	// shouldRun predicate. `needs` documents the prerequisite each phase
	// consumes (loaded from prior scans when the prerequisite isn't selected),
	// so the UI can render dependency hints without drifting from the engine.
	writeJSON(w, 200, map[string]any{"phases": []map[string]any{
		{"id": config.PhaseSubdomainEnum, "name": "Subdomain Enumeration", "tool": "subfinder + ffuf DNS", "needs": ""},
		{"id": config.PhasePassiveRecon, "name": "Passive Recon", "tool": "crt.sh / HackerTarget / AlienVault / chaos", "needs": ""},
		{"id": config.PhaseLiveCheck, "name": "Live Host Detection", "tool": "httpx", "needs": "subdomains"},
		{"id": config.PhaseTechDetection, "name": "Technology Detection", "tool": "webanalyze", "needs": "live_hosts"},
		{"id": config.PhaseEarlyCrawling, "name": "Deep Crawling", "tool": "katana", "needs": "live_hosts"},
		{"id": config.PhaseVulnScan, "name": "Vulnerability Scan", "tool": "nuclei", "needs": "live_hosts"},
		{"id": config.PhaseTakeover, "name": "Subdomain Takeover", "tool": "subzy", "needs": "live_hosts"},
		{"id": config.PhaseWAFDetect, "name": "WAF Detection", "tool": "wafw00f", "needs": "live_hosts"},
		{"id": config.PhasePortScan, "name": "Port Scan", "tool": "nmap", "needs": "live_hosts"},
		{"id": config.PhaseJSAnalysis, "name": "JS Analysis", "tool": "pure Go", "needs": "crawled_urls"},
		{"id": config.PhaseParamDiscovery, "name": "Parameter Discovery", "tool": "arjun", "needs": "crawled_urls"},
		{"id": config.PhaseSecretScan, "name": "Secret Scan", "tool": "trufflehog + gitleaks", "needs": "js_files"},
		{"id": config.PhasePriorityScoring, "name": "Priority Scoring", "tool": "scoring engine", "needs": ""},
	}})
}
