package api

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"

	uiembed "github.com/yourname/dark-recon/dark_recon/ui"
	"github.com/yourname/dark-recon/pkg/logger"
)

// RegisterRoutes sets up all HTTP routes on the given ServeMux.
func (h *Handlers) RegisterRoutes(mux *http.ServeMux, templateDir, staticDir string) {
	// ── API Routes ──────────────────────────────────────────────────

	// Scan management
	mux.HandleFunc("POST /api/scan/launch", h.LaunchScan)
	mux.HandleFunc("POST /api/scan/{target_name}/stop", h.StopScan)
	mux.HandleFunc("GET /api/scan/{target_name}/status", h.ScanStatus)
	mux.HandleFunc("GET /api/scan/{target_name}/logs", h.ScanLogs)
	mux.HandleFunc("GET /api/scans/active", h.ActiveScans)

	// Target data
	mux.HandleFunc("GET /api/targets", h.ListTargets)
	mux.HandleFunc("GET /api/dashboard/summary", h.GetDashboardSummary)
	mux.HandleFunc("DELETE /api/targets/bulk", h.BulkDeleteTargets)
	mux.HandleFunc("GET /api/target/{target_name}", h.GetTarget)
	mux.HandleFunc("DELETE /api/target/{target_name}", h.DeleteTarget)
	mux.HandleFunc("GET /api/target/{target_name}/vulns", h.GetVulns)
	mux.HandleFunc("GET /api/target/{target_name}/priority", h.GetPriority)
	mux.HandleFunc("GET /api/target/{target_name}/export", h.GetExport)
	mux.HandleFunc("GET /api/target/{target_name}/export/csv", h.ExportCSV)
	mux.HandleFunc("GET /api/target/{target_name}/handoff", h.GetHandoff)
	mux.HandleFunc("GET /api/target/{target_name}/subdomain/{subdomain}", h.GetSubdomainDetail)

	// Config
	mux.HandleFunc("GET /api/config", h.GetConfig)
	mux.HandleFunc("PUT /api/config", h.UpdateConfig)

	// Filesystem browser (directory picker on Settings page)
	mux.HandleFunc("GET /api/fs/dirs", h.BrowseDirs)

	// Tools
	mux.HandleFunc("GET /api/tools", h.GetTools)
	mux.HandleFunc("GET /api/tools/refresh", h.RefreshTools)
	mux.HandleFunc("GET /api/tools/{tool_name}", h.GetTool)
	mux.HandleFunc("POST /api/tools/{tool_name}/install", h.InstallTool)
	mux.HandleFunc("POST /api/tools/{tool_name}/uninstall", h.UninstallTool)
	mux.HandleFunc("POST /api/tools/{tool_name}/check", h.CheckTool)
	mux.HandleFunc("POST /api/tools/{tool_name}/toggle", h.ToggleTool)

	// Phases
	mux.HandleFunc("GET /api/phases", h.ListPhases)

	// ── Phase 1 advanced modules (read-only data endpoints) ──
	mux.HandleFunc("GET /api/phase1/{target_name}/findings", h.GetP1Findings)
	mux.HandleFunc("GET /api/phase1/{target_name}/ports", h.GetP1Ports)
	mux.HandleFunc("GET /api/phase1/{target_name}/js", h.GetP1JSFiles)
	mux.HandleFunc("GET /api/phase1/{target_name}/params", h.GetP1Params)
	mux.HandleFunc("GET /api/phase1/{target_name}/secrets", h.GetP1Secrets)
	mux.HandleFunc("GET /api/phase1/{target_name}/waf", h.GetP1WAF)
	mux.HandleFunc("GET /api/phase1/{target_name}/intel", h.GetP1Intel)
	mux.HandleFunc("GET /api/phase1/{target_name}/status", h.GetPhase1Status)

	// ── Phase 2 foundation (stubs; populated by later phases) ──
	mux.HandleFunc("POST /api/phase2/{target_name}/start", h.StartPhase2)
	mux.HandleFunc("GET /api/phase2/{target_name}/status", h.GetPhase2Status)

	// ── Phase 2 data API (Phase 1 → Phase 2 contract, Section 9) ──
	// Read-only joined queries Phase 2 consumes exclusively. Additive.
	mux.HandleFunc("GET /api/phase2/{target_name}/targets", h.GetPhase2Targets)
	mux.HandleFunc("GET /api/phase2/{target_name}/findings", h.GetPhase2Findings)
	mux.HandleFunc("GET /api/phase2/{target_name}/urls", h.GetPhase2URLs)
	mux.HandleFunc("GET /api/phase2/{target_name}/js", h.GetPhase2JS)
	mux.HandleFunc("GET /api/phase2/{target_name}/ports", h.GetPhase2Ports)

	// WebSocket
	mux.HandleFunc("GET /ws/{target_name}", h.WebSocketProgress)
	mux.HandleFunc("GET /ws", h.WebSocketGlobal)

	// Favicon (browsers request /favicon.ico at the site root by default)
	mux.HandleFunc("GET /favicon.ico", h.serveFavicon)

	// ── Static Files ────────────────────────────────────────────────
	// Prefer on-disk assets (dev), fall back to the embedded UI so the
	// installed binary is self-contained with no external file deps.
	if staticFS, ok := openStaticFS(staticDir); ok {
		mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	} else {
		if staticDir != "" {
			logger.Warn("Static dir not found (%q); serving embedded assets", staticDir)
		} else {
			logger.Success("Static: serving embedded assets")
		}
		mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(uiembed.StaticFS()))))
	}

	// ── HTML Page Routes ────────────────────────────────────────────
	// Prefer on-disk templates (dev), fall back to the embedded UI.
	useEmbedTmpl := templateDir == ""
	if _, err := os.Stat(templateDir); err != nil {
		useEmbedTmpl = true
	}
	if useEmbedTmpl {
		logger.Success("Templates: serving embedded assets")
	}
	serve := func(filename string) http.HandlerFunc {
		if useEmbedTmpl {
			return h.serveEmbeddedTemplate(filename)
		}
		return h.serveTemplate(templateDir, filename)
	}
	mux.HandleFunc("GET /", serve("dashboard.html"))
	mux.HandleFunc("GET /scan/new", serve("scan_launch.html"))
	mux.HandleFunc("GET /scan/{target_name}/progress", serve("live_progress.html"))
	mux.HandleFunc("GET /tools", serve("tools.html"))
	mux.HandleFunc("GET /settings", serve("settings.html"))
	mux.HandleFunc("GET /target/{target_name}", serve("target_detail.html"))
	mux.HandleFunc("GET /target/{target_name}/subdomain/{subdomain}", serve("subdomain_detail.html"))
}

// serveTemplate returns an http.HandlerFunc that serves an HTML file from
// disk. Templates are served as-is; JavaScript handles dynamic content via
// the API.
func (h *Handlers) serveTemplate(templateDir, filename string) http.HandlerFunc {
	templatePath := filepath.Join(templateDir, filename)
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(templatePath)
		if err != nil {
			logger.Err("Template not found: %s", templatePath)
			http.Error(w, "Page not found", 404)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	}
}

// serveEmbeddedTemplate serves an HTML file from the embedded UI assets, so
// the packaged binary works with no template directory on disk.
func (h *Handlers) serveEmbeddedTemplate(filename string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := uiembed.ReadTemplate(filename)
		if err != nil {
			logger.Err("Embedded template not found: %s", filename)
			http.Error(w, "Page not found", 404)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	}
}

// openStaticFS returns a filesystem rooted at the on-disk static asset
// directory, or (nil, false) if it is unavailable so the caller falls back to
// the embedded assets.
func openStaticFS(staticDir string) (fs.FS, bool) {
	if staticDir == "" {
		return nil, false
	}
	if _, err := os.Stat(staticDir); err != nil {
		return nil, false
	}
	return os.DirFS(staticDir), true
}

// serveFavicon serves the embedded SVG favicon at /favicon.ico so browsers
// that request it at the site root by default receive the Dark-Recon icon.
func (h *Handlers) serveFavicon(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(uiembed.StaticFS(), "favicon.svg")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}
