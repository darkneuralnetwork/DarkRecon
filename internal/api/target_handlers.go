package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yourname/dark-recon/internal/scoring"
	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/pkg/logger"
)

func (h *Handlers) ListTargets(w http.ResponseWriter, r *http.Request) {
	resultsDir := h.cfg.OutputDir
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		// Try to include running scans from active scans map even if ReadDir fails
		activeScans := h.scanMgr.GetAllActiveScans()
		if len(activeScans) > 0 {
			var targets []map[string]any
			for _, scan := range activeScans {
				targets = append(targets, map[string]any{
					"name":        scan["target"],
					"status":      "running",
					"scan_status": "running",
				})
			}
			writeJSON(w, 200, map[string]any{"targets": targets})
		} else {
			writeJSON(w, 200, map[string]any{"targets": []any{}})
		}
		return
	}

	var targets []map[string]any
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		targetName := entry.Name()
		targetDir := filepath.Join(resultsDir, targetName)

		dbPath := filepath.Join(targetDir, "scan.db")
		db, err := h.dbCache.Acquire(dbPath)
		if err != nil {
			targets = append(targets, map[string]any{
				"name":   targetName,
				"status": "unknown",
			})
			continue
		}

		meta, _ := db.GetScanByTarget(targetName)
		if meta == nil {
			// Check if this is a running scan in the active scans map
			if status := h.scanMgr.GetStatus(targetName); status != nil {
				if s, ok := status["status"].(string); ok && s == "running" {
					targets = append(targets, map[string]any{
						"name":        targetName,
						"status":      "running",
						"scan_status": "running",
					})
					db.Close()
					continue
				}
			}
			db.Close()
			targets = append(targets, map[string]any{
				"name":   targetName,
				"status": "unknown",
			})
			continue
		}

		vulns, _ := db.GetVulnerabilities(meta.ID)
		priority, _ := db.GetPriorityEntries(meta.ID)
		dirs, _ := db.GetDiscoveredDirs(meta.ID)
		db.Close()

		sevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
		for _, v := range vulns {
			sev := strings.ToLower(v.Severity)
			if _, ok := sevCounts[sev]; ok {
				sevCounts[sev]++
			}
		}

		scanStatus := "idle"
		if status := h.scanMgr.GetStatus(targetName); status != nil {
			if s, ok := status["status"].(string); ok {
				scanStatus = s
			}
		}

		var duration *float64
		if meta.DurationSeconds != nil {
			duration = meta.DurationSeconds
		}

		targets = append(targets, map[string]any{
			"name":             targetName,
			"status":           meta.Status,
			"start_time":       meta.StartTime,
			"duration":         duration,
			"scan_status":      scanStatus,
			"total_subdomains": len(priority),
			"total_vulns":      len(vulns),
			"critical":         sevCounts["critical"],
			"high":             sevCounts["high"],
			"medium":           sevCounts["medium"],
			"low":              sevCounts["low"],
			"info":             sevCounts["info"],
			"total_dirs":       len(dirs),
		})
	}

	// If we found no targets but there are active scans, add them
	if len(targets) == 0 {
		activeScans := h.scanMgr.GetAllActiveScans()
		for _, scan := range activeScans {
			targets = append(targets, map[string]any{
				"name":        scan["target"],
				"status":      "running",
				"scan_status": "running",
			})
		}
	}

	writeJSON(w, 200, map[string]any{"targets": targets})
}

func (h *Handlers) GetTarget(w http.ResponseWriter, r *http.Request) {
	targetName, ok := requireTarget(w, r)
	if !ok {
		return
	}
	targetDir := h.cfg.TargetDir(targetName)

	dbPath := filepath.Join(targetDir, "scan.db")
	db, err := h.dbCache.Acquire(dbPath)
	if err != nil {
		writeError(w, 404, "Target not found")
		return
	}
	defer db.Close()

	meta, _ := db.GetScanByTarget(targetName)
	if meta == nil {
		writeError(w, 404, "Target not found")
		return
	}

	liveHosts, _ := db.GetLiveHosts(meta.ID)
	vulns, _ := db.GetVulnerabilities(meta.ID)
	crawledURLs, _ := db.GetCrawledURLs(meta.ID)
	dirs, _ := db.GetDiscoveredDirs(meta.ID)
	// Generate priority entries on demand if Phase 6 never ran (e.g. an
	// interrupted scan) so the priority list is never empty when there is
	// live-host data to score.
	h.ensurePriority(db, meta, targetName)
	priority, _ := db.GetPriorityEntries(meta.ID)
	headerResult, _ := db.GetHeaderResult(meta.ID)
	subs, _ := db.GetSubdomains(meta.ID)
	techDetections, _ := db.GetTechDetections(meta.ID)
	takeovers, _ := db.GetTakeoverResults(meta.ID)

	// Phase-1 advanced module results (ports, WAF, JS, params, secrets, findings).
	p1Findings, _ := db.GetP1Findings(meta.ID)
	p1Ports, _ := db.GetP1Ports(meta.ID)
	p1JSFiles, _ := db.GetP1JSFiles(meta.ID)
	p1JSFindings, _ := db.GetP1JSFindings(meta.ID)
	p1Params, _ := db.GetP1Params(meta.ID)
	p1Secrets, _ := db.GetP1Secrets(meta.ID)
	p1HostIntel, _ := db.GetP1HostIntel(meta.ID)
	p1Passive, _ := db.GetP1PassiveRecon(meta.ID)

	// Compute severity counts
	sevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, v := range vulns {
		sev := strings.ToLower(v.Severity)
		if _, ok := sevCounts[sev]; ok {
			sevCounts[sev]++
		}
	}

	writeJSON(w, 200, map[string]any{
		"meta":            meta,
		"headers":         headerResult,
		"subdomains":      subs,
		"live_subdomains": liveHosts,
		"vulnerabilities": map[string]any{
			"vulnerabilities":  vulns,
			"total_vulns":      len(vulns),
			"by_severity":      sevCounts,
			"takeover_results": takeovers,
		},
		"tech_detection":  techDetections,
		"missing_headers": parseMissingHeaders(headerResult),
		"urls_with_params": crawledURLs,
		"directories": map[string]any{
			"directories":      dirs,
			"total_discovered": len(dirs),
		},
		"priority_ranking": map[string]any{
			"priority_list": priority,
			"total_scored":  len(priority),
		},
		// Phase-1 advanced modules
		"phase1": map[string]any{
			"findings":     p1Findings,
			"ports":        p1Ports,
			"js_files":     p1JSFiles,
			"js_findings":  p1JSFindings,
			"params":       p1Params,
			"secrets":      p1Secrets,
			"host_intel":   p1HostIntel,
			"passive_recon": p1Passive,
			"total_findings": len(p1Findings),
			"total_ports":    len(p1Ports),
			"total_secrets":  len(p1Secrets),
			"total_params":   len(p1Params),
			"total_js_files": len(p1JSFiles),
		},
	})
}

func (h *Handlers) GetVulns(w http.ResponseWriter, r *http.Request) {
	targetName, ok := requireTarget(w, r)
	if !ok {
		return
	}
	targetDir := h.cfg.TargetDir(targetName)

	dbPath := filepath.Join(targetDir, "scan.db")
	db, err := h.dbCache.Acquire(dbPath)
	if err != nil {
		writeError(w, 404, "Target not found")
		return
	}
	defer db.Close()

	meta, _ := db.GetScanByTarget(targetName)
	if meta == nil {
		writeError(w, 404, "Target not found")
		return
	}

	vulns, _ := db.GetVulnerabilities(meta.ID)

	// Filter by severity
	severity := r.URL.Query().Get("severity")
	if severity != "" {
		sevList := strings.Split(severity, ",")
		var filtered []storage.Vulnerability
		for _, v := range vulns {
			for _, s := range sevList {
				if strings.EqualFold(v.Severity, strings.TrimSpace(s)) {
					filtered = append(filtered, v)
					break
				}
			}
		}
		vulns = filtered
	}

	// Search filter
	search := r.URL.Query().Get("search")
	if search != "" {
		q := strings.ToLower(search)
		var filtered []storage.Vulnerability
		for _, v := range vulns {
			if strings.Contains(strings.ToLower(v.Name), q) ||
				strings.Contains(strings.ToLower(v.Subdomain), q) ||
				strings.Contains(strings.ToLower(v.URL), q) {
				filtered = append(filtered, v)
			}
		}
		vulns = filtered
	}

	// Pagination
	page := 1
	limit := 50
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := parseInt(p); err == nil && v > 0 {
			page = v
		}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := parseInt(l); err == nil && v > 0 {
			limit = v
		}
	}

	total := len(vulns)
	start := (page - 1) * limit
	end := start + limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	paginated := vulns[start:end]

	totalPages := (total + limit - 1) / limit
	if totalPages == 0 {
		totalPages = 1
	}

	writeJSON(w, 200, map[string]any{
		"vulnerabilities": paginated,
		"total":           total,
		"page":            page,
		"limit":           limit,
		"total_pages":     totalPages,
	})
}

func (h *Handlers) GetPriority(w http.ResponseWriter, r *http.Request) {
	targetName, ok := requireTarget(w, r)
	if !ok {
		return
	}
	targetDir := h.cfg.TargetDir(targetName)

	dbPath := filepath.Join(targetDir, "scan.db")
	db, err := h.dbCache.Acquire(dbPath)
	if err != nil {
		writeError(w, 404, "Target not found")
		return
	}
	defer db.Close()

	meta, _ := db.GetScanByTarget(targetName)
	if meta == nil {
		writeError(w, 404, "Target not found")
		return
	}

	// Populate priority entries on demand for scans that never reached Phase 6,
	// so /api/target/{name}/priority always returns a usable ranking.
	h.ensurePriority(db, meta, targetName)

	priority, _ := db.GetPriorityEntries(meta.ID)
	writeJSON(w, 200, map[string]any{
		"target":        targetName,
		"total_scored":  len(priority),
		"priority_list": priority,
	})
}

func (h *Handlers) DeleteTarget(w http.ResponseWriter, r *http.Request) {
	targetName, ok := requireTarget(w, r)
	if !ok {
		return
	}
	targetDir := h.cfg.TargetDir(targetName)

	h.scanMgr.StopScan(targetName)

	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		writeError(w, 404, "Target not found")
		return
	}

	// Drop any cached read handle for this target before removing the file,
	// so we don't keep (or write through) a handle to a deleted DB.
	h.dbCache.Evict(filepath.Join(targetDir, "scan.db"))

	if err := os.RemoveAll(targetDir); err != nil {
		writeError(w, 500, err.Error())
		return
	}

	writeJSON(w, 200, map[string]string{"status": "deleted", "target": targetName})
}

func (h *Handlers) ExportCSV(w http.ResponseWriter, r *http.Request) {
	targetName, ok := requireTarget(w, r)
	if !ok {
		return
	}
	targetDir := h.cfg.TargetDir(targetName)

	dbPath := filepath.Join(targetDir, "scan.db")
	db, err := h.dbCache.Acquire(dbPath)
	if err != nil {
		writeError(w, 404, "Target not found")
		return
	}
	defer db.Close()

	meta, _ := db.GetScanByTarget(targetName)
	if meta == nil {
		writeError(w, 404, "Target not found")
		return
	}

	vulns, _ := db.GetVulnerabilities(meta.ID)

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename="+targetName+"_vulns.csv")

	writer := csv.NewWriter(w)
	writer.Write([]string{"Subdomain", "Severity", "Name", "Template ID", "Type", "URL", "Description"})

	for _, v := range vulns {
		tmplID := ""
		if v.TemplateID != nil {
			tmplID = *v.TemplateID
		}
		desc := ""
		if v.Description != nil {
			desc = *v.Description
		}
		writer.Write([]string{v.Subdomain, v.Severity, v.Name, tmplID, v.Type, v.URL, desc})
	}
	writer.Flush()
}

func parseInt(s string) (int, error) {
	return strconv.Atoi(s)
}

// ensurePriority generates priority entries on demand for a scan that has live
// hosts but no priority_entries yet — typically a scan interrupted before
// Phase 6 (priority scoring) ran. It is a no-op when entries already exist,
// when there are no live hosts to score, or while a scan is genuinely running
// (Phase 6 will populate the table itself, and racing it could duplicate
// rows). This makes the priority list usable immediately for stale/abandoned
// scans instead of showing an empty list.
func (h *Handlers) ensurePriority(db *storage.DB, meta *storage.ScanMeta, targetName string) {
	if meta == nil {
		return
	}
	// Serialize the fallback so two concurrent reads can't double-insert.
	h.priorityMu.Lock()
	defer h.priorityMu.Unlock()

	existing, _ := db.GetPriorityEntries(meta.ID)
	if len(existing) > 0 {
		return
	}
	live, _ := db.GetLiveHosts(meta.ID)
	if len(live) == 0 {
		return
	}
	// Never generate while the pipeline is still running for this target.
	for _, s := range h.scanMgr.GetAllActiveScans() {
		if s["target"] == targetName {
			return
		}
	}

	// Bind a config copy to this target and run the scoring engine, which
	// computes scores, persists priority_entries, and writes the ranking JSON
	// + Phase 2 handoff — exactly what Phase 6 does at scan time.
	cfg := *h.cfg
	cfg.Target = targetName
	scorer := scoring.New(&cfg, db, meta.ID)
	if _, err := scorer.Run(context.Background()); err != nil {
		logger.Err("on-demand priority scoring failed for %s: %v", targetName, err)
	}
}

// parseMissingHeaders safely extracts the missing security headers from a HeaderResult.
func parseMissingHeaders(h *storage.HeaderResult) []string {
	if h == nil || h.MissingSecurityHeaders == "" {
		return []string{}
	}
	var arr []string
	if err := json.Unmarshal([]byte(h.MissingSecurityHeaders), &arr); err != nil {
		return []string{}
	}
	return arr
}
