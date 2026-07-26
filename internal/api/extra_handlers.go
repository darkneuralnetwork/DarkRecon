package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
)

// GetHandoff returns the phase2 handoff JSON for a target.
func (h *Handlers) GetHandoff(w http.ResponseWriter, r *http.Request) {
	targetName, ok := requireTarget(w, r)
	if !ok {
		return
	}
	handoffPath := filepath.Join(h.cfg.PriorityDir(targetName), "phase2_handoff.json")

	data, err := os.ReadFile(handoffPath)
	if err != nil {
		// Generate handoff on-the-fly from DB
		h.generateHandoffResponse(w, r, targetName)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *Handlers) generateHandoffResponse(w http.ResponseWriter, r *http.Request, targetName string) {
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
	priority, _ := db.GetPriorityEntries(meta.ID)
	crawledURLs, _ := db.GetCrawledURLs(meta.ID)

	var paramURLs []map[string]any
	for _, u := range crawledURLs {
		if u.HasParams {
			var params []string
			_ = json.Unmarshal([]byte(u.ParamNames), &params)
			paramURLs = append(paramURLs, map[string]any{
				"url":       u.URL,
				"subdomain": u.Subdomain,
				"params":    params,
			})
		}
	}

	writeJSON(w, 200, map[string]any{
		"target":               targetName,
		"total_subdomains":     len(liveHosts),
		"total_vulnerabilities": len(vulns),
		"priority_targets":     priority,
		"all_urls_with_params": paramURLs,
	})
}

// BulkDeleteTargets deletes multiple targets at once.
func (h *Handlers) BulkDeleteTargets(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Targets []string `json:"targets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "Invalid request body")
		return
	}

	type result struct {
		Target string `json:"target"`
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	}
	var results []result

	for _, targetName := range req.Targets {
		h.scanMgr.StopScan(targetName)
		targetDir := h.cfg.TargetDir(targetName)
		if _, err := os.Stat(targetDir); os.IsNotExist(err) {
			results = append(results, result{Target: targetName, Status: "error", Error: "not found"})
			continue
		}
		h.dbCache.Evict(filepath.Join(targetDir, "scan.db"))
		if err := os.RemoveAll(targetDir); err != nil {
			results = append(results, result{Target: targetName, Status: "error", Error: err.Error()})
			continue
		}
		results = append(results, result{Target: targetName, Status: "deleted"})
	}

	writeJSON(w, 200, map[string]any{"results": results})
}

// GetExport returns all target data as JSON (for the export button).
func (h *Handlers) GetExport(w http.ResponseWriter, r *http.Request) {
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
	priority, _ := db.GetPriorityEntries(meta.ID)
	subs, _ := db.GetSubdomains(meta.ID)

	writeJSON(w, 200, map[string]any{
		"target":          targetName,
		"meta":            meta,
		"subdomains":      subs,
		"live_hosts":      liveHosts,
		"vulnerabilities": vulns,
		"crawled_urls":    crawledURLs,
		"directories":     dirs,
		"priority":        priority,
	})
}
