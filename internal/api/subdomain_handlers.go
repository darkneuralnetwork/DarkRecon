package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"

	"github.com/yourname/dark-recon/internal/storage"
)

// GetSubdomainDetail returns all data for a specific subdomain within a target.
func (h *Handlers) GetSubdomainDetail(w http.ResponseWriter, r *http.Request) {
	targetName, ok := requireTarget(w, r)
	if !ok {
		return
	}
	subdomain := r.PathValue("subdomain")
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

	// Fetch all data and filter by subdomain
	liveHosts, _ := db.GetLiveHosts(meta.ID)
	allVulns, _ := db.GetVulnerabilities(meta.ID)
	crawledURLs, _ := db.GetCrawledURLs(meta.ID)
	dirs, _ := db.GetDiscoveredDirs(meta.ID)
	priority, _ := db.GetPriorityEntries(meta.ID)
	takeovers, _ := db.GetTakeoverResults(meta.ID)

	// Find the live host info for this subdomain
	var info *storage.LiveHost
	for i := range liveHosts {
		if liveHosts[i].Subdomain == subdomain {
			info = &liveHosts[i]
			break
		}
	}

	// Filter vulnerabilities
	var vulns []storage.Vulnerability
	for _, v := range allVulns {
		if v.Subdomain == subdomain {
			vulns = append(vulns, v)
		}
	}

	// Filter takeover results
	var takeover []storage.TakeoverResult
	for _, t := range takeovers {
		if t.Subdomain == subdomain {
			takeover = append(takeover, t)
		}
	}

	// Filter crawled URLs with params
	var paramURLs []map[string]any
	for _, u := range crawledURLs {
		if u.Subdomain == subdomain && u.HasParams {
			var params []string
			if u.ParamNames != "" {
				_ = json.Unmarshal([]byte(u.ParamNames), &params)
			}
			paramURLs = append(paramURLs, map[string]any{
				"url":         u.URL,
				"method":      "GET",
				"param_names": params,
			})
		}
	}

	// Filter discovered dirs
	var subDirs []storage.DiscoveredDir
	for _, d := range dirs {
		if d.Subdomain == subdomain {
			subDirs = append(subDirs, d)
		}
	}

	// Find priority entry for this subdomain
	var priEntry *storage.PriorityEntry
	for i := range priority {
		if priority[i].Subdomain == subdomain {
			priEntry = &priority[i]
			break
		}
	}

	// Build priority data with parsed JSON fields
	var priData map[string]any
	if priEntry != nil {
		priData = map[string]any{
			"priority_score":       priEntry.PriorityScore,
			"rank":                 priEntry.Rank,
			"reasons":              parseJSONArr(priEntry.Reasons),
			"tech_stack":           parseJSONArr(priEntry.TechStack),
			"vulnerabilities":      parseJSONArr(priEntry.Vulnerabilities),
			"missing_headers":      parseJSONArr(priEntry.MissingHeaders),
			"suggested_manual_tests": parseJSONArr(priEntry.SuggestedTests),
			"takeover_vulnerable":  priEntry.TakeoverVulnerable,
		}
	}

	writeJSON(w, 200, map[string]any{
		"target":        targetName,
		"subdomain":     subdomain,
		"info":          info,
		"priority":      priData,
		"vulnerabilities": vulns,
		"takeover":      takeover,
		"param_urls":    paramURLs,
		"directories":   subDirs,
	})
}

func parseJSONArr(s string) []any {
	if s == "" {
		return []any{}
	}
	var arr []any
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		return []any{}
	}
	return arr
}
