package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// GetDashboardSummary aggregates scan results across every target on disk
// into a single payload the dashboard can render in one round-trip:
//
//   - global severity counts (critical/high/medium/low/info) and totals
//   - a per-target summary (name, status, vuln counts, last scan time)
//   - the most recent CVE-tagged findings across all targets, newest first
//
// It reuses the per-target DB cache (read-only) and tolerates any single
// target's DB being missing/corrupt — that target is simply skipped so one
// bad scan never blanks the whole dashboard.
func (h *Handlers) GetDashboardSummary(w http.ResponseWriter, r *http.Request) {
	resultsDir := h.cfg.OutputDir
	entries, err := os.ReadDir(resultsDir)

	// Aggregate accumulators.
	sev := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	var totalVulns, totalSubdomains, totalLiveHosts, totalSecrets, totalOpenPorts int
	secretsByTool := map[string]int{}
	secretsByType := map[string]int{}
	portsByNumber := map[string]int{} // "80/tcp" -> host count, for the graph
	var targetSummaries []map[string]any
	var latestCVEs []map[string]any
	var latestSecrets []map[string]any
	var latestPorts []map[string]any

	// Always include active (running) scans even before they have a DB row,
	// so the dashboard reflects in-flight work immediately.
	activeStatus := map[string]string{}
	for _, scan := range h.scanMgr.GetAllActiveScans() {
		if t, ok := scan["target"]; ok {
			activeStatus[t] = "running"
		}
	}

	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			targetName := entry.Name()
			targetDir := filepath.Join(resultsDir, targetName)
			dbPath := filepath.Join(targetDir, "scan.db")

			db, err := h.dbCache.Acquire(dbPath)
			if err != nil {
				targetSummaries = append(targetSummaries, baseTargetSummary(targetName, "unknown", activeStatus))
				continue
			}

			meta, _ := db.GetScanByTarget(targetName)
			if meta == nil {
				// No completed scan record yet — maybe still running.
				st := "unknown"
				if s, ok := activeStatus[targetName]; ok {
					st = s
				} else if status := h.scanMgr.GetStatus(targetName); status != nil {
					if sv, ok := status["status"].(string); ok && sv != "" {
						st = sv
					}
				}
				targetSummaries = append(targetSummaries, baseTargetSummary(targetName, st, activeStatus))
				db.Close()
				continue
			}

			vulns, _ := db.GetVulnerabilities(meta.ID)
			// Generate priority entries on demand for scans interrupted before
			// Phase 6, so the dashboard's subdomain/priority counts are never
			// blank for a target that has live-host data.
			h.ensurePriority(db, meta, targetName)
			priority, _ := db.GetPriorityEntries(meta.ID)
			liveHosts, _ := db.GetLiveHosts(meta.ID)
			dirs, _ := db.GetDiscoveredDirs(meta.ID)
			secrets, _ := db.GetP1Secrets(meta.ID)
			ports, _ := db.GetP1Ports(meta.ID)
			db.Close()

			tSev := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
			for _, v := range vulns {
				s := strings.ToLower(v.Severity)
				if _, ok := tSev[s]; ok {
					tSev[s]++
				}
			}
			for k, v := range tSev {
				sev[k] += v
			}
			totalVulns += len(vulns)
			totalSubdomains += len(priority)
			totalLiveHosts += len(liveHosts)
			totalSecrets += len(secrets)
			totalOpenPorts += len(ports)
			for _, s := range secrets {
				if s.Tool != "" {
					secretsByTool[s.Tool]++
				}
				if s.SecretType != "" {
					secretsByType[s.SecretType]++
				}
			}

			scanStatus := meta.Status
			if s, ok := activeStatus[targetName]; ok {
				scanStatus = s
			}

			// Collect CVE-tagged findings from this target for the global
			// "latest CVE" feed. A single vuln may carry multiple CVE ids.
			for _, v := range vulns {
				cves := parseCVEIDs(v.CVEIDs)
				if len(cves) == 0 {
					continue
				}
				for _, cve := range cves {
					latestCVEs = append(latestCVEs, map[string]any{
						"cve":       cve,
						"target":    targetName,
						"severity":  strings.ToLower(v.Severity),
						"name":      v.Name,
						"url":       v.URL,
						"subdomain": v.Subdomain,
						"vuln_id":   v.ID,
						"scan_id":   meta.ID,
					})
				}
			}

			// Collect leaked secrets for the global "sensitive summary" feed.
			for _, s := range secrets {
				raw := s.RawMatch
				if len(raw) > 80 {
					raw = raw[:80] + "..."
				}
				sub := ""
				if s.Subdomain != nil {
					sub = *s.Subdomain
				}
				src := ""
				if s.SourceURL != nil {
					src = *s.SourceURL
				}
				latestSecrets = append(latestSecrets, map[string]any{
					"target":      targetName,
					"subdomain":   sub,
					"tool":        s.Tool,
					"secret_type": s.SecretType,
					"source_url":  src,
					"raw_match":   raw,
					"secret_id":   s.ID,
				})
			}

			// Collect open ports for the global "open ports" feed + graph. A
			// port is aggregated per (port,protocol) for the frequency graph and
			// also emitted as a latest-ports row so the dashboard can list every
			// host:port discovered across all targets.
			for _, p := range ports {
				key := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
				portsByNumber[key]++
				svc := ""
				if p.Service != nil {
					svc = *p.Service
				}
				latestPorts = append(latestPorts, map[string]any{
					"target":    targetName,
					"subdomain": p.Subdomain,
					"port":      p.Port,
					"protocol":  p.Protocol,
					"service":   svc,
					"port_id":   p.ID,
				})
			}

			targetSummaries = append(targetSummaries, map[string]any{
				"name":             targetName,
				"status":           meta.Status,
				"scan_status":      scanStatus,
				"start_time":       meta.StartTime,
				"total_vulns":      len(vulns),
				"critical":         tSev["critical"],
				"high":             tSev["high"],
				"medium":           tSev["medium"],
				"low":              tSev["low"],
				"info":             tSev["info"],
				"total_subdomains": len(priority),
				"total_live":       len(liveHosts),
				"total_dirs":       len(dirs),
				"total_secrets":    len(secrets),
				"total_ports":      len(ports),
			})
		}
	}

	// Sort the CVE feed newest-first by vuln id (monotonic with insert order,
	// since the dashboard has no per-finding timestamp). Stable so ties keep
	// their disk order.
	sort.SliceStable(latestCVEs, func(i, j int) bool {
		ci, _ := latestCVEs[i]["vuln_id"].(int64)
		cj, _ := latestCVEs[j]["vuln_id"].(int64)
		return ci > cj
	})
	if len(latestCVEs) > 12 {
		latestCVEs = latestCVEs[:12]
	}

	// Newest secrets first by id (monotonic with insert order). Capped so the
	// dashboard payload stays small even on secret-heavy scans.
	sort.SliceStable(latestSecrets, func(i, j int) bool {
		ci, _ := latestSecrets[i]["secret_id"].(int64)
		cj, _ := latestSecrets[j]["secret_id"].(int64)
		return ci > cj
	})
	if len(latestSecrets) > 12 {
		latestSecrets = latestSecrets[:12]
	}

	// Newest open ports first by id (monotonic with insert order). Capped so
	// the dashboard payload stays small on port-heavy scans; the full per-host
	// breakdown remains available on the target detail page.
	sort.SliceStable(latestPorts, func(i, j int) bool {
		ci, _ := latestPorts[i]["port_id"].(int64)
		cj, _ := latestPorts[j]["port_id"].(int64)
		return ci > cj
	})
	if len(latestPorts) > 12 {
		latestPorts = latestPorts[:12]
	}

	// Newest targets first (by start time desc); running scans float to top.
	sort.SliceStable(targetSummaries, func(i, j int) bool {
		ri := targetRunningScore(targetSummaries[i])
		rj := targetRunningScore(targetSummaries[j])
		if ri != rj {
			return ri > rj
		}
		return startTimeOf(targetSummaries[i]).After(startTimeOf(targetSummaries[j]))
	})

	totalTargets := len(targetSummaries)
	// Percentage share of each severity vs. the total vuln count (0 when none).
	pct := map[string]float64{}
	for k, v := range sev {
		if totalVulns > 0 {
			pct[k] = round2(float64(v) * 100.0 / float64(totalVulns))
		} else {
			pct[k] = 0
		}
	}

	writeJSON(w, 200, map[string]any{
		"totals": map[string]any{
			"targets":         totalTargets,
			"vulnerabilities": totalVulns,
			"subdomains":      totalSubdomains,
			"live_hosts":      totalLiveHosts,
			"secrets":         totalSecrets,
			"open_ports":      totalOpenPorts,
			"by_severity":     sev,
		},
		"percentages":     pct,
		"targets":         targetSummaries,
		"latest_cves":     latestCVEs,
		"latest_secrets":  latestSecrets,
		"latest_ports":    latestPorts,
		"ports_by_number": portsByNumber,
		"secrets_by_tool": secretsByTool,
		"secrets_by_type": secretsByType,
		"severity_order":  []string{"critical", "high", "medium", "low", "info"},
	})
}

// baseTargetSummary renders a minimal target entry for targets whose DB isn't
// available yet (running scan with no row, or a corrupt/unreadable DB). The
// active map supplies the running flag so the UI can badge it.
func baseTargetSummary(name, status string, active map[string]string) map[string]any {
	scanStatus := status
	if s, ok := active[name]; ok {
		scanStatus = s
	}
	return map[string]any{
		"name":        name,
		"status":      status,
		"scan_status": scanStatus,
		"total_vulns": 0,
		"critical":    0, "high": 0, "medium": 0, "low": 0, "info": 0,
		"total_subdomains": 0, "total_live": 0, "total_dirs": 0, "total_secrets": 0, "total_ports": 0,
	}
}

// targetRunningScore ranks running scans above everything else so they float
// to the top of the side list.
func targetRunningScore(t map[string]any) int {
	if s, ok := t["scan_status"].(string); ok && s == "running" {
		return 1
	}
	return 0
}

// startTimeOf extracts the start_time from a target summary map as a
// time.Time. storage.ScanMeta.StartTime is a time.Time, but it round-trips
// through the empty-interface map as that concrete type; anything else (nil,
// string) falls back to the zero time so it sorts oldest.
func startTimeOf(t map[string]any) time.Time {
	if v, ok := t["start_time"]; ok {
		if tt, ok := v.(time.Time); ok {
			return tt
		}
	}
	return time.Time{}
}

// parseCVEIDs decodes the JSON array string stored on Vulnerability.CVEIDs
// (e.g. `["CVE-2021-44228"]`) into a slice of CVE ids. A non-JSON / empty
// value yields an empty slice — never an error — so a malformed row just
// drops out of the CVE feed instead of failing the whole dashboard.
func parseCVEIDs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	// Some importers store a bare comma-separated list rather than JSON; handle
	// both so we never miss a CVE.
	if !strings.HasPrefix(raw, "[") {
		parts := strings.Split(raw, ",")
		var out []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	var arr []string
	if err := json.Unmarshal([]byte(raw), &arr); err != nil {
		return nil
	}
	var out []string
	for _, p := range arr {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// round2 rounds to 2 decimal places for clean percentage display.
func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100.0
}
