package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"

	"github.com/yourname/dark-recon/internal/storage"
)

// resolveScanDB opens the per-target scan database and returns it together
// with the scan metadata. Centralises the (target_name -> open db + meta)
// lookup that every phase-1 endpoint needs. Uses the shared DBCache so we
// don't re-open + re-migrate on every poll; callers Release (not Close) it.
func (h *Handlers) resolveScanDB(w http.ResponseWriter, r *http.Request) (*storage.DB, *storage.ScanMeta, bool) {
	targetName, ok := requireTarget(w, r)
	if !ok {
		return nil, nil, false
	}
	targetDir := h.cfg.TargetDir(targetName)
	dbPath := filepath.Join(targetDir, "scan.db")
	db, err := h.dbCache.Acquire(dbPath)
	if err != nil {
		writeError(w, 404, "Target not found")
		return nil, nil, false
	}
	meta, _ := db.GetScanByTarget(targetName)
	if meta == nil {
		h.dbCache.Release(dbPath)
		writeError(w, 404, "Target not found")
		return nil, nil, false
	}
	return db, meta, true
}

// parsePhases unmarshals the JSON phases_completed column into a set.
func parsePhases(meta *storage.ScanMeta) map[string]bool {
	set := make(map[string]bool)
	if meta == nil {
		return set
	}
	var arr []string
	if meta.PhasesCompleted != "" {
		_ = json.Unmarshal([]byte(meta.PhasesCompleted), &arr)
	}
	for _, p := range arr {
		set[p] = true
	}
	return set
}

// GetP1Findings returns the unified findings table (nmap/wafw00f/js/trufflehog/gitleaks).
func (h *Handlers) GetP1Findings(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	findings, _ := db.GetP1Findings(meta.ID)
	writeJSON(w, 200, map[string]any{"findings": findings, "count": len(findings)})
}

// GetP1Ports returns discovered open ports (nmap).
func (h *Handlers) GetP1Ports(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	ports, _ := db.GetP1Ports(meta.ID)
	writeJSON(w, 200, map[string]any{"ports": ports, "count": len(ports)})
}

// GetP1JSFiles returns crawled JS files and their extracted endpoints/secrets.
func (h *Handlers) GetP1JSFiles(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	files, _ := db.GetP1JSFiles(meta.ID)
	findings, _ := db.GetP1JSFindings(meta.ID)
	writeJSON(w, 200, map[string]any{"js_files": files, "js_findings": findings, "file_count": len(files), "finding_count": len(findings)})
}

// GetP1Params returns hidden parameters discovered by arjun.
func (h *Handlers) GetP1Params(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	params, _ := db.GetP1Params(meta.ID)
	writeJSON(w, 200, map[string]any{"params": params, "count": len(params)})
}

// GetP1Secrets returns secrets found by trufflehog + gitleaks.
func (h *Handlers) GetP1Secrets(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	secrets, _ := db.GetP1Secrets(meta.ID)
	writeJSON(w, 200, map[string]any{"secrets": secrets, "count": len(secrets)})
}

// GetP1WAF returns WAF detection results per host (wafw00f).
func (h *Handlers) GetP1WAF(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	intel, _ := db.GetP1HostIntel(meta.ID)
	writeJSON(w, 200, map[string]any{"intel": intel, "count": len(intel)})
}

// GetP1Intel returns the aggregated per-host intel (ports/params/secrets/js/waf).
func (h *Handlers) GetP1Intel(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	intel, _ := db.GetP1HostIntel(meta.ID)
	passive, _ := db.GetP1PassiveRecon(meta.ID)
	writeJSON(w, 200, map[string]any{"host_intel": intel, "passive_recon": passive, "host_count": len(intel)})
}

// GetPhase1Status reports whether phase 1 has completed for a target.
func (h *Handlers) GetPhase1Status(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	phaseSet := parsePhases(meta)
	var phases []string
	_ = json.Unmarshal([]byte(meta.PhasesCompleted), &phases)
	complete := phaseSet["phase1_complete"] || meta.Status == "completed"
	writeJSON(w, 200, map[string]any{
		"phase1_complete":  complete,
		"completed_phases": phases,
		"scan_status":      meta.Status,
	})
}

// ── Phase 2 foundation (stubs) ────────────────────────────────────────
// These endpoints exist now so the UI can show a "Start Phase 2" affordance
// once Phase 1 is complete. The actual Phase 2 workflow is added later.

// StartPhase2 is a stub that records intent to start Phase 2. It validates
// Phase 1 completion and returns a placeholder session descriptor.
func (h *Handlers) StartPhase2(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	phaseSet := parsePhases(meta)
	if !phaseSet["phase1_complete"] && meta.Status != "completed" {
		writeError(w, 409, "Phase 1 has not completed yet for this target")
		return
	}
	// Phase 2 is not yet implemented — acknowledge the request with a stub.
	writeJSON(w, 202, map[string]any{
		"status":  "accepted",
		"message": "Phase 2 workflow is not yet implemented (foundation only)",
		"target":  r.PathValue("target_name"),
		"scan_id": meta.ID,
	})
}

// GetPhase2Status reports Phase 2 readiness.
func (h *Handlers) GetPhase2Status(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	phaseSet := parsePhases(meta)
	ready := phaseSet["phase1_complete"] || meta.Status == "completed"
	writeJSON(w, 200, map[string]any{
		"phase2_ready":    ready,
		"phase2_started":  false,
		"phase2_complete": false,
	})
}
