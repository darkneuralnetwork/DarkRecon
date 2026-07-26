package config

import "testing"

// TestIsPhaseEnabled_RunAllWhenUnset verifies the legacy behaviour: when no
// opt-in selection is provided, every phase is enabled (run the whole
// pipeline).
func TestIsPhaseEnabled_RunAllWhenUnset(t *testing.T) {
	cfg := &Config{}
	for _, p := range []string{
		PhaseSubdomainEnum, PhasePassiveRecon, PhaseLiveCheck, PhaseTechDetection,
		PhaseEarlyCrawling, PhaseVulnScan, PhaseTakeover, PhaseWAFDetect,
		PhasePortScan, PhaseJSAnalysis, PhaseParamDiscovery, PhaseSecretScan,
		PhasePriorityScoring,
	} {
		if !cfg.IsPhaseEnabled(p) {
			t.Fatalf("expected %s enabled when RunPhases unset", p)
		}
	}
}

// TestIsPhaseEnabled_OptIn verifies that when an opt-in selection is provided,
// only the listed phases are enabled — the basis for per-phase customisation.
func TestIsPhaseEnabled_OptIn(t *testing.T) {
	cfg := &Config{RunPhases: map[string]bool{
		PhasePortScan:      true,
		PhaseSubdomainEnum: true,
	}}
	if !cfg.IsPhaseEnabled(PhasePortScan) {
		t.Fatal("port_scan should be enabled")
	}
	if !cfg.IsPhaseEnabled(PhaseSubdomainEnum) {
		t.Fatal("subdomain_enum should be enabled")
	}
	if cfg.IsPhaseEnabled(PhaseVulnScan) {
		t.Fatal("vuln_scan should be DISABLED (not selected)")
	}
	if cfg.IsPhaseEnabled(PhasePriorityScoring) {
		t.Fatal("priority_scoring should be DISABLED (not selected)")
	}
}

// TestAsStringSet verifies the JSON-array and map shapes the UI sends both
// resolve to a usable opt-in set.
func TestAsStringSet(t *testing.T) {
	// JSON array of strings arrives as []any.
	s := asStringSet([]any{"port_scan", "subdomain_enum"})
	if !s["port_scan"] || !s["subdomain_enum"] || s["vuln_scan"] {
		t.Fatalf("array coercion wrong: %v", s)
	}
	// Native []string.
	s2 := asStringSet([]string{"waf_detect"})
	if !s2["waf_detect"] || len(s2) != 1 {
		t.Fatalf("[]string coercion wrong: %v", s2)
	}
	// Empty values are ignored.
	s3 := asStringSet([]any{"", "port_scan"})
	if len(s3) != 1 || !s3["port_scan"] {
		t.Fatalf("empty-value handling wrong: %v", s3)
	}
}

// TestLoadRunPhasesOverride verifies the full API→config flow: a run_phases
// override (as the UI sends it, a JSON []any of names) populates RunPhases and
// syncs the Phase-1 module toggles so the engine and module-internal checks
// agree. This is what makes a per-scan opt-in selection actually take effect.
func TestLoadRunPhasesOverride(t *testing.T) {
	cfg, err := Load("", map[string]any{
		"run_phases": []any{"port_scan", "subdomain_enum"},
	})
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !cfg.RunPhases[PhasePortScan] || !cfg.RunPhases[PhaseSubdomainEnum] {
		t.Fatalf("RunPhases not populated: %v", cfg.RunPhases)
	}
	if cfg.RunPhases[PhaseVulnScan] {
		t.Fatal("vuln_scan should not be in RunPhases")
	}
	// Sync: port_scan on, js_analysis off (default-on but not selected).
	if !cfg.Phase1.PortScan {
		t.Fatal("Phase1.PortScan should be synced to true")
	}
	if cfg.Phase1.JSAnalysis {
		t.Fatal("Phase1.JSAnalysis should be synced to false (not selected)")
	}
	if !cfg.IsPhaseEnabled(PhasePortScan) {
		t.Fatal("IsPhaseEnabled(port_scan) should be true")
	}
	if cfg.IsPhaseEnabled(PhaseJSAnalysis) {
		t.Fatal("IsPhaseEnabled(js_analysis) should be false")
	}
}

// TestLoadNoRunPhasesRunsAll verifies that without a run_phases override the
// config keeps the legacy "run all" semantics and the default module toggles
// (e.g. JSAnalysis on) are preserved.
func TestLoadNoRunPhasesRunsAll(t *testing.T) {
	cfg, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfg.RunPhases) != 0 {
		t.Fatalf("RunPhases should be empty, got %v", cfg.RunPhases)
	}
	if !cfg.IsPhaseEnabled(PhaseVulnScan) || !cfg.IsPhaseEnabled(PhasePortScan) {
		t.Fatal("every phase should be enabled when RunPhases unset")
	}
	if !cfg.Phase1.JSAnalysis {
		t.Fatal("default JSAnalysis should remain on when no selection given")
	}
}
