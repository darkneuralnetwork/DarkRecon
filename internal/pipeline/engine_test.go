package pipeline

import (
	"testing"

	"github.com/yourname/dark-recon/internal/config"
)

// newTestEngine builds an Engine bound only to a config (no DB/tools), enough
// to exercise the pure gating predicates shouldRun and requiredTools.
func newTestEngine(t *testing.T, runPhases map[string]bool) *Engine {
	t.Helper()
	return &Engine{cfg: &config.Config{RunPhases: runPhases}}
}

// TestShouldRun_RunAllWhenNoSelection verifies the legacy behaviour: with no
// opt-in selection every phase runs.
func TestShouldRun_RunAllWhenNoSelection(t *testing.T) {
	e := newTestEngine(t, nil)
	for _, p := range []struct {
		name string
		num  int
	}{
		{config.PhaseSubdomainEnum, 1}, {config.PhaseLiveCheck, 2},
		{config.PhaseTechDetection, 3}, {config.PhaseEarlyCrawling, 4},
		{config.PhaseVulnScan, 5}, {config.PhasePriorityScoring, 6},
		{config.PhasePortScan, 0}, {config.PhaseWAFDetect, 0},
	} {
		if !e.shouldRun(p.name, p.num) {
			t.Fatalf("expected %s to run with no selection", p.name)
		}
	}
}

// TestShouldRun_OptInOnlySelected verifies the opt-in gate: only listed phases
// run; everything else is suppressed. This is the basis for "run only port
// scan" / "only subdomain enumeration" customisation.
func TestShouldRun_OptInOnlySelected(t *testing.T) {
	e := newTestEngine(t, map[string]bool{
		config.PhasePortScan:      true,
		config.PhaseSubdomainEnum: true,
	})
	if !e.shouldRun(config.PhasePortScan, 0) {
		t.Fatal("port_scan should run (selected)")
	}
	if !e.shouldRun(config.PhaseSubdomainEnum, 1) {
		t.Fatal("subdomain_enum should run (selected)")
	}
	if e.shouldRun(config.PhaseVulnScan, 5) {
		t.Fatal("vuln_scan should NOT run (not selected)")
	}
	if e.shouldRun(config.PhasePriorityScoring, 6) {
		t.Fatal("priority_scoring should NOT run (not selected)")
	}
}

// TestShouldRun_SkipPhasesStillHonoured verifies the legacy opt-out
// (cfg.SkipPhases) still disables a phase even when no opt-in selection is
// set, preserving backward compatibility for existing API callers.
func TestShouldRun_SkipPhasesStillHonoured(t *testing.T) {
	e := &Engine{cfg: &config.Config{SkipPhases: []int{5}}}
	if e.shouldRun(config.PhaseVulnScan, 5) {
		t.Fatal("vuln_scan (phase 5) should be skipped via skip_phases")
	}
	if !e.shouldRun(config.PhaseSubdomainEnum, 1) {
		t.Fatal("subdomain_enum (phase 1) should still run")
	}
}

// TestRequiredTools_PhaseAware verifies a narrow selection only requires the
// tools for the selected phases — so "only subdomain enumeration" doesn't try
// to install nuclei/katana/subzy and fail.
func TestRequiredTools_PhaseAware(t *testing.T) {
	// Only subdomain enumeration.
	e := newTestEngine(t, map[string]bool{config.PhaseSubdomainEnum: true})
	tools := e.requiredTools()
	if !contains(tools, "subfinder") || !contains(tools, "ffuf") {
		t.Fatalf("enum-only should require subfinder+ffuf, got %v", tools)
	}
	if contains(tools, "nuclei") || contains(tools, "katana") || contains(tools, "subzy") {
		t.Fatalf("enum-only should NOT require nuclei/katana/subzy, got %v", tools)
	}

	// Only nuclei.
	e2 := newTestEngine(t, map[string]bool{config.PhaseVulnScan: true})
	tools2 := e2.requiredTools()
	if !contains(tools2, "nuclei") {
		t.Fatalf("vuln-only should require nuclei, got %v", tools2)
	}
	if contains(tools2, "subfinder") {
		t.Fatalf("vuln-only should NOT require subfinder, got %v", tools2)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestGroupABSlots_NoLiveHostsZero is the regression test for the deadlock
// that made "only WAF" (or any host-dependent-only selection) hang forever at
// "running" on a target with no live hosts. The drain loop waits on exactly
// groupABSlots signals, so when there are no live hosts it MUST be 0 — a
// selected-but-skipped module must not reserve a slot it never signals.
func TestGroupABSlots_NoLiveHostsZero(t *testing.T) {
	if got := groupABSlots(true, true, true, true, false); got != 0 {
		t.Fatalf("with no live hosts, slots must be 0 (got %d) — otherwise the drain loop deadlocks", got)
	}
	// The exact scenario from the bug report: only WAF selected, no live hosts.
	if got := groupABSlots(false, false, true, false, false); got != 0 {
		t.Fatalf("only-WAF with no live hosts must be 0 slots (got %d)", got)
	}
}

// TestGroupABSlots_WithLiveHostsCountsSelected verifies that with live hosts
// present, each selected module reserves exactly one drain slot.
func TestGroupABSlots_WithLiveHostsCountsSelected(t *testing.T) {
	if got := groupABSlots(true, true, true, true, true); got != 4 {
		t.Fatalf("all selected with live hosts: expected 4 slots, got %d", got)
	}
	if got := groupABSlots(false, false, true, false, true); got != 1 {
		t.Fatalf("only WAF with live hosts: expected 1 slot, got %d", got)
	}
	if got := groupABSlots(false, false, false, false, true); got != 0 {
		t.Fatalf("nothing selected with live hosts: expected 0 slots, got %d", got)
	}
}
