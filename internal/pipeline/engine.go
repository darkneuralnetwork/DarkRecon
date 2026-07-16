package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yourname/dark-recon/internal/config"
	"github.com/yourname/dark-recon/internal/discovery"
	"github.com/yourname/dark-recon/internal/enumeration"
	"github.com/yourname/dark-recon/internal/installer"
	"github.com/yourname/dark-recon/internal/nuclei"
	"github.com/yourname/dark-recon/internal/phasemod"
	"github.com/yourname/dark-recon/internal/scoring"
	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/internal/takeover"
	"github.com/yourname/dark-recon/internal/technology"
	"github.com/yourname/dark-recon/pkg/logger"
)

// ProgressCallback is called after each phase completes.
type ProgressCallback func(data map[string]any)

// Engine orchestrates the full scan pipeline.
//
// NEW PIPELINE (Go):
//   1. Subdomain Enumeration (subfinder + ffuf DNS + DNS brute, parallel)
//   2. Live Host Detection (httpx)
//   3. Technology Detection (headers + webanalyze) — parallel with 4
//   4. Deep Crawling (Katana headless, active) — parallel with 3, runs on ALL live hosts
//   5. Nuclei + Subzy Scanning (parallel; Nuclei gets Katana URLs as input)
//   6. Priority Scoring Engine
type Engine struct {
	cfg      *config.Config
	db       *storage.DB
	scanID   int64
	progress ProgressCallback
}

// New creates a new scan pipeline engine.
func New(cfg *config.Config, db *storage.DB, scanID int64) *Engine {
	return &Engine{cfg: cfg, db: db, scanID: scanID}
}

// SetProgressCallback sets the callback for progress updates.
func (e *Engine) SetProgressCallback(cb ProgressCallback) {
	e.progress = cb
}

func (e *Engine) emit(data map[string]any) {
	if e.progress != nil {
		e.progress(data)
	}
}

// requiredTools returns the external binaries the selected phases need,
// honouring the opt-in RunPhases selection (and legacy SkipPhases). This keeps
// a narrow scan from trying to install unrelated tools and failing. A tool
// that's already installed is a cheap no-op in the installer.
func (e *Engine) requiredTools() []string {
	var tools []string
	if e.shouldRun(config.PhaseSubdomainEnum, 1) {
		tools = append(tools, "subfinder", "ffuf")
	}
	if e.shouldRun(config.PhaseLiveCheck, 2) {
		tools = append(tools, "httpx")
	}
	if e.shouldRun(config.PhaseTechDetection, 3) {
		tools = append(tools, "httpx") // webanalyze is optional; headers via httpx
	}
	if e.shouldRun(config.PhaseEarlyCrawling, 4) {
		tools = append(tools, "katana")
	}
	if e.shouldRun(config.PhaseVulnScan, 5) {
		tools = append(tools, "nuclei")
	}
	if e.shouldRun(config.PhaseTakeover, 5) {
		tools = append(tools, "subzy")
	}
	return tools
}

// shouldRun is the unified per-phase gate. It returns false when:
//   - the phase's legacy number is in cfg.SkipPhases (opt-out), OR
//   - an opt-in RunPhases selection is set and the phase isn't in it.
//
// `num` is 0 for the optional sub-modules (passive_recon, waf_detect,
// port_scan, js_analysis, param_discovery, secret_scan) which have no phase
// number of their own; for everything else it maps to the README phase number.
// When RunPhases is empty (no opt-in selection) only SkipPhases can disable a
// phase, preserving the legacy "run the whole pipeline" behaviour.
func (e *Engine) shouldRun(name string, num int) bool {
	if num > 0 {
		for _, s := range e.cfg.SkipPhases {
			if s == num {
				return false
			}
		}
	}
	if len(e.cfg.RunPhases) > 0 {
		return e.cfg.RunPhases[name]
	}
	return true
}

// ensureInputFiles regenerates the on-disk bridge files (subdomains.txt,
// live_subdomains.txt) from the DB for the current scan. Downstream tools
// (nuclei, subzy) read these files rather than the DB, so they must exist
// regardless of whether live hosts came from a fresh httpx run or were reused
// from a prior scan. Missing/empty results are written as empty files.
func (e *Engine) ensureInputFiles() {
	parsedDir := e.cfg.ParsedDir(e.cfg.Target)
	if subs, err := e.db.GetSubdomains(e.scanID); err == nil {
		var names []string
		for _, s := range subs {
			names = append(names, s.Subdomain)
		}
		_ = os.WriteFile(filepath.Join(parsedDir, "subdomains.txt"), []byte(strings.Join(names, "\n")), 0644)
	}
	if live, err := e.db.GetLiveHosts(e.scanID); err == nil {
		var urls []string
		for _, h := range live {
			urls = append(urls, h.URL)
		}
		_ = os.WriteFile(filepath.Join(parsedDir, "live_subdomains.txt"), []byte(strings.Join(urls, "\n")), 0644)
	}
}

// reuseSubdomainsFromPrior copies subdomains from the most recent prior scan
// of this target into the current scan when the current scan has none (i.e.
// subdomain enumeration was not selected). Returns the number reused. This is
// what lets a downstream-only selection (e.g. "only port scan") run standalone
// against a target that has already been enumerated.
func (e *Engine) reuseSubdomainsFromPrior() int {
	priorID, ok := e.db.GetPriorScanIDWithData(e.cfg.Target, "subdomains", e.scanID)
	if !ok {
		return 0
	}
	n, err := e.db.ReuseSubdomains(e.scanID, priorID)
	if err != nil || n == 0 {
		return 0
	}
	logger.Success("Reusing %d subdomains from prior scan #%d", n, priorID)
	e.emit(map[string]any{"phase": "reuse", "status": "info", "message": fmt.Sprintf("Reusing %d subdomains from prior scan", n), "count": n})
	return n
}

// reuseLiveHostsFromPrior copies live hosts from the most recent prior scan
// of this target into the current scan when the current scan has none. See
// reuseSubdomainsFromPrior.
func (e *Engine) reuseLiveHostsFromPrior() int {
	priorID, ok := e.db.GetPriorScanIDWithData(e.cfg.Target, "live_hosts", e.scanID)
	if !ok {
		return 0
	}
	n, err := e.db.ReuseLiveHosts(e.scanID, priorID)
	if err != nil || n == 0 {
		return 0
	}
	logger.Success("Reusing %d live hosts from prior scan #%d", n, priorID)
	e.emit(map[string]any{"phase": "reuse", "status": "info", "message": fmt.Sprintf("Reusing %d live hosts from prior scan", n), "count": n})
	return n
}

// reuseCrawledURLsFromPrior copies crawled URLs from the most recent prior scan
// of this target into the current scan when the current scan has none. This is
// the URL-dependent analogue of reuseLiveHostsFromPrior: it lets js_analysis,
// param_discovery and secret_scan run standalone on a previously-crawled target
// instead of finding zero URLs and producing blank results.
func (e *Engine) reuseCrawledURLsFromPrior() int {
	priorID, ok := e.db.GetPriorScanIDWithData(e.cfg.Target, "crawled_urls", e.scanID)
	if !ok {
		return 0
	}
	n, err := e.db.ReuseCrawledURLs(e.scanID, priorID)
	if err != nil || n == 0 {
		return 0
	}
	logger.Success("Reusing %d crawled URLs from prior scan #%d", n, priorID)
	e.emit(map[string]any{"phase": "reuse", "status": "info", "message": fmt.Sprintf("Reusing %d crawled URLs from prior scan", n), "count": n})
	return n
}

// seedTargetAsLiveHost adds the bare target domain (e.g. "acronis.com") and
// its www variant as a subdomain + live host when the scan has no live hosts
// at all. This is the fallback that lets a user select ONLY a host-dependent
// module (port_scan / waf_detect / vuln_scan / takeover) against a fresh target
// that was never enumerated — otherwise every such module would be skipped
// with "no live hosts" and the results page would be blank.
//
// It only fires when a host-dependent module is actually selected AND there
// is genuinely no prior live-host data, so it never duplicates hosts a real
// httpx run already produced. Returns true if at least one host was seeded.
func (e *Engine) seedTargetAsLiveHost() bool {
	needsHosts := e.shouldRun(config.PhaseWAFDetect, 0) ||
		e.shouldRun(config.PhasePortScan, 0) ||
		e.shouldRun(config.PhaseVulnScan, 5) ||
		e.shouldRun(config.PhaseTakeover, 5) ||
		e.shouldRun(config.PhaseTechDetection, 3) ||
		e.shouldRun(config.PhaseEarlyCrawling, 4) ||
		e.shouldRun(config.PhaseJSAnalysis, 0) ||
		e.shouldRun(config.PhaseParamDiscovery, 0) ||
		e.shouldRun(config.PhaseSecretScan, 0)
	if !needsHosts {
		return false
	}
	target := strings.TrimSuffix(strings.ToLower(e.cfg.Target), ".")
	if target == "" {
		return false
	}
	candidates := []string{target, "www." + target}
	var seeded int
	for _, sub := range candidates {
		_ = e.db.InsertSubdomain(e.scanID, sub, "seeded")
		for _, scheme := range []string{"https://", "http://"} {
			url := scheme + sub
			// InsertLiveHost uses INSERT OR IGNORE on (scan_id, url), so the
			// second scheme is a no-op if the first already exists.
			if err := e.db.InsertLiveHost(e.scanID, storage.LiveHost{
				URL:       url,
				Subdomain: sub,
			}); err == nil {
				seeded++
				break
			}
		}
	}
	if seeded > 0 {
		logger.Success("Seeded target domain %s as live host (no prior enumeration data)", target)
		e.emit(map[string]any{"phase": "live_check", "status": "info", "message": fmt.Sprintf("No prior subdomain data — seeded %s as live host for selected modules", target), "count": seeded})
	}
	return seeded > 0
}

// loadSubdomains reads the distinct subdomain names for the current scan from
// the DB (lowercased, deduplicated). This is the single source of truth for
// what httpx will probe: it unions the enumerators' result with anything
// passive recon wrote concurrently.
func (e *Engine) loadSubdomains() []string {
	subs, err := e.db.GetSubdomains(e.scanID)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool, len(subs))
	var out []string
	for _, s := range subs {
		key := strings.ToLower(strings.TrimSpace(s.Subdomain))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

// loadLiveHosts returns the live-host set for the current scan. If `fresh` is
// non-nil (just produced by httpx) it is used directly; otherwise the hosts are
// read back from the DB (covering the reuse-from-prior-scan path). The DB row
// and the discovery struct differ in shape, so convert field-by-field.
func (e *Engine) loadLiveHosts(fresh *discovery.LiveResult) *discovery.LiveResult {
	if fresh != nil && len(fresh.LiveHosts) > 0 {
		return fresh
	}
	res := &discovery.LiveResult{}
	hosts, err := e.db.GetLiveHosts(e.scanID)
	if err != nil {
		return res
	}
	for _, h := range hosts {
		lh := discovery.LiveHost{
			URL:           h.URL,
			Subdomain:     h.Subdomain,
			StatusCode:    h.StatusCode,
			Title:        h.Title,
			ContentLength: h.ContentLength,
			Webserver:     h.Webserver,
			CDN:           h.CDN,
			RedirectURL:   h.RedirectURL,
		}
		if h.TechDetected != "" {
			_ = json.Unmarshal([]byte(h.TechDetected), &lh.Technologies)
		}
		res.LiveHosts = append(res.LiveHosts, lh)
	}
	return res
}

// Run executes the full scan pipeline.
func (e *Engine) Run(ctx context.Context) error {
	startTime := time.Now()

	// degraded tracks whether any critical phase errored or panicked. If so,
	// the scan is still marked done (partial results are valuable) but with
	// status "completed_with_errors" instead of "completed", so the UI/logs
	// don't report a scan where e.g. Nuclei panicked as a clean success.
	var degraded bool

	logger.Header(e.cfg.Target, e.cfg.OutputDir, e.scanID)

	// Ensure output directories exist
	for _, dir := range []string{
		e.cfg.RawDir(e.cfg.Target),
		e.cfg.ParsedDir(e.cfg.Target),
		e.cfg.PriorityDir(e.cfg.Target),
		e.cfg.ReportsDir(e.cfg.Target),
	} {
		os.MkdirAll(dir, 0755)
	}

	// Ensure tools are installed. Only require the tools for the phases that
	// will actually run, so a narrow selection (e.g. "only subdomain enum")
	// doesn't try to install nuclei/katana/subzy and fail or stall.
	installer := installer.New(e.cfg.AutoInstall)
	required := e.requiredTools()
	if len(required) > 0 {
		installer.EnsureTools(required)
	}
	if e.shouldRun(config.PhaseVulnScan, 5) {
		installer.EnsureNucleiTemplates(e.cfg.Nuclei.Templates)
	}

	// Phase-1 advanced modules runner (passive recon, nmap, wafw00f, js,
	// arjun, trufflehog+gitleaks). Shares the existing progress callback so
	// every finding streams to the live-progress WebSocket.
	p1 := phasemod.NewRunner(e.cfg, e.db, e.scanID, e.cfg.Target, e.emit)

	// ── Phase 1: Subdomain Enumeration (+ Passive Recon in parallel) ──
	runEnum := e.shouldRun(config.PhaseSubdomainEnum, 1)
	runPassive := e.shouldRun(config.PhasePassiveRecon, 1)
	if runEnum || runPassive {
		e.emit(map[string]any{"phase": "subdomain_enum", "status": "running", "message": "Starting subdomain enumeration"})

		var enumResult *enumeration.Result
		var enumErr error
		var wgEnum sync.WaitGroup
		if runPassive {
			wgEnum.Add(1)
			go func() {
				defer wgEnum.Done()
				defer func() {
					if rec := recover(); rec != nil {
						logger.Err("Passive recon panicked: %v", rec)
					}
				}()
				p1.RunPassiveRecon(ctx)
			}()
		}

		if runEnum {
			enum := enumeration.New(e.cfg, e.db, e.scanID)
			enumResult, enumErr = enum.Run(ctx)
		}
		wgEnum.Wait()
		if enumErr != nil {
			// Don't abort the whole scan — passive recon may still have produced
			// hosts, and the user may have selected only enumeration. Log and
			// continue; downstream phases degrade gracefully if there are none.
			logger.Err("Subdomain enumeration failed: %v", enumErr)
			degraded = true
		}
		if runEnum {
			e.db.AddCompletedPhase(e.scanID, "subdomain_enum")
		}
		if runPassive {
			e.db.AddCompletedPhase(e.scanID, "passive_recon")
		}
		if enumResult != nil {
			e.emit(map[string]any{"phase": "subdomain_enum", "status": "completed", "count": len(enumResult.Subdomains)})
		} else {
			e.emit(map[string]any{"phase": "subdomain_enum", "status": "completed"})
		}
	} else {
		e.emit(map[string]any{"phase": "subdomain_enum", "status": "skipped", "message": "subdomain enumeration not selected"})
	}

	// Resolve the subdomain set for downstream phases. Enumeration may have
	// been skipped (opt-out) or found nothing; in either case try to reuse
	// subdomains from a prior scan of this target so a downstream-only
	// selection (e.g. "only port scan") still has hosts to work with.
	subdomains := e.loadSubdomains()
	if len(subdomains) == 0 {
		if e.reuseSubdomainsFromPrior() > 0 {
			subdomains = e.loadSubdomains()
		}
	}
	if len(subdomains) == 0 {
		logger.Warn("No subdomains available for %s; host-dependent phases will be skipped", e.cfg.Target)
		e.emit(map[string]any{"phase": "subdomain_enum", "status": "warning", "message": "No subdomains available — skipping host-dependent phases. Run Subdomain Enumeration first."})
	} else {
		e.ensureInputFiles()
	}

	// ── Phase 2: Live Host Detection ─────────────────────────────
	var liveResult *discovery.LiveResult
	runLive := e.shouldRun(config.PhaseLiveCheck, 2)
	if runLive && len(subdomains) > 0 {
		e.emit(map[string]any{"phase": "live_check", "status": "running", "message": "Checking live subdomains"})
		httpxChecker := discovery.NewHttpxChecker(e.cfg, e.db, e.scanID)
		var liveErr error
		liveResult, liveErr = httpxChecker.Run(ctx, subdomains)
		if liveErr != nil {
			logger.Err("Live check failed: %v", liveErr)
			degraded = true
		} else {
			e.db.AddCompletedPhase(e.scanID, "live_check")
			e.emit(map[string]any{"phase": "live_check", "status": "completed", "count": len(liveResult.LiveHosts)})
		}
	} else if !runLive {
		e.emit(map[string]any{"phase": "live_check", "status": "skipped", "message": "live host detection not selected"})
	}

	// Resolve live hosts for downstream phases (fresh result → DB → prior scan).
	liveResult = e.loadLiveHosts(liveResult)
	if len(liveResult.LiveHosts) == 0 {
		if e.reuseLiveHostsFromPrior() > 0 {
			liveResult = e.loadLiveHosts(nil)
		}
	}
	if len(liveResult.LiveHosts) == 0 {
		// Last resort: if the user selected only host-dependent modules (port
		// scan, WAF, etc.) against a target with no prior enumeration, seed the
		// bare target domain (and www.) as live hosts so the modules have at
		// least the apex domain to work with instead of silently skipping.
		if e.seedTargetAsLiveHost() {
			liveResult = e.loadLiveHosts(nil)
		}
	}
	if len(liveResult.LiveHosts) == 0 {
		logger.Warn("No live hosts available for %s; skipping live-host-dependent phases", e.cfg.Target)
		e.emit(map[string]any{"phase": "live_check", "status": "warning", "message": "No live hosts available — skipping vuln/crawl/waf/port phases. Run Subdomain Enumeration + Live Host Detection first."})
	} else {
		e.ensureInputFiles()
	}

	// ── Phase 3 + 4: Technology Detection + Early Crawling (PARALLEL) ──
	runTech := e.shouldRun(config.PhaseTechDetection, 3)
	runCrawl := e.shouldRun(config.PhaseEarlyCrawling, 4)
	if (runTech || runCrawl) && len(liveResult.LiveHosts) > 0 {
		logger.Subsection("Technology Detection + Deep Crawling (parallel)")
		e.emit(map[string]any{"phase": "tech_and_crawl", "status": "running", "message": "Technology detection + Katana crawling in parallel"})

		parallelCtx, parallelCancel := context.WithCancel(ctx)
		defer parallelCancel()

		var techErr, katanaErr error
		done := make(chan struct{}, 2)

		if !runTech {
			e.emit(map[string]any{"phase": "tech_detection", "status": "skipped"})
			done <- struct{}{}
		} else {
			go func() {
				defer func() { done <- struct{}{} }()
				defer func() {
					if r := recover(); r != nil {
						techErr = fmt.Errorf("technology detection panicked: %v", r)
						logger.Err("Technology detection panicked: %v", r)
					}
				}()
				detector := technology.New(e.cfg, e.db, e.scanID)
				_, techErr = detector.Run(parallelCtx, e.cfg.Target)
			}()
		}

		if !runCrawl {
			e.emit(map[string]any{"phase": "early_crawling", "status": "skipped"})
			done <- struct{}{}
		} else {
			go func() {
				defer func() { done <- struct{}{} }()
				defer func() {
					if r := recover(); r != nil {
						katanaErr = fmt.Errorf("katana crawling panicked: %v", r)
						logger.Err("Katana crawling panicked: %v", r)
					}
				}()
				crawler := discovery.NewKatanaCrawler(e.cfg, e.db, e.scanID)
				_, katanaErr = crawler.Run(parallelCtx, liveResult.LiveHosts)
			}()
		}

		<-done
		<-done

		if techErr != nil {
			logger.Err("Technology detection error: %v", techErr)
			degraded = true
		}
		if katanaErr != nil {
			logger.Err("Katana crawling error: %v", katanaErr)
			degraded = true
		}
		if runTech {
			e.db.AddCompletedPhase(e.scanID, "tech_detection")
		}
		if runCrawl {
			e.db.AddCompletedPhase(e.scanID, "early_crawling")
		}
		e.emit(map[string]any{"phase": "tech_and_crawl", "status": "completed"})
	} else {
		if !runTech {
			e.emit(map[string]any{"phase": "tech_detection", "status": "skipped"})
		}
		if !runCrawl {
			e.emit(map[string]any{"phase": "early_crawling", "status": "skipped"})
		}
	}

	// Reuse crawled URLs from a prior scan when Katana didn't run (not selected
	// or no live hosts). The group-C modules (js_analysis, param_discovery,
	// secret_scan) depend on crawled URLs, so without this reuse an opt-in
	// "only js_analysis" scan on a previously-crawled target finds zero URLs.
	if urls, _ := e.db.GetCrawledURLs(e.scanID); len(urls) == 0 {
		e.reuseCrawledURLsFromPrior()
	}

	// ── Phase 5: Vuln + Takeover + WAF + Ports (group AB) + JS/Params/Secrets (group C) ──
	// Each sub-module is gated individually by shouldRun. Host-dependent modules
	// are skipped (with a warning) when there are no live hosts; the group-C
	// modules only need crawled URLs/JS files, so they still fire if Katana ran.
	phase5Active := e.shouldRun(config.PhaseVulnScan, 5) || e.shouldRun(config.PhaseTakeover, 5) ||
		e.shouldRun(config.PhaseWAFDetect, 0) || e.shouldRun(config.PhasePortScan, 0) ||
		e.shouldRun(config.PhaseJSAnalysis, 0) || e.shouldRun(config.PhaseParamDiscovery, 0) ||
		e.shouldRun(config.PhaseSecretScan, 0)
	if !phase5Active {
		e.emit(map[string]any{"phase": "vuln_scan", "status": "skipped"})
		e.emit(map[string]any{"phase": "phase1_groupC", "status": "skipped"})
	} else if vErr := e.runVulnPhase(ctx, p1, liveResult); vErr != nil {
		logger.Err("Phase 5 (vuln scanning) error: %v", vErr)
		degraded = true
	}

	// ── Phase 6: Priority Scoring ─────────────────────────────
	if !e.shouldRun(config.PhasePriorityScoring, 6) {
		e.emit(map[string]any{"phase": "priority_scoring", "status": "skipped"})
	} else {
		e.emit(map[string]any{"phase": "priority_scoring", "status": "running", "message": "Calculating priority scores"})
		scorer := scoring.New(e.cfg, e.db, e.scanID)
		_, err := scorer.Run(ctx)
		if err != nil {
			logger.Err("Priority scoring error: %v", err)
			degraded = true
		}
		e.db.AddCompletedPhase(e.scanID, "priority_scoring")
		e.emit(map[string]any{"phase": "priority_scoring", "status": "completed"})
	}

	// ── Phase 1 complete signal (enables the Phase 2 button in the UI) ──
	e.emit(map[string]any{"phase": "phase1_complete", "status": "completed", "target": e.cfg.Target, "session_id": e.scanID})

	// ── Finalize ─────────────────────────────────────────────────
	duration := time.Since(startTime).Seconds()
	finalStatus := "completed"
	if degraded {
		finalStatus = "completed_with_errors"
	}
	e.db.CompleteScan(e.scanID, finalStatus, duration)
	e.emit(map[string]any{"phase": "done", "status": finalStatus, "duration": duration})

	// Collect result counts for the summary footer
	counts := map[string]int{}
	if subs, err := e.db.GetSubdomains(e.scanID); err == nil {
		counts["subdomains"] = len(subs)
	}
	if live, err := e.db.GetLiveHosts(e.scanID); err == nil {
		counts["live_hosts"] = len(live)
	}
	if urls, err := e.db.GetCrawledURLs(e.scanID); err == nil {
		counts["crawled_urls"] = len(urls)
	}
	if vulns, err := e.db.GetVulnerabilities(e.scanID); err == nil {
		counts["vulnerabilities"] = len(vulns)
	}
	if tech, err := e.db.GetTechDetections(e.scanID); err == nil {
		counts["technologies"] = len(tech)
	}

	logger.Footer(e.cfg.Target, duration, counts)

	// Generate JSON report
	e.generateReport()

	return nil
}

// runVulnPhase runs Phase 5: parallel group AB (nuclei + subzy + waf + ports)
// immediately followed by parallel group C (js analysis + param discovery +
// secret scan). Each sub-module is gated individually by shouldRun, so the
// user can run any combination (e.g. "only port scan"). Host-dependent
// modules (nuclei/subzy/waf/port) are skipped with a warning when there are no
// live hosts; group-C modules only need crawled URLs/JS files, so they still
// fire when Katana ran. Returns an error only if a CRITICAL sub-task (nuclei
// or subzy) failed/panicked; everything else is logged but non-fatal, since
// partial coverage is still useful and shouldn't abort the scan.
func (e *Engine) runVulnPhase(ctx context.Context, p1 *phasemod.Runner, liveResult *discovery.LiveResult) error {
	liveHostNames := make([]string, 0, len(liveResult.LiveHosts))
	for _, h := range liveResult.LiveHosts {
		liveHostNames = append(liveHostNames, h.Subdomain)
	}
	hasLiveHosts := len(liveHostNames) > 0

	runNuclei := e.shouldRun(config.PhaseVulnScan, 5)
	runSubzy := e.shouldRun(config.PhaseTakeover, 5)
	runWAF := e.shouldRun(config.PhaseWAFDetect, 0)
	runPort := e.shouldRun(config.PhasePortScan, 0)

	// Group AB: nuclei + subzy + waf + ports (only the selected ones fire).
	groupABActive := runNuclei || runSubzy || runWAF || runPort
	var nucleiErr, takeoverErr error
	if groupABActive {
		logger.Subsection("Vuln + Takeover + WAF + Ports Scanning (parallel group AB)")
		e.emit(map[string]any{"phase": "vuln_scan", "status": "running", "message": "Nuclei + Subzy + WAF + Ports in parallel"})
		vulnCtx, vulnCancel := context.WithCancel(ctx)
		defer vulnCancel()

		if !hasLiveHosts {
			logger.Warn("No live hosts — skipping host-dependent modules (nuclei/subzy/waf/port)")
			e.emit(map[string]any{"phase": "vuln_scan", "status": "warning", "message": "No live hosts available — skipping nuclei/subzy/waf/port. Run Subdomain Enumeration + Live Host Detection first."})
		}

		// Capacity only for slots that will actually launch a goroutine. A
		// selected module with no live hosts is skipped (emits a "skipped"
		// event) but does NOT start a goroutine, so it must not reserve a drain
		// slot — otherwise the drain loop below deadlocks waiting for a signal
		// that never arrives. This is what made "only WAF" / "only port scan"
		// against an unenumerated target hang at "running" forever.
		slots := groupABSlots(runNuclei, runSubzy, runWAF, runPort, hasLiveHosts)
		vulnDone := make(chan struct{}, slots)

		// Nuclei — receives Katana-crawled URLs as additional input
		if runNuclei && hasLiveHosts {
			go func() {
				defer func() { vulnDone <- struct{}{} }()
				defer func() {
					if r := recover(); r != nil {
						nucleiErr = fmt.Errorf("nuclei scanning panicked: %v", r)
						logger.Err("Nuclei scanning panicked: %v", r)
					}
				}()
				scanner := nuclei.New(e.cfg, e.db, e.scanID)
				_, nucleiErr = scanner.Run(vulnCtx)
			}()
		} else if runNuclei {
			e.emit(map[string]any{"phase": "vuln_scan", "status": "skipped", "message": "nuclei skipped — no live hosts"})
		}

		// Subzy — subdomain takeover check
		if runSubzy && hasLiveHosts {
			go func() {
				defer func() { vulnDone <- struct{}{} }()
				defer func() {
					if r := recover(); r != nil {
						takeoverErr = fmt.Errorf("subzy takeover check panicked: %v", r)
						logger.Err("Subzy takeover check panicked: %v", r)
					}
				}()
				checker := takeover.New(e.cfg, e.db, e.scanID)
				_, takeoverErr = checker.Run(vulnCtx)
			}()
		} else if runSubzy {
			e.emit(map[string]any{"phase": "takeover", "status": "skipped", "message": "subzy skipped — no live hosts"})
		}

		// WAF detection (wafw00f)
		if runWAF && hasLiveHosts {
			go func() {
				defer func() { vulnDone <- struct{}{} }()
				defer func() {
					if r := recover(); r != nil {
						logger.Err("WAF detection panicked: %v", r)
					}
				}()
				p1.RunWAFDetection(vulnCtx, liveHostNames)
			}()
		} else if runWAF {
			e.emit(map[string]any{"phase": "waf_detect", "status": "skipped", "message": "waf detection skipped — no live hosts"})
		}

		// Port scan (nmap stealth)
		if runPort && hasLiveHosts {
			go func() {
				defer func() { vulnDone <- struct{}{} }()
				defer func() {
					if r := recover(); r != nil {
						logger.Err("Port scan panicked: %v", r)
					}
				}()
				p1.RunPortScan(vulnCtx, liveHostNames)
			}()
		} else if runPort {
			e.emit(map[string]any{"phase": "port_scan", "status": "skipped", "message": "port scan skipped — no live hosts"})
		}

		// Drain active slots.
		for i := 0; i < slots; i++ {
			<-vulnDone
		}

		if nucleiErr != nil {
			logger.Err("Nuclei error: %v", nucleiErr)
		}
		if takeoverErr != nil {
			logger.Err("Subzy error: %v", takeoverErr)
		}
		if runNuclei || runSubzy {
			e.db.AddCompletedPhase(e.scanID, "vuln_scanning")
		}
		if runWAF {
			e.db.AddCompletedPhase(e.scanID, "waf_detect")
		}
		if runPort {
			e.db.AddCompletedPhase(e.scanID, "port_scan")
		}
		e.emit(map[string]any{"phase": "vuln_scan", "status": "completed"})
	}

	// ── Group C: JS Analysis + Param Discovery + Secret Scan (ALL CONCURRENT) ──
	// All three consume Katana's crawled URLs / raw output dir and are mutually
	// independent, so they run as one concurrent block. JSAnalysis downloads .js
	// files into <rawdir>/js/ which SecretScan also sweeps — running them
	// concurrently is intentional for speed (secret scan covers whatever is on
	// disk at scan time).
	runJS := e.shouldRun(config.PhaseJSAnalysis, 0)
	runParams := e.shouldRun(config.PhaseParamDiscovery, 0)
	runSecrets := e.shouldRun(config.PhaseSecretScan, 0)
	groupCActive := runJS || runParams || runSecrets
	if groupCActive {
		logger.Subsection("JS Analysis + Param Discovery + Secret Scan (parallel group C)")
		e.emit(map[string]any{"phase": "phase1_groupC", "status": "running", "message": "JS + Params + Secrets in parallel"})
		cCtx, cCancel := context.WithCancel(ctx)
		defer cCancel()
		cSlots := 0
		for _, on := range []bool{runJS, runParams, runSecrets} {
			if on {
				cSlots++
			}
		}
		cDone := make(chan struct{}, cSlots)
		if runJS {
			go func() {
				defer func() { cDone <- struct{}{} }()
				defer func() {
					if r := recover(); r != nil {
						logger.Err("JS analysis panicked: %v", r)
					}
				}()
				p1.RunJSAnalysis(cCtx)
			}()
		}
		if runParams {
			go func() {
				defer func() { cDone <- struct{}{} }()
				defer func() {
					if r := recover(); r != nil {
						logger.Err("Param discovery panicked: %v", r)
					}
				}()
				p1.RunParamDiscovery(cCtx)
			}()
		}
		if runSecrets {
			go func() {
				defer func() { cDone <- struct{}{} }()
				defer func() {
					if r := recover(); r != nil {
						logger.Err("Secret scan panicked: %v", r)
					}
				}()
				p1.RunSecretScan(cCtx)
			}()
		}
		for i := 0; i < cSlots; i++ {
			select {
			case <-cDone:
			case <-cCtx.Done():
			}
		}
		if runJS {
			e.db.AddCompletedPhase(e.scanID, "js_analysis")
		}
		if runParams {
			e.db.AddCompletedPhase(e.scanID, "param_discovery")
		}
		if runSecrets {
			e.db.AddCompletedPhase(e.scanID, "secret_scan")
		}
		e.emit(map[string]any{"phase": "phase1_groupC", "status": "completed"})
	}

	// Only nuclei/subzy failures are critical enough to flag the scan degraded.
	if nucleiErr != nil && takeoverErr != nil {
		return fmt.Errorf("nuclei: %v; subzy: %v", nucleiErr, takeoverErr)
	}
	if nucleiErr != nil {
		return fmt.Errorf("nuclei: %v", nucleiErr)
	}
	if takeoverErr != nil {
		return fmt.Errorf("subzy: %v", takeoverErr)
	}
	return nil
}

// groupABSlots returns the number of group-AB goroutines that will actually
// start for this scan. Each host-dependent module (nuclei/subzy/waf/port)
// only launches a goroutine when it is both selected AND there are live hosts
// to scan; otherwise it is skipped and emits a "skipped" event without
// signalling the drain channel.
//
// This MUST match the goroutine-launch condition in runVulnPhase: the drain
// loop waits on exactly this many signals, so counting a slot for a module
// that doesn't start a goroutine deadlocks the scan (the original bug behind
// "only WAF" hanging at running forever on an unenumerated target).
func groupABSlots(runNuclei, runSubzy, runWAF, runPort, hasLiveHosts bool) int {
	if !hasLiveHosts {
		return 0
	}
	slots := 0
	if runNuclei {
		slots++
	}
	if runSubzy {
		slots++
	}
	if runWAF {
		slots++
	}
	if runPort {
		slots++
	}
	return slots
}

// generateReport creates a consolidated JSON report.
func (e *Engine) generateReport() {
	report := map[string]any{
		"target":     e.cfg.Target,
		"scan_id":    e.scanID,
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	// Load data from DB
	if liveHosts, err := e.db.GetLiveHosts(e.scanID); err == nil {
		report["live_hosts"] = liveHosts
	}
	if vulns, err := e.db.GetVulnerabilities(e.scanID); err == nil {
		report["vulnerabilities"] = vulns
	}
	if crawledURLs, err := e.db.GetCrawledURLs(e.scanID); err == nil {
		report["crawled_urls"] = crawledURLs
	}
	if dirs, err := e.db.GetDiscoveredDirs(e.scanID); err == nil {
		report["directories"] = dirs
	}
	if priority, err := e.db.GetPriorityEntries(e.scanID); err == nil {
		report["priority_ranking"] = priority
	}

	reportPath := filepath.Join(e.cfg.ReportsDir(e.cfg.Target), "report.json")
	data, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(reportPath, data, 0644)
	logger.Success("Report saved to %s", reportPath)

	// Store individual result files in the result folder
	e.storeIndividualResults()
}

// storeIndividualResults writes separate JSON files for each result type.
func (e *Engine) storeIndividualResults() {
	targetDir := e.cfg.TargetDir(e.cfg.Target)

	// Live hosts
	if liveHosts, err := e.db.GetLiveHosts(e.scanID); err == nil {
		path := filepath.Join(targetDir, "live_hosts.json")
		data, _ := json.MarshalIndent(liveHosts, "", "  ")
		os.WriteFile(path, data, 0644)
		logger.Success("Live hosts saved to %s", path)
	}

	// Vulnerabilities
	if vulns, err := e.db.GetVulnerabilities(e.scanID); err == nil {
		path := filepath.Join(targetDir, "vulnerabilities.json")
		data, _ := json.MarshalIndent(vulns, "", "  ")
		os.WriteFile(path, data, 0644)
		logger.Success("Vulnerabilities saved to %s", path)
	}

	// Crawled URLs
	if crawledURLs, err := e.db.GetCrawledURLs(e.scanID); err == nil {
		path := filepath.Join(targetDir, "crawled_urls.json")
		data, _ := json.MarshalIndent(crawledURLs, "", "  ")
		os.WriteFile(path, data, 0644)
		logger.Success("Crawled URLs saved to %s", path)
	}

	// Discovered directories
	if dirs, err := e.db.GetDiscoveredDirs(e.scanID); err == nil {
		path := filepath.Join(targetDir, "directories.json")
		data, _ := json.MarshalIndent(dirs, "", "  ")
		os.WriteFile(path, data, 0644)
		logger.Success("Directories saved to %s", path)
	}

	// Priority ranking
	if priority, err := e.db.GetPriorityEntries(e.scanID); err == nil {
		path := filepath.Join(targetDir, "priority_ranking.json")
		data, _ := json.MarshalIndent(priority, "", "  ")
		os.WriteFile(path, data, 0644)
		logger.Success("Priority ranking saved to %s", path)
	}

	// Subdomains
	if subs, err := e.db.GetSubdomains(e.scanID); err == nil {
		path := filepath.Join(targetDir, "subdomains.json")
		data, _ := json.MarshalIndent(subs, "", "  ")
		os.WriteFile(path, data, 0644)
		logger.Success("Subdomains saved to %s", path)
	}

	// Tech detections
	if tech, err := e.db.GetTechDetections(e.scanID); err == nil {
		path := filepath.Join(targetDir, "tech_detections.json")
		data, _ := json.MarshalIndent(tech, "", "  ")
		os.WriteFile(path, data, 0644)
		logger.Success("Tech detections saved to %s", path)
	}

	// Header results
	if headers, err := e.db.GetHeaderResult(e.scanID); err == nil && headers != nil {
		path := filepath.Join(targetDir, "header_results.json")
		data, _ := json.MarshalIndent(headers, "", "  ")
		os.WriteFile(path, data, 0644)
		logger.Success("Header results saved to %s", path)
	}
}
