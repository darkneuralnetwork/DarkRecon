// Package mcp implements the Dark-Recon MCP (Model Context Protocol)
// server. It exposes the full Dark-Recon reconnaissance platform — every
// REST endpoint of the running Go web server — as MCP tools and resources,
// so an MCP-compatible LLM client (Claude Desktop, Cursor, Cline, …) can
// launch scans, monitor them, and retrieve prioritised findings.
//
// It is built into the same binary as the web server and invoked via the
// `dark-recon mcp` subcommand, so a single self-contained binary serves
// both the browser UI (HTTP) and LLM clients (stdio MCP).
//
// The MCP server is a thin client over the Dark-Recon REST API: it does
// not open the SQLite databases or run the pipeline directly. Point it at a
// running server with DARK_RECON_URL (default http://localhost:5000).
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ─────────────────────────────────────────────────────────────────────────────
// Configuration & HTTP client
// ─────────────────────────────────────────────────────────────────────────────

var (
	baseURL     string
	httpClient  = &http.Client{Timeout: 120 * time.Second}
	serverName  = "dark-recon"
	serverVer   = "1.0.0"
)

// Run starts the MCP server over the stdio transport. It parses the given
// args (the slice after the "mcp" subcommand) for a -url flag, falling back
// to the DARK_RECON_URL env var, then http://localhost:5000.
func Run(args []string) error {
	fs := flag.NewFlagSet("dark-recon-mcp", flag.ContinueOnError)
	urlFlag := fs.String("url", "", "Dark-Recon server base URL (default: $DARK_RECON_URL or http://localhost:5000)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	switch {
	case *urlFlag != "":
		baseURL = strings.TrimRight(*urlFlag, "/")
	case os.Getenv("DARK_RECON_URL") != "":
		baseURL = strings.TrimRight(os.Getenv("DARK_RECON_URL"), "/")
	default:
		baseURL = "http://localhost:5000"
	}

	// MCP protocol lives on stdout; keep all diagnostics on stderr.
	fmt.Fprintf(os.Stderr, "[dark-recon-mcp] connecting to %s\n", baseURL)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := buildServer()
	return srv.Run(ctx, &mcp.StdioTransport{})
}

func buildServer() *mcp.Server {
	srv := mcp.NewServer(
		&mcp.Implementation{Name: serverName, Title: "Dark-Recon", Version: serverVer},
		&mcp.ServerOptions{
			Instructions: instructions,
			Logger:       slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		},
	)
	registerTools(srv)
	registerResources(srv)
	return srv
}

const instructions = `Dark-Recon — automated reconnaissance & attack-surface discovery.

This server controls a running Dark-Recon instance over its REST API. Typical workflow:
  1. launch_scan(domain="example.com")  — starts an 8-phase recon pipeline
  2. get_scan_status(target=...) / get_scan_logs(target=...) — monitor
  3. wait_for_scan(target=...) — block until the scan finishes
  4. list_targets() / get_target(target=...) — retrieve consolidated results
  5. get_priority(target=...) — ranked subdomains by attack priority (0-100)
  6. get_phase2_targets/findings/urls — the prioritised Phase 2 handoff

Optional advanced modules (passive_recon, port_scan, waf_detect, js_analysis,
param_discovery, secret_scan) are enabled per-scan or in config. Use
list_phases() for the pipeline map and list_tools() to check that
subfinder/ffuf/httpx/nuclei/katana/subzy/webanalyze are installed.

Always ensure you have authorisation before scanning a target.`

// ─────────────────────────────────────────────────────────────────────────────
// Low-level HTTP helpers
// ─────────────────────────────────────────────────────────────────────────────

// apiJSON performs a request expecting a JSON object response.
func apiJSON(ctx context.Context, method, path string, query url.Values, body any) (map[string]any, error) {
	raw, err := apiRaw(ctx, method, path, query, body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		// Non-object JSON (rare); wrap so the tool still returns an object.
		return map[string]any{"result": string(raw)}, nil
	}
	return out, nil
}

// apiText performs a request returning the raw text body (e.g. CSV export).
func apiText(ctx context.Context, method, path string, query url.Values) (string, error) {
	raw, err := apiRaw(ctx, method, path, query, nil)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func apiRaw(ctx context.Context, method, path string, query url.Values, body any) ([]byte, error) {
	u := baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach Dark-Recon at %s (%w). Is the server running? Start it with: ./dark-recon -port 5000", baseURL, err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, e.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(data), 500))
	}
	return data, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ptr helpers for optional scalar query/body params.
func strPtr(s string) *string { return &s }
func intptr(i int) *int       { return &i }

// ─────────────────────────────────────────────────────────────────────────────
// Shared input structs (jsonschema tag = property description)
// ─────────────────────────────────────────────────────────────────────────────

type noInput struct{}

type targetInput struct {
	Target string `json:"target" jsonschema:"the target domain name (e.g. example.com)"`
}

type toolInput struct {
	Tool string `json:"tool" jsonschema:"tool name (e.g. nuclei, subfinder, httpx)"`
}

type targetSubInput struct {
	Target    string `json:"target" jsonschema:"the target domain name"`
	Subdomain string `json:"subdomain" jsonschema:"the specific subdomain (e.g. admin.example.com)"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool registration
// ─────────────────────────────────────────────────────────────────────────────

func registerTools(s *mcp.Server) {
	// Each tool is a 1:1 wrapper over a REST endpoint. Tools return
	// map[string]any (a JSON object); the SDK emits it as both structured
	// content and JSON text content automatically. The CSV export wraps its
	// text in {"csv": "..."}.
	//
	// Naming, arguments and descriptions mirror the Python MCP server.

	// ── 1. Scan management ──
	mcp.AddTool(s, &mcp.Tool{Name: "launch_scan", Description: `Launch a full recon scan against a target domain.

Runs Dark-Recon's 8-phase pipeline (subdomain enumeration -> live host detection -> tech fingerprinting -> Katana crawl -> Nuclei/Subzy scanning -> priority scoring) in a background goroutine and returns immediately.`}, func(ctx context.Context, _ *mcp.CallToolRequest, in launchScanInput) (*mcp.CallToolResult, map[string]any, error) {
		body := map[string]any{"domain": in.Domain, "resume": in.Resume}
		if in.Threads != nil {
			body["threads"] = *in.Threads
		}
		if in.Timeout != nil {
			body["timeout"] = *in.Timeout
		}
		if in.TopSubdomains != nil {
			body["top_subdomains"] = *in.TopSubdomains
		}
		if len(in.SkipPhases) > 0 {
			body["skip_phases"] = in.SkipPhases
		}
		if in.PassiveRecon != nil {
			body["passive_recon"] = *in.PassiveRecon
		}
		if in.PortScan != nil {
			body["port_scan"] = *in.PortScan
		}
		if in.WAFDetect != nil {
			body["waf_detect"] = *in.WAFDetect
		}
		if in.JSAnalysis != nil {
			body["js_analysis"] = *in.JSAnalysis
		}
		if in.ParamDiscovery != nil {
			body["param_discovery"] = *in.ParamDiscovery
		}
		if in.SecretScan != nil {
			body["secret_scan"] = *in.SecretScan
		}
		if in.ChaosAPIKey != nil {
			body["chaos_api_key"] = *in.ChaosAPIKey
		}
		out, err := apiJSON(ctx, "POST", "/api/scan/launch", nil, body)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "stop_scan", Description: "Gracefully stop a running scan for a target. Cancels the scan context; already-collected results are kept."}, func(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "POST", "/api/scan/"+in.Target+"/stop", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "get_scan_status", Description: "Get the current status of a scan and its recent log entries. Status: running, stopping, completed, completed_with_errors, failed, idle."}, func(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/scan/"+in.Target+"/status", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "get_scan_logs", Description: "Get the full in-memory progress log for a scan. Each entry: {timestamp, phase, status, message, count}. Capped at the most recent 5000 entries."}, func(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/scan/"+in.Target+"/logs", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "list_active_scans", Description: "List all currently-running scans."}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/scans/active", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "wait_for_scan", Description: `Block until a scan reaches a terminal state, polling periodically.

A convenience helper for synchronous workflows: launches are async on the server, so an LLM can call this to wait for completion before fetching results. Terminal states: completed, completed_with_errors, failed.`}, func(ctx context.Context, _ *mcp.CallToolRequest, in waitScanInput) (*mcp.CallToolResult, map[string]any, error) {
		timeout := 1800
		if in.Timeout != nil {
			timeout = *in.Timeout
		}
		interval := 3
		if in.PollInterval != nil {
			interval = *in.PollInterval
		}
		deadline := time.Now().Add(time.Duration(timeout) * time.Second)
		terminal := map[string]bool{"completed": true, "completed_with_errors": true, "failed": true, "idle": true}
		var last map[string]any
		for {
			last, _ = apiJSON(ctx, "GET", "/api/scan/"+in.Target+"/status", nil, nil)
			if s, ok := last["status"].(string); ok && terminal[s] {
				return nil, last, nil
			}
			if time.Now().After(deadline) {
				return nil, nil, fmt.Errorf("scan for %s did not finish within %ds (last status: %v). Use get_scan_status to keep polling.", in.Target, timeout, last["status"])
			}
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(time.Duration(interval) * time.Second):
			}
		}
	})

	// ── 2. Target data ──
	mcp.AddTool(s, &mcp.Tool{Name: "list_targets", Description: "List all scanned targets with summary stats (name, status, vuln counts by severity, total_dirs, etc.)."}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/targets", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "get_target", Description: "Get the complete consolidated dataset for a target: metadata, subdomains, live subdomains, vulnerabilities, tech detections, header analysis, crawled URLs, directories, priority ranking, and all Phase-1 advanced-module results."}, func(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/target/"+in.Target, nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "delete_target", Description: "Delete a target and ALL of its data (database, raw output, screenshots, reports). Stops any running scan first. Irreversible."}, func(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "DELETE", "/api/target/"+in.Target, nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "bulk_delete_targets", Description: "Delete multiple targets at once."}, func(ctx context.Context, _ *mcp.CallToolRequest, in bulkDeleteInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "DELETE", "/api/targets/bulk", nil, map[string]any{"targets": in.Targets})
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "get_vulnerabilities", Description: "Get vulnerabilities for a target (Nuclei + Subzy findings), with severity/search filtering and pagination."}, func(ctx context.Context, _ *mcp.CallToolRequest, in vulnsInput) (*mcp.CallToolResult, map[string]any, error) {
		q := url.Values{}
		if in.Severity != nil {
			q.Set("severity", *in.Severity)
		}
		if in.Search != nil {
			q.Set("search", *in.Search)
		}
		page := 1
		if in.Page != nil {
			page = *in.Page
		}
		limit := 50
		if in.Limit != nil {
			limit = *in.Limit
		}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("limit", fmt.Sprintf("%d", limit))
		out, err := apiJSON(ctx, "GET", "/api/target/"+in.Target+"/vulns", q, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "get_priority", Description: "Get the priority ranking for a target — subdomains scored 0-100 by attack surface. Tiers: Critical (70-100), High (45-69.9), Medium (25-44.9), Low (0-24.9). Each entry includes reasons, tech_stack, vulnerabilities, missing_headers, suggested_manual_tests."}, func(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/target/"+in.Target+"/priority", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "export_target_json", Description: "Export a target's full dataset as a JSON object (meta, subdomains, live_hosts, vulns, crawled_urls, directories, priority)."}, func(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/target/"+in.Target+"/export", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "export_target_csv", Description: "Export a target's vulnerabilities as CSV text (Subdomain, Severity, Name, Template ID, Type, URL, Description). Returns {\"csv\": \"...\"}."}, func(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, map[string]any, error) {
		csv, err := apiText(ctx, "GET", "/api/target/"+in.Target+"/export/csv", nil)
		if err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"csv": csv}, nil
	})

	mcp.AddTool(s, &mcp.Tool{Name: "get_handoff", Description: "Get the Phase-2 handoff document for a target — the consolidated, prioritised contract for the exploitation phase (priority_targets + all URLs with parameters)."}, func(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/target/"+in.Target+"/handoff", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "get_subdomain_detail", Description: "Get a per-subdomain breakdown: live-host info, priority score with parsed reasons/tech/vulns/missing-headers/suggested-tests, vulnerabilities, takeover status, parameter-rich URLs, and discovered directories."}, func(ctx context.Context, _ *mcp.CallToolRequest, in targetSubInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/target/"+in.Target+"/subdomain/"+in.Subdomain, nil, nil)
		return nil, out, err
	})

	// ── 3. Configuration ──
	mcp.AddTool(s, &mcp.Tool{Name: "get_config", Description: "Get the current Dark-Recon configuration as a flat map (output_dir, threads, timeout, nuclei_*, katana_*, seclists_*, phase1 toggles, config_path, etc.)."}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/config", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "update_config", Description: `Update the Dark-Recon configuration (partial update — only the keys you provide are changed). Persisted to config.yaml; takes effect for subsequent scans.

Recognised flat keys: output_dir, threads, timeout, auto_install, top_subdomains_for_scanning, skip_phases, nuclei_templates_dir, nuclei_severity (array), nuclei_rate, nuclei_concurrent, nuclei_cvss_min, nuclei_timeout, nuclei_bulk_size, katana_depth, katana_concurrency, katana_headless, katana_js_parse, seclists_base_dir, dns_wordlist, dir_common_wordlist, dir_big_wordlist, dir_medium_wordlist, api_endpoints_wordlist, passive_recon, port_scan, waf_detect, js_analysis, param_discovery, secret_scan, chaos_api_key.`}, func(ctx context.Context, _ *mcp.CallToolRequest, in updateConfigInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "PUT", "/api/config", nil, in.Updates)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "browse_dirs", Description: "List subdirectories of a filesystem path (used to pick SecLists / nuclei template directories). Only directories returned; symlinks followed; dotfiles hidden."}, func(ctx context.Context, _ *mcp.CallToolRequest, in browseDirsInput) (*mcp.CallToolResult, map[string]any, error) {
		q := url.Values{}
		if in.Path != nil {
			q.Set("path", *in.Path)
		}
		out, err := apiJSON(ctx, "GET", "/api/fs/dirs", q, nil)
		return nil, out, err
	})

	// ── 4. Tool management ──
	mcp.AddTool(s, &mcp.Tool{Name: "list_tools", Description: "List all Dark-Recon-managed security tools with install status (subfinder, ffuf, httpx, webanalyze, katana, nuclei, subzy, chaos, nmap, naabu, wafw00f, arjun, trufflehog, gitleaks)."}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/tools", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "refresh_tools", Description: "Re-check the installation status of all tools (re-scans PATH + ~/go/bin)."}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/tools/refresh", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "get_tool", Description: "Get the status of a single tool (installed/path/version/description/phase)."}, func(ctx context.Context, _ *mcp.CallToolRequest, in toolInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/tools/"+in.Tool, nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "install_tool", Description: "Install a security tool (via go install / apt-get / pip depending on the tool). May take several minutes for large Go modules."}, func(ctx context.Context, _ *mcp.CallToolRequest, in toolInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "POST", "/api/tools/"+in.Tool+"/install", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "uninstall_tool", Description: "Uninstall a tool (removes ~/go/bin binary or runs apt remove). System-managed binaries cannot be auto-removed."}, func(ctx context.Context, _ *mcp.CallToolRequest, in toolInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "POST", "/api/tools/"+in.Tool+"/uninstall", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "check_tool", Description: "Check whether a tool is installed and report its version."}, func(ctx context.Context, _ *mcp.CallToolRequest, in toolInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "POST", "/api/tools/"+in.Tool+"/check", nil, nil)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{Name: "toggle_tool", Description: "Enable or disable a tool (note: in the current build all tools are effectively always enabled; this acknowledges the toggle for compatibility)."}, func(ctx context.Context, _ *mcp.CallToolRequest, in toggleToolInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "POST", "/api/tools/"+in.Tool+"/toggle", nil, map[string]any{"enabled": in.Enabled})
		return nil, out, err
	})

	// ── 5. Pipeline phases ──
	mcp.AddTool(s, &mcp.Tool{Name: "list_phases", Description: "List the Dark-Recon pipeline phases with their numbers and whether they are skippable/optional."}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := apiJSON(ctx, "GET", "/api/phases", nil, nil)
		return nil, out, err
	})

	// ── 6. Phase 1 advanced module results (read-only) ──
	phase1Tools := []struct {
		name, path, desc string
	}{
		{"get_phase1_findings", "/findings", "Get unified Phase-1 findings (nmap / wafw00f / js_analysis / trufflehog / gitleaks)."},
		{"get_phase1_ports", "/ports", "Get discovered open ports (nmap)."},
		{"get_phase1_js", "/js", "Get crawled JS files and the endpoints/secrets extracted from them."},
		{"get_phase1_params", "/params", "Get hidden parameters discovered by arjun."},
		{"get_phase1_secrets", "/secrets", "Get leaked secrets found by trufflehog + gitleaks (+ js_analysis)."},
		{"get_phase1_waf", "/waf", "Get per-host WAF detection results (wafw00f) and aggregated host intel."},
		{"get_phase1_intel", "/intel", "Get the aggregated per-host intel (ports/params/secrets/js/waf) plus passive-recon results."},
		{"get_phase1_status", "/status", "Report whether Phase 1 has completed, including completed phases and scan status."},
	}
	for _, t := range phase1Tools {
		t := t
		mcp.AddTool(s, &mcp.Tool{Name: t.name, Description: t.desc}, func(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, map[string]any, error) {
			out, err := apiJSON(ctx, "GET", "/api/phase1/"+in.Target+t.path, nil, nil)
			return nil, out, err
		})
	}

	// ── 7. Phase 2 foundation & data contract ──
	phase2Tools := []struct {
		name, path, desc string
		post bool
	}{
		{"start_phase2", "/start", "Signal intent to start Phase 2 (exploitation). Validates Phase 1 is complete. (Foundation stub in the current build.)", true},
		{"get_phase2_status", "/status", "Report Phase 2 readiness (phase2_ready/started/complete).", false},
		{"get_phase2_targets", "/targets", "Phase 2 contract — Query 1: prioritised targets. One row per live host joined with port/url/param/finding/secret counts, WAF, and priority score/tier.", false},
		{"get_phase2_findings", "/findings", "Phase 2 contract — Query 2: all findings ordered by severity. Unifies p1_findings with nuclei/subzy vulnerabilities.", false},
		{"get_phase2_urls", "/urls", "Phase 2 contract — Query 3: URLs with parameters for injection testing (Katana + arjun).", false},
		{"get_phase2_js", "/js", "Phase 2 contract — Query 4: JS findings (endpoints + secrets) joined to source JS URL.", false},
		{"get_phase2_ports", "/ports", "Phase 2 contract — Query 5: open ports joined with host priority score and WAF.", false},
	}
	for _, t := range phase2Tools {
		t := t
		method := "GET"
		if t.post {
			method = "POST"
		}
		mcp.AddTool(s, &mcp.Tool{Name: t.name, Description: t.desc}, func(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, map[string]any, error) {
			out, err := apiJSON(ctx, method, "/api/phase2/"+in.Target+t.path, nil, nil)
			return nil, out, err
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Input struct definitions
// ─────────────────────────────────────────────────────────────────────────────

type launchScanInput struct {
	Domain         string `json:"domain" jsonschema:"target root domain, e.g. example.com (required)"`
	Threads        *int   `json:"threads,omitempty" jsonschema:"per-tool concurrency (overrides config)"`
	Timeout        *int   `json:"timeout,omitempty" jsonschema:"per-request HTTP timeout in seconds"`
	TopSubdomains  *int   `json:"top_subdomains,omitempty" jsonschema:"top-N live hosts selected for directory enumeration"`
	SkipPhases     []int  `json:"skip_phases,omitempty" jsonschema:"phase numbers to skip (1=subdomain enum,2=live check,3=tech detection,4=crawling,5=vuln scanning,6=priority scoring)"`
	Resume         bool   `json:"resume,omitempty" jsonschema:"reserved for future resume-from-checkpoint support"`
	PassiveRecon   *bool  `json:"passive_recon,omitempty" jsonschema:"enable crt.sh/HackerTarget/AlienVault/chaos passive subdomain enumeration"`
	PortScan       *bool  `json:"port_scan,omitempty" jsonschema:"enable nmap stealth port scanning of live hosts"`
	WAFDetect      *bool  `json:"waf_detect,omitempty" jsonschema:"enable wafw00f WAF detection per host"`
	JSAnalysis     *bool  `json:"js_analysis,omitempty" jsonschema:"download & analyze JS files for endpoints/secrets (on by default)"`
	ParamDiscovery *bool  `json:"param_discovery,omitempty" jsonschema:"enable arjun hidden-parameter discovery"`
	SecretScan     *bool  `json:"secret_scan,omitempty" jsonschema:"enable trufflehog + gitleaks secret scanning"`
	ChaosAPIKey    *string `json:"chaos_api_key,omitempty" jsonschema:"ProjectDiscovery Chaos API key (for passive_recon)"`
}

type waitScanInput struct {
	Target        string `json:"target" jsonschema:"the target domain name"`
	Timeout       *int   `json:"timeout,omitempty" jsonschema:"maximum seconds to wait (default 1800 = 30 min)"`
	PollInterval  *int   `json:"poll_interval,omitempty" jsonschema:"seconds between status polls (default 3)"`
}

type bulkDeleteInput struct {
	Targets []string `json:"targets" jsonschema:"list of target domain names to delete"`
}

type vulnsInput struct {
	Target   string  `json:"target" jsonschema:"the target domain name"`
	Severity *string `json:"severity,omitempty" jsonschema:"comma-separated severity filter, e.g. critical,high"`
	Search   *string `json:"search,omitempty" jsonschema:"case-insensitive substring filter over name/subdomain/url"`
	Page     *int    `json:"page,omitempty" jsonschema:"1-indexed page number (default 1)"`
	Limit    *int    `json:"limit,omitempty" jsonschema:"page size (default 50)"`
}

type updateConfigInput struct {
	Updates map[string]any `json:"updates" jsonschema:"a JSON object of config keys to set (partial update)"`
}

type browseDirsInput struct {
	Path *string `json:"path,omitempty" jsonschema:"absolute path to browse (default /). ~ expands to home"`
}

type toggleToolInput struct {
	Tool    string `json:"tool" jsonschema:"tool name"`
	Enabled bool   `json:"enabled" jsonschema:"true to enable, false to disable"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Resources (read-only, addressable data)
// ─────────────────────────────────────────────────────────────────────────────

func registerResources(s *mcp.Server) {
	jsonMime := "application/json"

	// Static resources.
	static := []struct {
		uri, name, desc, path string
	}{
		{"dark-recon://config", "config", "Current Dark-Recon configuration", "/api/config"},
		{"dark-recon://phases", "phases", "Pipeline phase list", "/api/phases"},
		{"dark-recon://tools", "tools", "Security-tool inventory with install status", "/api/tools"},
		{"dark-recon://targets", "targets", "All scanned targets with summary stats", "/api/targets"},
		{"dark-recon://active-scans", "active-scans", "Currently running scans", "/api/scans/active"},
	}
	for _, r := range static {
		r := r
		s.AddResource(&mcp.Resource{URI: r.uri, Name: r.name, Description: r.desc, MIMEType: jsonMime},
			func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				return readResource(ctx, req.Params.URI, r.path, nil, nil)
			})
	}

	// Templated resources (one per target).
	tmpl := []struct {
		uri, name, desc, path string
	}{
		{"dark-recon://target/{target}/priority", "target-priority", "Priority ranking for a target", "/api/target/{t}/priority"},
		{"dark-recon://target/{target}/handoff", "target-handoff", "Phase-2 handoff document for a target", "/api/target/{t}/handoff"},
		{"dark-recon://target/{target}/vulns", "target-vulns", "All vulnerabilities for a target (up to 10000)", "/api/target/{t}/vulns"},
	}
	for _, r := range tmpl {
		r := r
		s.AddResourceTemplate(&mcp.ResourceTemplate{URITemplate: r.uri, Name: r.name, Description: r.desc, MIMEType: jsonMime},
			func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				t := extractTarget(req.Params.URI)
				path := strings.Replace(r.path, "{t}", t, 1)
				var q url.Values
				if strings.Contains(path, "/vulns") {
					q = url.Values{"page": {"1"}, "limit": {"10000"}}
				}
				return readResource(ctx, req.Params.URI, path, q, nil)
			})
	}
}

// readResource fetches a JSON endpoint and returns it as a text resource.
func readResource(ctx context.Context, uri, path string, query url.Values, body any) (*mcp.ReadResourceResult, error) {
	out, err := apiJSON(ctx, "GET", path, query, body)
	if err != nil {
		return nil, err
	}
	pretty, _ := json.MarshalIndent(out, "", "  ")
	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{
			URI:      uri,
			MIMEType: "application/json",
			Text:     string(pretty),
		}},
	}, nil
}

// extractTarget pulls the {target} variable out of a matched resource URI of
// the form dark-recon://target/<target>/...  (target domains contain dots,
// not slashes, so a simple split suffices).
func extractTarget(uri string) string {
	rest := strings.TrimPrefix(uri, "dark-recon://target/")
	if i := strings.Index(rest, "/"); i >= 0 {
		return rest[:i]
	}
	return rest
}

// keep strPtr/intptr referenced (future use / avoids unused warnings if helpers
// are trimmed later).
var _ = strPtr
var _ = intptr
