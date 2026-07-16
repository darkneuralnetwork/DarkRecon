<div align="center">

# 🦇 Dark-Recon

### Automated Attack-Surface Reconnaissance Platform

**A single Go binary that runs the entire Phase-1 recon lifecycle — from subdomain discovery to a prioritized, exploitation-ready target list — with a live web UI, REST API, and MCP integration for LLM agents.**

Engineered by [**Team Dark Neural Network (DNN)**](https://darkneuralnetwork.com)

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-red)](#license-disclaimer)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey)](#prerequisites)
[![Binary](https://img.shields.io/badge/Binary-Static%20%2F%20Self--contained-success)](#installation)

</div>

---

## Table of Contents

- [What is Dark-Recon?](#what-is-dark-recon)
- [Why Use It?](#why-use-it)
- [Features](#features)
  - [Core Pipeline](#core-pipeline)
  - [Platform](#platform)
  - [Engineering](#engineering)
- [Advanced Features](#advanced-features)
  - [1. Priority Scoring Engine](#1-priority-scoring-engine)
  - [2. Phase-1 Advanced Modules (opt-in per scan)](#2-phase-1-advanced-modules-opt-in-per-scan)
  - [3. MCP / LLM Integration](#3-mcp-llm-integration)
  - [4. Self-Healing Toolchain](#4-self-healing-toolchain)
  - [5. Phase-2 Handoff](#5-phase-2-handoff)
- [The Tools It Drives](#the-tools-it-drives)
- [Architecture](#architecture)
- [Scan Pipeline](#scan-pipeline)
- [Priority Scoring Engine](#priority-scoring-engine)
- [Prerequisites](#prerequisites)
  - [System Requirements](#system-requirements)
  - [Prerequisites Engine](#prerequisites-engine)
  - [SecLists & Nuclei Templates](#seclists-nuclei-templates)
- [Installation](#installation)
  - [Option 1 — Install script (recommended, any Linux/macOS)](#option-1-install-script-recommended-any-linuxmacos)
  - [Option 2 — `go install` (requires Go)](#option-2-go-install-requires-go)
  - [Option 3 — Build from source](#option-3-build-from-source)
  - [Option 4 — Debian/Ubuntu package (.deb)  ⭐ self-bootstrapping](#option-4-debianubuntu-package-deb-self-bootstrapping)
  - [Verify the install](#verify-the-install)
- [Configuration](#configuration)
  - [`config.yaml` (Main Config)](#configyaml-main-config)
  - [`tools_config.yaml` (Tool Config)](#tools_configyaml-tool-config)
  - [`llm_config.yaml` (LLM Config — for AI-assisted features)](#llm_configyaml-llm-config-for-ai-assisted-features)
- [Usage](#usage)
  - [Starting the server](#starting-the-server)
  - [Launching a scan](#launching-a-scan)
  - [Viewing results](#viewing-results)
- [API Reference](#api-reference)
  - [Scan Management](#scan-management)
  - [Target Data](#target-data)
  - [Phase-1 Advanced Modules](#phase-1-advanced-modules)
  - [Phase-2 Handoff](#phase-2-handoff)
  - [Configuration & Tools](#configuration-tools)
  - [WebSocket](#websocket)
- [MCP / LLM Integration](#mcp-llm-integration)
- [Web UI](#web-ui)
- [Output & Database](#output-database)
  - [Database Schema (11 tables, per target)](#database-schema-11-tables-per-target)
- [Security](#security)
- [Development](#development)
  - [Make targets](#make-targets)
  - [Dependencies](#dependencies)
  - [Project structure](#project-structure)
  - [Adding a new tool](#adding-a-new-tool)
  - [Adding a new module](#adding-a-new-module)
- [License & Disclaimer](#license-disclaimer)

---

## What is Dark-Recon?

**Dark-Recon** is a **Phase-1 Reconnaissance & Attack-Surface Discovery Engine**. You give it a root domain, and it autonomously orchestrates a multi-phase pipeline of industry-standard security tools to map the target's entire external attack surface — then ranks every finding by exploitability so you know *exactly where to attack first*.

It is not just a script wrapper. It is a **platform**: a concurrent pipeline engine, a SQLite data layer, a real-time web dashboard, a REST API, and an MCP server that lets AI agents drive the whole thing.

> **The problem it solves:** Manual recon is slow, repetitive, and inconsistent. Raw tool output is noisy and unranked. Dark-Recon turns a domain into a **prioritized, evidence-backed target list** with a Phase-2 handoff document — in minutes, consistently, every time.

---

## Why Use It?

| You're tired of… | Dark-Recon gives you… |
|---|---|
| Running 8 tools by hand and stitching outputs | One command → the full pipeline, automated |
| Drowning in unranked Nuclei findings | A **0–100 priority score** per subdomain with *why* |
| Losing track of what to attack first | A **Phase-2 handoff** doc: top targets, params, vulns |
| Re-doing recon with no history | **SQLite per-target databases** — resumable & queryable |
| Staring at a terminal during long scans | A **live web UI** with WebSocket progress streaming |
| Gluing tools into a CI/LLM workflow | A **REST API** + **MCP server** for Claude/Cursor/Cline |
| Half-installed toolchains on new boxes | A **self-bootstrapping** `.deb` that auto-installs its tools |
| Insecure `shell=True` recon scripts | **No shell injection** — `exec.Command` arg slices everywhere |

**In short:** Dark-Recon is the bridge between "I have a domain" and "I have a prioritized exploitation plan."

---

## Features

### Core Pipeline
- **8-phase orchestrator** with parallel execution wherever dependencies allow
- **Katana crawling before Nuclei** — crawled URLs are fed *into* Nuclei as extra targets
- **Subdomain takeover detection** (subzy) running in parallel with vuln scanning
- **Priority scoring** across 7 factors, normalized to a 0–100 scale with tiers
- **Resumable scans** — prior subdomain/live-host/URL data is reused when re-running phases

### Platform
- **Single static binary** — web UI embedded, no external asset dirs, no CGO
- **Real-time WebSocket** progress streaming during live scans
- **SQLite storage** (WAL mode, single-writer) — one DB per target, 11 tables
- **Pure HTML + JS frontend** — no server-side templating, no build step
- **REST API** — full programmatic control over scans, targets, tools, config
- **MCP server** — expose the whole platform to LLM clients over stdio
- **Tool auto-installation** — missing tools installed via `go install` on demand
- **Context-based cancellation** — long scans stop gracefully, partial results kept
- **Self-bootstrapping `.deb`** — checks + auto-installs prerequisites on first launch

### Engineering
- **No shell injection** — every subprocess uses `exec.CommandContext` with arg slices
- **Per-tool timeouts** via `context.WithTimeout` — nothing hangs forever
- **Structured logging** (`log/slog`) to console + rotating file
- **Decoupled modules** — each phase gets `*config.Config`, `*storage.DB`, `scanID`

---

## Advanced Features

### 1. Priority Scoring Engine
Every live subdomain is scored across **7 weighted factors** and normalized to **0–100**:

| Factor | Max | What it measures |
|---|---|---|
| Subdomain keywords | 30 | High-value names (`admin`, `api`, `staging`, `vpn`, …) |
| Vulnerability severity | 35 | Critical=35, High=25, Medium=15, Low=5 |
| Subdomain takeover | 25 | subzy-confirmed takeover |
| Exposed sensitive paths | 20 | `.env`, `.git`, `/admin`, `/phpmyadmin`, … |
| Missing security headers | 15 | CSP, HSTS, X-Frame-Options, … |
| Tech-stack risk | 12 | EOL/vulnerable patterns (PHP 5.x, Apache 2.4.49, …) |
| Parameter-rich URLs | 10 | Injection surface (query-param counts) |

**Tiers:** Critical (70–100) · High (45–69.9) · Medium (25–44.9) · Low (0–24.9)

The engine also emits **context-aware suggested manual tests** (e.g. `.env` → check credentials, `.git` → source leakage, missing CSP → XSS) — so the output isn't just a score, it's an action plan.

### 2. Phase-1 Advanced Modules (opt-in per scan)
Beyond the core 8 phases, Dark-Recon runs a set of additive advanced modules, each with a bounded worker-pool and graceful degradation if a tool is missing:

| Module | Tool | What it does |
|---|---|---|
| **Passive Recon** | crt.sh, HackerTarget, AlienVault, chaos | Certificate-transparency & OSINT subdomain intel |
| **Port Scan** | nmap | Stealth SYN / TCP-connect port scanning |
| **WAF Detection** | wafw00f | Identify the WAF protecting each host |
| **JS Analysis** | *pure Go* | Parse JS files for endpoints, secrets, and sourcemaps |
| **Parameter Discovery** | arjun | Discover hidden HTTP parameters |
| **Secret Scanning** | trufflehog + gitleaks | Find leaked secrets in crawled JS/files |

### 3. MCP / LLM Integration
The same binary doubles as an **MCP (Model Context Protocol) server**. Point Claude Desktop, Cursor, or Cline at it and an LLM can:
- Launch & monitor scans (`launch_scan`, `wait_for_scan`)
- Retrieve prioritized findings & Phase-2 handoffs
- Manage tools and edit configuration
- Export JSON/CSV reports

> One binary, two interfaces: **HTTP** for humans, **stdio MCP** for agents.

### 4. Self-Healing Toolchain
The bundled prerequisites engine (`scripts/check-prereqs.sh`) is the **single source of truth** — shared by the CLI, the web UI, and the `.deb` launcher. When installed from the `.deb`, the launcher **auto-installs missing required Go tools on first run** (no `sudo` needed for the core pipeline) and caches the result so subsequent launches are instant.

### 5. Phase-2 Handoff
Dark-Recon doesn't stop at "findings." It emits a `phase2_handoff.json` — a consolidated, prioritized contract for the exploitation phase: top priority targets, all URLs with parameters, vuln counts by severity. Recon hands off cleanly to offense.

---

## The Tools It Drives

Dark-Recon orchestrates these external tools (installed automatically when missing):

| Tool | Phase | Install |
|---|---|---|
| **subfinder** | Subdomain enumeration (passive) | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **ffuf** | DNS brute + directory fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |
| **httpx** | Live host detection | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **webanalyze** | Technology fingerprinting | `go install github.com/rverton/webanalyze/cmd/webanalyze@latest` |
| **katana** | Web crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| **nuclei** | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **subzy** | Subdomain takeover | `go install github.com/PentestPad/subzy@latest` |
| **nmap** *(opt)* | Port scanning | `sudo apt install nmap` |
| **naabu** *(opt)* | Fast port scanning (alt) | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| **chaos** *(opt)* | Passive subdomain intel | `go install github.com/projectdiscovery/chaos/cmd/chaos@latest` |
| **trufflehog** *(opt)* | Secret scanning | `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| **gitleaks** *(opt)* | Secret scanning | `go install github.com/gitleaks/gitleaks/v8@latest` |
| **wafw00f** *(opt)* | WAF detection | `pip install wafw00f` |
| **arjun** *(opt)* | Parameter discovery | `pip install arjun` |
| **seclists** *(rec)* | Wordlists | `sudo apt install seclists` |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Web Browser / LLM Agent               │
│  (HTML+JS UI, fetch() REST, WebSocket)   (MCP over stdio)    │
└──────────────────────────┬───────────────────────────────────┘
                           │ HTTP / WebSocket / stdio
┌──────────────────────────▼───────────────────────────────────┐
│            API Layer (internal/api) + MCP (internal/mcp)      │
│  REST handlers · WebSocket upgrader · static/template serving │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                  Scan Manager (internal/scanmgr)              │
│  Background goroutines · progress tracking · cancel context   │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│            Pipeline Engine (internal/pipeline)                │
│  8-phase orchestrator + Phase-1 advanced modules              │
└──────────────────────────┬───────────────────────────────────┘
                           │
        ┌──────────┬───────┴───────┬──────────┬──────────────┐
        ▼          ▼               ▼          ▼              ▼
   enumeration  discovery     technology   nuclei      scoring
   (subfinder,  (httpx,       (webanalyze  (nuclei,    (priority
    ffuf DNS)    katana)       + headers)   subzy)      ranking)
        │          │               │          │              │
        ▼          ▼               ▼          ▼              ▼
┌──────────────────────────────────────────────────────────────┐
│                   Storage Layer (internal/storage)            │
│        SQLite (WAL mode) — 11 tables, one DB per target       │
└──────────────────────────────────────────────────────────────┘
        │                                          │
        ▼                                          ▼
   pkg/executor                              pkg/parser
   (subprocess runner, no shell)            (output parsers)
```

**Design principles:** concurrency (parallel phases) · context cancellation · decoupled modules (no shared mutable state) · single-writer SQLite · no shell injection · structured logging.

---

## Scan Pipeline

```
Phase 1: Subdomain Enumeration (+ Passive Recon in parallel)
    │  subfinder (passive) + ffuf DNS brute + Go-native DNS resolution
    │  (+ crt.sh / HackerTarget / AlienVault / chaos if passive_recon)
    ▼
Phase 2: Live Host Detection
    │  httpx probes all subdomains — status, title, webserver, CDN, tech, redirect
    ▼
Phase 3 + Phase 4  (PARALLEL)
    │  ┌─ Technology Detection (webanalyze + HTTP header analysis)
    │  └─ Deep Crawling (Katana, ALL live hosts) → URLs feed into Nuclei
    ▼
Phase 5: URL Intelligence Layer
    │  ffuf directory enumeration on top-N live hosts (SecLists wordlists)
    ▼
Phase 6: Vulnerability Scanning (PARALLEL)
    │  ┌─ Nuclei (live hosts + Katana-crawled URLs), filtered by severity + CVSS
    │  └─ Subzy (subdomain takeover detection)
    ▼
Phase 7: Screenshot Collection
    │  gowitness captures screenshots of all live hosts
    ▼
Phase 8: Priority Scoring
    │  Scores every subdomain across 7 factors → 0-100 → tier
    │  Generates report.json + phase2_handoff.json
    ▼
DONE → SQLite DB + JSON reports + handoff file
```

Phase-1 advanced modules (passive recon, port scan, WAF detect, JS analysis, param discovery, secret scan) run **additively** alongside the relevant phases when enabled in config.

---

## Priority Scoring Engine

See the [Advanced Features](#1-priority-scoring-engine) section above for the 7-factor breakdown.

**Output files (per target):**
- `priority/priority_ranking.json` — full ranked list with scores, reasons, tech stack, vulns, param URLs, exposed dirs, missing headers, takeover status, suggested tests
- `priority/phase2_handoff.json` — consolidated handoff for exploitation: target, total subdomains, vuln counts by severity, all priority targets, all URLs with parameters
- `reports/report.json` — consolidated report (live hosts, vulns, crawled URLs, directories, priority)

---

## Prerequisites

### System Requirements
- **Linux** (tested on Parrot OS / Debian-based), amd64 or arm64 *(macOS also builds)*
- **libc6** — the only hard `.deb` dependency; always present on Debian/Ubuntu
- ~50MB free disk for binaries + output data
- **Go** (any recent release) — *only needed to `go install` the security tools*. The Dark-Recon server binary itself is pre-built and statically linked, so it runs without Go. (Building from source declares `go 1.25` in `go.mod`; the Go toolchain auto-downloads a compatible compiler on demand.)

### Prerequisites Engine
A single script — `scripts/check-prereqs.sh` — is the source of truth for the CLI, the web UI, and the `.deb` launcher. It checks the system, the build toolchain, every security tool (with installed version + path), and the wordlists/templates, and can auto-install missing items.

```bash
make check-prereqs                                  # read-only status report (versions + paths)
make install-tools                                  # install missing REQUIRED tools
bash scripts/check-prereqs.sh --install             # same, explicitly
bash scripts/check-prereqs.sh --install --strict    # also install OPTIONAL tools
```

### SecLists & Nuclei Templates
```bash
sudo apt install seclists                  # wordlists for dir/DNS brute
nuclei -update-templates                   # templates install to ~/nuclei-templates/
```
Ensure paths in `config.yaml` match your installation.

---

## Installation

Dark-Recon ships as a single static, self-contained binary — the web UI is embedded, so there are no external asset directories to manage. Pick whichever method suits you.

> 💡 **New install? Use the `.deb` (Option 4) on Debian/Ubuntu** — it auto-installs its own prerequisites on first launch.

### Option 1 — Install script (recommended, any Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/yourname/dark-recon/main/install.sh | bash
```

Downloads the correct binary for your OS/arch (linux & macOS, amd64 & arm64), verifies its sha256 checksum, installs it to `/usr/local/bin` (or `~/.local/bin`), then runs the prerequisites check. Falls back to `go install` or build-from-source if no pre-built binary exists for your platform.

```bash
# Options:
curl ... | bash -s -- --version v1.0.0     # specific release tag
curl ... | bash -s -- --skip-check         # don't run prereqs check
```

### Option 2 — `go install` (requires Go)

```bash
go install github.com/yourname/dark-recon/cmd/dark-recon@latest
```
The binary lands in `$(go env GOPATH)/bin` — make sure that's on your `PATH`.

### Option 3 — Build from source

```bash
git clone https://github.com/yourname/dark-recon.git
cd dark-recon
make build          # produces ./dark-recon (static, CGO disabled)
./dark-recon -port 5000
```

### Option 4 — Debian/Ubuntu package (.deb)  ⭐ self-bootstrapping

Build it locally, or download a pre-built `.deb` from the [GitHub Releases](https://github.com/yourname/dark-recon/releases) (attached automatically on every tag push via CI for both `amd64` and `arm64`), then install:

```bash
make deb                                # produces dist/dark-recon_<ver>_<arch>.deb
sudo apt install ./dist/dark-recon_*.deb

# Or install straight from a downloaded release asset:
sudo apt install ./dark-recon_1.0.0_amd64.deb
```

The package installs the static server binary, default config, wordlists, UI assets, and the prerequisites engine under `/usr/share/dark-recon/`, plus a launcher at `/usr/local/bin/dark-recon`. Only `libc6` is a hard dependency; everything else (nmap, git, ca-certificates, golang-go, seclists) is a `Recommends` so the install never blocks on a minimal system.

**At install time** `postinst` runs a fast, read-only **prerequisites verification** (system check, no network) so you see what's present/missing immediately. **On first launch** the launcher runs the prerequisites engine with `--install`, which checks the system and **auto-installs any missing required Go security tools** (subfinder, ffuf, httpx, webanalyze, katana, nuclei, subzy — no `sudo` needed). Optional tools are reported, not installed. A successful check is cached (`/var/lib/dark-recon/.prereqs-ok` for root, or `~/.cache/dark-recon/.prereqs-ok` otherwise) so subsequent launches are instant.

```bash
dark-recon prereqs                       # read-only status report
dark-recon prereqs --install             # install missing REQUIRED tools
dark-recon prereqs --install --strict    # also install OPTIONAL tools

# Env knobs:
DARK_RECON_SKIP_PREREQS=1 dark-recon ...        # skip the first-run check entirely
DARK_RECON_FORCE_PREREQS=1 dark-recon ...       # force a recheck
DARK_RECON_INSTALL_PREREQS=1 sudo apt install ./dark-recon_*.deb   # full bootstrap at install time
```

### Verify the install

```bash
dark-recon -h                # prints usage
dark-recon prereqs           # confirms all tools present
```

---

## Configuration

### `config.yaml` (Main Config)

```yaml
target: ''                            # Target domain (set at scan launch)
output_dir: ~/dark_recon_results      # Base output directory
threads: 200                          # Concurrency for tools
timeout: 10                           # HTTP timeout (seconds)
auto_install: true                    # Auto-install missing tools
top_subdomains_for_scanning: 10       # Top-N for dir enumeration

seclists:
  base_dir: /usr/share/wordlists/seclists
  dns_wordlist:  /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
  dir_common:    /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
  dir_big:       /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
  dir_medium:    /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
  api_endpoints: /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt

nuclei:
  templates: ~/nuclei-templates
  severity: [critical, high]           # Severity levels to include
  rate: 250                            # Requests per second
  concurrent: 50                       # Concurrent templates
  cvss_min: 8                          # Minimum CVSS score to report
  timeout: 90                          # Max scan duration (minutes)
  bulk_size: 50                        # Hosts per batch

katana:
  depth: 3
  concurrency: 50
  headless: true                       # active browser-based crawling
  js_parse: true                       # parse + crawl JS endpoints

# Phase-1 advanced modules (all OFF by default; opt in per scan)
phase1:
  passive_recon: false
  port_scan: false
  waf_detect: false
  js_analysis: true
  param_discovery: false
  secret_scan: false
  chaos_api_key: ""
  passive_recon_workers: 5
  port_scan_workers: 50
  waf_workers: 20
  js_analysis_workers: 30
  param_discovery_workers: 5
  secret_scan_workers: 10

priority_keywords:
  critical: [admin, api, staging, internal, vpn, auth, login, dashboard, console, manage]
  high:     [dev, test, uat, beta, app, portal, gateway, control, panel, root]
  medium:   [www, mail, cdn, static, blog, shop, store, media]

exposed_path_scores:
  .env: 20
  .git: 15
  /admin: 10
  /phpmyadmin: 12
  # ... (see config.yaml for the full list)

skip_phases: []                       # Phase numbers to skip (1-8)
```

### `tools_config.yaml` (Tool Config)

```yaml
enabled_tools:
  subfinder: true
  ffuf: true
  httpx: true
  nuclei: true
  katana: true
  subzy: true
  webanalyze: true
  nmap: true
tool_config:
  nuclei:
    args: ''
    phase: ''
```

### `llm_config.yaml` (LLM Config — for AI-assisted features)

```yaml
enabled: true
provider: ollama          # ollama, openai, etc.
model: llama3
api_key: ''
base_url: http://localhost:11434
onboarded: true
```

Config can be viewed and edited at runtime via the **Settings** page or the API (`GET`/`PUT /api/config`).

---

## Usage

### Starting the server

```bash
# Compiled binary
./dark-recon -port 5000

# Via make
make run          # builds + runs on port 5000

# Via go
go run ./cmd/dark-recon/ -port 5000
```

**Command-line flags:**

| Flag | Default | Description |
|---|---|---|
| `-port` | `5000` | HTTP server port |
| `-config` | `config.yaml` (auto-detected) | Path to config file |
| `-templates` | `dark_recon/ui/templates` (auto-detected) | HTML template directory |
| `-static` | `dark_recon/ui/static` (auto-detected) | Static files directory |

**Subcommand:**

| Subcommand | Description |
|---|---|
| `dark-recon mcp` | Run the MCP server over stdio (for LLM clients) |
| `dark-recon prereqs [--install] [--strict]` | Run the prerequisites engine |

### Launching a scan

1. Open `http://localhost:5000` in your browser
2. Click **New Scan** in the sidebar
3. Enter a target domain (e.g. `example.com`)
4. Adjust settings (threads, timeout, severity filters, opt-in modules)
5. Click **Launch Scan**
6. Get redirected to the live progress page with real-time WebSocket updates

### Viewing results

| Page | Route | What you see |
|---|---|---|
| Dashboard | `/` | All scanned targets with stats + bulk delete |
| Target Detail | `/target/{name}` | Subdomains, vulns, priority, tech, takeover, dirs |
| Subdomain Detail | `/target/{name}/subdomain/{sub}` | Per-subdomain breakdown + suggested manual tests |
| Live Progress | `/scan/{name}/progress` | Real-time phase tracker + log stream |
| Tools | `/tools` | Tool install status, install/uninstall, toggle |
| Settings | `/settings` | Full config editor |

---

## API Reference

All API endpoints return JSON. Base URL: `http://localhost:5000`

### Scan Management
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan/launch` | Launch a scan (`{"target": "example.com", ...}`) |
| `POST` | `/api/scan/{target}/stop` | Stop a running scan |
| `GET` | `/api/scan/{target}/status` | Scan status + recent logs |
| `GET` | `/api/scan/{target}/logs` | Full progress log |
| `GET` | `/api/scans/active` | List all active scans |

### Target Data
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/targets` | List all scanned targets |
| `GET` | `/api/dashboard/summary` | Dashboard summary stats |
| `GET` | `/api/target/{target}` | Full target dataset |
| `DELETE` | `/api/target/{target}` | Delete a target + all data |
| `DELETE` | `/api/targets/bulk` | Bulk delete targets |
| `GET` | `/api/target/{target}/vulns` | Vulnerabilities (filterable) |
| `GET` | `/api/target/{target}/priority` | Priority ranking |
| `GET` | `/api/target/{target}/export` | Export as JSON |
| `GET` | `/api/target/{target}/export/csv` | Export priority as CSV |
| `GET` | `/api/target/{target}/handoff` | Phase-2 handoff file |
| `GET` | `/api/target/{target}/subdomain/{sub}` | Subdomain detail |

### Phase-1 Advanced Modules
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/phase1/{target}/findings` | All Phase-1 findings |
| `GET` | `/api/phase1/{target}/ports` | Port-scan results |
| `GET` | `/api/phase1/{target}/js` | JS analysis results |
| `GET` | `/api/phase1/{target}/params` | Discovered parameters |
| `GET` | `/api/phase1/{target}/secrets` | Secret-scan findings |
| `GET` | `/api/phase1/{target}/waf` | WAF detection results |
| `GET` | `/api/phase1/{target}/intel` | Passive recon intel |
| `GET` | `/api/phase1/{target}/status` | Phase-1 module status |

### Phase-2 Handoff
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/phase2/{target}/start` | Start Phase-2 tracking |
| `GET` | `/api/phase2/{target}/status` | Phase-2 status |
| `GET` | `/api/phase2/{target}/targets` | Phase-2 priority targets |
| `GET` | `/api/phase2/{target}/findings` | Phase-2 findings |
| `GET` | `/api/phase2/{target}/urls` | URLs with parameters |

### Configuration & Tools
| Method | Endpoint | Description |
|---|---|---|
| `GET` `PUT` | `/api/config` | Get / update configuration |
| `GET` | `/api/fs/dirs` | Browse filesystem dirs (for wordlist/template pickers) |
| `GET` | `/api/tools` | List all tools with install status |
| `POST` | `/api/tools/{tool}/install` | Install a tool |
| `POST` | `/api/tools/{tool}/uninstall` | Uninstall a tool |
| `GET` | `/api/phases` | List all pipeline phases |

### WebSocket
| Endpoint | Description |
|---|---|
| `ws://localhost:5000/ws/{target}` | Live progress stream for a scan |
| `ws://localhost:5000/ws` | Global progress stream (all scans) |

**Message format:**
```json
{ "timestamp": "14:32:05", "phase": "subdomain_enum", "status": "completed", "message": "...", "count": 42 }
```

---

## MCP / LLM Integration

Dark-Recon's binary doubles as an **MCP server**, exposing the full platform to LLM clients (Claude Desktop, Cursor, Cline, …) over stdio. It's a thin client over the REST API — point it at a running server:

```bash
# Start the web server
dark-recon -port 5000 &

# Run the MCP server (same binary)
dark-recon mcp                       # uses http://localhost:5000
DARK_RECON_URL=http://localhost:5000 dark-recon mcp
dark-recon mcp -url http://host:5000
```

**Exposed MCP tools** (1:1 wrappers over the REST API):
- `launch_scan`, `stop_scan`, `get_scan_status`, `get_scan_logs`, `list_active_scans`, `wait_for_scan`
- `list_targets`, `get_target`, `delete_target`, `bulk_delete_targets`
- `get_vulnerabilities`, `get_priority`, `get_subdomain_detail`
- `export_target_json`, `export_target_csv`, `get_handoff`
- `get_config`, `update_config`, `browse_dirs`
- `list_tools`, `refresh_tools`, `get_tool`, `install_tool`, `uninstall_tool`

**Example Claude Desktop config** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "dark-recon": {
      "command": "dark-recon",
      "args": ["mcp"]
    }
  }
}
```

Then ask Claude: *"Launch a recon scan against example.com, wait for it to finish, and give me the top 5 priority targets with reasons."*

---

## Web UI

The frontend is **pure HTML + JavaScript** — no server-side templating, no build step. All dynamic content renders client-side via `fetch()` to the REST API.

| Page | Description |
|---|---|
| **Dashboard** | Grid of target cards with vuln counts, priority-tier badges, bulk delete |
| **Scan Launch** | Target input + config overrides + active scan list |
| **Live Progress** | Real-time WebSocket log stream, phase tracker with status indicators, exponential-backoff reconnect |
| **Target Detail** | Stats overview, tech badges, sortable priority table, expandable vuln rows with severity filter, takeover results, discovered dirs |
| **Subdomain Detail** | Priority score breakdown, vulns, takeover status, parameter-rich URLs, suggested manual tests |
| **Tools** | Tool cards with install status, search/filter, install/uninstall, enable/disable toggle |
| **Settings** | Full config editor — all fields populated from API, save via PUT |

Includes a dark/light theme toggle with `localStorage` persistence.

---

## Output & Database

Each scan creates files under `~/dark_recon_results/<target>/`:

```
<target>/
├── scan.db                      # SQLite database (primary storage)
├── dark-recon.log               # Application log
├── raw/                         # Raw tool outputs
│   ├── subfinder.txt   ffuf_dns.txt   httpx.json
│   ├── katana.json     nuclei.json    webanalyze.json   subzy.txt
├── parsed/                      # Parsed/intermediate files
│   ├── subdomains.txt   live_subdomains.txt   all_urls.txt   nuclei_targets.txt
├── priority/                    # Scoring output
│   ├── priority_ranking.json    # Full priority ranking
│   └── phase2_handoff.json      # Handoff for Phase 2 (exploitation)
├── reports/
│   └── report.json              # Consolidated JSON report
└── screenshots/                 # gowitness screenshots
    └── *.png
```

### Database Schema (11 tables, per target)
`scan_meta` · `subdomains` · `live_hosts` · `tech_detections` · `crawled_urls` · `discovered_dirs` · `vulnerabilities` · `takeover_results` · `screenshots` · `priority_entries` · `header_results`

All tables indexed on `scan_id` and relevant lookup columns. WAL journal mode + `MaxOpenConns(1)` for safe concurrent reads during scans.

---

## Security

Dark-Recon was rewritten in Go specifically to fix the security issues common in shell-based recon scripts:

| Concern | How Dark-Recon handles it |
|---|---|
| **Command injection** | `exec.CommandContext` with argument slices — never invokes a shell |
| **Path traversal** | `filepath.Join()` used throughout |
| **Runaway tools** | Every execution has a `context.WithTimeout` |
| **Uncancellable scans** | `context.CancelFunc` propagated to all goroutines |
| **Concurrent DB writes** | SQLite WAL mode + `MaxOpenConns(1)` single-writer |
| **Secrets in logs** | Tool output truncated in logs (200 chars for errors) |
| **Broken toolchains** | Robust availability check runs `<tool> -version` (not just `LookPath`) — catches half-installed/zero-byte binaries |

---

## Development

### Make targets
```bash
make help            # list all targets
make build           # static binary (CGO disabled)
make run             # build + run on port 5000
make mcp             # run the MCP server
make vet             # go vet
make test            # go vet + tests
make fmt             # format Go code
make check-prereqs   # read-only prerequisites report
make install-tools   # install missing security tools
make deb             # build the .deb package
make clean           # remove build artifacts
```

### Dependencies

| Module | Version | Purpose |
|---|---|---|
| `github.com/gorilla/websocket` | v1.5.3 | WebSocket live progress |
| `github.com/modelcontextprotocol/go-sdk` | v1.6.1 | MCP server for LLM clients |
| `gopkg.in/yaml.v3` | v3.0.1 | YAML config parsing |
| `modernc.org/sqlite` | v1.53.0 | Pure-Go SQLite driver (no CGO) |

### Project structure
```
dark-recon/
├── cmd/dark-recon/main.go         # Entry point
├── internal/
│   ├── api/        # REST + WebSocket handlers (29 routes)
│   ├── config/     # YAML config loader
│   ├── enumeration/  discovery/   technology/   direnum/
│   ├── nuclei/     takeover/      scoring/       scanmgr/
│   ├── pipeline/   # 8-phase orchestrator
│   ├── phasemod/   # Phase-1 advanced modules
│   ├── installer/  # Tool management (BuiltinTools map)
│   ├── mcp/        # MCP server (LLM integration)
│   └── storage/    # SQLite schema + CRUD
├── pkg/
│   ├── executor/   # subprocess runner (no shell)
│   ├── parser/     # JSONL/subfinder/katana/subzy parsers
│   └── logger/     # slog structured logging
├── dark_recon/ui/  # embedded HTML templates + static assets
├── scripts/        # check-prereqs.sh, install-tools.sh
├── dist/           # build-deb.sh
├── config.yaml     tools_config.yaml   llm_config.yaml
└── Makefile
```

### Adding a new tool
1. Add the tool definition to `BuiltinTools` in `internal/installer/installer.go`
2. **Keep it in sync** with the `TOOLS` table in `scripts/check-prereqs.sh` (single source of truth)
3. Add an `enabled_tools` entry in `tools_config.yaml`
4. Invoke via `executor.Run()`; add a parser in `pkg/parser/` if the output format is new

### Adding a new module
1. Create a package under `internal/<module>/`
2. Implement a `Run(ctx context.Context) (*Result, error)` method
3. Add the phase to `internal/pipeline/engine.go`
4. Add storage methods + models if new tables are needed
5. Add API handlers + register routes in `internal/api/routes.go`

---


## ⚖️ License

This project is intended for **authorized security testing and educational use only**. Always obtain proper written authorization before scanning any target you do not own. The authors are not responsible for misuse or damage caused by this tool.

DarkRecon is proudly open-source, released under the **GNU General Public License v3.0 (GPL-3.0)**. 

You are free to use, study, modify, and distribute this software, provided all derivative works remain under the GPL-3.0 license. [Read the full license here](LICENSE).

---

<div align="center">

### Engineered by [Dark Neural Network](https://darkneuralnetwork.com)
*Building the next generation of intelligent autonomous systems.*

🌐 [Website](https://darkneuralnetwork.com) &nbsp;&nbsp;•&nbsp;&nbsp; ⭐ Star on GitHub &nbsp;&nbsp;•&nbsp;&nbsp; 🤝 Join the Community

**Dark-Recon v1.0.0** — *Built with Go, structured logging, and a passion for automated recon.*

🦇 From domain → prioritized attack plan, in minutes.

</div>

---
