package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/yourname/dark-recon/internal/api"
	"github.com/yourname/dark-recon/internal/config"
	mcpserver "github.com/yourname/dark-recon/internal/mcp"
	"github.com/yourname/dark-recon/internal/scanmgr"
	"github.com/yourname/dark-recon/pkg/logger"
)

func main() {
	// `dark-recon mcp` runs the MCP (Model Context Protocol) server over
	// stdio, exposing the running Dark-Recon instance to LLM clients. It is
	// the same binary as the web server.
	if len(os.Args) > 1 && os.Args[1] == "mcp" {
		if err := mcpserver.Run(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "mcp: %v\n", err)
			os.Exit(1)
		}
		return
	}

	port := flag.Int("port", 5000, "HTTP server port")
	configPath := flag.String("config", "", "Path to config.yaml")
	templateDir := flag.String("templates", "", "Path to HTML template directory")
	staticDir := flag.String("static", "", "Path to static files directory")
	flag.Parse()

	// Resolve config path
	if *configPath == "" {
		*configPath = config.DefaultConfigPath()
	}

	// Load config
	cfg, err := config.Load(*configPath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logFile := filepath.Join(cfg.OutputDir, "dark-recon.log")
	logger.Init(0, logFile)

	logger.Success("Dark-Recon v1.0.0 (Go)")
	logger.Success("Target: %s", cfg.Target)
	logger.Success("Output: %s", cfg.OutputDir)
	logger.Success("Config: %s", *configPath)

	// Resolve template and static directories
	if *templateDir == "" {
		// Try relative paths from the executable / cwd
		candidates := []string{
			"dark_recon/ui/templates",
			"../dark_recon/ui/templates",
			filepath.Join(filepath.Dir(*configPath), "dark_recon/ui/templates"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				*templateDir = c
				break
			}
		}
	}
	if *staticDir == "" {
		candidates := []string{
			"dark_recon/ui/static",
			"../dark_recon/ui/static",
			filepath.Join(filepath.Dir(*configPath), "dark_recon/ui/static"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				*staticDir = c
				break
			}
		}
	}

	if *templateDir == "" {
		logger.Success("Templates: (will use embedded assets)")
	} else {
		logger.Success("Templates: %s", *templateDir)
	}
	if *staticDir == "" {
		logger.Success("Static: (will use embedded assets)")
	} else {
		logger.Success("Static: %s", *staticDir)
	}

	// Create scan manager (no shared DB — each scan opens its own)
	scanMgr := scanmgr.New(nil)

	// Create API handlers
	handlers := api.New(cfg, *configPath, scanMgr)

	// Register routes
	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux, *templateDir, *staticDir)

	// Start HTTP server
	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	logger.Success("Server starting on http://localhost:%d", *port)
	if err := server.ListenAndServe(); err != nil {
		logger.Err("Server failed: %v", err)
		os.Exit(1)
	}
}
