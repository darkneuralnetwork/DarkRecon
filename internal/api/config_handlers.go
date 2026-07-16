package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/yourname/dark-recon/internal/config"
)

func (h *Handlers) GetConfig(w http.ResponseWriter, r *http.Request) {
	// Return a FLAT map so the Settings page (and app.js) can read fields
	// directly as cfg.threads / cfg.nuclei_rate / cfg.seclists_base_dir.
	out := h.cfg.ToMap()
	out["config_path"] = h.configPath
	writeJSON(w, 200, out)
}

func (h *Handlers) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	var updates map[string]any
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeError(w, 400, "Invalid request body")
		return
	}

	cfg, err := config.Load(h.configPath, updates)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if err := cfg.Save(h.configPath); err != nil {
		writeError(w, 500, err.Error())
		return
	}

	h.cfg = cfg

	writeJSON(w, 200, map[string]string{"status": "saved", "config_path": h.configPath})
}

// BrowseDirs lists the subdirectories of a path for the Settings page's
// directory picker (SecLists base dir / wordlist paths / nuclei templates).
// Only directories are returned — never file contents. Hidden entries
// (starting with '.') are hidden to keep the list navigable.
//
//	GET /api/fs/dirs?path=/usr/share
func (h *Handlers) BrowseDirs(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}
	path = expandHomePath(path)

	type dirItem struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	dirs := []dirItem{}

	if info, err := os.Stat(path); err == nil && info.IsDir() {
		if entries, err := os.ReadDir(path); err == nil {
			for _, e := range entries {
				name := e.Name()
				if strings.HasPrefix(name, ".") {
					continue
				}
				full := filepath.Join(path, name)
				// Follow symlinks: os.Stat resolves the link target, so a
				// symlink pointing at a directory is navigable. This matters
				// on Kali where /usr/share/wordlists/* are mostly symlinks.
				fi, err := os.Stat(full)
				if err != nil || !fi.IsDir() {
					continue
				}
				dirs = append(dirs, dirItem{Name: name, Path: full})
			}
		}
	}

	writeJSON(w, 200, map[string]any{
		"path":   path,
		"parent": parentDir(path),
		"dirs":   dirs,
	})
}

// expandHomePath resolves a leading ~ to the user's home directory.
func expandHomePath(p string) string {
	if p == "" {
		return "/"
	}
	if p == "~" {
		home, _ := os.UserHomeDir()
		return home
	}
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}

// parentDir returns the parent of a path, rooted at "/".
func parentDir(p string) string {
	p = strings.TrimRight(p, "/")
	if p == "" || p == "/" {
		return "/"
	}
	parent := filepath.Dir(p)
	if parent == "." {
		return "/"
	}
	return parent
}
