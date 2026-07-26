package installer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/yourname/dark-recon/pkg/executor"
	"github.com/yourname/dark-recon/pkg/logger"
)

// ToolDef defines a single tool's installation metadata.
type ToolDef struct {
	Method      string `yaml:"method" json:"method"`
	InstallCmd  string `yaml:"install_cmd" json:"install_cmd"`
	CheckCmd    string `yaml:"check_cmd" json:"check_cmd"`
	Description string `yaml:"description" json:"description"`
	Phase       string `yaml:"phase" json:"phase"` // scan phase that uses this tool
}

// ToolStatus holds the full status of a tool for the UI.
type ToolStatus struct {
	Name        string `json:"name"`
	Installed   bool   `json:"installed"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Method      string `json:"method"`
	InstallCmd  string `json:"install_cmd"`
	CheckCmd    string `json:"check_cmd"`
	Enabled     bool   `json:"enabled"`
	Phase       string `json:"phase"`
	Args        string `json:"args"`
	IsCustom    bool   `json:"is_custom"`
}

// BuiltinTools is the Go equivalent of Python's TOOL_DEFINITIONS.
// Every tool the pipeline can invoke is listed here, tagged with the scan
// phase that uses it, so the Tools UI shows a complete inventory with status.
var BuiltinTools = map[string]ToolDef{
	// ── Core Phase 1 pipeline ──
	"subfinder":  {Method: "go", Phase: "Subdomain Enum", InstallCmd: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", CheckCmd: "subfinder -version", Description: "Passive subdomain enumeration"},
	"ffuf":       {Method: "go", Phase: "Subdomain Enum + Dir Brute", InstallCmd: "go install github.com/ffuf/ffuf/v2@latest", CheckCmd: "ffuf -V", Description: "Fast web fuzzer (DNS + directory brute)"},
	"httpx":      {Method: "go", Phase: "Live Host Detection", InstallCmd: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", CheckCmd: "httpx -version", Description: "Fast HTTP prober"},
	"webanalyze": {Method: "go", Phase: "Tech Detection", InstallCmd: "go install github.com/rverton/webanalyze/cmd/webanalyze@latest", CheckCmd: "webanalyze -h", Description: "Wappalyzer-style tech detection"},
	"katana":     {Method: "go", Phase: "Crawling", InstallCmd: "go install github.com/projectdiscovery/katana/cmd/katana@latest", CheckCmd: "katana -version", Description: "Web crawler"},
	"nuclei":     {Method: "go", Phase: "Vuln Scanning", InstallCmd: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", CheckCmd: "nuclei -version", Description: "Vulnerability scanner"},
	"subzy":      {Method: "go", Phase: "Takeover Check", InstallCmd: "go install github.com/PentestPad/subzy@latest", CheckCmd: "subzy version", Description: "Subdomain takeover checker"},

	// ── Phase 1 advanced modules ──
	"chaos":      {Method: "go", Phase: "Passive Recon", InstallCmd: "go install github.com/projectdiscovery/chaos/cmd/chaos@latest", CheckCmd: "chaos -version", Description: "ProjectDiscovery subdomain intel (needs PDCP_API_KEY)"},
	"nmap":       {Method: "apt", Phase: "Port Scan", InstallCmd: "sudo apt-get install -y nmap", CheckCmd: "nmap --version", Description: "Network port scanner (stealth SYN / TCP connect)"},
	"naabu":      {Method: "go", Phase: "Port Scan (alt)", InstallCmd: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", CheckCmd: "naabu -version", Description: "ProjectDiscovery fast port scanner (alternate; pipeline uses nmap)"},
	"wafw00f":    {Method: "pip", Phase: "WAF Detection", InstallCmd: "pip install wafw00f", CheckCmd: "wafw00f -V", Description: "WAF detection tool"},
	"arjun":      {Method: "pip", Phase: "Param Discovery", InstallCmd: "pip install arjun", CheckCmd: "arjun --version", Description: "HTTP hidden parameter discovery"},
	"trufflehog": {Method: "go", Phase: "Secret Scan", InstallCmd: "go install github.com/trufflesecurity/trufflehog/v3@latest", CheckCmd: "trufflehog --version", Description: "Secret scanner (filesystem mode)"},
	"gitleaks":   {Method: "go", Phase: "Secret Scan", InstallCmd: "go install github.com/gitleaks/gitleaks/v8@latest", CheckCmd: "gitleaks version", Description: "Secret scanner (no-git mode)"},
}

// Installer checks and installs security tools.
type Installer struct {
	AutoInstall bool
	goBin       string
}

// New creates a new Installer.
func New(autoInstall bool) *Installer {
	home, _ := os.UserHomeDir()
	return &Installer{
		AutoInstall: autoInstall,
		goBin:       filepath.Join(home, "go", "bin"),
	}
}

// IsInstalled checks if a tool is available.
func (i *Installer) IsInstalled(name string) bool {
	return executor.IsInstalled(name)
}

// GetToolPath returns the full path to a tool.
func (i *Installer) GetToolPath(name string) string {
	return executor.ToolPath(name)
}

// InstallTool installs a single tool via go or apt.
func (i *Installer) InstallTool(name string) (bool, string) {
	def, ok := BuiltinTools[name]
	if !ok {
		return false, fmt.Sprintf("Unknown tool: %s", name)
	}

	logger.Tool("installer", "Installing %s via %s...", name, def.Method)

	parts := strings.Fields(def.InstallCmd)
	if len(parts) == 0 {
		return false, "Empty install command"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Env = append(os.Environ(), "PATH="+i.goBin+":"+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()

	if err != nil {
		return false, fmt.Sprintf("Install failed: %s", strings.TrimSpace(string(output)))
	}

	if i.IsInstalled(name) {
		logger.Success("Successfully installed %s", name)
		return true, fmt.Sprintf("Installed %s", name)
	}

	return false, fmt.Sprintf("Installation command succeeded but %s not found", name)
}

// EnsureTools checks all required tools and installs missing ones.
func (i *Installer) EnsureTools(required []string) map[string]bool {
	results := make(map[string]bool)
	var missing []string

	for _, tool := range required {
		installed := i.IsInstalled(tool)
		results[tool] = installed
		if installed {
			logger.Success("%s: installed", tool)
		} else {
			logger.Warn("%s: NOT installed", tool)
			missing = append(missing, tool)
		}
	}

	if len(missing) > 0 && i.AutoInstall {
		for _, tool := range missing {
			success, _ := i.InstallTool(tool)
			results[tool] = success
			if !success {
				logger.Err("Could not install %s. Please install manually.", tool)
			}
		}
	}

	return results
}

// EnsureNucleiTemplates ensures nuclei templates are downloaded.
func (i *Installer) EnsureNucleiTemplates(templatesDir string) bool {
	if info, err := os.Stat(templatesDir); err == nil && info.IsDir() {
		entries, _ := os.ReadDir(templatesDir)
		if len(entries) > 0 {
			return true
		}
	}

	logger.Tool("installer", "Nuclei templates not found. Updating...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	result := executor.Run(ctx, executor.Config{
		Args:    []string{"nuclei", "-update-templates"},
		Timeout: 10 * time.Minute,
	})
	if result.ReturnCode == 0 {
		logger.Success("Nuclei templates updated")
		return true
	}
	logger.Err("Failed to update nuclei templates: %s", result.Stderr)
	return false
}

// GetToolVersion runs the tool's check command and extracts version.
func (i *Installer) GetToolVersion(name string) string {
	if !i.IsInstalled(name) {
		return ""
	}

	def, ok := BuiltinTools[name]
	if !ok {
		return "installed"
	}

	checkCmd := def.CheckCmd
	if checkCmd == "" {
		checkCmd = name + " --version"
	}

	parts := strings.Fields(checkCmd)
	if len(parts) == 0 {
		return "installed"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := executor.Run(ctx, executor.Config{
		Args:    parts,
		Timeout: 10 * time.Second,
	})

	output := strings.TrimSpace(result.Stdout + " " + result.Stderr)
	if output == "" {
		return "installed"
	}

	// Try to extract version number
	re := regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?)`)
	if match := re.FindStringSubmatch(output); len(match) > 1 {
		return match[1]
	}

	// Return first non-empty line
	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		first := strings.TrimSpace(lines[0])
		if len(first) > 100 {
			return first[:100]
		}
		return first
	}
	return "installed"
}

// GetAllToolsStatus returns the status of all tools for the UI.
func (i *Installer) GetAllToolsStatus() map[string]ToolStatus {
	result := make(map[string]ToolStatus)
	for name, def := range BuiltinTools {
		installed := i.IsInstalled(name)
		var version string
		if installed {
			version = i.GetToolVersion(name)
		}
		result[name] = ToolStatus{
			Name:        name,
			Installed:   installed,
			Path:        i.GetToolPath(name),
			Version:     version,
			Description: def.Description,
			Method:      def.Method,
			InstallCmd:  def.InstallCmd,
			CheckCmd:    def.CheckCmd,
			Enabled:     true, // Default enabled
			Phase:       def.Phase,
		}
	}
	return result
}

// GetToolDetail returns detailed status of a single tool.
func (i *Installer) GetToolDetail(name string) *ToolStatus {
	def, ok := BuiltinTools[name]
	if !ok {
		return nil
	}
	installed := i.IsInstalled(name)
	var version string
	if installed {
		version = i.GetToolVersion(name)
	}
	return &ToolStatus{
		Name:        name,
		Installed:   installed,
		Path:        i.GetToolPath(name),
		Version:     version,
		Description: def.Description,
		Method:      def.Method,
		InstallCmd:  def.InstallCmd,
		CheckCmd:    def.CheckCmd,
		Enabled:     true,
		Phase:       def.Phase,
	}
}

// UninstallTool removes a tool.
func (i *Installer) UninstallTool(name string) (bool, string) {
	if !i.IsInstalled(name) {
		return false, fmt.Sprintf("%s is not installed", name)
	}

	def, ok := BuiltinTools[name]
	if !ok {
		return false, fmt.Sprintf("Unknown tool: %s", name)
	}

	if def.Method == "apt" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sudo", "apt", "remove", "-y", name)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return false, fmt.Sprintf("apt remove failed: %s", strings.TrimSpace(string(output)))
		}
		return true, fmt.Sprintf("Uninstalled %s", name)
	}

	if def.Method == "go" {
		goBinPath := filepath.Join(i.goBin, name)
		if _, err := os.Stat(goBinPath); err == nil {
			if err := os.Remove(goBinPath); err != nil {
				return false, err.Error()
			}
			return true, fmt.Sprintf("Removed %s", goBinPath)
		}
		// Check system path
		if p, err := exec.LookPath(name); err == nil {
			return false, fmt.Sprintf("%s is installed at %s (system-managed, cannot auto-remove)", name, p)
		}
	}

	return false, fmt.Sprintf("Cannot auto-uninstall tools installed via '%s' method", def.Method)
}
