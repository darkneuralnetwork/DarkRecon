package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourname/dark-recon/pkg/logger"
)

// Result holds the outcome of a tool execution.
type Result struct {
	ReturnCode int
	Stdout     string
	Stderr     string
	Err        error
}

// Config controls how a tool is executed.
type Config struct {
	Cmd         string        // Full command string
	Args        []string      // Parsed args (used when Cmd is empty)
	Timeout     time.Duration // Execution timeout
	Env         map[string]string // Extra env vars
}

// Run executes an external tool with context cancellation support.
// It NEVER uses shell=True — args are passed directly to exec.Command
// to prevent command injection.
func Run(ctx context.Context, cfg Config) Result {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var cmd *exec.Cmd
	if len(cfg.Args) > 0 {
		cmd = exec.CommandContext(ctx, cfg.Args[0], cfg.Args[1:]...)
	} else {
		// Parse the command string safely (no shell)
		parts := parseArgs(cfg.Cmd)
		if len(parts) == 0 {
			return Result{ReturnCode: -1, Err: fmt.Errorf("empty command")}
		}
		cmd = exec.CommandContext(ctx, parts[0], parts[1:]...)
	}

	// Build environment with ~/go/bin on PATH
	env := os.Environ()
	goBin := filepath.Join(os.Getenv("HOME"), "go", "bin")
	env = appendToPath(env, goBin)
	for k, v := range cfg.Env {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	rc := -1
	if cmd.ProcessState != nil {
		rc = cmd.ProcessState.ExitCode()
	}

	if ctx.Err() == context.DeadlineExceeded {
		logger.Err("Command timed out after %s: %s", timeout, truncateCmd(cfg))
		return Result{ReturnCode: -1, Stdout: stdout.String(), Stderr: "Timeout after " + timeout.String()}
	}

	if err != nil && rc == -1 {
		// Check if command not found
		if strings.Contains(err.Error(), "executable file not found") {
			name := ""
			if len(cfg.Args) > 0 {
				name = cfg.Args[0]
			} else {
				parts := parseArgs(cfg.Cmd)
				if len(parts) > 0 {
					name = parts[0]
				}
			}
			logger.Err("Command not found: %s", name)
			return Result{ReturnCode: -1, Stderr: "Command not found: " + name}
		}
	}

	return Result{
		ReturnCode: rc,
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		Err:        err,
	}
}

// RunSimple is a convenience wrapper that takes a command string and timeout.
func RunSimple(ctx context.Context, cmd string, timeout time.Duration) Result {
	return Run(ctx, Config{Cmd: cmd, Timeout: timeout})
}

// IsInstalled checks if a tool is available on PATH or in ~/go/bin.
func IsInstalled(name string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	goBinPath := filepath.Join(os.Getenv("HOME"), "go", "bin", name)
	if _, err := os.Stat(goBinPath); err == nil {
		return true
	}
	return false
}

// ToolPath returns the full path to a tool, or empty string.
func ToolPath(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	goBinPath := filepath.Join(os.Getenv("HOME"), "go", "bin", name)
	if _, err := os.Stat(goBinPath); err == nil {
		return goBinPath
	}
	return ""
}

// parseArgs splits a command string into program + args without shell.
// Handles simple quoted strings.
func parseArgs(cmd string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if inQuote {
			if c == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(c)
			}
		} else {
			switch c {
			case '"', '\'':
				inQuote = true
				quoteChar = c
			case ' ', '\t':
				if current.Len() > 0 {
					args = append(args, current.String())
					current.Reset()
				}
			default:
				current.WriteByte(c)
			}
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

func appendToPath(env []string, dir string) []string {
	for i, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			val := e[5:]
			if !strings.Contains(val, dir) {
				env[i] = "PATH=" + dir + ":" + val
			}
			return env
		}
	}
	return append(env, "PATH="+dir+":"+os.Getenv("PATH"))
}

func truncateCmd(cfg Config) string {
	s := cfg.Cmd
	if s == "" && len(cfg.Args) > 0 {
		s = strings.Join(cfg.Args, " ")
	}
	if len(s) > 100 {
		return s[:100] + "..."
	}
	return s
}

// TruncateLog safely truncates a string to at most n characters.
// If the string is shorter than n, it is returned unchanged.
// This prevents "slice bounds out of range" panics when logging
// tool stderr output that may be shorter than the desired truncation length.
func TruncateLog(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
