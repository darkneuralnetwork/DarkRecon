package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ── ANSI color codes ──────────────────────────────────────────
const (
	cReset  = "\033[0m"
	cDim    = "\033[2m"
	cBold   = "\033[1m"
	cCyan   = "\033[36m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cRed    = "\033[31m"
	cGray   = "\033[90m"
)

var (
	defaultLogger *slog.Logger
	output        io.Writer // shared writer (terminal + optional file)
	useColor      bool
	mu            sync.Mutex // guards banner/line writes from interleaving
	once          sync.Once
)

// isTerminal reports whether f is a character device (a real TTY).
func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return (st.Mode() & os.ModeCharDevice) != 0
}

// Init initializes the default logger with console + optional file output.
// Terminal output is clean and colored (no slog key=value noise); the file
// receives the same readable text without color codes.
func Init(level slog.Level, logFile string) *slog.Logger {
	once.Do(func() {
		useColor = isTerminal(os.Stderr)
		var w io.Writer = os.Stderr
		if logFile != "" {
			if f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				w = io.MultiWriter(os.Stderr, f)
			}
		}
		output = w
		defaultLogger = slog.New(&consoleHandler{w: w, level: level, color: useColor})
		slog.SetDefault(defaultLogger)
	})
	return defaultLogger
}

// Get returns the default logger.
func Get() *slog.Logger {
	if defaultLogger == nil {
		return Init(slog.LevelInfo, "")
	}
	return defaultLogger
}

// SetLogFile adds a file handler for a specific target scan.
func SetLogFile(target, baseDir string) {
	logPath := filepath.Join(baseDir, target, "scan.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	w := io.MultiWriter(os.Stderr, f)
	output = w
	defaultLogger = slog.New(&consoleHandler{w: w, level: slog.LevelDebug, color: useColor})
	slog.SetDefault(defaultLogger)
}

// ── Console handler (clean, readable output) ──────────────────

type consoleHandler struct {
	w     io.Writer
	level slog.Level
	color bool
}

func (h *consoleHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *consoleHandler) Handle(_ context.Context, r slog.Record) error {
	ts := r.Time.Format("15:04:05")
	msg := r.Message

	// Append any structured attrs (rarely used, but keep them visible).
	var sb strings.Builder
	r.Attrs(func(a slog.Attr) bool {
		if sb.Len() == 0 {
			sb.WriteString("  ")
		} else {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "%s=%v", a.Key, a.Value.Any())
		return true
	})

	mu.Lock()
	defer mu.Unlock()
	if h.color {
		fmt.Fprintf(h.w, "%s%s%s  %s%s\n", cGray, ts, cReset, colorize(r.Level, msg), cReset)
	} else {
		fmt.Fprintf(h.w, "%s  %s\n", ts, msg)
	}
	if sb.Len() > 0 {
		fmt.Fprintf(h.w, "         %s\n", sb.String())
	}
	return nil
}

func (h *consoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *consoleHandler) WithGroup(name string) slog.Handler       { return h }

func colorize(level slog.Level, msg string) string {
	switch {
	case level >= slog.LevelError:
		return cRed + msg + cReset
	case level >= slog.LevelWarn:
		return cYellow + msg + cReset
	default:
		return msg
	}
}

// ── Writer access for banner helpers ──────────────────────────

func writeOut(s string) {
	mu.Lock()
	defer mu.Unlock()
	if output == nil {
		output = os.Stderr
	}
	fmt.Fprint(output, s)
}

// ── Convenience helpers (same API as before, cleaner output) ──

// Phase prints a prominent banner heading for a scan section. Use this at the
// start of every phase so the terminal clearly separates sections.
func Phase(format string, args ...any) {
	Section(fmt.Sprintf(format, args...))
}

// Section prints a banner heading.
func Section(title string) {
	const bar = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	ts := time.Now().Format("15:04:05")
	head := strings.ToUpper(strings.TrimSpace(title))
	var b strings.Builder
	b.WriteString("\n")
	if useColor {
		b.WriteString(cCyan + cBold + bar + cReset + "\n")
		b.WriteString(cCyan + cBold + "  ▶ " + head + cReset + " " + cGray + "[" + ts + "]" + cReset + "\n")
		b.WriteString(cCyan + cBold + bar + cReset + "\n")
	} else {
		b.WriteString(bar + "\n")
		b.WriteString("  >> " + head + "  [" + ts + "]\n")
		b.WriteString(bar + "\n")
	}
	writeOut(b.String())
}

// Subsection prints a lighter sub-heading inside a phase.
func Subsection(title string) {
	ts := time.Now().Format("15:04:05")
	var b strings.Builder
	if useColor {
		b.WriteString("\n" + cBold + "  ■ " + strings.ToUpper(title) + cReset + " " + cGray + "[" + ts + "]" + cReset + "\n")
		b.WriteString("  " + cGray + strings.Repeat("─", 52) + cReset + "\n")
	} else {
		b.WriteString("\n  -- " + strings.ToUpper(title) + "  [" + ts + "]\n")
		b.WriteString("  " + strings.Repeat("-", 52) + "\n")
	}
	writeOut(b.String())
}

// Result prints a labelled result line, aligned for readability.
//   Result("subdomains found", 93)
//   →    subdomains found ........... 93
func Result(label string, value any) {
	dots := 40 - len(label)
	if dots < 3 {
		dots = 3
	}
	val := fmt.Sprintf("%v", value)
	if useColor {
		writeOut(fmt.Sprintf("    %s%s%s%s%s\n", label, cGray, strings.Repeat(".", dots), cReset, cBold+val+cReset))
	} else {
		writeOut(fmt.Sprintf("    %s%s%s\n", label, strings.Repeat(".", dots), val))
	}
}

func Success(format string, args ...any) {
	slog.Info(fmt.Sprintf("[+] "+format, args...))
}

func Warn(format string, args ...any)    { slog.Warn(fmt.Sprintf("[!] "+format, args...)) }
func Err(format string, args ...any)     { slog.Error(fmt.Sprintf("[-] "+format, args...)) }
func Tool(name, format string, args ...any) {
	slog.Info(fmt.Sprintf("[%s] "+format, append([]any{name}, args...)...))
}

// Header prints a top-of-scan banner with the target + key config.
func Header(target, outputDir string, scanID int64) {
	const bar = "═══════════════════════════════════════════════════════════════════════"
	ts := time.Now().Format("2006-01-02 15:04:05")
	var b strings.Builder
	b.WriteString("\n")
	if useColor {
		b.WriteString(cGreen + cBold + bar + cReset + "\n")
		b.WriteString(cGreen + cBold + "  DARK-RECON — RECONNAISSANCE SCAN" + cReset + "\n")
		b.WriteString(cGreen + cBold + bar + cReset + "\n")
	} else {
		b.WriteString(bar + "\n  DARK-RECON — RECONNAISSANCE SCAN\n" + bar + "\n")
	}
	writeOut(b.String())
	Result("Target", target)
	Result("Output dir", outputDir)
	Result("Scan ID", scanID)
	Result("Started", ts)
}

// Footer prints an end-of-scan summary banner.
func Footer(target string, duration float64, counts map[string]int) {
	const bar = "═══════════════════════════════════════════════════════════════════════"
	var b strings.Builder
	b.WriteString("\n")
	if useColor {
		b.WriteString(cGreen + cBold + bar + cReset + "\n")
		b.WriteString(cGreen + cBold + "  SCAN COMPLETE — " + strings.ToUpper(target) + cReset + "\n")
		b.WriteString(cGreen + cBold + bar + cReset + "\n")
	} else {
		b.WriteString(bar + "\n  SCAN COMPLETE — " + strings.ToUpper(target) + "\n" + bar + "\n")
	}
	writeOut(b.String())
	Result("Duration", fmt.Sprintf("%.1fs", duration))
	// Print counts in a stable order
	order := []string{"subdomains", "live_hosts", "crawled_urls", "directories", "vulnerabilities", "takeovers", "technologies"}
	for _, k := range order {
		if v, ok := counts[k]; ok {
			Result(k, v)
		}
	}
}
