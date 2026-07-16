package scanmgr

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/yourname/dark-recon/internal/config"
	"github.com/yourname/dark-recon/internal/pipeline"
	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/pkg/logger"
)

// ScanInfo holds the state of a running scan.
type ScanInfo struct {
	Target    string
	Status    string // running, completed, completed_with_errors, failed, stopping
	StartTime *time.Time
	Error     string
	cancel    context.CancelFunc
}

const (
	// maxProgressLogEntries caps the in-memory progress log per target so a
	// very long scan can't grow it without bound. The full history lives in
	// the DB; this is only for the live WebSocket tail.
	maxProgressLogEntries = 5000
	// pruneGracePeriod is how long a finished scan's in-memory state is kept
	// after it reaches a terminal status, so the WebSocket can deliver the
	// final "done"/"failed" message before the entries are dropped.
	pruneGracePeriod = 30 * time.Second
)

// ProgressEntry represents a single log entry.
type ProgressEntry struct {
	Timestamp string         `json:"timestamp"`
	Phase     string         `json:"phase"`
	Status    string         `json:"status"`
	Message   string         `json:"message,omitempty"`
	Count     int            `json:"count,omitempty"`
	Extra     map[string]any `json:"-"`
}

// Manager manages background scan execution and progress tracking.
type Manager struct {
	mu          sync.Mutex
	activeScans map[string]*ScanInfo
	progressLog map[string][]ProgressEntry
	db          *storage.DB
}

// New creates a new scan manager.
func New(db *storage.DB) *Manager {
	return &Manager{
		activeScans: make(map[string]*ScanInfo),
		progressLog: make(map[string][]ProgressEntry),
		db:          db,
	}
}

// LaunchScan starts a scan in a background goroutine.
func (m *Manager) LaunchScan(target string, overrides map[string]any, configPath string) bool {
	m.mu.Lock()
	if info, ok := m.activeScans[target]; ok && info.Status == "running" {
		m.mu.Unlock()
		return false
	}
	m.mu.Unlock()

	// Load config
	cfg, err := config.Load(configPath, overrides)
	if err != nil {
		logger.Err("Failed to load config: %v", err)
		return false
	}
	cfg.Target = target

	// Open database
	dbPath := filepath.Join(cfg.TargetDir(target), "scan.db")
	db, err := storage.Open(dbPath)
	if err != nil {
		logger.Err("Failed to open database: %v", err)
		return false
	}

	// Create scan record
	scanID, err := db.CreateScan(target)
	if err != nil {
		logger.Err("Failed to create scan record: %v", err)
		db.Close()
		return false
	}

	ctx, cancel := context.WithCancel(context.Background())

	info := &ScanInfo{
		Target:    target,
		Status:    "running",
		StartTime: &[]time.Time{time.Now()}[0],
		cancel:    cancel,
	}

	m.mu.Lock()
	m.activeScans[target] = info
	m.progressLog[target] = nil
	m.mu.Unlock()

	go func() {
		defer db.Close()
		// Recover from a panic in engine.Run so the scan is marked failed
		// (instead of staying "running" forever) and the goroutine doesn't
		// die silently. Registered before the body so it runs before db.Close.
		defer func() {
			if r := recover(); r != nil {
				m.mu.Lock()
				if info.Status == "running" || info.Status == "stopping" {
					info.Status = "failed"
					info.Error = fmt.Sprintf("scan panicked: %v", r)
					db.UpdateScanStatus(scanID, "failed", &info.Error)
				}
				m.mu.Unlock()
				logger.Err("Scan panicked for %s: %v", target, r)
			}
			// Whether we panicked or not, drop this scan's in-memory state
			// after a grace window so logs don't leak for the process lifetime.
			m.schedulePrune(target, pruneGracePeriod)
		}()

		engine := pipeline.New(cfg, db, scanID)
		engine.SetProgressCallback(func(data map[string]any) {
			entry := ProgressEntry{
				Timestamp: time.Now().Format("15:04:05"),
			}
			if v, ok := data["phase"]; ok {
				entry.Phase = v.(string)
			}
			if v, ok := data["status"]; ok {
				entry.Status = v.(string)
			}
			if v, ok := data["message"]; ok {
				entry.Message = v.(string)
			}
			if v, ok := data["count"]; ok {
				entry.Count = v.(int)
			}

			m.mu.Lock()
			m.progressLog[target] = append(m.progressLog[target], entry)
			// Safety cap: keep only the most recent entries so a very long scan
			// can't grow the in-memory log without bound.
			if len(m.progressLog[target]) > maxProgressLogEntries {
				m.progressLog[target] = m.progressLog[target][len(m.progressLog[target])-maxProgressLogEntries:]
			}
			// Check if stopping was requested
			if info.Status == "stopping" {
				m.mu.Unlock()
				cancel()
				return
			}
			m.mu.Unlock()
		})

		err := engine.Run(ctx)

		m.mu.Lock()
		if err != nil {
			info.Status = "failed"
			info.Error = err.Error()
			db.UpdateScanStatus(scanID, "failed", &info.Error)
			logger.Err("Scan failed for %s: %v", target, err)
		} else {
			// The engine already finalized the DB row via CompleteScan with its
			// own status — which may be "completed_with_errors" when a critical
			// phase (nuclei/subzy/tech/scoring) panicked or errored. Read it
			// back instead of clobbering it with "completed" (which would also
			// discard the duration the engine recorded).
			info.Status = "completed"
			if scan, _ := db.GetScanByTarget(target); scan != nil && scan.Status != "" {
				info.Status = scan.Status
			}
		}
		m.mu.Unlock()
	}()

	return true
}

// StopScan marks a scan as stopping.
func (m *Manager) StopScan(target string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.activeScans[target]; ok && info.Status == "running" {
		info.Status = "stopping"
		if info.cancel != nil {
			info.cancel()
		}
		return true
	}
	return false
}

// GetStatus returns scan status for a target.
func (m *Manager) GetStatus(target string) map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, ok := m.activeScans[target]
	logs := m.progressLog[target]

	if !ok {
		return map[string]any{
			"target":    target,
			"status":    "idle",
			"log_count": 0,
		}
	}

	// Get recent logs (last 20)
	recentCount := 20
	if len(logs) < recentCount {
		recentCount = len(logs)
	}
	recentLogs := logs[len(logs)-recentCount:]

	startTimeStr := ""
	if info.StartTime != nil {
		startTimeStr = info.StartTime.Format(time.RFC3339)
	}

	return map[string]any{
		"target":      target,
		"status":      info.Status,
		"start_time":  startTimeStr,
		"error":       info.Error,
		"log_count":   len(logs),
		"recent_logs": recentLogs,
	}
}

// GetProgressLog returns the full progress log for a target.
func (m *Manager) GetProgressLog(target string) []ProgressEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	logs := m.progressLog[target]
	result := make([]ProgressEntry, len(logs))
	copy(result, logs)
	return result
}

// GetAllActiveScans returns all running scans.
func (m *Manager) GetAllActiveScans() []map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var scans []map[string]string
	for target, info := range m.activeScans {
		if info.Status == "running" {
			scans = append(scans, map[string]string{
				"target": target,
				"status": info.Status,
			})
		}
	}
	return scans
}

// ClearCompleted removes completed/failed scans from memory.
func (m *Manager) ClearCompleted() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for target, info := range m.activeScans {
		if isTerminal(info.Status) {
			delete(m.activeScans, target)
			delete(m.progressLog, target)
			count++
		}
	}
	return count
}

// isTerminal reports whether a scan status is final (no longer running).
func isTerminal(status string) bool {
	switch status {
	case "completed", "completed_with_errors", "failed", "stopping":
		return true
	}
	return false
}

// schedulePrune drops a scan's in-memory state after a grace period, but only
// if it is still in a terminal state at that point — so a rescan that started
// for the same target during the window (status back to "running") is left
// alone. This is what keeps finished scans from leaking progressLog memory,
// since nothing in the request path calls ClearCompleted.
func (m *Manager) schedulePrune(target string, after time.Duration) {
	time.AfterFunc(after, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if info, ok := m.activeScans[target]; ok && isTerminal(info.Status) {
			delete(m.activeScans, target)
			delete(m.progressLog, target)
		}
	})
}

// FormatDuration formats a duration for display.
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%.1fm", d.Minutes())
}
