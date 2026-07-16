package api

import (
	"net/http"
	"time"

	"github.com/yourname/dark-recon/pkg/logger"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for local tool
	},
}

// WebSocketProgress handles WebSocket connections for real-time scan progress.
func (h *Handlers) WebSocketProgress(w http.ResponseWriter, r *http.Request) {
	targetName, ok := requireTarget(w, r)
	if !ok {
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Err("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	lastLogCount := 0

	for {
		status := h.scanMgr.GetStatus(targetName)
		logs := h.scanMgr.GetProgressLog(targetName)

		// Send new logs
		if len(logs) > lastLogCount {
			newLogs := logs[lastLogCount:]
			msg := map[string]any{
				"type":       "logs",
				"logs":       newLogs,
				"total_logs": len(logs),
			}
			if err := conn.WriteJSON(msg); err != nil {
				break
			}
			lastLogCount = len(logs)
		}

		// Send status
		statusMsg := map[string]any{
			"type":   "status",
			"status": status["status"],
		}
		if errVal, ok := status["error"]; ok && errVal != "" {
			statusMsg["error"] = errVal
		}
		if err := conn.WriteJSON(statusMsg); err != nil {
			break
		}

		// Check if done. "completed_with_errors" is also a terminal state
		// (the engine sets it when a non-fatal phase errored/panicked); without
		// it here, any degraded scan would leave the UI stranded at "running".
		s, _ := status["status"].(string)
		if s == "completed" || s == "completed_with_errors" || s == "failed" || s == "stopping" {
			conn.WriteJSON(map[string]any{
				"type":     "done",
				"status":   s,
				"redirect": "/target/" + targetName,
			})
			break
		}

		time.Sleep(1 * time.Second)
	}
}

// WebSocketGlobal handles the legacy global WebSocket endpoint.
func (h *Handlers) WebSocketGlobal(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
		conn.WriteJSON(map[string]string{"status": "connected"})
	}
}
