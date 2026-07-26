package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/yourname/dark-recon/internal/config"
	"github.com/yourname/dark-recon/pkg/logger"
)

// LoginRequest is the JSON body accepted by POST /login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Next     string `json:"next,omitempty"` // post-login redirect target
}

// LoginHandler processes a login submission (POST /login). It accepts either a
// JSON body ({username,password}) — used by the login page's fetch-based JS —
// or an application/x-www-form-urlencoded body as a no-JS fallback.
//
// On success it mints a session, sets the HttpOnly cookie, and responds with
// either a 200 JSON envelope (for fetch clients) or a 303 redirect to `next`
// (for form clients). On failure it returns 401 JSON (fetch) or redirects
// back to /login?error=1 (form).
func (h *Handlers) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if h.auth == nil || !h.auth.Enabled() {
		// Auth disabled: nothing to log in to. Send the user home.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	var username, password, next string
	jsonBody := strings.Contains(r.Header.Get("Content-Type"), "application/json")

	if jsonBody {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, 400, "Invalid request body")
			return
		}
		username, password, next = req.Username, req.Password, req.Next
	} else {
		if err := r.ParseForm(); err != nil {
			writeError(w, 400, "Invalid form data")
			return
		}
		username = r.FormValue("username")
		password = r.FormValue("password")
		next = r.FormValue("next")
	}

	token, ok := h.auth.Login(username, password)
	if !ok {
		logger.Warn("Failed login for user %q from %s", username, r.RemoteAddr)
		if jsonBody {
			writeError(w, 401, "Invalid username or password")
			return
		}
		dest := "/login?error=1"
		if next != "" {
			dest += "&next=" + next
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}

	logger.Success("User %q logged in from %s", username, r.RemoteAddr)
	h.auth.SetSessionCookie(w, r, token)

	if jsonBody {
		writeJSON(w, 200, map[string]any{
			"status":   "ok",
			"username": username,
		})
		return
	}

	// Form fallback: validate the redirect target before trusting it.
	if !isSafeRedirect(next) {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// LogoutHandler revokes the current session and clears the cookie (POST
// /logout). Responds with 200 JSON for fetch clients and a 303 redirect to
// /login for form clients.
func (h *Handlers) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if h.auth != nil {
		if token := h.auth.TokenFromRequest(r); token != "" {
			h.auth.Logout(token)
		}
		h.auth.ClearSessionCookie(w)
	}
	jsonBody := strings.Contains(r.Header.Get("Accept"), "application/json") ||
		strings.Contains(r.Header.Get("Content-Type"), "application/json")
	if jsonBody {
		writeJSON(w, 200, map[string]string{"status": "ok"})
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// CurrentUser reports the authenticated identity for the calling session (GET
// /api/auth/me). The UI uses this to confirm an active session on load and to
// display the username in the topbar.
func (h *Handlers) CurrentUser(w http.ResponseWriter, r *http.Request) {
	if h.auth == nil || !h.auth.Enabled() {
		writeJSON(w, 200, map[string]any{"authenticated": true, "username": "", "auth_enabled": false})
		return
	}
	token := h.auth.TokenFromRequest(r)
	if token == "" || !h.auth.Valid(token) {
		writeJSON(w, 401, map[string]any{"authenticated": false, "auth_enabled": true})
		return
	}
	writeJSON(w, 200, map[string]any{
		"authenticated": true,
		"username":      h.auth.UsernameFor(token),
		"auth_enabled":  true,
	})
}

// isSafeRedirect guards the form-login redirect target against open-redirect
// abuse: only same-origin absolute paths (starting with "/" but not "//") are
// allowed. Query strings are preserved by the caller.
func isSafeRedirect(target string) bool {
	if target == "" {
		return false
	}
	if strings.HasPrefix(target, "//") {
		return false // protocol-relative → off-site
	}
	if strings.HasPrefix(target, "/") {
		return true
	}
	return false // anything else is either a scheme:// URL or a relative path
}

// ChangePasswordRequest is the JSON body for POST /api/auth/change-password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePasswordHandler lets the authenticated user change their password
// (POST /api/auth/change-password). It verifies the current password, enforces
// a minimum length on the new one, updates the in-memory hash, revokes all
// existing sessions (forcing re-login everywhere), and persists a bcrypt hash
// of the new password to config.yaml so it survives restarts.
//
// The caller must already be authenticated (the middleware enforces this), so
// we know the session is valid — but we still require the current password as
// a defense-in-depth check against a hijacked session being used to lock the
// real owner out.
func (h *Handlers) ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if h.auth == nil || !h.auth.Enabled() {
		writeError(w, 400, "Authentication is disabled")
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "Invalid request body")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, 400, "Current and new passwords are required")
		return
	}

	// Update the in-memory hash + revoke all sessions.
	if err := h.auth.ChangePassword(req.CurrentPassword, req.NewPassword); err != nil {
		// 401 for wrong current password, 400 for validation errors.
		status := 400
		if strings.Contains(err.Error(), "incorrect current password") {
			status = 401
		}
		writeError(w, status, err.Error())
		return
	}

	// Persist a bcrypt hash (not the plaintext) to config.yaml so the new
	// password survives a restart and the plaintext is never on disk.
	hashed, err := h.auth.HashPasswordForConfig(req.NewPassword)
	if err != nil {
		logger.Err("Failed to hash password for persistence: %v", err)
		writeError(w, 500, "Password changed in memory but failed to persist to disk")
		return
	}
	cfg, err := config.Load(h.configPath, map[string]any{"auth_password": hashed})
	if err != nil {
		logger.Err("Failed to reload config for password save: %v", err)
		writeError(w, 500, "Password changed in memory but failed to persist to disk")
		return
	}
	if err := cfg.Save(h.configPath); err != nil {
		logger.Err("Failed to save config after password change: %v", err)
		writeError(w, 500, "Password changed in memory but failed to persist to disk")
		return
	}
	h.cfg = cfg

	logger.Success("Password changed for user %q; all sessions revoked", h.auth.UsernameFor(h.auth.TokenFromRequest(r)))
	writeJSON(w, 200, map[string]string{
		"status":  "changed",
		"message": "Password changed. Please log in again with your new password.",
	})
}
