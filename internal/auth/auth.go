// Package auth implements simple session-based authentication for the
// Dark-Recon web UI and REST API.
//
// Credentials come from config.yaml (default admin/admin). The configured
// password is bcrypt-hashed at startup (if not already a hash) so the
// plaintext value is never retained in memory after initialization. A
// pre-computed bcrypt hash (any of the "$2a$"/"$2b$"/"$2y$" forms) may be
// stored in config.yaml instead of the plaintext for stronger at-rest
// security.
//
// Successful login mints an opaque, cryptographically-random session token
// (32 bytes from crypto/rand, hex-encoded) carried in an HttpOnly,
// SameSite=Lax cookie. Active sessions live in an in-memory map protected by
// a RWMutex, with a sliding expiry renewed on each authenticated request and
// a background reaper that purges expired tokens.
//
// When Auth.Enabled is false the middleware becomes a pass-through, preserving
// the legacy "open" behaviour for local-only / dev use.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yourname/dark-recon/internal/config"
	"github.com/yourname/dark-recon/pkg/logger"
	"golang.org/x/crypto/bcrypt"
)

// CookieName is the name of the session cookie.
const CookieName = "dark_recon_session"

// publicPaths bypass authentication entirely (login/logout/static/favicon).
// Static assets and the login page must be reachable without a session,
// otherwise the user could never load the login form or its CSS.
var publicPaths = []string{"/login", "/logout", "/static/", "/favicon.ico"}

// Auth manages user credentials and active sessions.
type Auth struct {
	enabled      bool
	username     string
	passwordHash []byte
	ttl          time.Duration

	mu       sync.RWMutex
	sessions map[string]*session // token -> session
}

type session struct {
	username  string
	expiresAt time.Time
}

// New creates an Auth instance from config. See package docs for the
// password-handling rules. Returns an Auth with Enabled=false (a pass-through
// middleware) when auth is disabled.
func New(cfg *config.Config) (*Auth, error) {
	ttl, err := time.ParseDuration(cfg.Auth.SessionTTL)
	if err != nil || ttl <= 0 {
		ttl = 24 * time.Hour
	}

	a := &Auth{
		enabled:  cfg.Auth.Enabled,
		username: cfg.Auth.Username,
		ttl:      ttl,
		sessions: make(map[string]*session),
	}

	if cfg.Auth.Enabled {
		if cfg.Auth.Username == "" || cfg.Auth.Password == "" {
			return nil, fmt.Errorf("auth: enabled but username/password are empty (set them in config.yaml)")
		}
		// If the configured password is already a bcrypt hash, use it as-is;
		// otherwise hash the plaintext now so it is never retained in memory.
		if isBcryptHash(cfg.Auth.Password) {
			a.passwordHash = []byte(cfg.Auth.Password)
		} else {
			h, err := bcrypt.GenerateFromPassword([]byte(cfg.Auth.Password), bcrypt.DefaultCost)
			if err != nil {
				return nil, fmt.Errorf("auth: hash password: %w", err)
			}
			a.passwordHash = h
		}
		logger.Success("Authentication enabled (user: %s, session TTL: %s)", cfg.Auth.Username, ttl)
	} else {
		logger.Warn("Authentication DISABLED — the web UI/API is open to anyone who can reach it")
	}

	// Background session reaper: drops expired tokens so the map can't grow
	// without bound for a long-lived server process.
	go a.reaper()

	return a, nil
}

// Enabled reports whether authentication is active.
func (a *Auth) Enabled() bool { return a.enabled }

// Login validates the credentials and, on success, mints a new session token.
// Returns ("", false) on mismatch. The token is opaque to the caller and
// should be set as the value of the session cookie.
func (a *Auth) Login(username, password string) (string, bool) {
	if !a.enabled {
		return "", false
	}
	// Constant-time comparison of the username so a timing oracle can't be
	// used to enumerate valid usernames. The password is checked with bcrypt,
	// which is itself constant-time w.r.t. the hash.
	userOK := subtle.ConstantTimeCompare([]byte(strings.ToLower(username)), []byte(strings.ToLower(a.username))) == 1
	if !userOK {
		// Still run a bcrypt comparison against the real hash so the failure
		// path takes roughly the same time as a wrong-password attempt,
		// blinding the username-existence oracle.
		_ = bcrypt.CompareHashAndPassword(a.passwordHash, []byte(password))
		return "", false
	}
	if err := bcrypt.CompareHashAndPassword(a.passwordHash, []byte(password)); err != nil {
		return "", false
	}

	token, err := randomToken()
	if err != nil {
		return "", false
	}

	a.mu.Lock()
	a.sessions[token] = &session{
		username:  a.username,
		expiresAt: time.Now().Add(a.ttl),
	}
	a.mu.Unlock()

	return token, true
}

// Logout revokes a session token. It is safe to call with an unknown/already
// expired token (no-op).
func (a *Auth) Logout(token string) {
	if token == "" {
		return
	}
	a.mu.Lock()
	delete(a.sessions, token)
	a.mu.Unlock()
}

// Valid reports whether the token refers to a live, unexpired session. As a
// side effect it renews the sliding expiry and lazily drops the token if it
// has expired, so callers don't need a separate cleanup pass.
func (a *Auth) Valid(token string) bool {
	if !a.enabled || token == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(s.expiresAt) {
		delete(a.sessions, token)
		return false
	}
	// Sliding renewal: each authenticated request extends the session.
	s.expiresAt = time.Now().Add(a.ttl)
	return true
}

// UsernameFor returns the authenticated username for a live token, or "".
func (a *Auth) UsernameFor(token string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if s, ok := a.sessions[token]; ok && time.Now().Before(s.expiresAt) {
		return s.username
	}
	return ""
}

// MinPasswordLength is the minimum length enforced for new passwords.
const MinPasswordLength = 6

// ChangePassword validates the current password and, if correct, replaces the
// in-memory hash with one for the new password. It does NOT persist the new
// password to config.yaml — the caller (API handler) is responsible for that
// so this method stays free of file-I/O concerns and testable in isolation.
//
// Returns nil on success. Errors:
//   - "auth disabled" — password changes are meaningless when auth is off
//   - "incorrect current password" — currentPassword doesn't match
//   - "password too short" — newPassword is shorter than MinPasswordLength
//   - "password unchanged" — newPassword equals currentPassword
func (a *Auth) ChangePassword(currentPassword, newPassword string) error {
	if !a.enabled {
		return fmt.Errorf("auth disabled")
	}
	if err := bcrypt.CompareHashAndPassword(a.passwordHash, []byte(currentPassword)); err != nil {
		return fmt.Errorf("incorrect current password")
	}
	if len(newPassword) < MinPasswordLength {
		return fmt.Errorf("password too short (minimum %d characters)", MinPasswordLength)
	}
	if newPassword == currentPassword {
		return fmt.Errorf("password unchanged")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	a.mu.Lock()
	a.passwordHash = h
	// Revoke every existing session so the user must re-authenticate with the
	// new password on every device. This is the standard security posture for
	// a password change: it instantly invalidates stolen/leaked credentials.
	a.sessions = make(map[string]*session)
	a.mu.Unlock()
	return nil
}

// HashPasswordForConfig returns a bcrypt hash of password, used by the API
// handler to persist a hashed password to config.yaml (so the plaintext is
// never written to disk).
func (a *Auth) HashPasswordForConfig(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// TokenFromRequest extracts the session token from the request's cookie, if
// present. Returns "" when there is no cookie or auth is disabled.
func (a *Auth) TokenFromRequest(r *http.Request) string {
	if !a.enabled {
		return ""
	}
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// SetSessionCookie writes the session cookie on the response. The cookie is a
// browser-session cookie: it has NO MaxAge/Expires, so the browser discards it
// the moment the user closes the browser ("terminate the session" → automatic
// logout). The server-side session still carries its TTL as a hard expiry and
// the reaper cleans up any orphaned tokens.
//
// The Secure flag is set only when the login request arrived over TLS, so HTTP
// local-dev (./dark-recon -port 5000) still works while HTTPS deployments get
// the browser's full transport-layer cookie protection.
func (a *Auth) SetSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		// Deliberately no MaxAge/Expires → browser-session cookie: cleared when
		// the browser is closed, giving automatic logout on session end.
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie expires the session cookie on the client.
func (a *Auth) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Middleware protects the wrapped handler. Public paths (login/logout/static/
// favicon) bypass auth. API and WebSocket paths ("/api/", "/ws") return a
// 401 JSON response when unauthenticated so fetch clients can detect it;
// every other path is HTML and gets a 302 redirect to /login?next=<original>.
//
// When auth is disabled the middleware is a pure pass-through.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enabled || isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		c, err := r.Cookie(CookieName)
		if err == nil && a.Valid(c.Value) {
			next.ServeHTTP(w, r)
			return
		}

		if isAPIPath(r.URL.Path) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer realm="dark-recon"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		// HTML route: redirect to login, preserving the original URL so the
		// user lands back where they were headed after authenticating.
		dest := r.URL.Path
		if r.URL.RawQuery != "" {
			dest += "?" + r.URL.RawQuery
		}
		target := "/login?next=" + url.QueryEscape(dest)
		http.Redirect(w, r, target, http.StatusSeeOther)
	})
}

// reaper periodically drops expired sessions so the in-memory map can't grow
// unbounded for a long-running server. Runs every 10 minutes; cheap because
// Valid() also lazily expires tokens on access.
func (a *Auth) reaper() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		a.mu.Lock()
		for token, s := range a.sessions {
			if now.After(s.expiresAt) {
				delete(a.sessions, token)
			}
		}
		a.mu.Unlock()
	}
}

// isBcryptHash reports whether s looks like a pre-computed bcrypt hash, so the
// startup code can use it directly instead of re-hashing it.
func isBcryptHash(s string) bool {
	return strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$")
}

// isPublicPath reports whether path bypasses authentication.
func isPublicPath(path string) bool {
	for _, p := range publicPaths {
		if p == path || (strings.HasSuffix(p, "/") && strings.HasPrefix(path, p)) {
			return true
		}
	}
	return false
}

// isAPIPath reports whether path is an API/WebSocket endpoint, which gets a
// 401 JSON response instead of an HTML redirect when unauthenticated.
func isAPIPath(path string) bool {
	return strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/ws")
}

// randomToken returns 32 crypto-random bytes hex-encoded (64 chars). This is
// the session token — 256 bits of entropy, far beyond the feasibility of any
// online/offline guessing attack.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
