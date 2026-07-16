package api

import (
	"encoding/json"
	"net/http"
	"regexp"
)

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// validTargetName is a hostname-safe pattern that rejects path separators,
// ../ sequences, and any character not legal in a DNS label or directory
// name. This is the first line of defense against path-traversal via the
// {target_name} URL path parameter; config.TargetDir also sanitizes.
var validTargetName = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// requireTarget extracts and validates the {target_name} path parameter.
// It writes a 400 response and returns ("", false) when the name is missing
// or contains characters outside the hostname-safe set.
func requireTarget(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("target_name")
	if name == "" || !validTargetName.MatchString(name) {
		writeError(w, 400, "Invalid target name")
		return "", false
	}
	return name, true
}
