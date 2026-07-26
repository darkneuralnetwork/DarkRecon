package phasemod

import (
	"testing"
)

// TestToolAvailableMissingBinary verifies the robust availability check
// returns false for a binary that does not exist (and never shells out
// successfully). This is the guard that prevents broken/zero-byte binaries
// (e.g. a half-installed naabu) from being treated as available.
func TestToolAvailableMissingBinary(t *testing.T) {
	if toolAvailable("this-tool-definitely-does-not-exist-xyz", "--version") {
		t.Fatal("expected toolAvailable to return false for a missing binary")
	}
	if toolPath("this-tool-definitely-does-not-exist-xyz") != "" {
		t.Fatal("expected empty path for a missing binary")
	}
}

// TestJSPatternsCompile ensures every JS-analysis regex compiles and matches
// representative sample data. This guards against the raw-string backtick bug
// that originally broke the build.
func TestJSPatternsCompile(t *testing.T) {
	if len(jsPatterns) == 0 {
		t.Fatal("expected jsPatterns to be non-empty")
	}
	// Each pattern must already be compiled at init time (regexp.MustCompile
	// panics on bad syntax), so reaching here means they compiled. Now verify
	// a few match representative input.
	samples := map[string]string{
		"api_path":     `var u = "/api/v1/users";`,
		"relative_path": `fetch("/assets/main.bundle.js")`,
		"full_url":     `var e = "https://api.example.com/v2/data"`,
		"internal_ip":  `host: "192.168.1.10"`,
		"aws_key":      `AKIAIOSFODNN7EXAMPLE`,
		"github_token": `ghp_abcdefghijklmnopqrstuvwxyz0123456789AB`,
		"google_api":   `AIzaSyAabcdefghijklmnopqrstuvwxyz0123456`,
		"jwt":          `eyJhbGci.eyJzdWIi.SflKxwRJSMeKKF2QT4f`,
		"private_key":  `-----BEGIN RSA PRIVATE KEY-----`,
	}
	for _, p := range jsPatterns {
		if p.pattern == nil {
			t.Fatalf("pattern %q has nil regexp", p.name)
		}
		if want, ok := samples[p.name]; ok {
			if !p.pattern.MatchString(want) {
				t.Errorf("pattern %q did not match sample %q", p.name, want)
			}
		}
	}
}
