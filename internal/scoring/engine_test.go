package scoring

import "testing"

// TestHostnameOf covers the helper that scopes the missing-headers score to
// the host whose headers were actually grabbed (BUG-9). It must tolerate
// scheme/path/port/userinfo and return "" for empties so the factor is
// skipped rather than mis-attributed.
func TestHostnameOf(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "EXAMPLE.COM"}, // case preserved; callers lowercase
		{"https://example.com:443", "example.com"},
		{"", ""},
		{"https://example.com/path", "example.com"},
		{"http://blog.example.com:8080/x?q=1", "blog.example.com"},
		{"https://user:pass@api.example.com/", "api.example.com"},
		{"/just/a/path", ""}, // no scheme/host -> empty, factor skipped
	}
	for _, c := range cases {
		if got := hostnameOf(c.in); got != c.want {
			t.Errorf("hostnameOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestMaxRawScoreMatchesFactorCaps guards BUG-3: the normalization denominator
// must equal the sum of the per-factor caps, otherwise every priority score is
// systematically skewed. If a factor cap changes, update both the constant and
// this test together.
func TestMaxRawScoreMatchesFactorCaps(t *testing.T) {
	// Caps mirrored from the comments on maxRawScore in engine.go.
	want := 30.0 + 35.0 + 25.0 + 20.0 + 15.0 + 12.0 + 10.0 + 10.0 // = 157
	if maxRawScore != want {
		t.Fatalf("maxRawScore = %v, expected %v (sum of factor caps). Update "+
			"the constant and its comment together when a factor changes.",
			maxRawScore, want)
	}
}
