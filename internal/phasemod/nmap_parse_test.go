package phasemod

import (
	"testing"
)

func TestParseNmapGreppable_AttributesByIP(t *testing.T) {
	// Simulate nmap -oG output where -n left the parens empty (the bug case).
	out := `# Nmap 7.95 scan initiated
Host: 45.33.32.156 ()	Status: Up
Host: 45.33.32.156 ()	Ports: 80/open/tcp//http///, 443/open/tcp//https///
Host: 1.2.3.4 ()	Ports: 6379/open/tcp//redis///
# Nmap done`
	// Our forward resolution: scanme.nmap.org -> 45.33.32.156,
	// and two subdomains (a,b) share 1.2.3.4.
	ipToSubs := map[string][]string{
		"45.33.32.156": {"scanme.nmap.org"},
		"1.2.3.4":      {"a.example.com", "b.example.com"},
	}
	r := &Runner{}
	got := r.parseNmapGreppable(out, ipToSubs)

	// scanme.nmap.org should have ports 80 + 443
	ports, ok := got["scanme.nmap.org"]
	if !ok {
		t.Fatalf("expected scanme.nmap.org in results, got %v", got)
	}
	if len(ports) != 2 || ports[0].Port != 80 || ports[1].Port != 443 {
		t.Fatalf("unexpected ports for scanme: %+v", ports)
	}
	// Both shared-host subdomains must get port 6379 attributed.
	for _, sub := range []string{"a.example.com", "b.example.com"} {
		p, ok := got[sub]
		if !ok || len(p) != 1 || p[0].Port != 6379 {
			t.Fatalf("expected %s to have port 6379, got %+v", sub, p)
		}
	}
	// No raw IP keys should leak into the result map.
	if _, ok := got["45.33.32.156"]; ok {
		t.Fatalf("IP leaked as subdomain key (the bug): got 45.33.32.156")
	}
	if _, ok := got["1.2.3.4"]; ok {
		t.Fatalf("IP leaked as subdomain key (the bug): got 1.2.3.4")
	}
}

func TestParseNmapGreppable_FallbackWhenIPMissing(t *testing.T) {
	// IP not in our map and parens empty -> fall back to IP so data isn't lost.
	out := "Host: 9.9.9.9 ()\tPorts: 53/open/tcp//domain///"
	r := &Runner{}
	got := r.parseNmapGreppable(out, map[string][]string{})
	if len(got) != 1 || len(got["9.9.9.9"]) != 1 || got["9.9.9.9"][0].Port != 53 {
		t.Fatalf("expected fallback to IP 9.9.9.9, got %v", got)
	}
}

func TestNormaliseHostname(t *testing.T) {
	cases := map[string]string{
		"www.target.com":                              "www.target.com",
		"http://www.target.com":                       "www.target.com",
		"https://www.target.com/path":                 "www.target.com",
		"www.target.com:443":                          "www.target.com",
		"HTTP://User:Pass@WWW.Target.COM.:8080/x?q=1": "www.target.com",
		"api.target.com":                              "api.target.com",
		"":                                            "",
		"   ":                                         "",
	}
	for in, want := range cases {
		if got := normaliseHostname(in); got != want {
			t.Errorf("normaliseHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExcludeWWWAlias(t *testing.T) {
	// Apex target: the www alias (in bare and URL form) must be dropped while
	// the apex itself and all other subdomains survive.
	r := &Runner{target: "target.com"}
	in := []string{"target.com", "www.target.com", "http://www.target.com", "api.target.com"}
	got := r.excludeWWWAlias(in)
	want := map[string]bool{"target.com": true, "api.target.com": true}
	if len(got) != len(want) {
		t.Fatalf("expected %d hosts after filtering, got %d: %v", len(want), len(got), got)
	}
	for _, h := range got {
		if !want[h] {
			t.Errorf("unexpected host survived filter: %q (got %v)", h, got)
		}
	}
	// www alias must be gone entirely.
	for _, h := range got {
		if normaliseHostname(h) == "www.target.com" {
			t.Errorf("www alias was not filtered out: %q", h)
		}
	}
}

func TestExcludeWWWAlias_NotAppliedWhenTargetIsWWW(t *testing.T) {
	// If the scan target is itself a www host, nothing should be filtered.
	r := &Runner{target: "www.target.com"}
	in := []string{"www.target.com", "api.target.com"}
	got := r.excludeWWWAlias(in)
	if len(got) != len(in) {
		t.Fatalf("expected no filtering when target is a www host, got %v", got)
	}
}

func TestExcludeWWWAlias_EmptyTarget(t *testing.T) {
	r := &Runner{target: ""}
	in := []string{"www.target.com", "api.target.com"}
	got := r.excludeWWWAlias(in)
	if len(got) != len(in) {
		t.Fatalf("expected no filtering when target is empty, got %v", got)
	}
}
