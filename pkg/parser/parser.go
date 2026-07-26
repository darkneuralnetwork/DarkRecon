package parser

import (
	"encoding/json"
	"strings"
)

// MarshalArray marshals a slice/any to a JSON string, returning "[]"
// instead of "null" when the value is nil. Go's json.Marshal emits
// "null" for nil slices, which the UI's parseJSONField then turned
// into JS null (crashing .slice()/.forEach() callers).
func MarshalArray(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	s := string(b)
	if s == "null" {
		return "[]"
	}
	return s
}

// ParseJSONLines parses newline-delimited JSON (used by httpx, nuclei, ffuf).
func ParseJSONLines(output string) []map[string]any {
	var results []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		results = append(results, obj)
	}
	return results
}

// ParseSubfinderOutput parses subfinder output (one subdomain per line).
func ParseSubfinderOutput(output string) []string {
	var subdomains []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			subdomains = append(subdomains, strings.ToLower(line))
		}
	}
	return subdomains
}

// ParseFfufJSON parses ffuf JSON output (one JSON object per line).
func ParseFfufJSON(output string) []map[string]any {
	return ParseJSONLines(output)
}

// ParseKatanaOutput parses katana output (one URL per line).
func ParseKatanaOutput(output string) []string {
	var urls []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && (strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://")) {
			urls = append(urls, line)
		}
	}
	return urls
}

// ParseSubzyOutput parses subzy text output for takeover findings.
type TakeoverResult struct {
	Subdomain   string
	Vulnerable  bool
	Service     string
	Fingerprint string
}

func ParseSubzyOutput(output string) []TakeoverResult {
	var results []TakeoverResult
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		upper := strings.ToUpper(line)
		if strings.Contains(upper, "VULNERABLE") {
			parts := strings.Fields(line)
			subdomain := ""
			service := ""
			for _, part := range parts {
				if strings.Contains(part, ".") && !strings.HasPrefix(part, "[") {
					subdomain = strings.Trim(part, "()[]")
				}
				if strings.Contains(part, "(") {
					service = strings.Trim(part, "()")
				}
			}
			results = append(results, TakeoverResult{
				Subdomain:   subdomain,
				Vulnerable:  true,
				Service:     service,
				Fingerprint: line,
			})
		}
	}
	return results
}

// Deduplicate removes duplicates while preserving order.
func Deduplicate(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		key := strings.ToLower(item)
		if !seen[key] {
			seen[key] = true
			result = append(result, item)
		}
	}
	return result
}

// ExtractParamsFromURL extracts parameter names from a URL query string.
// Returns (hasParams, paramNames, paramCount).
func ExtractParamsFromURL(rawURL string) (bool, []string, int) {
	// Find the query part
	idx := strings.Index(rawURL, "?")
	if idx == -1 {
		return false, nil, 0
	}
	query := rawURL[idx+1:]
	if query == "" {
		return false, nil, 0
	}
	var params []string
	for _, pair := range strings.Split(query, "&") {
		if eq := strings.Index(pair, "="); eq != -1 {
			params = append(params, pair[:eq])
		} else if pair != "" {
			params = append(params, pair)
		}
	}
	if len(params) == 0 {
		return false, nil, 0
	}
	return true, params, len(params)
}

// staticAssetExts lists file extensions that are low-value for vulnerability
// scanning. Nuclei still evaluates templates against every target, so feeding
// it CSS/JS/image/font files wastes a huge amount of time and requests.
var staticAssetExts = map[string]bool{
	"css": true, "js": true, "mjs": true, "map": true,
	"png": true, "jpg": true, "jpeg": true, "gif": true, "webp": true, "svg": true, "ico": true, "bmp": true,
	"woff": true, "woff2": true, "ttf": true, "otf": true, "eot": true,
	"mp4": true, "mp3": true, "webm": true, "avi": true, "mov": true,
	"pdf": true, "zip": true, "gz": true, "tar": true, "rar": true, "7z": true,
	"xml": true, "txt": true, "csv": true, "json": true,
}

// IsStaticAsset reports whether a URL points at a static asset (by extension).
// It strips the query string before checking so "/foo.js?v=1" is still flagged.
func IsStaticAsset(rawURL string) bool {
	u := rawURL
	if i := strings.IndexAny(u, "?#"); i != -1 {
		u = u[:i]
	}
	u = strings.ToLower(u)
	dot := strings.LastIndex(u, ".")
	if dot == -1 {
		return false
	}
	slash := strings.LastIndex(u, "/")
	if slash > dot {
		return false
	}
	return staticAssetExts[u[dot+1:]]
}

// ExtractHostname extracts the hostname from a URL.
func ExtractHostname(rawURL string) string {
	// Strip scheme
	if idx := strings.Index(rawURL, "://"); idx != -1 {
		rest := rawURL[idx+3:]
		if slash := strings.Index(rest, "/"); slash != -1 {
			rest = rest[:slash]
		}
		if colon := strings.Index(rest, ":"); colon != -1 {
			rest = rest[:colon]
		}
		return rest
	}
	// No scheme
	if slash := strings.Index(rawURL, "/"); slash != -1 {
		rawURL = rawURL[:slash]
	}
	if colon := strings.Index(rawURL, ":"); colon != -1 {
		rawURL = rawURL[:colon]
	}
	return rawURL
}
