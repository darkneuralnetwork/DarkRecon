package phasemod

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yourname/dark-recon/internal/storage"
	"github.com/yourname/dark-recon/pkg/executor"
	"github.com/yourname/dark-recon/pkg/logger"
)

// defaultPortList — the top-ports set from the spec, scanned by nmap.
const defaultPortList = "80,443,8080,8443,8888,8008,3000,3001,4000,4001,4443," +
	"9090,9091,5000,5001,6060,6379,27017,5432,3306,1433," +
	"2181,9200,9300,7001,4848,8161,61616"

// interestingPorts maps a port to a human label; finding one is logged as a
// medium-severity finding in p1_findings.
var interestingPorts = map[int]string{
	6379:  "Redis open",
	27017: "MongoDB open",
	9200:  "Elasticsearch open",
	9300:  "Elasticsearch open",
	5432:  "PostgreSQL open",
	3306:  "MySQL open",
	1433:  "MSSQL open",
	8161:  "ActiveMQ admin open",
	61616: "ActiveMQ open",
	7001:  "WebLogic open",
	4848:  "GlassFish admin open",
	9090:  "Prometheus/management open",
}

// RunPortScan scans all live hosts with nmap. Per your request this uses
// nmap's stealth SYN scan (-sS) when the process runs as root; otherwise it
// transparently falls back to a TCP connect scan (-sT) which needs no
// privileges. nmap scans ALL hosts in a single invocation with -T4 so its
// internal host/ports parallelism is used — far faster than spawning one
// nmap per host.
func (r *Runner) RunPortScan(ctx context.Context, hosts []string) {
	if !r.cfg.Phase1.PortScan {
		return
	}
	if !toolAvailable("nmap", "--version") {
		r.emit(map[string]any{"phase": "port_scan", "status": "skipped", "message": "nmap not found, skipping port scan"})
		logger.Warn("nmap not found, skipping port scan")
		return
	}
	if len(hosts) == 0 {
		return
	}
	// Drop the "www.<apex-target>" alias when the apex target itself is in
	// scope: it almost always resolves to the same IP(s) and web ports
	// (80/443) as the apex, so scanning it just duplicates nmap work and the
	// resulting open-port findings. Mirrors the recon practice of treating
	// example.com and www.example.com as a single host.
	hosts = r.excludeWWWAlias(hosts)
	if len(hosts) == 0 {
		return
	}
	if len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}

	scanType := "-sT" // TCP connect scan (no root needed)
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		scanType = "-sS" // stealth SYN scan (root only)
	}

	r.emit(map[string]any{"phase": "port_scan", "status": "running", "message": fmt.Sprintf("nmap %s on %d hosts", scanType, len(hosts))})
	logger.Phase("Phase 1+ — Port Scan (nmap %s): %d hosts", scanType, len(hosts))

	// Ensure the raw dir exists (the engine creates it at scan start, but be
	// defensive so a directly invoked module doesn't fail on a missing dir).
	rawDir := r.cfg.RawDir(r.target)
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		logger.Warn("nmap: cannot create raw dir: %v", err)
		return
	}

	// Resolve every subdomain to its IP(s) up-front and build an IP→subdomain
	// reverse map. nmap's greppable output (-oG) reports hosts by IP, not by the
	// hostname we feed it via -iL, and with -n the hostname field is empty — so
	// the only reliable way to attribute a scanned IP back to the subdomain(s)
	// that produced it is to resolve them ourselves first. Resolving up-front
	// (rather than letting nmap do forward DNS) also guarantees the IPs we scan
	// are exactly the ones we can attribute, which matters for round-robin/CDN
	// hosts where successive lookups may return different addresses.
	ipToSubs, uniqueIPs := r.resolveSubdomainsToIPs(ctx, hosts)
	if len(uniqueIPs) == 0 {
		r.emit(map[string]any{"phase": "port_scan", "status": "skipped", "message": "nmap: no hosts resolved to an IP, skipping port scan"})
		logger.Warn("nmap: no hosts resolved to an IP, skipping port scan")
		return
	}

	// Feed the deduplicated IPs to nmap (not the hostnames) so -n is truly
	// correct and every output IP is guaranteed to be in ipToSubs.
	hostFile := filepath.Join(rawDir, "nmap_hosts.txt")
	if err := os.WriteFile(hostFile, []byte(strings.Join(uniqueIPs, "\n")), 0644); err != nil {
		logger.Warn("nmap: cannot write host file: %v", err)
		return
	}

	args := []string{
		"nmap",
		scanType,
		"-p", defaultPortList,
		"-T4",
		"--open",
		"-n",       // no DNS resolution — we pass IPs and attribute via ipToSubs
		"-Pn",      // skip host discovery — we know they're live from httpx
		"-oG", "-", // greppable output to stdout
		"-iL", hostFile,
	}

	// nmap timeout scales with host count + port count.
	portCount := strings.Count(defaultPortList, ",") + 1
	timeout := time.Duration(len(uniqueIPs)*portCount*15) * time.Millisecond
	if timeout < 60*time.Second {
		timeout = 60 * time.Second
	}
	if timeout > 20*time.Minute {
		timeout = 20 * time.Minute
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// nmap is a system binary resolved via PATH (already verified by
	// toolAvailable); the child inherits this process's environment.
	cmd := exec.CommandContext(cmdCtx, args[0], args[1:]...)
	out, err := cmd.Output()
	if err != nil {
		// nmap returns non-zero on partial scans sometimes; still parse stdout.
		logger.Warn("nmap: %v (stderr: %s)", err, executor.TruncateLog(string(out), 160))
	}
	// Save raw greppable output.
	rawPath := filepath.Join(r.cfg.RawDir(r.target), "nmap_ports.txt")
	_ = os.WriteFile(rawPath, out, 0644)

	found := r.parseNmapGreppable(string(out), ipToSubs)
	totalPorts := 0
	for host, ports := range found {
		totalPorts += len(ports)
		_ = r.db.UpsertP1HostIntel(r.scanID, storage.P1HostIntel{
			Subdomain:     host,
			OpenPortCount: len(ports),
			HasOpenPorts:  len(ports) > 0,
		})
		for _, p := range ports {
			_ = r.db.InsertP1Port(r.scanID, storage.P1Port{
				Subdomain: host, Port: p.Port, Protocol: p.Protocol, Service: p.Service,
			})
			r.emit(map[string]any{
				"phase": "port_scan", "status": "port",
				"message": fmt.Sprintf("%s: %d/%s open", host, p.Port, p.Protocol),
				"finding": map[string]any{"host": host, "port": p.Port, "protocol": p.Protocol},
			})
			if label, ok := interestingPorts[p.Port]; ok {
				desc := fmt.Sprintf("Port %d open on %s", p.Port, host)
				_ = r.db.InsertP1Finding(r.scanID, storage.P1Finding{
					Subdomain: host, Tool: "nmap", Severity: "medium",
					Name: label, Description: &desc,
				})
				r.emitFinding(host, "nmap", "medium", label, "")
			}
		}
	}

	r.emit(map[string]any{"phase": "port_scan", "status": "completed", "count": totalPorts, "message": fmt.Sprintf("Port scan complete: %d open ports", totalPorts)})
	logger.Success("nmap: %d open ports across %d hosts", totalPorts, len(found))
}

type nmapPort struct {
	Port     int
	Protocol string
	Service  *string
}

// parseNmapGreppable parses nmap -oG - output lines like:
//
//	Host: 1.2.3.4 (host.example.com)	Ports: 80/open/tcp//http///, 443/open/tcp//https///
//
// The first token after "Host:" is always the IP nmap scanned. We look that
// IP up in ipToSubs (built from our own forward resolution) to recover the
// original subdomain name(s). If the IP is somehow missing from the map (e.g.
// it resolved differently for nmap), we fall back to the reverse-DNS name in
// parentheses, then to the IP itself, so results are never silently dropped.
// Every open port on a shared IP is attributed to each subdomain that
// resolved to it, since they are all served by the same host.
func (r *Runner) parseNmapGreppable(out string, ipToSubs map[string][]string) map[string][]nmapPort {
	result := make(map[string][]nmapPort)
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "Host: ") {
			continue
		}
		if !strings.Contains(line, "Ports:") {
			continue
		}
		hostField := strings.TrimSpace(strings.TrimPrefix(line, "Host: "))
		// hostField = "1.2.3.4 ()\tStatus: Up\tPorts: ..."
		tokens := strings.Fields(hostField)
		if len(tokens) == 0 {
			continue
		}
		ip := tokens[0]

		hostKeys := ipToSubs[ip]
		if len(hostKeys) == 0 {
			if name := extractParensName(hostField); name != "" {
				hostKeys = []string{name}
			} else {
				hostKeys = []string{ip}
			}
		}

		pi := strings.Index(hostField, "Ports:")
		if pi < 0 {
			continue
		}
		portsStr := strings.TrimSpace(hostField[pi+len("Ports:"):])
		var ports []nmapPort
		for _, entry := range strings.Split(portsStr, ",") {
			entry = strings.TrimSpace(entry)
			// entry: "80/open/tcp//http///"
			parts := strings.Split(entry, "/")
			if len(parts) < 3 {
				continue
			}
			if strings.TrimSpace(parts[1]) != "open" {
				continue
			}
			port, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil || port == 0 {
				continue
			}
			proto := strings.TrimSpace(parts[2])
			if proto == "" {
				proto = "tcp"
			}
			var service *string
			if len(parts) > 4 {
				svc := strings.TrimSpace(parts[4])
				if svc != "" {
					service = &svc
				}
			}
			ports = append(ports, nmapPort{Port: port, Protocol: proto, Service: service})
		}
		for _, hk := range hostKeys {
			hk = strings.ToLower(strings.TrimSpace(hk))
			if hk == "" {
				continue
			}
			result[hk] = append(result[hk], ports...)
		}
	}
	return result
}

// extractParensName returns the substring inside the first (...) in s, or "".
func extractParensName(s string) string {
	lp := strings.Index(s, "(")
	if lp < 0 {
		return ""
	}
	rp := strings.Index(s[lp:], ")")
	if rp <= 1 { // "()" or no closing paren → empty
		return ""
	}
	return strings.TrimSpace(s[lp+1 : lp+rp])
}

// resolveSubdomainsToIPs resolves each subdomain to its A/AAAA records and
// returns an IP→subdomain reverse map plus the deduplicated list of unique IPs
// to feed to nmap. Resolution is concurrent with a bounded worker pool,
// matching the project's enumeration style. Subdomains that fail to resolve
// (e.g. transient DNS errors) are simply omitted — nmap couldn't scan them
// anyway. See RunPortScan for why up-front resolution is required.
func (r *Runner) resolveSubdomainsToIPs(ctx context.Context, hosts []string) (ipToSubs map[string][]string, uniqueIPs []string) {
	ipToSubs = make(map[string][]string)
	seen := make(map[string]bool)
	var mu sync.Mutex

	workers := r.cfg.Phase1.PortScanWorkers
	if workers <= 0 {
		workers = 50
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	resolver := net.DefaultResolver
	for _, h := range hosts {
		if ctx.Err() != nil {
			break
		}
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					logger.Warn("nmap: DNS resolution panicked for %s: %v", host, rec)
				}
			}()
			lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			ips, err := resolver.LookupIPAddr(lookupCtx, host)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, ip := range ips {
				addr := ip.IP.String()
				if addr == "" {
					continue
				}
				if !seen[addr] {
					seen[addr] = true
					uniqueIPs = append(uniqueIPs, addr)
				}
				if !containsString(ipToSubs[addr], host) {
					ipToSubs[addr] = append(ipToSubs[addr], host)
				}
			}
		}(h)
	}
	wg.Wait()
	return ipToSubs, uniqueIPs
}

// containsString reports whether s contains v (small-list helper).
func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// excludeWWWAlias drops the "www.<apex-target>" host from the scan list when
// the configured scan target is the apex domain. The www variant almost
// always resolves to the same IP(s) and same web ports (80/443) as the apex,
// so scanning it duplicates nmap effort and the open-port findings. Each entry
// is normalised (scheme / userinfo / path / port stripped, lower-cased)
// before comparison, so a stray "http://www.target.com" URL is matched just
// like the bare "www.target.com" hostname. If the scan target is itself a
// www host, or empty, the list is returned unchanged.
func (r *Runner) excludeWWWAlias(hosts []string) []string {
	apex := normaliseHostname(r.target)
	if apex == "" || strings.HasPrefix(apex, "www.") {
		return hosts
	}
	ignore := "www." + apex
	out := make([]string, 0, len(hosts))
	dropped := 0
	for _, h := range hosts {
		if normaliseHostname(h) == ignore {
			dropped++
			continue
		}
		out = append(out, h)
	}
	if dropped > 0 {
		r.emit(map[string]any{
			"phase":   "port_scan",
			"status":  "info",
			"message": fmt.Sprintf("nmap: skipping %d www-alias host(s) (%s) — same server as apex target", dropped, ignore),
		})
		logger.Tool("nmap", "skipping %d www-alias host(s) (%s) — same server as apex target", dropped, ignore)
	}
	return out
}

// normaliseHostname reduces a host or URL to a bare lower-cased hostname (no
// scheme, userinfo, port, path or query) so equivalence checks are robust
// against the variety of forms a "host" entry can take (bare hostname,
// http://www.target.com, www.target.com:443/path, etc.).
func normaliseHostname(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip userinfo user:pass@
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	// Strip path / query / fragment.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// Strip a trailing :port. A bare hostname has no colon; we never feed IPv6
	// literals to nmap here, so this is safe.
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}
