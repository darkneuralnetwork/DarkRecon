package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite database connection.
type DB struct {
	conn *sql.DB
	// onClose, when set, is invoked by Close instead of closing the underlying
	// *sql.DB. The DBCache uses this so that handles handed to API readers are
	// "closed" by decrementing the cache refcount (so the shared connection
	// stays open for the next reader) rather than being torn down. A handle
	// opened directly via Open has onClose == nil and closes normally.
	onClose func()
}

// Open opens (or creates) the SQLite database at the given path.
func Open(dbPath string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	conn, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	conn.SetMaxOpenConns(1) // SQLite single-writer
	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

// Close closes the database connection, unless this handle is cache-managed
// (onClose set), in which case it releases the cache refcount instead. This
// lets existing callers that do `defer db.Close()` work unchanged whether the
// handle came from Open (real close) or DBCache.Acquire (refcount release).
func (db *DB) Close() error {
	if db.onClose != nil {
		db.onClose()
		return nil
	}
	return db.conn.Close()
}

// Conn returns the underlying *sql.DB. Exposed so the phasemod orchestrator
// and the Phase-2 API handlers can run ad-hoc aggregate queries without a
// dedicated storage method for each one.
func (db *DB) Conn() *sql.DB {
	return db.conn
}

func (db *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scan_meta (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		start_time TEXT NOT NULL,
		end_time TEXT,
		duration_seconds REAL,
		status TEXT DEFAULT 'running',
		phases_completed TEXT DEFAULT '[]',
		error TEXT
	);

	CREATE TABLE IF NOT EXISTS subdomains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL REFERENCES scan_meta(id),
		subdomain TEXT NOT NULL,
		source TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
	-- Unique on (scan_id, subdomain) so passive recon and the enumerators
	-- (which run concurrently and both insert) can't create duplicate rows for
	-- the same host within a scan. Additive: safe on pre-existing DBs.
	CREATE UNIQUE INDEX IF NOT EXISTS idx_subdomains_unique ON subdomains(scan_id, subdomain);

	CREATE TABLE IF NOT EXISTS live_hosts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL REFERENCES scan_meta(id),
		url TEXT NOT NULL,
		subdomain TEXT NOT NULL,
		status_code INTEGER,
		title TEXT,
		content_length INTEGER,
		webserver TEXT,
		cdn TEXT,
		redirect_url TEXT,
		tech_detected TEXT DEFAULT '[]'
	);
	CREATE INDEX IF NOT EXISTS idx_live_hosts_scan ON live_hosts(scan_id);
	CREATE INDEX IF NOT EXISTS idx_live_hosts_sub ON live_hosts(subdomain);

	CREATE TABLE IF NOT EXISTS tech_detections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL REFERENCES scan_meta(id),
		subdomain TEXT NOT NULL,
		name TEXT NOT NULL,
		version TEXT,
		category TEXT,
		confidence TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_tech_scan ON tech_detections(scan_id);

	CREATE TABLE IF NOT EXISTS crawled_urls (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL REFERENCES scan_meta(id),
		url TEXT NOT NULL,
		subdomain TEXT NOT NULL,
		has_params INTEGER DEFAULT 0,
		param_names TEXT DEFAULT '[]',
		param_count INTEGER DEFAULT 0,
		source TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_crawled_scan ON crawled_urls(scan_id);
	CREATE INDEX IF NOT EXISTS idx_crawled_sub ON crawled_urls(subdomain);

	CREATE TABLE IF NOT EXISTS discovered_dirs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL REFERENCES scan_meta(id),
		url TEXT NOT NULL,
		subdomain TEXT NOT NULL,
		path TEXT NOT NULL,
		status_code INTEGER,
		content_length INTEGER,
		wordlist_used TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_dirs_scan ON discovered_dirs(scan_id);
	CREATE INDEX IF NOT EXISTS idx_dirs_sub ON discovered_dirs(subdomain);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL REFERENCES scan_meta(id),
		template_id TEXT,
		name TEXT NOT NULL,
		severity TEXT,
		url TEXT,
		subdomain TEXT,
		cve_ids TEXT DEFAULT '[]',
		description TEXT,
		matcher_name TEXT,
		extracted_results TEXT DEFAULT '[]',
		reference TEXT DEFAULT '[]',
		type TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
	CREATE INDEX IF NOT EXISTS idx_vulns_sub ON vulnerabilities(subdomain);

	CREATE TABLE IF NOT EXISTS takeover_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL REFERENCES scan_meta(id),
		subdomain TEXT NOT NULL,
		vulnerable INTEGER DEFAULT 0,
		service TEXT,
		fingerprint TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_takeover_scan ON takeover_results(scan_id);

	CREATE TABLE IF NOT EXISTS priority_entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL REFERENCES scan_meta(id),
		rank INTEGER,
		subdomain TEXT NOT NULL,
		url TEXT,
		priority_score REAL,
		priority_tier TEXT,
		reasons TEXT DEFAULT '[]',
		tech_stack TEXT DEFAULT '[]',
		vulnerabilities TEXT DEFAULT '[]',
		urls_with_params TEXT DEFAULT '[]',
		exposed_dirs TEXT DEFAULT '[]',
		missing_headers TEXT DEFAULT '[]',
		takeover_vulnerable INTEGER DEFAULT 0,
		suggested_tests TEXT DEFAULT '[]'
	);
	CREATE INDEX IF NOT EXISTS idx_priority_scan ON priority_entries(scan_id);

	CREATE TABLE IF NOT EXISTS header_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL REFERENCES scan_meta(id),
		url TEXT,
		status_code INTEGER,
		headers TEXT DEFAULT '{}',
		detected_tech TEXT DEFAULT '[]',
		frameworks TEXT DEFAULT '[]',
		server TEXT,
		missing_security_headers TEXT DEFAULT '[]'
	);
	CREATE INDEX IF NOT EXISTS idx_headers_scan ON header_results(scan_id);

	-- ── Phase 1 advanced modules (additive, prefixed p1_ to avoid clashing
	-- with existing subdomains/vulnerabilities/crawled_urls tables) ──

	CREATE TABLE IF NOT EXISTS p1_passive_recon (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id     INTEGER NOT NULL REFERENCES scan_meta(id),
		subdomain   TEXT NOT NULL,
		source      TEXT,
		data_type   TEXT,
		value       TEXT,
		raw         TEXT,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_p1_passive_scan ON p1_passive_recon(scan_id);
	CREATE INDEX IF NOT EXISTS idx_p1_passive_sub ON p1_passive_recon(subdomain);

	CREATE TABLE IF NOT EXISTS p1_ports (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id     INTEGER NOT NULL REFERENCES scan_meta(id),
		subdomain   TEXT NOT NULL,
		port        INTEGER NOT NULL,
		protocol    TEXT DEFAULT 'tcp',
		service     TEXT,
		banner      TEXT,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_p1_ports_scan ON p1_ports(scan_id);
	CREATE INDEX IF NOT EXISTS idx_p1_ports_sub ON p1_ports(subdomain);

	CREATE TABLE IF NOT EXISTS p1_js_files (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id     INTEGER NOT NULL REFERENCES scan_meta(id),
		subdomain   TEXT NOT NULL,
		url         TEXT NOT NULL,
		size_bytes  INTEGER,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_p1_jsfiles_scan ON p1_js_files(scan_id);

	CREATE TABLE IF NOT EXISTS p1_js_findings (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id     INTEGER NOT NULL REFERENCES scan_meta(id),
		js_file_id  INTEGER,
		subdomain   TEXT NOT NULL,
		type        TEXT,
		pattern     TEXT,
		value       TEXT,
		context     TEXT,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_p1_jsfind_scan ON p1_js_findings(scan_id);
	CREATE INDEX IF NOT EXISTS idx_p1_jsfind_sub ON p1_js_findings(subdomain);

	CREATE TABLE IF NOT EXISTS p1_params (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id     INTEGER NOT NULL REFERENCES scan_meta(id),
		subdomain   TEXT NOT NULL,
		url         TEXT NOT NULL,
		param_name  TEXT NOT NULL,
		param_type  TEXT,
		source      TEXT,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_p1_params_scan ON p1_params(scan_id);
	CREATE INDEX IF NOT EXISTS idx_p1_params_sub ON p1_params(subdomain);

	CREATE TABLE IF NOT EXISTS p1_secrets (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id     INTEGER NOT NULL REFERENCES scan_meta(id),
		subdomain   TEXT,
		source_url  TEXT,
		secret_type TEXT,
		raw_match   TEXT,
		entropy     REAL,
		tool        TEXT,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_p1_secrets_scan ON p1_secrets(scan_id);

	CREATE TABLE IF NOT EXISTS p1_findings (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id      INTEGER NOT NULL REFERENCES scan_meta(id),
		subdomain    TEXT NOT NULL,
		tool         TEXT NOT NULL,
		template_id  TEXT,
		severity     TEXT,
		name         TEXT,
		description  TEXT,
		evidence     TEXT,
		verified     BOOLEAN DEFAULT 0,
		false_pos    BOOLEAN DEFAULT 0,
		created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_p1_findings_scan ON p1_findings(scan_id);
	CREATE INDEX IF NOT EXISTS idx_p1_findings_sub ON p1_findings(subdomain);
	CREATE INDEX IF NOT EXISTS idx_p1_findings_sev ON p1_findings(severity);

	CREATE TABLE IF NOT EXISTS p1_host_intel (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id           INTEGER NOT NULL REFERENCES scan_meta(id),
		subdomain         TEXT NOT NULL UNIQUE,
		waf               TEXT,
		waf_manufacturer  TEXT,
		open_port_count   INTEGER DEFAULT 0,
		param_count       INTEGER DEFAULT 0,
		secret_count      INTEGER DEFAULT 0,
		js_endpoint_count INTEGER DEFAULT 0,
		has_open_ports    BOOLEAN DEFAULT 0,
		has_params        BOOLEAN DEFAULT 0,
		has_secrets       BOOLEAN DEFAULT 0,
		has_js_endpoints  BOOLEAN DEFAULT 0,
		created_at        DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_p1_intel_scan ON p1_host_intel(scan_id);
	`
	_, err := db.conn.Exec(schema)
	return err
}

// ── Scan Meta ──────────────────────────────────────────────────────

// CreateScan creates a new scan record and returns its ID.
func (db *DB) CreateScan(target string) (int64, error) {
	res, err := db.conn.Exec(
		`INSERT INTO scan_meta (target, start_time, status, phases_completed) VALUES (?, ?, 'running', '[]')`,
		target, time.Now().Format(time.RFC3339),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateScanStatus updates the scan status and end time.
func (db *DB) UpdateScanStatus(scanID int64, status string, errMsg *string) error {
	_, err := db.conn.Exec(
		`UPDATE scan_meta SET status = ?, error = ?, end_time = ? WHERE id = ?`,
		status, errMsg, time.Now().Format(time.RFC3339), scanID,
	)
	return err
}

// CompleteScan finalizes the scan with duration.
func (db *DB) CompleteScan(scanID int64, status string, duration float64) error {
	_, err := db.conn.Exec(
		`UPDATE scan_meta SET status = ?, end_time = ?, duration_seconds = ? WHERE id = ?`,
		status, time.Now().Format(time.RFC3339), duration, scanID,
	)
	return err
}

// AddCompletedPhase appends a phase to the phases_completed array.
func (db *DB) AddCompletedPhase(scanID int64, phase string) error {
	var phases string
	err := db.conn.QueryRow(`SELECT phases_completed FROM scan_meta WHERE id = ?`, scanID).Scan(&phases)
	if err != nil {
		return err
	}
	var arr []string
	_ = json.Unmarshal([]byte(phases), &arr)
	for _, p := range arr {
		if p == phase {
			return nil // already added
		}
	}
	arr = append(arr, phase)
	data, _ := json.Marshal(arr)
	_, err = db.conn.Exec(`UPDATE scan_meta SET phases_completed = ? WHERE id = ?`, string(data), scanID)
	return err
}

// GetScanMeta retrieves scan metadata by ID.
func (db *DB) GetScanMeta(scanID int64) (*ScanMeta, error) {
	row := db.conn.QueryRow(`SELECT id, target, start_time, end_time, duration_seconds, status, phases_completed, error FROM scan_meta WHERE id = ?`, scanID)
	m := &ScanMeta{}
	var startTime, endTime, errMsg sql.NullString
	var duration sql.NullFloat64
	if err := row.Scan(&m.ID, &m.Target, &startTime, &endTime, &duration, &m.Status, &m.PhasesCompleted, &errMsg); err != nil {
		return nil, err
	}
	if startTime.Valid {
		t, _ := time.Parse(time.RFC3339, startTime.String)
		m.StartTime = t
	}
	if endTime.Valid {
		t, _ := time.Parse(time.RFC3339, endTime.String)
		m.EndTime = &t
	}
	if duration.Valid {
		d := duration.Float64
		m.DurationSeconds = &d
	}
	if errMsg.Valid {
		m.Error = &errMsg.String
	}
	return m, nil
}

// ListScans returns all scan records, ordered by most recent.
func (db *DB) ListScans() ([]ScanMeta, error) {
	rows, err := db.conn.Query(`SELECT id, target, start_time, end_time, duration_seconds, status, phases_completed, error FROM scan_meta ORDER BY start_time DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []ScanMeta
	for rows.Next() {
		m := ScanMeta{}
		var startTime, endTime, errMsg sql.NullString
		var duration sql.NullFloat64
		if err := rows.Scan(&m.ID, &m.Target, &startTime, &endTime, &duration, &m.Status, &m.PhasesCompleted, &errMsg); err != nil {
			continue
		}
		if startTime.Valid {
			t, _ := time.Parse(time.RFC3339, startTime.String)
			m.StartTime = t
		}
		if endTime.Valid {
			t, _ := time.Parse(time.RFC3339, endTime.String)
			m.EndTime = &t
		}
		if duration.Valid {
			d := duration.Float64
			m.DurationSeconds = &d
		}
		if errMsg.Valid {
			m.Error = &errMsg.String
		}
		scans = append(scans, m)
	}
	return scans, nil
}

// GetScanByTarget returns the most recent scan for a target.
func (db *DB) GetScanByTarget(target string) (*ScanMeta, error) {
	row := db.conn.QueryRow(`SELECT id, target, start_time, end_time, duration_seconds, status, phases_completed, error FROM scan_meta WHERE target = ? ORDER BY start_time DESC LIMIT 1`, target)
	m := &ScanMeta{}
	var startTime, endTime, errMsg sql.NullString
	var duration sql.NullFloat64
	if err := row.Scan(&m.ID, &m.Target, &startTime, &endTime, &duration, &m.Status, &m.PhasesCompleted, &errMsg); err != nil {
		return nil, err
	}
	if startTime.Valid {
		t, _ := time.Parse(time.RFC3339, startTime.String)
		m.StartTime = t
	}
	if endTime.Valid {
		t, _ := time.Parse(time.RFC3339, endTime.String)
		m.EndTime = &t
	}
	if duration.Valid {
		d := duration.Float64
		m.DurationSeconds = &d
	}
	if errMsg.Valid {
		m.Error = &errMsg.String
	}
	return m, nil
}

// GetPriorScanID returns the most recent scan id for the target that was
// created before `before` (i.e. a previous scan), or (0, false) if none.
// Used by the pipeline to reuse prerequisite results (subdomains/live hosts)
// when a user launches a scan that only selects a downstream phase — e.g.
// "only port scan" — on a target that already has enumeration data from an
// earlier scan. The per-target DB persists across scans, so this lets an
// opt-in phase selection run standalone instead of failing for missing inputs.
func (db *DB) GetPriorScanID(target string, before int64) (int64, bool) {
	var id int64
	err := db.conn.QueryRow(
		`SELECT id FROM scan_meta WHERE target = ? AND id < ? ORDER BY id DESC LIMIT 1`,
		target, before,
	).Scan(&id)
	if err != nil {
		return 0, false
	}
	return id, true
}

// GetPriorScanIDWithData returns the most recent prior scan id (before `before`)
// for the target that actually has at least one row in `table` (e.g.
// "live_hosts", "crawled_urls", "subdomains"). This is the robust form of
// GetPriorScanID for the reuse path: a downstream-only scan (e.g. "only JS
// analysis") itself has no crawled URLs, so the naive most-recent-prior-scan
// lookup would copy zero rows from it. Searching for a prior scan that truly
// has the data makes reuse work even when several narrow scans were run in
// between. Returns (0, false) when no qualifying scan exists.
func (db *DB) GetPriorScanIDWithData(target, table string, before int64) (int64, bool) {
	// `table` is only ever one of the hardcoded internal table names (callers
	// pass string literals), so it is safe to interpolate. Never user input.
	var id int64
	q := fmt.Sprintf(
		`SELECT scan_id FROM %s WHERE scan_id IN (SELECT id FROM scan_meta WHERE target = ? AND id < ?) GROUP BY scan_id ORDER BY scan_id DESC LIMIT 1`,
		table,
	)
	err := db.conn.QueryRow(q, target, before).Scan(&id)
	if err != nil {
		return 0, false
	}
	return id, true
}

// ReuseSubdomains copies every distinct subdomain from srcScanID into dstScanID
// (skipping duplicates via the unique (scan_id, subdomain) index) and returns
// the number of rows actually inserted. This makes a downstream-only scan
// self-contained: its own scanID carries the hosts it depends on, so reports
// and DB queries keyed on the current scanID see them.
func (db *DB) ReuseSubdomains(dstScanID, srcScanID int64) (int, error) {
	res, err := db.conn.Exec(
		`INSERT OR IGNORE INTO subdomains (scan_id, subdomain, source)
		 SELECT ?, subdomain, source FROM subdomains WHERE scan_id = ?`,
		dstScanID, srcScanID,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ReuseLiveHosts copies live hosts from srcScanID into dstScanID (a fresh
// scanID, so no duplicate guard is needed) and returns the number copied.
// See ReuseSubdomains for why this exists.
func (db *DB) ReuseLiveHosts(dstScanID, srcScanID int64) (int, error) {
	res, err := db.conn.Exec(
		`INSERT INTO live_hosts (scan_id, url, subdomain, status_code, title,
		    content_length, webserver, cdn, redirect_url, tech_detected)
		 SELECT ?, url, subdomain, status_code, title,
		    content_length, webserver, cdn, redirect_url, tech_detected
		 FROM live_hosts WHERE scan_id = ?`,
		dstScanID, srcScanID,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ReuseCrawledURLs copies crawled URLs from srcScanID into dstScanID so that
// URL-dependent modules (js_analysis, param_discovery, secret_scan) can run
// standalone on a target that already has crawl data from an earlier scan —
// exactly the way ReuseLiveHosts lets waf_detect/port_scan run standalone.
// Without this, selecting "only js_analysis" on a previously-scanned target
// finds zero crawled URLs and produces no results.
func (db *DB) ReuseCrawledURLs(dstScanID, srcScanID int64) (int, error) {
	res, err := db.conn.Exec(
		`INSERT INTO crawled_urls (scan_id, url, subdomain, has_params, param_names, param_count, source)
		 SELECT ?, url, subdomain, has_params, param_names, param_count, source
		 FROM crawled_urls WHERE scan_id = ?`,
		dstScanID, srcScanID,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ── Subdomains ─────────────────────────────────────────────────────

func (db *DB) InsertSubdomain(scanID int64, subdomain, source string) error {
	_, err := db.conn.Exec(`INSERT OR IGNORE INTO subdomains (scan_id, subdomain, source) VALUES (?, ?, ?)`, scanID, subdomain, source)
	return err
}

func (db *DB) InsertSubdomains(scanID int64, subs []Subdomain) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	stmt, _ := tx.Prepare(`INSERT OR IGNORE INTO subdomains (scan_id, subdomain, source) VALUES (?, ?, ?)`)
	defer stmt.Close()
	for _, s := range subs {
		_, _ = stmt.Exec(scanID, s.Subdomain, s.Source)
	}
	return tx.Commit()
}

func (db *DB) GetSubdomains(scanID int64) ([]Subdomain, error) {
	rows, err := db.conn.Query(`SELECT id, scan_id, subdomain, source FROM subdomains WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var subs []Subdomain
	for rows.Next() {
		s := Subdomain{}
		_ = rows.Scan(&s.ID, &s.ScanID, &s.Subdomain, &s.Source)
		subs = append(subs, s)
	}
	return subs, nil
}

// ── Live Hosts ─────────────────────────────────────────────────────

func (db *DB) InsertLiveHost(scanID int64, h LiveHost) error {
	_, err := db.conn.Exec(
		`INSERT INTO live_hosts (scan_id, url, subdomain, status_code, title, content_length, webserver, cdn, redirect_url, tech_detected) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, h.URL, h.Subdomain, h.StatusCode, h.Title, h.ContentLength, h.Webserver, h.CDN, h.RedirectURL, h.TechDetected,
	)
	return err
}

func (db *DB) GetLiveHosts(scanID int64) ([]LiveHost, error) {
	// Exclude 404 (not found) and 5xx (server error) responses — they offer no
	// actionable attack surface and must never appear in the live list, live
	// counts, or be fed to downstream phases (tech detect / crawl / nuclei /
	// priority). httpx already drops them at insert time; this query-level
	// filter is a safety net for legacy DB rows and any other importer so the
	// UI list stays clean regardless of how the row was written.
	rows, err := db.conn.Query(`SELECT id, scan_id, url, subdomain, status_code, title, content_length, webserver, cdn, redirect_url, tech_detected FROM live_hosts WHERE scan_id = ? AND status_code != 404 AND (status_code < 500 OR status_code > 599) ORDER BY subdomain`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hosts []LiveHost
	for rows.Next() {
		h := LiveHost{}
		_ = rows.Scan(&h.ID, &h.ScanID, &h.URL, &h.Subdomain, &h.StatusCode, &h.Title, &h.ContentLength, &h.Webserver, &h.CDN, &h.RedirectURL, &h.TechDetected)
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// ── Tech Detections ────────────────────────────────────────────────

func (db *DB) InsertTechDetection(scanID int64, t TechDetection) error {
	_, err := db.conn.Exec(
		`INSERT INTO tech_detections (scan_id, subdomain, name, version, category, confidence) VALUES (?, ?, ?, ?, ?, ?)`,
		scanID, t.Subdomain, t.Name, t.Version, t.Category, t.Confidence,
	)
	return err
}

func (db *DB) GetTechDetections(scanID int64) ([]TechDetection, error) {
	rows, err := db.conn.Query(
		`SELECT id, scan_id, subdomain, name, version, category, confidence FROM tech_detections WHERE scan_id = ?`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var detections []TechDetection
	for rows.Next() {
		t := TechDetection{}
		_ = rows.Scan(&t.ID, &t.ScanID, &t.Subdomain, &t.Name, &t.Version, &t.Category, &t.Confidence)
		detections = append(detections, t)
	}
	return detections, nil
}

// ── Crawled URLs ───────────────────────────────────────────────────

func (db *DB) InsertCrawledURL(scanID int64, u CrawledURL) error {
	_, err := db.conn.Exec(
		`INSERT INTO crawled_urls (scan_id, url, subdomain, has_params, param_names, param_count, source) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		scanID, u.URL, u.Subdomain, u.HasParams, u.ParamNames, u.ParamCount, u.Source,
	)
	return err
}

func (db *DB) GetCrawledURLs(scanID int64) ([]CrawledURL, error) {
	rows, err := db.conn.Query(`SELECT id, scan_id, url, subdomain, has_params, param_names, param_count, source FROM crawled_urls WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var urls []CrawledURL
	for rows.Next() {
		u := CrawledURL{}
		_ = rows.Scan(&u.ID, &u.ScanID, &u.URL, &u.Subdomain, &u.HasParams, &u.ParamNames, &u.ParamCount, &u.Source)
		urls = append(urls, u)
	}
	return urls, nil
}

// ── Discovered Dirs ────────────────────────────────────────────────

func (db *DB) InsertDiscoveredDir(scanID int64, d DiscoveredDir) error {
	_, err := db.conn.Exec(
		`INSERT INTO discovered_dirs (scan_id, url, subdomain, path, status_code, content_length, wordlist_used) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		scanID, d.URL, d.Subdomain, d.Path, d.StatusCode, d.ContentLength, d.WordlistUsed,
	)
	return err
}

func (db *DB) GetDiscoveredDirs(scanID int64) ([]DiscoveredDir, error) {
	rows, err := db.conn.Query(`SELECT id, scan_id, url, subdomain, path, status_code, content_length, wordlist_used FROM discovered_dirs WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var dirs []DiscoveredDir
	for rows.Next() {
		d := DiscoveredDir{}
		_ = rows.Scan(&d.ID, &d.ScanID, &d.URL, &d.Subdomain, &d.Path, &d.StatusCode, &d.ContentLength, &d.WordlistUsed)
		dirs = append(dirs, d)
	}
	return dirs, nil
}

// ── Vulnerabilities ────────────────────────────────────────────────

func (db *DB) InsertVulnerability(scanID int64, v Vulnerability) error {
	_, err := db.conn.Exec(
		`INSERT INTO vulnerabilities (scan_id, template_id, name, severity, url, subdomain, cve_ids, description, matcher_name, extracted_results, reference, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, v.TemplateID, v.Name, v.Severity, v.URL, v.Subdomain, v.CVEIDs, v.Description, v.MatcherName, v.ExtractedResults, v.References, v.Type,
	)
	return err
}

func (db *DB) GetVulnerabilities(scanID int64) ([]Vulnerability, error) {
	rows, err := db.conn.Query(`SELECT id, scan_id, template_id, name, severity, url, subdomain, cve_ids, description, matcher_name, extracted_results, reference, type FROM vulnerabilities WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var vulns []Vulnerability
	for rows.Next() {
		v := Vulnerability{}
		_ = rows.Scan(&v.ID, &v.ScanID, &v.TemplateID, &v.Name, &v.Severity, &v.URL, &v.Subdomain, &v.CVEIDs, &v.Description, &v.MatcherName, &v.ExtractedResults, &v.References, &v.Type)
		vulns = append(vulns, v)
	}
	return vulns, nil
}

// ── Takeover Results ───────────────────────────────────────────────

func (db *DB) InsertTakeover(scanID int64, t TakeoverResult) error {
	_, err := db.conn.Exec(
		`INSERT INTO takeover_results (scan_id, subdomain, vulnerable, service, fingerprint) VALUES (?, ?, ?, ?, ?)`,
		scanID, t.Subdomain, t.Vulnerable, t.Service, t.Fingerprint,
	)
	return err
}

func (db *DB) GetTakeoverResults(scanID int64) ([]TakeoverResult, error) {
	rows, err := db.conn.Query(
		`SELECT id, scan_id, subdomain, vulnerable, service, fingerprint FROM takeover_results WHERE scan_id = ?`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []TakeoverResult
	for rows.Next() {
		t := TakeoverResult{}
		_ = rows.Scan(&t.ID, &t.ScanID, &t.Subdomain, &t.Vulnerable, &t.Service, &t.Fingerprint)
		results = append(results, t)
	}
	return results, nil
}

// ── Priority Entries ───────────────────────────────────────────────

func (db *DB) InsertPriorityEntry(scanID int64, p PriorityEntry) error {
	_, err := db.conn.Exec(
		`INSERT INTO priority_entries (scan_id, rank, subdomain, url, priority_score, priority_tier, reasons, tech_stack, vulnerabilities, urls_with_params, exposed_dirs, missing_headers, takeover_vulnerable, suggested_tests) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, p.Rank, p.Subdomain, p.URL, p.PriorityScore, p.PriorityTier, p.Reasons, p.TechStack, p.Vulnerabilities, p.URLsWithParams, p.ExposedDirs, p.MissingHeaders, p.TakeoverVulnerable, p.SuggestedTests,
	)
	return err
}

func (db *DB) GetPriorityEntries(scanID int64) ([]PriorityEntry, error) {
	rows, err := db.conn.Query(`SELECT id, scan_id, rank, subdomain, url, priority_score, priority_tier, reasons, tech_stack, vulnerabilities, urls_with_params, exposed_dirs, missing_headers, takeover_vulnerable, suggested_tests FROM priority_entries WHERE scan_id = ? ORDER BY priority_score DESC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []PriorityEntry
	for rows.Next() {
		p := PriorityEntry{}
		_ = rows.Scan(&p.ID, &p.ScanID, &p.Rank, &p.Subdomain, &p.URL, &p.PriorityScore, &p.PriorityTier, &p.Reasons, &p.TechStack, &p.Vulnerabilities, &p.URLsWithParams, &p.ExposedDirs, &p.MissingHeaders, &p.TakeoverVulnerable, &p.SuggestedTests)
		entries = append(entries, p)
	}
	return entries, nil
}

// ── Header Results ─────────────────────────────────────────────────

func (db *DB) InsertHeaderResult(scanID int64, h HeaderResult) error {
	_, err := db.conn.Exec(
		`INSERT INTO header_results (scan_id, url, status_code, headers, detected_tech, frameworks, server, missing_security_headers) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, h.URL, h.StatusCode, h.Headers, h.DetectedTech, h.Frameworks, h.Server, h.MissingSecurityHeaders,
	)
	return err
}

func (db *DB) GetHeaderResult(scanID int64) (*HeaderResult, error) {
	row := db.conn.QueryRow(`SELECT id, scan_id, url, status_code, headers, detected_tech, frameworks, server, missing_security_headers FROM header_results WHERE scan_id = ? LIMIT 1`, scanID)
	h := &HeaderResult{}
	if err := row.Scan(&h.ID, &h.ScanID, &h.URL, &h.StatusCode, &h.Headers, &h.DetectedTech, &h.Frameworks, &h.Server, &h.MissingSecurityHeaders); err != nil {
		return nil, err
	}
	return h, nil
}

// ── Deletion ───────────────────────────────────────────────────────

// DeleteScan removes all data for a scan.
func (db *DB) DeleteScan(scanID int64) error {
	tables := []string{"subdomains", "live_hosts", "tech_detections", "crawled_urls",
		"discovered_dirs", "vulnerabilities", "takeover_results",
		"priority_entries", "header_results",
		"p1_passive_recon", "p1_ports", "p1_js_files", "p1_js_findings",
		"p1_params", "p1_secrets", "p1_findings", "p1_host_intel"}
	for _, t := range tables {
		if _, err := db.conn.Exec(fmt.Sprintf("DELETE FROM %s WHERE scan_id = ?", t), scanID); err != nil {
			return err
		}
	}
	_, err := db.conn.Exec("DELETE FROM scan_meta WHERE id = ?", scanID)
	return err
}

// ── Phase 1 advanced module storage ───────────────────────────────

func (db *DB) InsertP1PassiveRecon(scanID int64, r P1PassiveRecon) error {
	_, err := db.conn.Exec(
		`INSERT OR IGNORE INTO p1_passive_recon (scan_id, subdomain, source, data_type, value, raw) VALUES (?, ?, ?, ?, ?, ?)`,
		scanID, r.Subdomain, r.Source, r.DataType, r.Value, r.Raw,
	)
	return err
}

func (db *DB) GetP1PassiveRecon(scanID int64) ([]P1PassiveRecon, error) {
	rows, err := db.conn.Query(`SELECT id, scan_id, subdomain, source, data_type, value, raw FROM p1_passive_recon WHERE scan_id = ? ORDER BY source, subdomain`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []P1PassiveRecon
	for rows.Next() {
		r := P1PassiveRecon{ScanID: scanID}
		if err := rows.Scan(&r.ID, &r.ScanID, &r.Subdomain, &r.Source, &r.DataType, &r.Value, &r.Raw); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (db *DB) InsertP1Port(scanID int64, p P1Port) error {
	_, err := db.conn.Exec(
		`INSERT OR IGNORE INTO p1_ports (scan_id, subdomain, port, protocol, service, banner) VALUES (?, ?, ?, ?, ?, ?)`,
		scanID, p.Subdomain, p.Port, p.Protocol, p.Service, p.Banner,
	)
	return err
}

func (db *DB) GetP1Ports(scanID int64) ([]P1Port, error) {
	rows, err := db.conn.Query(`SELECT id, scan_id, subdomain, port, protocol, service, banner FROM p1_ports WHERE scan_id = ? ORDER BY subdomain, port`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []P1Port
	for rows.Next() {
		p := P1Port{ScanID: scanID}
		if err := rows.Scan(&p.ID, &p.ScanID, &p.Subdomain, &p.Port, &p.Protocol, &p.Service, &p.Banner); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func (db *DB) InsertP1JSFile(scanID int64, j P1JSFile) (int64, error) {
	res, err := db.conn.Exec(
		`INSERT OR IGNORE INTO p1_js_files (scan_id, subdomain, url, size_bytes) VALUES (?, ?, ?, ?)`,
		scanID, j.Subdomain, j.URL, j.SizeBytes,
	)
	if err != nil {
		return 0, err
	}
	var id int64
	if n, _ := res.RowsAffected(); n == 0 {
		_ = db.conn.QueryRow(`SELECT id FROM p1_js_files WHERE scan_id = ? AND url = ?`, scanID, j.URL).Scan(&id)
	} else {
		id, _ = res.LastInsertId()
	}
	return id, nil
}

func (db *DB) GetP1JSFiles(scanID int64) ([]P1JSFile, error) {
	rows, err := db.conn.Query(`SELECT id, scan_id, subdomain, url, size_bytes FROM p1_js_files WHERE scan_id = ? ORDER BY subdomain`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []P1JSFile
	for rows.Next() {
		j := P1JSFile{ScanID: scanID}
		if err := rows.Scan(&j.ID, &j.ScanID, &j.Subdomain, &j.URL, &j.SizeBytes); err != nil {
			continue
		}
		out = append(out, j)
	}
	return out, nil
}

func (db *DB) InsertP1JSFinding(scanID int64, f P1JSFinding) error {
	_, err := db.conn.Exec(
		`INSERT INTO p1_js_findings (scan_id, js_file_id, subdomain, type, pattern, value, context) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		scanID, f.JsFileID, f.Subdomain, f.Type, f.Pattern, f.Value, f.Context,
	)
	return err
}

func (db *DB) GetP1JSFindings(scanID int64) ([]P1JSFinding, error) {
	rows, err := db.conn.Query(`SELECT id, scan_id, js_file_id, subdomain, type, pattern, value, context FROM p1_js_findings WHERE scan_id = ? ORDER BY CASE type WHEN 'secret' THEN 0 ELSE 1 END, subdomain`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []P1JSFinding
	for rows.Next() {
		f := P1JSFinding{ScanID: scanID}
		if err := rows.Scan(&f.ID, &f.ScanID, &f.JsFileID, &f.Subdomain, &f.Type, &f.Pattern, &f.Value, &f.Context); err != nil {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func (db *DB) InsertP1Param(scanID int64, p P1Param) error {
	_, err := db.conn.Exec(
		`INSERT OR IGNORE INTO p1_params (scan_id, subdomain, url, param_name, param_type, source) VALUES (?, ?, ?, ?, ?, ?)`,
		scanID, p.Subdomain, p.URL, p.ParamName, p.ParamType, p.Source,
	)
	return err
}

func (db *DB) GetP1Params(scanID int64) ([]P1Param, error) {
	rows, err := db.conn.Query(`SELECT id, scan_id, subdomain, url, param_name, param_type, source FROM p1_params WHERE scan_id = ? ORDER BY subdomain, param_name`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []P1Param
	for rows.Next() {
		p := P1Param{ScanID: scanID}
		if err := rows.Scan(&p.ID, &p.ScanID, &p.Subdomain, &p.URL, &p.ParamName, &p.ParamType, &p.Source); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func (db *DB) InsertP1Secret(scanID int64, s P1Secret) error {
	_, err := db.conn.Exec(
		`INSERT INTO p1_secrets (scan_id, subdomain, source_url, secret_type, raw_match, entropy, tool) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		scanID, s.Subdomain, s.SourceURL, s.SecretType, s.RawMatch, s.Entropy, s.Tool,
	)
	return err
}

func (db *DB) GetP1Secrets(scanID int64) ([]P1Secret, error) {
	rows, err := db.conn.Query(`SELECT id, scan_id, subdomain, source_url, secret_type, raw_match, entropy, tool FROM p1_secrets WHERE scan_id = ? ORDER BY tool, secret_type`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []P1Secret
	for rows.Next() {
		s := P1Secret{ScanID: scanID}
		if err := rows.Scan(&s.ID, &s.ScanID, &s.Subdomain, &s.SourceURL, &s.SecretType, &s.RawMatch, &s.Entropy, &s.Tool); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

func (db *DB) InsertP1Finding(scanID int64, f P1Finding) error {
	_, err := db.conn.Exec(
		`INSERT INTO p1_findings (scan_id, subdomain, tool, template_id, severity, name, description, evidence, verified, false_pos) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, f.Subdomain, f.Tool, f.TemplateID, f.Severity, f.Name, f.Description, f.Evidence, f.Verified, f.FalsePos,
	)
	return err
}

func (db *DB) GetP1Findings(scanID int64) ([]P1Finding, error) {
	rows, err := db.conn.Query(`SELECT id, scan_id, subdomain, tool, template_id, severity, name, description, evidence, verified, false_pos FROM p1_findings WHERE scan_id = ? AND false_pos = 0 ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, subdomain`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []P1Finding
	for rows.Next() {
		f := P1Finding{ScanID: scanID}
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Subdomain, &f.Tool, &f.TemplateID, &f.Severity, &f.Name, &f.Description, &f.Evidence, &f.Verified, &f.FalsePos); err != nil {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// UpdateP1HostWAF upserts WAF info for a host.
func (db *DB) UpdateP1HostWAF(scanID int64, subdomain, waf, manufacturer string) error {
	ptr := func(s string) *string { if s == "" { return nil }; return &s }
	_, err := db.conn.Exec(
		`INSERT INTO p1_host_intel (scan_id, subdomain, waf, waf_manufacturer)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(subdomain) DO UPDATE SET waf=excluded.waf, waf_manufacturer=excluded.waf_manufacturer`,
		scanID, subdomain, ptr(waf), ptr(manufacturer),
	)
	return err
}

// UpsertP1HostIntel fully upserts the per-host intel row.
func (db *DB) UpsertP1HostIntel(scanID int64, i P1HostIntel) error {
	_, err := db.conn.Exec(
		`INSERT INTO p1_host_intel (scan_id, subdomain, waf, waf_manufacturer, open_port_count, param_count, secret_count, js_endpoint_count, has_open_ports, has_params, has_secrets, has_js_endpoints)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(subdomain) DO UPDATE SET
		   waf=COALESCE(excluded.waf, p1_host_intel.waf),
		   waf_manufacturer=COALESCE(excluded.waf_manufacturer, p1_host_intel.waf_manufacturer),
		   open_port_count=excluded.open_port_count,
		   param_count=excluded.param_count,
		   secret_count=excluded.secret_count,
		   js_endpoint_count=excluded.js_endpoint_count,
		   has_open_ports=excluded.has_open_ports,
		   has_params=excluded.has_params,
		   has_secrets=excluded.has_secrets,
		   has_js_endpoints=excluded.has_js_endpoints`,
		scanID, i.Subdomain, i.WAF, i.WAFManufacturer, i.OpenPortCount, i.ParamCount, i.SecretCount, i.JSEndpointCount,
		i.HasOpenPorts, i.HasParams, i.HasSecrets, i.HasJSEndpoints,
	)
	return err
}

func (db *DB) GetP1HostIntel(scanID int64) ([]P1HostIntel, error) {
	rows, err := db.conn.Query(`SELECT id, scan_id, subdomain, waf, waf_manufacturer, open_port_count, param_count, secret_count, js_endpoint_count, has_open_ports, has_params, has_secrets, has_js_endpoints FROM p1_host_intel WHERE scan_id = ? ORDER BY subdomain`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []P1HostIntel
	for rows.Next() {
		i := P1HostIntel{ScanID: scanID}
		if err := rows.Scan(&i.ID, &i.ScanID, &i.Subdomain, &i.WAF, &i.WAFManufacturer, &i.OpenPortCount, &i.ParamCount, &i.SecretCount, &i.JSEndpointCount, &i.HasOpenPorts, &i.HasParams, &i.HasSecrets, &i.HasJSEndpoints); err != nil {
			continue
		}
		out = append(out, i)
	}
	return out, nil
}
