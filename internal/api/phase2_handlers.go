package api

import (
	"net/http"

	"github.com/yourname/dark-recon/internal/storage"
)

// ── Phase 2 data API (the Phase 1 → Phase 2 contract, Section 9) ──────────
//
// These five read-only endpoints expose the prioritised, joined dataset that
// Phase 2 consumes exclusively (no file I/O). Each maps 1:1 to a query in
// update_work.md Section 9, adapted to the actual additive schema used by this
// codebase (live_hosts + p1_* tables + priority_entries) instead of the doc's
// proposed single-table schema. They are additive: no existing route or
// handler is touched.
//
// Routes (registered in routes.go):
//
//	GET /api/phase2/{target_name}/targets   → Query 1 (prioritised targets)
//	GET /api/phase2/{target_name}/findings  → Query 2 (all findings, by severity)
//	GET /api/phase2/{target_name}/urls      → Query 3 (URLs with params)
//	GET /api/phase2/{target_name}/js        → Query 4 (JS findings)
//	GET /api/phase2/{target_name}/ports     → Query 5 (open ports)

// queryRows runs a SELECT and returns each row as a string-keyed map. NULL
// columns come back as nil; TEXT columns returned as []byte by the driver are
// normalised to strings so the JSON encoder emits clean strings.
func queryRows(db *storage.DB, query string, args ...any) ([]map[string]any, error) {
	rows, err := db.Conn().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var out []map[string]any
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			v := values[i]
			if b, ok := v.([]byte); ok {
				row[c] = string(b)
			} else {
				row[c] = v
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// GetPhase2Targets — Query 1: prioritised targets for Phase 2.
// One row per live host, joined with open-port / url / param / finding /
// secret counts and the WAF + priority score from p1_host_intel and
// priority_entries. Ordered by priority score then finding count.
func (h *Handlers) GetPhase2Targets(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()

	const q = `
SELECT
	lh.subdomain                       AS host,
	lh.url                             AS url,
	lh.status_code                     AS status_code,
	lh.title                           AS title,
	lh.tech_detected                   AS tech_stack,
	hi.waf                             AS waf,
	pe.priority_score                  AS score,
	pe.priority_tier                   AS tier,
	COUNT(DISTINCT p.id)               AS open_ports,
	COUNT(DISTINCT cu.id)              AS url_count,
	SUM(CASE WHEN cu.has_params = 1 THEN 1 ELSE 0 END) AS param_url_count,
	COUNT(DISTINCT pa.id)              AS param_count,
	(SELECT COUNT(*) FROM p1_findings f
	     WHERE f.scan_id = lh.scan_id AND f.subdomain = lh.subdomain AND f.false_pos = 0)
	+ (SELECT COUNT(*) FROM vulnerabilities v
	     WHERE v.scan_id = lh.scan_id AND v.subdomain = lh.subdomain) AS finding_count,
	COUNT(DISTINCT s.id)               AS secret_count
FROM live_hosts lh
LEFT JOIN p1_host_intel hi ON hi.subdomain = lh.subdomain AND hi.scan_id = lh.scan_id
LEFT JOIN p1_ports p       ON p.subdomain  = lh.subdomain AND p.scan_id  = lh.scan_id
LEFT JOIN crawled_urls cu  ON cu.subdomain = lh.subdomain AND cu.scan_id = lh.scan_id
LEFT JOIN p1_params pa     ON pa.subdomain = lh.subdomain AND pa.scan_id = lh.scan_id
LEFT JOIN p1_secrets s     ON s.subdomain  = lh.subdomain AND s.scan_id  = lh.scan_id
LEFT JOIN priority_entries pe ON pe.subdomain = lh.subdomain AND pe.scan_id = lh.scan_id
WHERE lh.scan_id = ?
GROUP BY lh.id
ORDER BY pe.priority_score DESC, finding_count DESC`

	rows, err := queryRows(db, q, meta.ID)
	if err != nil {
		writeError(w, 500, "failed to query phase 2 targets")
		return
	}
	writeJSON(w, 200, map[string]any{"targets": rows, "count": len(rows)})
}

// GetPhase2Findings — Query 2: all findings for a session, ordered by
// severity. Unifies the new p1_findings (nmap/wafw00f/js/trufflehog/gitleaks)
// with the existing vulnerabilities (nuclei/subzy) via UNION ALL, enriching
// each row with the host's WAF, tech stack and priority score.
func (h *Handlers) GetPhase2Findings(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()

	const q = `
SELECT * FROM (
	SELECT
		'p1' AS source,
		f.id, f.subdomain AS host, f.tool, f.template_id, f.severity,
		f.name, f.description, f.evidence, f.verified, f.false_pos,
		hi.waf, lh.tech_detected AS tech_stack, pe.priority_score AS score
	FROM p1_findings f
	LEFT JOIN live_hosts lh       ON lh.subdomain = f.subdomain AND lh.scan_id = f.scan_id
	LEFT JOIN p1_host_intel hi    ON hi.subdomain = f.subdomain AND hi.scan_id = f.scan_id
	LEFT JOIN priority_entries pe ON pe.subdomain = f.subdomain AND pe.scan_id = f.scan_id
	WHERE f.scan_id = ? AND f.false_pos = 0
	UNION ALL
	SELECT
		'nuclei' AS source,
		v.id, v.subdomain AS host, v.type AS tool, v.template_id, v.severity,
		v.name, v.description, NULL AS evidence, 0 AS verified, 0 AS false_pos,
		hi.waf, lh.tech_detected AS tech_stack, pe.priority_score AS score
	FROM vulnerabilities v
	LEFT JOIN live_hosts lh       ON lh.subdomain = v.subdomain AND lh.scan_id = v.scan_id
	LEFT JOIN p1_host_intel hi    ON hi.subdomain = v.subdomain AND hi.scan_id = v.scan_id
	LEFT JOIN priority_entries pe ON pe.subdomain = v.subdomain AND pe.scan_id = v.scan_id
	WHERE v.scan_id = ?
)
ORDER BY
	CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
	              WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
	score DESC`

	rows, err := queryRows(db, q, meta.ID, meta.ID)
	if err != nil {
		writeError(w, 500, "failed to query phase 2 findings")
		return
	}
	writeJSON(w, 200, map[string]any{"findings": rows, "count": len(rows)})
}

// GetPhase2URLs — Query 3: URLs with parameters for injection testing.
// Combines Katana's param-bearing URLs with arjun-discovered params,
// enriching each with the host WAF and priority score.
func (h *Handlers) GetPhase2URLs(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()

	const q = `
SELECT
	cu.url,
	cu.subdomain                       AS host,
	cu.source                          AS source,
	cu.param_names                     AS params,
	hi.waf                             AS waf,
	pe.priority_score                  AS score,
	GROUP_CONCAT(pa.param_name)        AS discovered_params
FROM crawled_urls cu
LEFT JOIN p1_host_intel hi    ON hi.subdomain = cu.subdomain AND hi.scan_id = cu.scan_id
LEFT JOIN priority_entries pe ON pe.subdomain = cu.subdomain AND pe.scan_id = cu.scan_id
LEFT JOIN p1_params pa        ON pa.url = cu.url AND pa.scan_id = cu.scan_id
WHERE cu.scan_id = ? AND (cu.has_params = 1 OR pa.param_name IS NOT NULL)
GROUP BY cu.url
ORDER BY pe.priority_score DESC`

	rows, err := queryRows(db, q, meta.ID)
	if err != nil {
		writeError(w, 500, "failed to query phase 2 urls")
		return
	}
	writeJSON(w, 200, map[string]any{"urls": rows, "count": len(rows)})
}

// GetPhase2JS — Query 4: JS findings for context enrichment.
// Endpoints and secrets extracted from JS files, joined to the source JS URL.
func (h *Handlers) GetPhase2JS(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()

	const q = `
SELECT
	jf.subdomain   AS host,
	jf.type        AS type,
	jf.value       AS value,
	jf.context     AS context,
	jfi.url        AS js_source_url
FROM p1_js_findings jf
LEFT JOIN p1_js_files jfi ON jfi.id = jf.js_file_id
WHERE jf.scan_id = ?
ORDER BY
	CASE jf.type WHEN 'secret' THEN 1 WHEN 'endpoint' THEN 2 ELSE 3 END`

	rows, err := queryRows(db, q, meta.ID)
	if err != nil {
		writeError(w, 500, "failed to query phase 2 js findings")
		return
	}
	writeJSON(w, 200, map[string]any{"js_findings": rows, "count": len(rows)})
}

// GetPhase2Ports — Query 5: open ports for service-specific scanning.
// Per-port rows joined with the host priority score and WAF.
func (h *Handlers) GetPhase2Ports(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()

	const q = `
SELECT
	p.subdomain        AS host,
	p.port             AS port,
	p.protocol         AS protocol,
	p.service          AS service,
	pe.priority_score  AS score,
	hi.waf             AS waf
FROM p1_ports p
LEFT JOIN p1_host_intel hi    ON hi.subdomain = p.subdomain AND hi.scan_id = p.scan_id
LEFT JOIN priority_entries pe ON pe.subdomain = p.subdomain AND pe.scan_id = p.scan_id
WHERE p.scan_id = ?
ORDER BY pe.priority_score DESC, p.port ASC`

	rows, err := queryRows(db, q, meta.ID)
	if err != nil {
		writeError(w, 500, "failed to query phase 2 ports")
		return
	}
	writeJSON(w, 200, map[string]any{"ports": rows, "count": len(rows)})
}
