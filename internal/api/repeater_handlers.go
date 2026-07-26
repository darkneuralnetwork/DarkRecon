package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yourname/dark-recon/internal/repeater"
	"github.com/yourname/dark-recon/internal/storage"
)

// ── Repeater API ─────────────────────────────────────────────────
//
// The Repeater is Dark-Recon's Burp-Repeater-style manual request editor.
// These endpoints let the UI save raw HTTP requests, send them (with scope +
// SSRF guards enforced by internal/repeater.Forwarder), and read back the
// captured response. Every request is scoped to a scan so it travels with the
// target it was created from.
//
// Routes (registered in routes.go):
//
//	POST   /api/repeater/{target}/send              → send a raw request, save + return response
//	GET    /api/repeater/{target}/requests          → list saved requests (history)
//	GET    /api/repeater/{target}/requests/{id}     → get one saved request + its last response
//	PUT    /api/repeater/{target}/requests/{id}     → save edited raw request / notes
//	DELETE /api/repeater/{target}/requests/{id}     → delete a saved request
//	POST   /api/repeater/{target}/from-url          → pre-build a raw request from a discovered URL

// repeaterForwarder is lazily instantiated on first use. It has no per-target
// state (the scope check is delegated to the scan DB via resolveScanDB), so a
// single shared instance serves all targets.
func (h *Handlers) repeaterForwarder() *repeater.Forwarder {
	if h.fwd == nil {
		// InsecureSkipVerify is appropriate for a pentest tool that routinely
		// targets self-signed / expired-cert hosts; the user is intentionally
		// probing hosts they may not trust.
		h.fwd = repeater.NewForwarder(nil, true)
	}
	return h.fwd
}

// resolveScanDBForRepeater opens the per-target scan DB for a Repeater request.
// It reuses resolveScanDB (cached, read-only handle) and returns the shared
// forwarder; the scope checker is passed per-Send so there's no binding race.
func (h *Handlers) resolveScanDBForRepeater(w http.ResponseWriter, r *http.Request) (*storage.DB, *storage.ScanMeta, *repeater.Forwarder, bool) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return nil, nil, nil, false
	}
	return db, meta, h.repeaterForwarder(), true
}

// SendRequest — POST /api/repeater/{target}/send
//
// Request body:
//
//	{
//	  "raw_request": "GET /path HTTP/1.1\r\nHost: ...",
//	  "request_id": 12,            // optional: update an existing saved request
//	  "allow_internal": false,     // optional: allow private/loopback IPs
//	  "follow_redirects": false,   // optional: follow 3xx up to 5 hops
//	  "timeout_seconds": 15,       // optional: per-request timeout
//	  "notes": ""                  // optional: save notes with the request
//	}
//
// Response: the saved RepeaterRequest (with id, raw_request, response_*).
func (h *Handlers) SendRequest(w http.ResponseWriter, r *http.Request) {
	db, meta, fwd, ok := h.resolveScanDBForRepeater(w, r)
	if !ok {
		return
	}
	defer db.Close()

	var body struct {
		RawRequest      string `json:"raw_request"`
		RequestID       *int64 `json:"request_id,omitempty"`
		AllowInternal   bool   `json:"allow_internal"`
		FollowRedirects bool   `json:"follow_redirects"`
		TimeoutSeconds  int    `json:"timeout_seconds"`
		Notes           string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "Invalid request body")
		return
	}
	if strings.TrimSpace(body.RawRequest) == "" {
		writeError(w, 400, "raw_request is required")
		return
	}

	opts := repeater.Options{
		AllowInternal:   body.AllowInternal,
		FollowRedirects: body.FollowRedirects,
	}
	if body.TimeoutSeconds > 0 {
		opts.Timeout = time.Duration(body.TimeoutSeconds) * time.Second
	}

	resp, pr := fwd.Send(r.Context(), db, meta.ID, body.RawRequest, opts)

	// Determine the method + host for the saved row from the parsed request;
	// if parsing failed we fall back to empty strings.
	method := "GET"
	host := ""
	urlStr := ""
	if pr != nil {
		method = pr.Method
		host = pr.URL.Hostname()
		urlStr = pr.URL.String()
	}

	var reqID int64
	if body.RequestID != nil {
		// Update an existing request in place: save the edited raw text + the
		// freshly captured response.
		reqID = *body.RequestID
		rr := &storage.RepeaterRequest{ID: reqID, ScanID: meta.ID, Method: method, RawRequest: body.RawRequest}
		if host != "" {
			rr.Subdomain = &host
		}
		if urlStr != "" {
			rr.URL = &urlStr
		}
		rr.Notes = body.Notes
		if err := db.UpdateRepeaterRequest(rr); err != nil {
			writeError(w, 500, "failed to update request")
			return
		}
	} else {
		// Create a new saved request.
		rr := &storage.RepeaterRequest{
			ScanID:     meta.ID,
			Target:     meta.Target,
			Method:     method,
			RawRequest: body.RawRequest,
			Notes:      body.Notes,
		}
		if host != "" {
			rr.Subdomain = &host
		}
		if urlStr != "" {
			rr.URL = &urlStr
		}
		id, err := db.CreateRepeaterRequest(rr)
		if err != nil {
			writeError(w, 500, "failed to save request")
			return
		}
		reqID = id
	}

	// Store the captured response against the saved row.
	var statusPtr *int
	if resp.StatusCode != 0 {
		s := resp.StatusCode
		statusPtr = &s
	}
	var headersPtr, bodyPtr, errPtr *string
	if resp.Headers != "" {
		headersPtr = &resp.Headers
	}
	if resp.Body != "" {
		bodyPtr = &resp.Body
	}
	if resp.Err != "" {
		errPtr = &resp.Err
	}
	var durPtr *int64
	if resp.DurationMs > 0 {
		d := resp.DurationMs
		durPtr = &d
	}
	_ = db.UpdateRepeaterResponse(meta.ID, reqID, statusPtr, headersPtr, bodyPtr, errPtr, durPtr)

	// Return the full saved row so the UI can render it directly.
	saved, err := db.GetRepeaterRequest(meta.ID, reqID)
	if err != nil || saved == nil {
		// Fallback: build a minimal response from what we have.
		writeJSON(w, 200, map[string]any{
			"id":              reqID,
			"raw_request":     body.RawRequest,
			"method":          method,
			"subdomain":       host,
			"url":             urlStr,
			"response_status": statusPtr,
			"response_headers": headersPtr,
			"response_body":   bodyPtr,
			"response_error":  errPtr,
			"duration_ms":     durPtr,
		})
		return
	}
	writeJSON(w, 200, saved)
}

// ListRequests — GET /api/repeater/{target}/requests
// Returns the saved-request history for a scan, most recent first.
func (h *Handlers) ListRequests(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	reqs, _ := db.ListRepeaterRequests(meta.ID)
	writeJSON(w, 200, map[string]any{"requests": reqs, "count": len(reqs)})
}

// GetRequest — GET /api/repeater/{target}/requests/{id}
// Returns a single saved request with its last captured response.
func (h *Handlers) GetRequest(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 400, "Invalid request id")
		return
	}
	req, err := db.GetRepeaterRequest(meta.ID, id)
	if err != nil || req == nil {
		writeError(w, 404, "Request not found")
		return
	}
	writeJSON(w, 200, req)
}

// UpdateRequest — PUT /api/repeater/{target}/requests/{id}
// Saves an edited raw request and/or notes without sending. Body:
// {"raw_request": "...", "notes": "...", "method": "GET"}
func (h *Handlers) UpdateRequest(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 400, "Invalid request id")
		return
	}
	var body struct {
		RawRequest string `json:"raw_request"`
		Notes      string `json:"notes"`
		Method     string `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "Invalid request body")
		return
	}
	// Re-parse to extract method/host/url from the (possibly edited) raw text.
	method := body.Method
	var host, urlStr string
	if strings.TrimSpace(body.RawRequest) != "" {
		if pr, perr := repeater.ParseRequest(body.RawRequest); perr == nil {
			if method == "" {
				method = pr.Method
			}
			host = pr.URL.Hostname()
			urlStr = pr.URL.String()
		}
	}
	rr := &storage.RepeaterRequest{ID: id, ScanID: meta.ID, Method: method, RawRequest: body.RawRequest, Notes: body.Notes}
	if host != "" {
		rr.Subdomain = &host
	}
	if urlStr != "" {
		rr.URL = &urlStr
	}
	if err := db.UpdateRepeaterRequest(rr); err != nil {
		writeError(w, 500, "failed to save request")
		return
	}
	saved, _ := db.GetRepeaterRequest(meta.ID, id)
	writeJSON(w, 200, saved)
}

// DeleteRequest — DELETE /api/repeater/{target}/requests/{id}
func (h *Handlers) DeleteRequest(w http.ResponseWriter, r *http.Request) {
	db, meta, ok := h.resolveScanDB(w, r)
	if !ok {
		return
	}
	defer db.Close()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 400, "Invalid request id")
		return
	}
	if err := db.DeleteRepeaterRequest(meta.ID, id); err != nil {
		writeError(w, 500, "failed to delete request")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

// FromURL — POST /api/repeater/{target}/from-url
// Loads a discovered URL into the Repeater by performing a LIVE probe: the
// request is actually sent (scope + SSRF guards enforced) so the editor is
// populated with the REAL request as sent — not a synthetic template — and the
// response pane shows the server's actual reply. Different URLs therefore
// produce different requests (real path, real query, real response), and the
// method can be changed afterwards via the editor or the method selector.
//
// Body: {"url": "https://sub.target.com/path?x=1", "method": "GET"}
// The URL's host must be in scope (present in live_hosts / crawled_urls).
func (h *Handlers) FromURL(w http.ResponseWriter, r *http.Request) {
	db, meta, fwd, ok := h.resolveScanDBForRepeater(w, r)
	if !ok {
		return
	}
	defer db.Close()

	var body struct {
		URL    string `json:"url"`
		Method string `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "Invalid request body")
		return
	}
	if strings.TrimSpace(body.URL) == "" {
		writeError(w, 400, "url is required")
		return
	}
	if body.Method == "" {
		body.Method = "GET"
	}

	// Enrich with arjun/katana-discovered params for this exact URL so the
	// probe exercises every known parameter.
	params := db.GetParamsForURL(meta.ID, body.URL)

	// Build the seed raw request from the discovered URL. This is what gets
	// sent on the wire; the normalized version (returned by Send as pr.Raw) is
	// what we persist as the "original request" in the editor.
	ub := repeater.URLBuilder{}
	rawReq, err := ub.BuildRawRequest(body.URL, body.Method, params)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}

	// Scope check: the URL's host must be in this scan's recon data.
	pr, err := repeater.ParseRequest(rawReq)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	host := pr.URL.Hostname()
	inScope, err := db.IsHostInScope(meta.ID, host)
	if err != nil {
		writeError(w, 500, "scope check failed")
		return
	}
	if !inScope {
		writeError(w, 403, "host is not in scope for this scan")
		return
	}

	// Live probe: actually send the request so the editor loads the REAL
	// request (as normalized and sent) and the response pane shows the
	// server's actual reply — the "original request" to this domain, not a
	// hardcoded template that looks identical for every URL. Redirects are NOT
	// followed so the user sees the true first-hop response. A short timeout
	// keeps the page load responsive when the host is slow or down.
	probeOpts := repeater.Options{Timeout: 10 * time.Second}
	sendResp, sentPR := fwd.Send(r.Context(), db, meta.ID, rawReq, probeOpts)

	// Persist the normalized sent request (fall back to the seed if parsing
	// failed for some reason). pr.Raw is the request as it was actually sent —
	// real path, real query, corrected Content-Length — not the seed template.
	savedRaw := rawReq
	method := body.Method
	if sentPR != nil {
		if sentPR.Raw != "" {
			savedRaw = sentPR.Raw
		}
		if sentPR.Method != "" {
			method = sentPR.Method
		}
	}

	rr := &storage.RepeaterRequest{
		ScanID:     meta.ID,
		Target:     meta.Target,
		Method:     method,
		RawRequest: savedRaw,
	}
	if host != "" {
		rr.Subdomain = &host
	}
	urlCopy := body.URL
	rr.URL = &urlCopy
	id, err := db.CreateRepeaterRequest(rr)
	if err != nil {
		writeError(w, 500, "failed to save request")
		return
	}

	// Store the captured response so the response pane renders immediately
	// alongside the sent request — the user lands on a fully populated
	// request/response pair, not an empty editor.
	var statusPtr *int
	if sendResp.StatusCode != 0 {
		s := sendResp.StatusCode
		statusPtr = &s
	}
	var headersPtr, bodyPtr, errPtr *string
	if sendResp.Headers != "" {
		headersPtr = &sendResp.Headers
	}
	if sendResp.Body != "" {
		bodyPtr = &sendResp.Body
	}
	if sendResp.Err != "" {
		errPtr = &sendResp.Err
	}
	var durPtr *int64
	if sendResp.DurationMs > 0 {
		d := sendResp.DurationMs
		durPtr = &d
	}
	_ = db.UpdateRepeaterResponse(meta.ID, id, statusPtr, headersPtr, bodyPtr, errPtr, durPtr)

	saved, _ := db.GetRepeaterRequest(meta.ID, id)
	writeJSON(w, 200, saved)
}

// Brute — POST /api/repeater/{target}/brute
//
// Runs a Burp-Intruder-style brute-force / directory-busting attack. Each
// non-empty, non-comment line of a server-side wordlist replaces the marker
// (default "§§") in the raw request template, and every variant is sent
// (scope + SSRF guards enforced per request via the Forwarder). Results stream
// back as newline-delimited JSON so the UI updates live; aborting the fetch
// cancels the run via the request context.
//
// Body:
//
//	{
//	  "raw_request":      "GET /§§ HTTP/1.1\r\nHost: ...",
//	  "wordlist_path":    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
//	  "marker":           "§§",            // optional, default "§§"
//	  "concurrency":      10,              // optional, default 10, cap 50
//	  "delay_ms":         0,               // optional, per-worker pause
//	  "allow_internal":   false,
//	  "follow_redirects": false,
//	  "timeout_seconds":  10
//	}
//
// Response: application/x-ndjson. Each line is a JSON object:
//
//	{"event":"start","total":4600,"host":"example.com","marker":"§§"}
//	{"event":"result","result":{"idx":0,"word":"admin","status":200,"length":1234,"duration_ms":45,"error":""}}
//	{"event":"done","sent":4600,"errors":3}
func (h *Handlers) Brute(w http.ResponseWriter, r *http.Request) {
	db, meta, fwd, ok := h.resolveScanDBForRepeater(w, r)
	if !ok {
		return
	}
	defer db.Close()

	var body struct {
		RawRequest      string `json:"raw_request"`
		WordlistPath    string `json:"wordlist_path"`
		Marker          string `json:"marker"`
		Concurrency     int    `json:"concurrency"`
		DelayMs         int    `json:"delay_ms"`
		AllowInternal   bool   `json:"allow_internal"`
		FollowRedirects bool   `json:"follow_redirects"`
		TimeoutSeconds  int    `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "Invalid request body")
		return
	}
	if strings.TrimSpace(body.RawRequest) == "" {
		writeError(w, 400, "raw_request is required")
		return
	}
	if strings.TrimSpace(body.WordlistPath) == "" {
		writeError(w, 400, "wordlist_path is required")
		return
	}
	marker := body.Marker
	if marker == "" {
		marker = "§§"
	}
	if !strings.Contains(body.RawRequest, marker) {
		writeError(w, 400, fmt.Sprintf(
			"request template has no %q marker — place %s where the wordlist word should go (e.g. GET /%s HTTP/1.1)",
			marker, marker, marker))
		return
	}
	if body.Concurrency <= 0 {
		body.Concurrency = 10
	}
	if body.Concurrency > 50 {
		body.Concurrency = 50
	}

	// Open the wordlist (server-side path — words never cross the wire, so a
	// 20k-entry list costs one open, not 20k HTTP body bytes).
	wp := expandHomePath(body.WordlistPath)
	f, err := os.Open(wp)
	if err != nil {
		writeError(w, 400, fmt.Sprintf("cannot open wordlist %q: %v", wp, err))
		return
	}
	defer f.Close()

	// Validate + scope-check the template BEFORE streaming starts. Once we
	// write the NDJSON header we can no longer return a JSON error, so every
	// validation that can fail must happen here.
	pr, err := repeater.ParseRequest(body.RawRequest)
	if err != nil {
		writeError(w, 400, fmt.Sprintf("parse template: %v", err))
		return
	}
	host := pr.URL.Hostname()
	inScope, err := db.IsHostInScope(meta.ID, host)
	if err != nil {
		writeError(w, 500, "scope check failed")
		return
	}
	if !inScope {
		writeError(w, 403, fmt.Sprintf("host %q is not in scope for this scan", host))
		return
	}

	// Pre-count words for the progress bar (best-effort; non-fatal — the scan
	// still runs if this returns 0).
	total := countWordlist(f)
	_, _ = f.Seek(0, 0)

	// Begin streaming. X-Accel-Buffering defeats nginx/reverse-proxy buffering
	// so each result flushes to the client immediately.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	// The server's global WriteTimeout (60s in main.go) is a hard deadline
	// measured from the end of the request headers to the end of the response
	// body. A directory-bust over a large wordlist streams for minutes, which
	// would exceed that deadline and the server would reset the connection —
	// surfacing in the browser as a generic "network error" on the fetch.
	// Clearing the per-connection write deadline here leaves only the request
	// context (client disconnect) as the cancellation source, which the
	// worker loop below already honours via ctx.Err().
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})

	flusher, _ := w.(http.Flusher)
	writeLine := func(obj any) {
		b, _ := json.Marshal(obj)
		_, _ = w.Write(b)
		_, _ = w.Write([]byte("\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	writeLine(map[string]any{"event": "start", "total": total, "host": host, "marker": marker})

	opts := repeater.Options{
		AllowInternal:   body.AllowInternal,
		FollowRedirects: body.FollowRedirects,
		Timeout:         10 * time.Second,
	}
	if body.TimeoutSeconds > 0 {
		opts.Timeout = time.Duration(body.TimeoutSeconds) * time.Second
	}

	ctx := r.Context()
	type job struct {
		word string
		idx  int
	}
	jobs := make(chan job, body.Concurrency*2)
	var wg sync.WaitGroup
	var writeMu sync.Mutex // serialise NDJSON writes + counter increments
	var sent, errors int

	for i := 0; i < body.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				raw := strings.Replace(body.RawRequest, marker, j.word, 1)
				resp, _ := fwd.Send(ctx, db, meta.ID, raw, opts)
				errMsg := ""
				if resp.Err != "" {
					errMsg = resp.Err
				}
				result := map[string]any{
					"idx":         j.idx,
					"word":        j.word,
					"status":      resp.StatusCode,
					"length":      len(resp.Body),
					"duration_ms": resp.DurationMs,
					"error":       errMsg,
				}
				writeMu.Lock()
				writeLine(map[string]any{"event": "result", "result": result})
				sent++
				if errMsg != "" {
					errors++
				}
				writeMu.Unlock()
				if body.DelayMs > 0 {
					select {
					case <-ctx.Done():
					case <-time.After(time.Duration(body.DelayMs) * time.Millisecond):
					}
				}
			}
		}()
	}

	// Feed wordlist lines into the job channel. Blank lines and # comments are
	// skipped (matches ffuf/dirb convention).
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	idx := 0
feed:
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		select {
		case <-ctx.Done():
			break feed
		case jobs <- job{word: word, idx: idx}:
		}
		idx++
	}
	close(jobs)
	wg.Wait()

	writeLine(map[string]any{"event": "done", "sent": sent, "errors": errors})
}

// countWordlist counts the non-empty, non-comment lines in f. Best-effort:
// on read error it returns 0. The caller should Seek(0,0) afterwards to
// re-read the file for the actual attack.
func countWordlist(f *os.File) int {
	count := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count
}
