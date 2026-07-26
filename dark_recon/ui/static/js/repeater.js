/* ── Repeater: manual HTTP request editor ──────────────────────── */
/* Dark-Recon's Burp-Repeater-style request editor. Talks to the
 * /api/repeater/{target}/* endpoints. All sends are scope-checked server-side
 * (the host must be in the scan's live_hosts / crawled_urls). */

// Extract target from URL: /target/{target}/repeater?url=...&method=...
const PATH_PARTS = window.location.pathname.split('/').filter(Boolean);
const TARGET = PATH_PARTS.length >= 2 ? decodeURIComponent(PATH_PARTS[1]) : '';
const PARAMS = new URLSearchParams(window.location.search);
const INITIAL_URL = PARAMS.get('url') || '';
const INITIAL_METHOD = (PARAMS.get('method') || 'GET').toUpperCase();

// In-memory copy of the history list + the currently-loaded request.
let history = [];
let currentRequest = null;   // the loaded RepeaterRequest object
let respTab = 'raw';          // 'raw' = status+headers+body in one view, 'render' = HTML
let notesTimer = null;

// ── Intruder (brute-force) state ────────────────────────────────
let attackController = null;  // AbortController for the in-flight /brute request
let attackResults = [];       // every result received so far (for re-filtering)
let attackTotal = 0;
let attackSent = 0;
let attackErrors = 0;
let wordlistModal = null;     // lazily-built filesystem picker

document.getElementById('page-title').textContent = `Repeater — ${TARGET}`;
document.getElementById('back-link').href = `/target/${TARGET}`;

// ── Element refs ─────────────────────────────────────────────────
const el = {
 historyList:   document.getElementById('history-list'),
 historySearch: document.getElementById('history-search'),
 newBtn:        document.getElementById('new-request-btn'),
 sendBtn:       document.getElementById('send-btn'),
 editor:        document.getElementById('request-editor'),
 notes:         document.getElementById('notes-editor'),
 notesStatus:   document.getElementById('notes-status'),
 reqId:         document.getElementById('req-id-display'),
 reqHost:       document.getElementById('req-host-display'),
 reqSize:       document.getElementById('req-size-badge'),
 respStatus:    document.getElementById('resp-status-badge'),
 respTime:      document.getElementById('resp-time-badge'),
 respView:      document.getElementById('response-view'),
 allowInternal: document.getElementById('opt-allow-internal'),
 followRedir:   document.getElementById('opt-follow-redirects'),
 methodSelect:  document.getElementById('method-select'),
 errorBanner:   document.getElementById('repeater-error'),

 // Intruder (brute-force) controls
 intrWordlist:      document.getElementById('intruder-wordlist-path'),
 intrBrowse:        document.getElementById('intruder-browse-btn'),
 intrMarker:        document.getElementById('intruder-marker'),
 intrMarkPath:      document.getElementById('intruder-mark-path-btn'),
 intrConcurrency:   document.getElementById('intruder-concurrency'),
 intrAllowInternal: document.getElementById('intruder-allow-internal'),
 intrFollowRedir:   document.getElementById('intruder-follow-redirects'),
 intrStartBtn:      document.getElementById('intruder-start-btn'),
 intrStopBtn:       document.getElementById('intruder-stop-btn'),
 intrEditor:        document.getElementById('intruder-editor'),
 intrTemplateSize:  document.getElementById('intruder-template-size'),
 intrProgress:      document.getElementById('intruder-progress'),
 intrFilter:        document.getElementById('intruder-filter'),
 intrHide404:       document.getElementById('intruder-hide404'),
 intrResultsBody:   document.getElementById('intruder-results-body'),
 intrEmpty:         document.getElementById('intruder-empty'),
};

// ── Init ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  bindEvents();
  loadHistory().then(() => {
    // If opened via ?url=..., pre-build a request from that URL.
    if (INITIAL_URL) {
      fromURL(INITIAL_URL, INITIAL_METHOD);
    } else if (history.length > 0) {
      loadRequest(history[0].id);
    } else {
      newBlankRequest();
    }
  });
});

function bindEvents() {
  el.sendBtn.addEventListener('click', sendRequest);
  el.newBtn.addEventListener('click', newBlankRequest);
  el.editor.addEventListener('input', () => updateReqMeta());
  // Method selector: rewrite the leading method token on the request line.
  // Keeps the path/query intact; the user can then add a body / headers by
  // hand for methods that need them.
  el.methodSelect.addEventListener('change', () => {
    const m = el.methodSelect.value;
    const raw = el.editor.value;
    // Replace only the first whitespace-delimited token on the first line.
    el.editor.value = raw.replace(/^(\S+)\s/, m + ' ');
    updateReqMeta();
  });
  el.editor.addEventListener('keydown', (e) => {
    // Ctrl/Cmd+Enter sends; Tab inserts a tab (not focus-change).
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      sendRequest();
    }
    if (e.key === 'Tab') {
      e.preventDefault();
      const start = el.editor.selectionStart;
      el.editor.value = el.editor.value.substring(0, start) + '\t' + el.editor.value.substring(el.editor.selectionEnd);
      el.editor.selectionStart = el.editor.selectionEnd = start + 1;
    }
  });

  // Notes auto-save (debounced 800ms).
  el.notes.addEventListener('input', () => {
    el.notesStatus.textContent = 'unsaved';
    el.notesStatus.classList.add('dirty');
    clearTimeout(notesTimer);
    notesTimer = setTimeout(saveNotes, 800);
  });

  // History filter.
  el.historySearch.addEventListener('input', () => renderHistory());

  // Response tabs.
  document.querySelectorAll('.resp-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.resp-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      respTab = tab.dataset.respTab;
      renderResponse();
    });
  });

  // ── Mode tabs: Repeater ↔ Intruder ───────────────────────────
  document.querySelectorAll('.mode-tab').forEach(tab => {
    tab.addEventListener('click', () => setMode(tab.dataset.mode));
  });

  // Send the current Repeater request to the Intruder for brute-forcing.
  document.getElementById('send-to-intruder-btn').addEventListener('click', sendToIntruder);

  // Intruder controls.
  el.intrBrowse.addEventListener('click', browseWordlist);
  el.intrMarkPath.addEventListener('click', markIntruderPath);
  el.intrStartBtn.addEventListener('click', startAttack);
  el.intrStopBtn.addEventListener('click', stopAttack);
  el.intrEditor.addEventListener('input', () => updateIntruderMeta());
  el.intrFilter.addEventListener('input', rerenderIntruderResults);
  el.intrHide404.addEventListener('change', rerenderIntruderResults);
  // Ctrl/Cmd+Enter starts the attack from the intruder editor.
  el.intrEditor.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); startAttack(); }
  });
}

// ── History ──────────────────────────────────────────────────────

async function loadHistory() {
  try {
    const resp = await fetch(`/api/repeater/${encodeURIComponent(TARGET)}/requests`);
    if (!resp.ok) return;
    const data = await resp.json();
    history = data.requests || [];
    renderHistory();
  } catch (e) { /* non-fatal */ }
}

function renderHistory() {
  const q = (el.historySearch.value || '').toLowerCase();
  const filtered = history.filter(r => {
    if (!q) return true;
    const host = r.subdomain || r.url || '';
    const method = r.method || '';
    return (host + ' ' + method).toLowerCase().includes(q);
  });

  if (filtered.length === 0) {
    el.historyList.innerHTML = `<p class="text-muted history-empty">${q ? 'No matches.' : 'No saved requests yet.'}</p>`;
    return;
  }

  el.historyList.innerHTML = filtered.map(r => {
    const active = currentRequest && r.id === currentRequest.id ? ' active' : '';
    const method = (r.method || 'GET').toUpperCase();
    const methodCls = method.toLowerCase();
    const host = r.subdomain || hostFromURL(r.url) || '—';
    const status = r.response_status;
    let statusBadge = '';
    if (status) {
      const cls = status >= 500 ? 's5' : status >= 400 ? 's4' : status >= 300 ? 's3' : 's2';
      statusBadge = `<span class="history-item-status ${cls}">${status}</span>`;
    } else if (r.response_error) {
      statusBadge = `<span class="history-item-status err">err</span>`;
    }
    const time = r.duration_ms != null ? `<span>${r.duration_ms}ms</span>` : '';
    return `<div class="history-item${active}" data-id="${r.id}" onclick="loadRequest(${r.id})">
      <div>
        <span class="history-item-method ${methodCls}">${method}</span>
        <span class="history-item-host">${escapeHtml(host)}</span>
      </div>
      <div class="history-item-meta">
        ${statusBadge}${time}
        <button class="history-item-delete" title="Delete" onclick="deleteRequest(${r.id}, event)">×</button>
      </div>
    </div>`;
  }).join('');
}

// ── Load / New ───────────────────────────────────────────────────

async function loadRequest(id) {
  try {
    const resp = await fetch(`/api/repeater/${encodeURIComponent(TARGET)}/requests/${id}`);
    if (!resp.ok) { showError(`Failed to load request #${id}`); return; }
    currentRequest = await resp.json();
    el.editor.value = currentRequest.raw_request || '';
    el.notes.value = currentRequest.notes || '';
    el.reqId.textContent = `#${currentRequest.id}`;
    updateReqMeta();
    renderResponse();
    renderHistory();
    el.notesStatus.textContent = 'saved';
    el.notesStatus.classList.remove('dirty');
  } catch (e) {
    showError(`loadRequest: ${e.message}`);
  }
}

function newBlankRequest() {
  currentRequest = null;
  el.editor.value = 'GET / HTTP/1.1\r\nHost: \r\n\r\n';
  el.notes.value = '';
  el.reqId.textContent = '—';
  el.reqHost.textContent = '—';
  el.respStatus.textContent = '—';
  el.respStatus.className = 'pane-badge';
  el.respTime.textContent = '—';
  el.respView.innerHTML = '<span class="text-muted">No response yet. Send a request to see the response here.</span>';
  updateReqMeta();
  renderHistory();
}

// ── From URL (pre-populate via the API) ──────────────────────────

async function fromURL(url, method) {
  // The backend does a LIVE probe (actually sends the request) so the editor
  // loads the real sent request + the server's actual response. That can take
  // up to the probe timeout for slow/dead hosts, so surface a probing state
  // instead of leaving the panes blank.
  el.sendBtn.disabled = true;
  el.editor.value = `${method} ${url} HTTP/1.1\r\nHost: ${hostFromURL(url) || ''}\r\n\r\n`;
  el.reqId.textContent = '…';
  el.respStatus.textContent = '…';
  el.respStatus.className = 'pane-badge';
  el.respTime.textContent = '…';
  el.respView.innerHTML = `<span class="text-muted">Probing ${escapeHtml(url)} — capturing the original request &amp; response…</span>`;
  updateReqMeta();
  try {
    const resp = await fetch(`/api/repeater/${encodeURIComponent(TARGET)}/from-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, method }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      showError(`Could not load URL into Repeater: ${err.error || resp.statusText}`);
      newBlankRequest();
      // Still drop the URL into the editor so the user can see it.
      el.editor.value = `${method} ${url} HTTP/1.1\r\nHost: ${hostFromURL(url) || ''}\r\n\r\n`;
      updateReqMeta();
      return;
    }
    currentRequest = await resp.json();
    history.unshift(currentRequest);
    el.editor.value = currentRequest.raw_request || '';
    el.notes.value = currentRequest.notes || '';
    el.reqId.textContent = `#${currentRequest.id}`;
    updateReqMeta();
    renderResponse();
    renderHistory();
  } catch (e) {
    showError(`fromURL: ${e.message}`);
  } finally {
    el.sendBtn.disabled = false;
  }
}

// ── Send ─────────────────────────────────────────────────────────

async function sendRequest() {
  const raw = el.editor.value;
  if (!raw.trim()) { showError('Request is empty.'); return; }

  el.sendBtn.disabled = true;
  el.sendBtn.innerHTML = '<svg class="btn-svg spin" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg><span>Sending…</span>';
  hideError();

  const payload = {
    raw_request: raw,
    allow_internal: el.allowInternal.checked,
    follow_redirects: el.followRedir.checked,
  };
  if (currentRequest && currentRequest.id) {
    payload.request_id = currentRequest.id;
    payload.notes = el.notes.value;
  }

  try {
    const resp = await fetch(`/api/repeater/${encodeURIComponent(TARGET)}/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!resp.ok) {
      showError(data.error || `Send failed (${resp.status})`);
      return;
    }
    currentRequest = data;
    // Refresh history ordering (this request is now most-recent).
    history = history.filter(r => r.id !== data.id);
    history.unshift(data);
    el.reqId.textContent = `#${data.id}`;
    updateReqMeta();
    renderResponse();
    renderHistory();
  } catch (e) {
    showError(`sendRequest: ${e.message}`);
  } finally {
    el.sendBtn.disabled = false;
    el.sendBtn.innerHTML = '<svg class="btn-svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg><span>Send</span>';
  }
}

// ── Save notes ───────────────────────────────────────────────────

async function saveNotes() {
  if (!currentRequest || !currentRequest.id) {
    el.notesStatus.textContent = 'saved';
    el.notesStatus.classList.remove('dirty');
    return;
  }
  el.notesStatus.textContent = 'saving';
  el.notesStatus.classList.remove('dirty');
  el.notesStatus.classList.add('saving');
  try {
    await fetch(`/api/repeater/${encodeURIComponent(TARGET)}/requests/${currentRequest.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        raw_request: el.editor.value,
        notes: el.notes.value,
        method: currentRequest.method,
      }),
    });
  } catch (e) { /* non-fatal */ }
  el.notesStatus.textContent = 'saved';
  el.notesStatus.classList.remove('saving', 'dirty');
}

// ── Delete ───────────────────────────────────────────────────────

async function deleteRequest(id, ev) {
  ev.stopPropagation();
  if (!confirm('Delete this saved request?')) return;
  try {
    const resp = await fetch(`/api/repeater/${encodeURIComponent(TARGET)}/requests/${id}`, { method: 'DELETE' });
    if (!resp.ok) { showError('Failed to delete'); return; }
    history = history.filter(r => r.id !== id);
    if (currentRequest && currentRequest.id === id) {
      if (history.length > 0) loadRequest(history[0].id);
      else newBlankRequest();
    } else {
      renderHistory();
    }
  } catch (e) { showError(`deleteRequest: ${e.message}`); }
}

// ── Render helpers ───────────────────────────────────────────────

function renderResponse() {
  if (!currentRequest) {
    el.respView.innerHTML = '<span class="text-muted">No response yet. Send a request to see the response here.</span>';
    el.respStatus.textContent = '—';
    el.respStatus.className = 'pane-badge';
    el.respTime.textContent = '—';
    return;
  }

  const status = currentRequest.response_status;
  const err = currentRequest.response_error;
  const headers = currentRequest.response_headers || '';
  const body = currentRequest.response_body || '';
  const dur = currentRequest.duration_ms;

  // Status badge.
  if (status) {
    el.respStatus.textContent = status;
    el.respStatus.className = 'pane-badge status-ok';
  } else if (err) {
    el.respStatus.textContent = 'ERR';
    el.respStatus.className = 'pane-badge status-err';
  } else {
    el.respStatus.textContent = '—';
    el.respStatus.className = 'pane-badge';
  }
  el.respTime.textContent = dur != null ? `${dur}ms` : '—';

  if (err) {
    el.respView.innerHTML = `<span class="resp-error">⚠ ${escapeHtml(err)}</span>`;
    return;
  }

  if (respTab === 'raw') {
    // Single combined view: status line + headers + body in one pane.
    // Normalise \r\n → \n so carriage returns don't render as stray
    // characters or get swallowed by the browser's white-space handler.
    el.respView.className = 'response-view';
    let head = '';
    if (status) head += `HTTP/1.1 ${status}\n`;
    if (headers) head += headers.replace(/\r\n/g, '\n');
    const bodyText = (body || '').replace(/\r\n/g, '\n');
    el.respView.innerHTML =
      `<div class="resp-headers">${escapeHtml(head)}</div>` +
      `<div class="resp-body">${escapeHtml(bodyText)}</div>`;
  } else if (respTab === 'render') {
    el.respView.className = 'response-view render-mode';
    // Render the body in a sandboxed iframe so untrusted HTML can't touch the
    // app. scripts are disabled; same-origin is blocked via sandbox="".
    el.respView.innerHTML = '';
    const iframe = document.createElement('iframe');
    iframe.sandbox = '';
    iframe.srcdoc = body;
    el.respView.appendChild(iframe);
  } else {
    // body
    el.respView.className = 'response-view';
    el.respView.textContent = body || '(empty body)';
  }
}

function updateReqMeta() {
  const raw = el.editor.value;
  el.reqSize.textContent = `${raw.length} bytes`;
  // Parse the Host from the raw request for the header display.
  const hostMatch = raw.match(/^Host:\s*(.+)$/im);
  el.reqHost.textContent = hostMatch ? hostMatch[1].trim() : '—';
  // Sync the method selector to whatever is on the request line, so the
  // dropdown always reflects the editor (whether loaded from history, a
  // live probe, or typed by hand).
  const methodMatch = raw.match(/^(\S+)\s/);
  if (methodMatch) {
    const m = methodMatch[1].toUpperCase();
    const known = Array.from(el.methodSelect.options).map(o => o.value);
    if (known.includes(m)) el.methodSelect.value = m;
  }
}

// ── Mode switching (Repeater ↔ Intruder) ─────────────────────

function setMode(mode) {
  document.querySelectorAll('.mode-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.mode === mode);
  });
  document.getElementById('mode-repeater').classList.toggle('active', mode === 'repeater');
  document.getElementById('mode-intruder').classList.toggle('active', mode === 'intruder');
}

// ── Send to Intruder ─────────────────────────────────────────────
// Copies the current Repeater request into the Intruder template editor,
// switches to Intruder mode, and auto-marks the request path so the user
// can pick a wordlist and Start Attack immediately.
function sendToIntruder() {
  const raw = el.editor.value;
  if (!raw.trim()) { showError('Request is empty — nothing to send to Intruder.'); return; }
  el.intrEditor.value = raw;
  updateIntruderMeta();
  setMode('intruder');
  markIntruderPath();
  hideError();
}

// ── Intruder meta + path marking ─────────────────────────────────

function updateIntruderMeta() {
  el.intrTemplateSize.textContent = `${el.intrEditor.value.length} bytes`;
}

// Replace the request-line path with /<marker> so each wordlist word
// becomes a directory/file under root (the canonical dir-busting pattern).
function markIntruderPath() {
  const marker = el.intrMarker.value || '§§';
  const raw = el.intrEditor.value;
  // METHOD SP PATH SP HTTP/x.y  CRLF
  const m = raw.match(/^(\S+\s+)(\S+)(\s+HTTP\/[\d.]+\r?\n)/);
  if (!m) {
    showError('Could not find a request line to mark. Ensure the template starts with e.g. GET /path HTTP/1.1');
    return;
  }
  if (m[2].includes(marker)) { hideError(); return; } // already marked
  el.intrEditor.value = m[1] + '/' + marker + m[3] + raw.slice(m[0].length);
  updateIntruderMeta();
  hideError();
}

// ── Wordlist filesystem browser ──────────────────────────────────
// Modal that walks /api/fs/files (dirs + files with sizes). Selecting a
// file writes its absolute path into the wordlist input. Built once and
// reused; navigation just refreshes the body.
function browseWordlist() {
  if (!wordlistModal) {
    wordlistModal = document.createElement('div');
    wordlistModal.id = 'wordlist-modal';
    wordlistModal.className = 'modal-overlay';
    wordlistModal.innerHTML = `
      <div class="modal wordlist-modal">
        <div class="modal-header">
          <h3>Browse wordlist</h3>
          <button class="modal-close" data-action="cancel">&times;</button>
        </div>
        <div class="modal-body">
          <div class="wordlist-path-bar">
            <input type="text" id="wordlist-path-field" class="filter-input" placeholder="/usr/share/wordlists/..." />
            <button class="btn btn-secondary btn-small" id="wordlist-go-btn">Go</button>
          </div>
          <div id="wordlist-browser-body" class="wordlist-browser-body"></div>
          <div class="tool-detail-actions" style="margin-top:16px;">
            <button class="btn btn-secondary" data-action="cancel">Cancel</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(wordlistModal);
    wordlistModal.addEventListener('click', (e) => {
      if (e.target.dataset.action === 'cancel' || e.target === wordlistModal) closeWordlistModal();
    });
    document.getElementById('wordlist-go-btn').addEventListener('click', () => {
      loadWordlistDir(document.getElementById('wordlist-path-field').value || '/');
    });
    document.getElementById('wordlist-path-field').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') loadWordlistDir(document.getElementById('wordlist-path-field').value || '/');
    });
  }
  wordlistModal.classList.add('visible');
  const start = el.intrWordlist.value.trim() || '/usr/share/wordlists';
  loadWordlistDir(start);
}

function closeWordlistModal() {
  if (wordlistModal) wordlistModal.classList.remove('visible');
}

async function loadWordlistDir(path) {
  const body = document.getElementById('wordlist-browser-body');
  document.getElementById('wordlist-path-field').value = path;
  body.innerHTML = `<p class="text-muted">Loading…</p>`;
  try {
    const resp = await fetch(`/api/fs/files?path=${encodeURIComponent(path)}`);
    if (!resp.ok) { body.innerHTML = `<p class="resp-error">⚠ ${resp.status} ${resp.statusText}</p>`; return; }
    const data = await resp.json();
    renderWordlistDir(data);
  } catch (e) {
    body.innerHTML = `<p class="resp-error">⚠ ${escapeHtml(e.message)}</p>`;
  }
}

function renderWordlistDir(data) {
  const body = document.getElementById('wordlist-browser-body');
  const cwd = data.path || '/';
  const parent = data.parent || '/';
  let html = '';
  if (parent && parent !== cwd) {
    html += `<div class="wordlist-entry wordlist-dir" data-path="${escapeHtml(parent)}"><span class="wordlist-icon">📁</span> ..</div>`;
  }
  (data.dirs || []).forEach(d => {
    html += `<div class="wordlist-entry wordlist-dir" data-path="${escapeHtml(d.path)}"><span class="wordlist-icon">📁</span> ${escapeHtml(d.name)}</div>`;
  });
  (data.files || []).forEach(f => {
    const kb = f.size ? ` <span class="wordlist-size">${(f.size/1024).toFixed(1)} KB</span>` : '';
    html += `<div class="wordlist-entry wordlist-file" data-path="${escapeHtml(f.path)}"><span class="wordlist-icon">📄</span> ${escapeHtml(f.name)}${kb}</div>`;
  });
  if (!html) html = `<p class="text-muted">Empty directory.</p>`;
  body.innerHTML = html;
  body.querySelectorAll('.wordlist-dir').forEach(node => {
    node.addEventListener('click', () => loadWordlistDir(node.dataset.path));
  });
  body.querySelectorAll('.wordlist-file').forEach(node => {
    node.addEventListener('click', () => {
      el.intrWordlist.value = node.dataset.path;
      closeWordlistModal();
    });
  });
}

// ── Intruder attack (NDJSON streaming) ───────────────────────────
// POST /api/repeater/{target}/brute streams newline-delimited JSON:
//   {"event":"start",  "total":N,"host":...,"marker":...}
//   {"event":"result", "result":{"idx","word","status","length","duration_ms","error"}}
//   {"event":"done",   "sent":N,"errors":N}
// Aborting the fetch cancels the run server-side via the request context.
async function startAttack() {
  const raw = el.intrEditor.value;
  if (!raw.trim()) { showError('Request template is empty.'); return; }
  const wordlistPath = el.intrWordlist.value.trim();
  if (!wordlistPath) { showError('Pick a wordlist file first (Browse…).'); return; }
  const marker = el.intrMarker.value || '§§';
  if (!raw.includes(marker)) {
    showError(`Request template has no ${marker} marker. Click "Mark path" or place ${marker} where the word goes.`);
    return;
  }

  hideError();
  attackResults = [];
  attackTotal = 0;
  attackSent = 0;
  attackErrors = 0;
  el.intrResultsBody.innerHTML = '';
  el.intrEmpty.style.display = 'none';
  el.intrProgress.textContent = '0 / 0';
  el.intrStartBtn.style.display = 'none';
  el.intrStopBtn.style.display = '';

  attackController = new AbortController();
  const payload = {
    raw_request: raw,
    wordlist_path: wordlistPath,
    marker,
    concurrency: parseInt(el.intrConcurrency.value, 10) || 10,
    allow_internal: el.intrAllowInternal.checked,
    follow_redirects: el.intrFollowRedir.checked,
  };

  try {
    const resp = await fetch(`/api/repeater/${encodeURIComponent(TARGET)}/brute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: attackController.signal,
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      showError(err.error || `Attack failed (${resp.status})`);
      return;
    }
    // Stream NDJSON: decode incrementally, split on newlines, parse each line.
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop(); // retain the partial trailing line
      for (const line of lines) {
        if (!line.trim()) continue;
        try { handleAttackEvent(JSON.parse(line)); }
        catch { /* skip a malformed line */ }
      }
    }
    if (buf.trim()) {
      try { handleAttackEvent(JSON.parse(buf)); } catch { /* ignore */ }
    }
  } catch (e) {
    if (e.name !== 'AbortError') showError(`Attack error: ${e.message}`);
  } finally {
    finishAttack();
  }
}

function handleAttackEvent(ev) {
  if (ev.event === 'start') {
    attackTotal = ev.total || 0;
    el.intrProgress.textContent = `0 / ${attackTotal}`;
  } else if (ev.event === 'result') {
    attackSent++;
    const r = ev.result || {};
    if (r.error) attackErrors++;
    attackResults.push(r);
    appendResultRow(r);
    el.intrProgress.textContent = `${attackSent} / ${attackTotal || attackSent}`;
  } else if (ev.event === 'done') {
    attackSent = ev.sent || attackSent;
    attackErrors = ev.errors || attackErrors;
    el.intrProgress.textContent = `${attackSent} / ${attackTotal || attackSent}`;
  }
}

function stopAttack() {
  if (attackController) attackController.abort();
}

function finishAttack() {
  attackController = null;
  el.intrStartBtn.style.display = '';
  el.intrStopBtn.style.display = 'none';
  if (attackResults.length === 0) {
    el.intrEmpty.style.display = '';
    el.intrEmpty.textContent = 'No results.';
  }
}

// Append a single result row, honouring the live hide-404 + filter so the
// table stays responsive even with thousands of in-flight results.
function appendResultRow(r) {
  if (el.intrHide404.checked && r.status === 404) return;
  const q = el.intrFilter.value.trim().toLowerCase();
  if (q && !(`${r.word} ${r.status} ${r.error}`.toLowerCase().includes(q))) return;
  const tr = document.createElement('tr');
  tr.className = resultRowClass(r.status);
  tr.innerHTML = `<td class="col-idx">${r.idx}</td>` +
    `<td class="col-word">${escapeHtml(r.word)}</td>` +
    `<td class="col-status">${r.status || (r.error ? 'err' : '—')}</td>` +
    `<td class="col-length">${r.length != null ? r.length : '—'}</td>` +
    `<td class="col-time">${r.duration_ms != null ? r.duration_ms : '—'}</td>`;
  el.intrResultsBody.appendChild(tr);
}

function resultRowClass(status) {
  if (!status) return 'res-err';
  if (status >= 500) return 'res-s5';
  if (status >= 400) return 'res-s4';
  if (status >= 300) return 'res-s3';
  return 'res-s2';
}

// Re-render the whole results table when the filter / hide-404 toggles change.
function rerenderIntruderResults() {
  el.intrResultsBody.innerHTML = '';
  const q = el.intrFilter.value.trim().toLowerCase();
  const hide404 = el.intrHide404.checked;
  let shown = 0;
  for (const r of attackResults) {
    if (hide404 && r.status === 404) continue;
    if (q && !(`${r.word} ${r.status} ${r.error}`.toLowerCase().includes(q))) continue;
    const tr = document.createElement('tr');
    tr.className = resultRowClass(r.status);
    tr.innerHTML = `<td class="col-idx">${r.idx}</td>` +
      `<td class="col-word">${escapeHtml(r.word)}</td>` +
      `<td class="col-status">${r.status || (r.error ? 'err' : '—')}</td>` +
      `<td class="col-length">${r.length != null ? r.length : '—'}</td>` +
      `<td class="col-time">${r.duration_ms != null ? r.duration_ms : '—'}</td>`;
    el.intrResultsBody.appendChild(tr);
    shown++;
  }
  el.intrEmpty.style.display = shown === 0 ? '' : 'none';
  el.intrEmpty.textContent = attackResults.length === 0
    ? 'Load a request, pick a wordlist, and Start Attack. Results appear here in real time.'
    : 'No results match the current filter.';
}

// ── Utils ────────────────────────────────────────────────────────

function hostFromURL(url) {
  if (!url) return '';
  try {
    return new URL(url).hostname;
  } catch { return ''; }
}

function escapeHtml(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function showError(msg) {
  el.errorBanner.textContent = msg;
  el.errorBanner.style.display = 'block';
}
function hideError() {
  el.errorBanner.style.display = 'none';
}

// Expose for inline onclick handlers in history items.
window.loadRequest = loadRequest;
window.deleteRequest = deleteRequest;
