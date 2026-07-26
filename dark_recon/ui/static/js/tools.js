/* ── Tools Panel Interactivity ──────────────────────────────────── */

// ── Search + Filter ───────────────────────────────────────────────

// Re-query the cards on every call: tool cards are fetched asynchronously
// (after DOMContentLoaded), so capturing them once at load yields an empty
// list and breaks search/filter. Exposed globally so loadTools() can re-apply
// the active filter right after rendering the cards.
function applyToolsFilter() {
 const searchInput = document.getElementById('tools-search');
 const query = (searchInput?.value || '').toLowerCase();
 const activeChip = document.querySelector('.tools-filter-chip.active');
 const filter = activeChip?.dataset.filter || 'all';

 const toolCards = document.querySelectorAll('.tool-card:not(.tool-info-section .tool-card)');

 toolCards.forEach(card => {
 const searchText = card.dataset.toolSearch || '';
 const installed = card.dataset.toolInstalled === 'true';
 const isCustom = card.dataset.toolCustom === 'true';

 const matchesText = !query || searchText.includes(query);
 const matchesFilter =
 filter === 'all' ||
 (filter === 'installed' && installed) ||
 (filter === 'missing' && !installed) ||
 (filter === 'custom' && isCustom);

 card.style.display = (matchesText && matchesFilter) ? '' : 'none';
 });
}

document.addEventListener('DOMContentLoaded', function() {
 const searchInput = document.getElementById('tools-search');
 const filterChips = document.querySelectorAll('.tools-filter-chip');

 if (searchInput) {
 searchInput.addEventListener('input', applyToolsFilter);
 }

 filterChips.forEach(chip => {
 chip.addEventListener('click', function() {
 filterChips.forEach(c => c.classList.remove('active'));
 this.classList.add('active');
 applyToolsFilter();
 });
 });
});

// ── Toggle Enable/Disable ─────────────────────────────────────────

async function toggleTool(toolName, enabled) {
 try {
 const resp = await fetch(`/api/tools/${toolName}/toggle`, {
 method: 'PUT',
 headers: { 'Content-Type': 'application/json' },
 body: JSON.stringify({ enabled: enabled }),
 });
 const data = await resp.json();
 if (data.error) throw new Error(data.error);

 const card = document.querySelector(`[data-tool-name="${toolName}"]`);
 if (card) {
 card.classList.toggle('disabled', !enabled);
 }

 showToast(`${toolName} ${enabled ? 'enabled' : 'disabled'}`);
 } catch (err) {
 showToast(`Toggle failed: ${err.message}`, 'error');
 // Revert the toggle
 const toggle = document.getElementById(`toggle-${toolName}`);
 if (toggle) toggle.checked = !enabled;
 }
}

// ── Install Tool ──────────────────────────────────────────────────

async function installTool(toolName) {
 const confirmed = await confirmDialog(
 `Install <strong>${toolName}</strong>? This may take a few minutes.`,
 ' Install'
 );
 if (!confirmed) return;

 const btn = document.getElementById(`install-btn-${toolName}`);
 const card = document.querySelector(`[data-tool-name="${toolName}"]`);
 const overlay = document.getElementById(`loading-${toolName}`);

 if (btn) { btn.disabled = true; btn.innerHTML = ' Installing...'; }
 if (card) card.classList.add('loading');
 if (overlay) overlay.classList.remove('hidden');

 try {
 const resp = await fetch(`/api/tools/${toolName}/install`, { method: 'POST' });
 const data = await resp.json();
 if (data.error) throw new Error(data.error);

 showToast(` ${toolName} installed successfully!`);
 setTimeout(() => window.location.reload(), 1500);
 } catch (err) {
 showToast(` Install failed: ${err.message}`, 'error');
 if (btn) { btn.disabled = false; btn.innerHTML = ' Install'; }
 if (card) card.classList.remove('loading');
 if (overlay) overlay.classList.add('hidden');
 }
}

// ── Uninstall Tool ────────────────────────────────────────────────

async function uninstallTool(toolName) {
 const confirmed = await confirmDialog(
 `Uninstall <strong>${toolName}</strong>?`,
 ' Uninstall'
 );
 if (!confirmed) return;

 const btn = document.getElementById(`uninstall-btn-${toolName}`);
 const card = document.querySelector(`[data-tool-name="${toolName}"]`);
 const overlay = document.getElementById(`loading-${toolName}`);

 if (btn) { btn.disabled = true; btn.innerHTML = ' Removing...'; }
 if (card) card.classList.add('loading');
 if (overlay) overlay.classList.remove('hidden');

 try {
 const resp = await fetch(`/api/tools/${toolName}/uninstall`, { method: 'POST' });
 const data = await resp.json();
 if (data.error) throw new Error(data.error);

 showToast(` ${toolName} uninstalled`);
 setTimeout(() => window.location.reload(), 1500);
 } catch (err) {
 showToast(` Uninstall failed: ${err.message}`, 'error');
 if (btn) { btn.disabled = false; btn.innerHTML = ' Uninstall'; }
 if (card) card.classList.remove('loading');
 if (overlay) overlay.classList.add('hidden');
 }
}

// ── Check Tool (re-check status) ──────────────────────────────────

async function checkTool(toolName) {
 const btn = document.getElementById(`check-btn-${toolName}`);
 const card = document.querySelector(`[data-tool-name="${toolName}"]`);
 const overlay = document.getElementById(`loading-${toolName}`);

 if (btn) { btn.disabled = true; btn.innerHTML = ' Checking...'; }
 if (card) card.classList.add('loading');
 if (overlay) overlay.classList.remove('hidden');

 try {
 const resp = await fetch(`/api/tools/${toolName}/check`, { method: 'POST' });
 const data = await resp.json();
 if (data.error) throw new Error(data.error);

 // Update the version display
 const versionEl = document.getElementById(`version-${toolName}`);
 if (versionEl && data.version) {
 versionEl.textContent = data.version;
 }

 showToast(` ${toolName}: ${data.installed ? 'Installed' : 'Missing'}${data.version ? ' (v' + data.version + ')' : ''}`);
 setTimeout(() => window.location.reload(), 1000);
 } catch (err) {
 showToast(` Check failed: ${err.message}`, 'error');
 if (btn) { btn.disabled = false; btn.innerHTML = ' Check'; }
 if (card) card.classList.remove('loading');
 if (overlay) overlay.classList.add('hidden');
 }
}

// ── Refresh All Tools ─────────────────────────────────────────────

async function refreshAllTools() {
 const btn = document.getElementById('refresh-all-btn');
 if (btn) { btn.disabled = true; btn.innerHTML = ' Refreshing...'; }

 try {
 const resp = await fetch('/api/tools/refresh');
 const data = await resp.json();
 if (data.error) throw new Error(data.error);

 showToast('All tools refreshed');
 setTimeout(() => window.location.reload(), 1000);
 } catch (err) {
 showToast(` Refresh failed: ${err.message}`, 'error');
 if (btn) { btn.disabled = false; btn.innerHTML = ' Refresh All'; }
 }
}

// ── Tool Detail Panel ─────────────────────────────────────────────

async function showToolDetail(toolName) {
 const overlay = document.getElementById('tool-detail-overlay');
 const title = document.getElementById('tool-detail-title');
 const body = document.getElementById('tool-detail-body');

 title.innerHTML = ` ${toolName}`;
 body.innerHTML = '<p class="text-muted">Loading...</p>';
 overlay.classList.add('visible');

 try {
 const resp = await fetch(`/api/tools/${toolName}`);
 const data = await resp.json();
 if (data.error) throw new Error(data.error);

 let html = '';

 // Status section
 html += '<div class="tool-detail-section">';
 html += '<div class="tool-detail-section-title">Status</div>';
 html += `<div class="tool-card-meta" style="flex-direction:column;gap:8px;">`;
 html += `<div class="tool-meta-item"><strong>Installed:</strong> ${data.installed ? '<span class="status-badge status-completed">Yes</span>' : '<span class="status-badge status-failed">No</span>'}</div>`;
 html += `<div class="tool-meta-item"><strong>Enabled:</strong> ${data.enabled ? '<span class="status-badge status-completed">Yes</span>' : '<span class="status-badge status-unknown">No</span>'}</div>`;
 if (data.version) {
 html += `<div class="tool-meta-item"><strong>Version:</strong> <span class="mono">${data.version}</span></div>`;
 }
 if (data.path) {
 html += `<div class="tool-meta-item"><strong>Path:</strong> <span class="mono">${data.path}</span></div>`;
 }
 html += `</div></div>`;

 // Description
 if (data.description) {
 html += '<div class="tool-detail-section">';
 html += '<div class="tool-detail-section-title">Description</div>';
 html += `<div class="tool-card-desc">${data.description}</div>`;
 html += '</div>';
 }

 // Installation
 html += '<div class="tool-detail-section">';
 html += '<div class="tool-detail-section-title">Installation</div>';
 html += `<div class="tool-meta-item" style="margin-bottom:8px;"><strong>Method:</strong> <span class="tool-method-badge ${data.method}">${data.method}</span></div>`;
 if (data.install_cmd) {
 html += '<div class="tool-detail-section-title" style="margin-top:8px;">Install Command</div>';
 html += `<div class="tool-detail-cmd">${data.install_cmd}</div>`;
 }
 if (data.check_cmd) {
 html += '<div class="tool-detail-section-title" style="margin-top:8px;">Check Command</div>';
 html += `<div class="tool-detail-cmd">${data.check_cmd}</div>`;
 }
 html += '</div>';

 // Configuration
 if (data.args || data.phase) {
 html += '<div class="tool-detail-section">';
 html += '<div class="tool-detail-section-title">Configuration</div>';
 if (data.phase) {
 html += `<div class="tool-meta-item" style="margin-bottom:8px;"><strong>Phase:</strong> <span class="tool-phase-badge">${data.phase}</span></div>`;
 }
 if (data.args) {
 html += '<div class="tool-detail-section-title" style="margin-top:8px;">Custom Args</div>';
 html += `<div class="tool-detail-cmd">${data.args}</div>`;
 }
 html += '</div>';
 }

 // Actions
 html += '<div class="tool-detail-actions">';
 if (!data.installed) {
 html += `<button class="btn btn-primary" onclick="closeToolDetail();installTool('${toolName}')"> Install</button>`;
 } else {
 html += `<button class="btn btn-danger" onclick="closeToolDetail();uninstallTool('${toolName}')"> Uninstall</button>`;
 }
 html += `<button class="btn btn-secondary" onclick="closeToolDetail();checkTool('${toolName}')"> Re-check</button>`;
 html += '</div>';

 body.innerHTML = html;
 } catch (err) {
 body.innerHTML = `<div class="alert-critical">Failed to load tool details: ${err.message}</div>`;
 }
}

function closeToolDetail() {
 const overlay = document.getElementById('tool-detail-overlay');
 if (overlay) overlay.classList.remove('visible');
}

// Close detail on Escape
document.addEventListener('keydown', function(e) {
 if (e.key === 'Escape') closeToolDetail();
});
