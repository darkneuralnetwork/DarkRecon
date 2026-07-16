/* ════════════════════════════════════════════════════════════════ */
/*  Dark-Recon — App JS                                            */
/*  Top navbar + slide-in New Scan drawer                          */
/* ════════════════════════════════════════════════════════════════ */

// ── SVG Icon Library ────────────────────────────────────────────
const ICON = {
  dashboard: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>',
  rocket: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"/><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/></svg>',
  wrench: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>',
  settings: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  list: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>',
  plus: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',
  close: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  moon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>',
  sun: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>',
  shield: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  chevron: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>',
  stop: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="5" width="14" height="14" rx="2"/></svg>',
  bolt: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
};

// ════════════════════════════════════════════════════════════════
//  TOP NAVBAR INJECTION
// ════════════════════════════════════════════════════════════════
function injectTopbar() {
  const path = window.location.pathname;
  const isActive = (href) => {
    if (href === '/' && path === '/') return true;
    if (href !== '/' && path.startsWith(href)) return true;
    return false;
  };

  const topbarHTML = `
  <header class="topbar">
    <a href="/" class="topbar-brand">
      <span class="logo-mark">${ICON.shield}</span>
      <span class="logo">Dark-Recon</span>
    </a>
    <nav class="topbar-nav">
      <a href="/" class="nav-link ${isActive('/') && path !== '/scan/new' ? 'active' : ''}">
        <span class="nav-icon">${ICON.dashboard}</span><span>Dashboard</span>
      </a>
      <div class="dropdown" id="targets-dropdown">
        <button class="nav-link" id="targets-dropdown-btn" type="button">
          <span class="nav-icon">${ICON.list}</span><span>Targets</span>
          <span class="nav-icon" style="opacity:0.5">${ICON.chevron}</span>
        </button>
        <div class="dropdown-panel" id="target-list-panel">
          <h4>Scanned Targets</h4>
          <div id="target-list" class="target-list">
            <p class="text-muted">Loading...</p>
          </div>
        </div>
      </div>
      <a href="/tools" class="nav-link ${isActive('/tools') ? 'active' : ''}">
        <span class="nav-icon">${ICON.wrench}</span><span>Tools</span>
      </a>
      <a href="/settings" class="nav-link ${isActive('/settings') ? 'active' : ''}">
        <span class="nav-icon">${ICON.settings}</span><span>Settings</span>
      </a>
    </nav>
    <div class="topbar-actions">
      <div id="active-scans-badge" class="active-scans-badge" style="display:none;">
        <span class="status-badge status-running"><span id="active-scans-count">0</span> running</span>
      </div>
      <button class="btn btn-primary" id="new-scan-btn" type="button">
        ${ICON.plus}<span>New Scan</span>
      </button>
      <button class="theme-toggle" id="theme-toggle" title="Toggle theme" aria-label="Toggle theme">
        <span class="theme-icon-dark">${ICON.moon}</span>
        <span class="theme-icon-light">${ICON.sun}</span>
      </button>
    </div>
  </header>`;

  document.body.insertAdjacentHTML('afterbegin', topbarHTML);
  injectScanDrawer();
}

// ════════════════════════════════════════════════════════════════
//  NEW SCAN DRAWER (slide-in from right)
// ════════════════════════════════════════════════════════════════
function injectScanDrawer() {
  const drawerHTML = `
  <div class="drawer-overlay" id="drawer-overlay"></div>
  <aside class="drawer" id="scan-drawer" aria-hidden="true">
    <div class="drawer-header">
      <h2><span class="drawer-icon">${ICON.rocket}</span> New Scan</h2>
      <button class="drawer-close" id="drawer-close" aria-label="Close">${ICON.close}</button>
    </div>
    <div class="drawer-body">
      <div class="drawer-notice">
        ${ICON.bolt}<span>Scans run in the background — navigate freely, they won't stop.</span>
      </div>
      <form id="scan-form" onsubmit="return launchScan(event)">
        <div class="form-group">
          <label class="form-label" for="domain">Target Domain <span class="required">*</span></label>
          <input type="text" id="domain" name="domain" class="form-input"
            placeholder="example.com" required
            pattern="^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$">
          <span class="form-hint">Root domain to scan (e.g. example.com)</span>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label class="form-label" for="threads">Threads</label>
            <input type="number" id="threads" name="threads" class="form-input" value="50" min="1" max="500">
            <span class="form-hint">Concurrent threads</span>
          </div>
          <div class="form-group">
            <label class="form-label" for="timeout">HTTP Timeout (s)</label>
            <input type="number" id="timeout" name="timeout" class="form-input" value="10" min="1" max="120">
            <span class="form-hint">Request timeout</span>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label" for="top_subdomains">Top Subdomains for Crawling</label>
          <input type="number" id="top_subdomains" name="top_subdomains" class="form-input" value="10" min="1" max="100">
          <span class="form-hint">Top N priority subdomains for Katana + ffuf</span>
        </div>

        <div class="form-group">
          <label class="form-label">Select Scanning Phases</label>
          <div class="preset-row" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;">
            <button type="button" class="btn btn-small btn-secondary preset-btn" data-preset="all">All</button>
            <button type="button" class="btn btn-small btn-secondary preset-btn" data-preset="enum">Subdomain Enum Only</button>
            <button type="button" class="btn btn-small btn-secondary preset-btn" data-preset="advanced">Advanced Only</button>
            <button type="button" class="btn btn-small btn-secondary preset-btn" data-preset="none">Clear</button>
          </div>
          <div class="checkbox-group">
            <label class="checkbox-label"><input type="checkbox" class="phase-cb" value="subdomain_enum" checked><span>Subdomain Enumeration <span class="dep-hint">(subfinder + ffuf DNS)</span></span></label>
            <label class="checkbox-label"><input type="checkbox" class="phase-cb" value="passive_recon"><span>Passive Recon <span class="dep-hint">(crt.sh / chaos)</span></span></label>
            <label class="checkbox-label"><input type="checkbox" class="phase-cb" value="live_check" checked><span>Live Host Detection <span class="dep-hint">(httpx) — needs subdomains</span></span></label>
            <label class="checkbox-label"><input type="checkbox" class="phase-cb" value="tech_detection"><span>Technology Detection <span class="dep-hint">(webanalyze) — needs live hosts</span></span></label>
            <label class="checkbox-label"><input type="checkbox" class="phase-cb" value="early_crawling"><span>Deep Crawling <span class="dep-hint">(katana) — needs live hosts</span></span></label>
            <label class="checkbox-label"><input type="checkbox" class="phase-cb" value="vuln_scan"><span>Vulnerability Scan <span class="dep-hint">(nuclei) — needs live hosts</span></span></label>
            <label class="checkbox-label"><input type="checkbox" class="phase-cb" value="takeover"><span>Subdomain Takeover <span class="dep-hint">(subzy) — needs live hosts</span></span></label>
            <label class="checkbox-label"><input type="checkbox" class="phase-cb" value="waf_detect"><span>WAF Detection <span class="dep-hint">(wafw00f) — needs live hosts</span></span></label>
            <label class="checkbox-label"><input type="checkbox" class="phase-cb" value="port_scan"><span>Port Scan <span class="dep-hint">(nmap stealth) — needs live hosts</span></span></label>
            <label class="checkbox-label"><input type="checkbox" class="phase-cb" value="js_analysis"><span>JS Analysis <span class="dep-hint">(endpoints + secrets) — needs crawled URLs</span></span></label>
            <label class="checkbox-label"><input type="checkbox" class="phase-cb" value="param_discovery"><span>Parameter Discovery <span class="dep-hint">(arjun) — needs crawled URLs</span></span></label>
            <label class="checkbox-label"><input type="checkbox" class="phase-cb" value="secret_scan"><span>Secret Scan <span class="dep-hint">(trufflehog + gitleaks) — needs JS/crawled URLs</span></span></label>
            <label class="checkbox-label"><input type="checkbox" class="phase-cb" value="priority_scoring" checked><span>Priority Scoring</span></label>
          </div>
          <span class="form-hint">Check exactly what you want to run — any combination, individually or together. Missing inputs are reused from prior scans of the same target; if none exist, that phase is skipped with a warning (the scan won't fail).</span>
        </div>

        <div class="form-group">
          <label class="checkbox-label">
            <input type="checkbox" id="resume" name="resume">
            <span>Resume previous scan (if target exists)</span>
          </label>
        </div>

        <div class="form-actions">
          <button type="submit" class="btn btn-primary" id="scan-submit">${ICON.rocket}<span>Launch Scan</span></button>
        </div>
      </form>

      <div class="drawer-active-scans" id="drawer-active-scans-wrap" style="display:none;">
        <h3>Active Scans</h3>
        <div id="drawer-active-scans"></div>
      </div>
    </div>
  </aside>`;

  document.body.insertAdjacentHTML('beforeend', drawerHTML);
}

function initScanDrawer() {
  const btn = document.getElementById('new-scan-btn');
  const drawer = document.getElementById('scan-drawer');
  const overlay = document.getElementById('drawer-overlay');
  const closeBtn = document.getElementById('drawer-close');
  if (!btn || !drawer) return;

  btn.addEventListener('click', (e) => { e.preventDefault(); openScanDrawer(); });
  if (closeBtn) closeBtn.addEventListener('click', closeScanDrawer);
  if (overlay) overlay.addEventListener('click', closeScanDrawer);

  // Preset buttons: set the opt-in phase checkboxes to a named selection so
  // the user can one-click common configurations (all / enum-only /
  // advanced-only / clear) instead of ticking each box.
  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      applyPhasePreset(btn.dataset.preset);
    });
  });

  // Auto-open if requested (?new_scan=1 or /scan/new)
  const params = new URLSearchParams(window.location.search);
  if (params.get('new_scan') === '1' || window.location.pathname === '/scan/new') {
    setTimeout(openScanDrawer, 300);
  }
}

function openScanDrawer() {
  const drawer = document.getElementById('scan-drawer');
  const overlay = document.getElementById('drawer-overlay');
  if (!drawer) return;
  drawer.classList.add('visible');
  if (overlay) overlay.classList.add('visible');
  drawer.setAttribute('aria-hidden', 'false');
  loadScanConfigDefaults();
  loadDrawerActiveScans();
  const domainInput = document.getElementById('domain');
  if (domainInput) setTimeout(() => domainInput.focus(), 350);
}

function closeScanDrawer() {
  const drawer = document.getElementById('scan-drawer');
  const overlay = document.getElementById('drawer-overlay');
  if (!drawer) return;
  drawer.classList.remove('visible');
  if (overlay) overlay.classList.remove('visible');
  drawer.setAttribute('aria-hidden', 'true');
}

// applyPhasePreset checks/unchecks the opt-in phase checkboxes to match a
// named preset. "advanced" selects only the post-enumeration modules so the
// user can run e.g. just port scan / secrets against an already-enumerated
// target; "enum" selects only subdomain enumeration.
function applyPhasePreset(preset) {
  const cbs = document.querySelectorAll('input.phase-cb');
  const all = ['subdomain_enum','passive_recon','live_check','tech_detection','early_crawling','vuln_scan','takeover','waf_detect','port_scan','js_analysis','param_discovery','secret_scan','priority_scoring'];
  let on = [];
  switch (preset) {
    case 'all': on = all; break;
    case 'enum': on = ['subdomain_enum','passive_recon']; break;
    case 'advanced': on = ['port_scan','waf_detect','js_analysis','param_discovery','secret_scan','vuln_scan','takeover']; break;
    case 'none': on = []; break;
  }
  const set = new Set(on);
  cbs.forEach(cb => { cb.checked = set.has(cb.value); });
}

async function loadScanConfigDefaults() {
  try {
    const resp = await fetch('/api/config');
    const cfg = await resp.json();
    if (cfg.threads) document.getElementById('threads').value = cfg.threads;
    if (cfg.timeout) document.getElementById('timeout').value = cfg.timeout;
    if (cfg.top_subdomains_for_scanning) document.getElementById('top_subdomains').value = cfg.top_subdomains_for_scanning;
  } catch (e) { /* use defaults */ }
}

async function loadDrawerActiveScans() {
  try {
    const resp = await fetch('/api/scans/active');
    const data = await resp.json();
    const scans = data.scans || [];
    const wrap = document.getElementById('drawer-active-scans-wrap');
    const list = document.getElementById('drawer-active-scans');
    if (!wrap || !list) return;
    if (scans.length === 0) { wrap.style.display = 'none'; return; }
    wrap.style.display = 'block';
    list.innerHTML = scans.map(s => {
      const target = s.target || s.name || s;
      return `<div class="section-row" style="border:1px solid var(--border);border-radius:10px;padding:10px 12px;margin-bottom:8px;">
        <a href="/target/${target}" class="subdomain-link" style="flex:1;font-weight:600">${target}</a>
        <span class="status-badge status-running">running</span>
        <a href="/scan/${target}/progress" class="btn btn-small btn-secondary">Progress</a>
        <button class="btn btn-small btn-danger" onclick="stopScanFromDrawer('${target}')">${ICON.stop}<span>Stop</span></button>
      </div>`;
    }).join('');
  } catch (e) { /* ignore */ }
}

function launchScan(event) {
  event.preventDefault();
  const domain = document.getElementById('domain').value.trim();
  if (!domain) { showToast('Please enter a target domain', 'error'); return false; }

  // Opt-in phase selection: collect every checked phase checkbox. The backend
  // runs ONLY these; missing prerequisites are reused from prior scans.
  const phases = [];
  document.querySelectorAll('input.phase-cb:checked').forEach(cb => phases.push(cb.value));
  if (phases.length === 0) {
    showToast('Select at least one scanning phase', 'error');
    return false;
  }

  const body = {
    domain: domain,
    threads: parseInt(document.getElementById('threads').value) || null,
    timeout: parseInt(document.getElementById('timeout').value) || null,
    phases: phases,
    top_subdomains: parseInt(document.getElementById('top_subdomains').value) || 10,
    resume: document.getElementById('resume').checked,
  };
  const btn = document.getElementById('scan-submit');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span><span>Launching...</span>';

  fetch('/api/scan/launch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
    .then(resp => {
      if (resp.status === 409) throw new Error('A scan is already running for this target');
      return resp.json();
    })
    .then(data => {
      if (data.error) throw new Error(data.error);
      showToast(`Scan launched for ${domain}! Redirecting...`);
      setTimeout(() => { window.location.href = `/scan/${domain}/progress`; }, 900);
    })
    .catch(err => {
      showToast(err.message, 'error');
      btn.disabled = false;
      btn.innerHTML = ICON.rocket + '<span>Launch Scan</span>';
    });
  return false;
}

function stopScanFromDrawer(target) {
  confirmDialog(`Stop scan for <strong>${target}</strong>?`, 'Stop Scan')
    .then(confirmed => {
      if (!confirmed) return;
      fetch(`/api/scan/${target}/stop`, { method: 'POST' })
        .then(resp => resp.json())
        .then(() => {
          showToast(`Scan stopping for ${target}...`);
          setTimeout(() => loadDrawerActiveScans(), 1500);
        })
        .catch(() => showToast('Failed to stop scan', 'error'));
    });
}

// ════════════════════════════════════════════════════════════════
//  TARGET LIST (topbar dropdown)
// ════════════════════════════════════════════════════════════════
async function loadTargetList() {
  try {
    const resp = await fetch('/api/targets');
    const data = await resp.json();
    const list = document.getElementById('target-list');
    if (!list) return;

    const targets = data.targets || [];
    if (targets.length === 0) {
      const resp2 = await fetch('/api/scans/active');
      const data2 = await resp2.json();
      const scans = data2.scans || [];
      if (scans.length > 0) {
        list.innerHTML = scans.map(s =>
          `<a href="/target/${s.target}">${s.target} <span class="status-badge status-running">Running</span></a>`
        ).join('');
      } else {
        list.innerHTML = '<p class="text-muted">No targets yet</p>';
      }
    } else {
      list.innerHTML = targets.map(t => {
        const vulnCount = (t.critical || 0) + (t.high || 0) + (t.medium || 0) + (t.low || 0);
        const badge = vulnCount > 0
          ? `<span class="sev-badge sev-badge-${vulnCount > 5 ? 'critical' : 'high'}">${vulnCount}</span>`
          : '';
        return `<a href="/target/${t.name}">${t.name} ${badge}</a>`;
      }).join('');
    }
  } catch (e) {
    console.error('Failed to load targets', e);
  }
}

function initTargetsDropdown() {
  const dropdown = document.getElementById('targets-dropdown');
  const btn = document.getElementById('targets-dropdown-btn');
  if (!dropdown || !btn) return;
  btn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropdown.classList.toggle('open');
  });
  document.addEventListener('click', (e) => {
    if (!dropdown.contains(e.target)) dropdown.classList.remove('open');
  });
}

// ── Export ────────────────────────────────────────────────────────
async function exportTarget(target) {
  try {
    const resp = await fetch(`/api/target/${target}/export`);
    const data = await resp.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${target}_dark_recon.json`; a.click();
    URL.revokeObjectURL(url);
  } catch (e) { console.error('Export failed', e); }
}

async function exportCSV(target) {
  try {
    const resp = await fetch(`/api/target/${target}/export/csv`);
    if (!resp.ok) throw new Error('Export failed');
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${target}_vulns.csv`; a.click();
    URL.revokeObjectURL(url);
    showToast('CSV exported');
  } catch (e) {
    console.error('CSV export failed', e);
    showToast('CSV export failed', 'error');
  }
}

async function exportHandoff(target) {
  try {
    const resp = await fetch(`/api/target/${target}/handoff`);
    const data = await resp.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${target}_handoff.json`; a.click();
    URL.revokeObjectURL(url);
  } catch (e) { console.error('Handoff export failed', e); }
}

// ── Table Sorting ─────────────────────────────────────────────────
const sortStates = {};

function sortTable(tableId, colIdx) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const tbody = table.querySelector('tbody');
  if (!tbody) return;
  const rows = Array.from(tbody.querySelectorAll('tr:not(.vuln-expand-row)'));
  if (!sortStates[tableId]) sortStates[tableId] = { col: null, asc: true };
  const ss = sortStates[tableId];
  if (ss.col === colIdx) ss.asc = !ss.asc;
  else { ss.col = colIdx; ss.asc = true; }
  rows.sort((a, b) => {
    let aVal = a.cells[colIdx]?.textContent?.trim() || '';
    let bVal = b.cells[colIdx]?.textContent?.trim() || '';
    const aNum = parseFloat(aVal);
    const bNum = parseFloat(bVal);
    if (!isNaN(aNum) && !isNaN(bNum)) return ss.asc ? aNum - bNum : bNum - aNum;
    return ss.asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
  });
  rows.forEach(row => tbody.appendChild(row));
}

// ── Delete Target ────────────────────────────────────────────────
// Permanently removes a target's scan database and all associated files
// via DELETE /api/target/{name}. Uses the shared confirmDialog so the
// destructive action always requires an explicit confirm. After a
// successful delete:
//   - if opts.onDeleted is a function, it is called (dashboard re-renders);
//   - otherwise the browser is redirected to the dashboard (default).
// opts.redirect = false disables the auto-redirect (useful when a custom
// callback handles navigation).
async function deleteTarget(target, opts = {}) {
  if (!target) { showToast('No target specified', 'error'); return; }
  const esc = (s) => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const confirmed = await confirmDialog(
    `Delete all scan results for <strong>${esc(target)}</strong>?<br><br>This permanently removes the target database, subdomains, vulnerabilities, leaked secrets, and every associated file on disk. <strong>This action cannot be undone.</strong>`,
    'Delete Target',
    'Cancel'
  );
  if (!confirmed) return;
  try {
    const resp = await fetch(`/api/target/${encodeURIComponent(target)}`, { method: 'DELETE' });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.error || `Delete failed (${resp.status})`);
    }
    showToast(`Target "${target}" deleted`);
    if (typeof opts.onDeleted === 'function') {
      opts.onDeleted();
    } else if (opts.redirect !== false) {
      window.location.href = '/';
    }
  } catch (e) {
    console.error('Delete target failed', e);
    showToast(e.message || 'Delete failed', 'error');
  }
}

// ── Copy to Clipboard ─────────────────────────────────────────────
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard!');
  }).catch(() => showToast('Copy failed', 'error'));
}

// ── Custom Confirm Dialog ─────────────────────────────────────────
function confirmDialog(message, confirmLabel = 'Confirm', cancelLabel = 'Cancel') {
  return new Promise((resolve) => {
    const existing = document.getElementById('confirm-dialog');
    if (existing) existing.remove();
    const overlay = document.createElement('div');
    overlay.id = 'confirm-dialog';
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal" style="max-width: 440px;">
        <div class="modal-header">
          <h3>Confirm</h3>
          <button class="modal-close" data-action="cancel">&times;</button>
        </div>
        <div class="modal-body">
          <p style="font-size: 0.95em; line-height: 1.6; color: var(--text-secondary);">${message}</p>
          <div class="tool-detail-actions" style="margin-top: 20px;">
            <button class="btn btn-danger" data-action="confirm">${confirmLabel}</button>
            <button class="btn btn-secondary" data-action="cancel">${cancelLabel}</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    overlay.classList.add('visible');
    function close(result) {
      overlay.classList.remove('visible');
      overlay.remove();
      resolve(result);
    }
    overlay.addEventListener('click', function(e) {
      const action = e.target.dataset.action;
      if (action === 'confirm') close(true);
      else if (action === 'cancel') close(false);
      else if (e.target === overlay) close(false);
    });
    document.addEventListener('keydown', function handler(e) {
      if (e.key === 'Escape') { document.removeEventListener('keydown', handler); close(false); }
      else if (e.key === 'Enter') { document.removeEventListener('keydown', handler); close(true); }
    });
  });
}

// ── Toast Notification ────────────────────────────────────────────
function showToast(msg, type = 'success') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

// ── Timestamp Formatting ──────────────────────────────────────────
function formatTimestamp(ts) {
  if (!ts) return 'N/A';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

// ── Severity Color Helper ─────────────────────────────────────────
function getSeverityColor(sev) {
  const colors = {
    critical: '#f43f5e',
    high: '#fb923c',
    medium: '#facc15',
    low: '#34d399',
    info: '#38bdf8'
  };
  return colors[sev?.toLowerCase()] || '#38bdf8';
}

function getSeverityEmoji(sev) {
  return '';
}

// ── Collapsible Sections ──────────────────────────────────────────
function initCollapsibleSections() {
  document.querySelectorAll('.section-header').forEach(header => {
    header.addEventListener('click', function(e) {
      if (e.target.closest('button, a, .btn')) return;
      const section = this.closest('.section');
      if (section) section.classList.toggle('collapsed');
    });
  });
}

// ── Vulnerability Expandable Rows ─────────────────────────────────
function initVulnExpandableRows() {
  document.querySelectorAll('.vuln-row').forEach(row => {
    row.addEventListener('click', function(e) {
      if (e.target.closest('a, button, .btn')) return;
      const vulnId = this.dataset.vulnId;
      const expandRow = document.querySelector(`.vuln-expand-row[data-vuln-id="${vulnId}"]`);
      if (expandRow) {
        expandRow.classList.toggle('visible');
        this.classList.toggle('expanded');
      }
    });
  });
}

// ── Vulnerability Detail Modal ────────────────────────────────────
function showVulnModal(vulnId) {
  const row = document.querySelector(`.vuln-row[data-vuln-id="${vulnId}"]`);
  if (!row) return;
  const name = row.dataset.vulnName || 'Unknown';
  const severity = row.dataset.vulnSeverity || 'info';
  const template = row.dataset.vulnTemplate || 'N/A';
  const type = row.dataset.vulnType || 'N/A';
  const url = row.dataset.vulnUrl || '';
  const subdomain = row.dataset.vulnSubdomain || '';
  const cve = row.dataset.vulnCve || '';
  const description = row.dataset.vulnDesc || '';
  const matcher = row.dataset.vulnMatcher || '';
  const extracted = row.dataset.vulnExtracted || '';
  const refs = row.dataset.vulnRefs || '';

  const sevColor = getSeverityColor(severity);

  let modal = document.getElementById('vuln-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'vuln-modal';
    modal.className = 'modal-overlay';
    modal.innerHTML = `
      <div class="modal">
        <div class="modal-header">
          <h3 id="vuln-modal-title"></h3>
          <button class="modal-close" onclick="closeVulnModal()">&times;</button>
        </div>
        <div class="modal-body" id="vuln-modal-body"></div>
      </div>`;
    document.body.appendChild(modal);
    modal.addEventListener('click', function(e) { if (e.target === modal) closeVulnModal(); });
  }

  document.getElementById('vuln-modal-title').textContent = name;

  const body = document.getElementById('vuln-modal-body');
  let html = `
    <div class="vuln-detail-panel">
      <div class="vuln-detail-item">
        <span class="vuln-detail-label">Severity</span>
        <span class="vuln-detail-value" style="color:${sevColor};font-weight:700">${severity.toUpperCase()}</span>
      </div>
      <div class="vuln-detail-item">
        <span class="vuln-detail-label">Template ID</span>
        <span class="vuln-detail-value mono">${template}</span>
      </div>
      <div class="vuln-detail-item">
        <span class="vuln-detail-label">Type</span>
        <span class="vuln-detail-value">${type}</span>
      </div>
      <div class="vuln-detail-item">
        <span class="vuln-detail-label">Subdomain</span>
        <span class="vuln-detail-value">${subdomain}</span>
      </div>
      <div class="vuln-detail-item">
        <span class="vuln-detail-label">Endpoint / URL</span>
        <span class="vuln-detail-value url">${url ? `<a href="${url}" target="_blank">${url}</a>` : 'N/A'}</span>
      </div>
      <div class="vuln-detail-item">
        <span class="vuln-detail-label">CVE IDs</span>
        <span class="vuln-detail-value" style="color:var(--critical);font-weight:600">${cve || 'N/A'}</span>
      </div>`;

  if (matcher) {
    html += `<div class="vuln-detail-item"><span class="vuln-detail-label">Matcher</span><span class="vuln-detail-value mono">${matcher}</span></div>`;
  }
  if (extracted) {
    html += `<div class="vuln-detail-item"><span class="vuln-detail-label">Extracted Results</span><span class="vuln-detail-value mono">${extracted}</span></div>`;
  }
  html += `</div>`;

  if (description) {
    html += `<div class="modal-section-title">Description</div><div class="vuln-detail-description">${description}</div>`;
  }
  if (refs) {
    const refList = refs.split(',').filter(r => r.trim());
    if (refList.length > 0) {
      html += `<div class="modal-section-title">References</div><div class="vuln-detail-refs">${refList.map(r => `<a href="${r.trim()}" target="_blank">${r.trim()}</a>`).join('')}</div>`;
    }
  }
  html += `
    <div style="margin-top:16px;display:flex;gap:8px">
      <button class="btn btn-secondary btn-small" onclick="copyToClipboard('${url}')">Copy URL</button>
      <button class="btn btn-secondary btn-small" onclick="copyToClipboard('${template}')">Copy Template ID</button>
    </div>`;
  body.innerHTML = html;
  modal.classList.add('visible');
}

function closeVulnModal() {
  const modal = document.getElementById('vuln-modal');
  if (modal) modal.classList.remove('visible');
}

// ── Search / Filter ───────────────────────────────────────────────
let vulnPage = 1;
let vulnPageSize = 50;
let vulnFilteredRows = [];

function initVulnFilter() {
  const searchInput = document.getElementById('vuln-search');
  const sevChips = document.querySelectorAll('.filter-chip[data-sev]');
  const table = document.getElementById('vuln-table');
  if (!table) return;
  const tbody = table.querySelector('tbody');
  if (!tbody) return;
  const rows = Array.from(tbody.querySelectorAll('tr.vuln-row'));

  function applyFilter() {
    const query = searchInput?.value?.toLowerCase() || '';
    const activeSevs = Array.from(sevChips).filter(c => c.classList.contains('active')).map(c => c.dataset.sev);
    vulnFilteredRows = [];
    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      const sev = (row.dataset.vulnSeverity || '').toLowerCase();
      const matchesText = !query || text.includes(query);
      const matchesSev = activeSevs.length === 0 || activeSevs.includes(sev);
      const expandRow = tbody.querySelector(`.vuln-expand-row[data-vuln-id="${row.dataset.vulnId}"]`);
      if (matchesText && matchesSev) {
        vulnFilteredRows.push(row);
      } else {
        row.style.display = 'none';
        if (expandRow) expandRow.style.display = 'none';
      }
    });
    vulnPage = 1;
    renderVulnPage();
  }

  if (searchInput) searchInput.addEventListener('input', applyFilter);
  sevChips.forEach(chip => {
    chip.addEventListener('click', function() { this.classList.toggle('active'); applyFilter(); });
  });
  applyFilter();
}

function renderVulnPage() {
  const table = document.getElementById('vuln-table');
  if (!table) return;
  const tbody = table.querySelector('tbody');
  if (!tbody) return;
  const total = vulnFilteredRows.length;
  const totalPages = Math.max(1, Math.ceil(total / vulnPageSize));
  if (vulnPage > totalPages) vulnPage = totalPages;
  const start = (vulnPage - 1) * vulnPageSize;
  const end = start + vulnPageSize;
  vulnFilteredRows.forEach((row, idx) => {
    const expandRow = tbody.querySelector(`.vuln-expand-row[data-vuln-id="${row.dataset.vulnId}"]`);
    if (idx >= start && idx < end) {
      row.style.display = '';
      if (expandRow && row.classList.contains('expanded')) expandRow.style.display = '';
      else if (expandRow) expandRow.style.display = 'none';
    } else {
      row.style.display = 'none';
      if (expandRow) expandRow.style.display = 'none';
    }
  });
  const controls = document.getElementById('vuln-pagination');
  const pageInfo = document.getElementById('vuln-page-info');
  const prevBtn = document.getElementById('vuln-prev-page');
  const nextBtn = document.getElementById('vuln-next-page');
  if (controls) {
    if (total > vulnPageSize) {
      controls.style.display = 'flex';
      if (pageInfo) pageInfo.textContent = `Page ${vulnPage} of ${totalPages} (${total} vulns)`;
      if (prevBtn) prevBtn.disabled = vulnPage <= 1;
      if (nextBtn) nextBtn.disabled = vulnPage >= totalPages;
    } else {
      controls.style.display = 'none';
    }
  }
}

function changeVulnPage(delta) {
  const total = vulnFilteredRows.length;
  const totalPages = Math.max(1, Math.ceil(total / vulnPageSize));
  const newPage = vulnPage + delta;
  if (newPage < 1 || newPage > totalPages) return;
  vulnPage = newPage;
  renderVulnPage();
}

function changeVulnPageSize(size) {
  vulnPageSize = parseInt(size) || 50;
  vulnPage = 1;
  renderVulnPage();
}

// ── Directory URL Filter ──────────────────────────────────────────
function initDirFilter() {
  const searchInput = document.getElementById('dir-search');
  if (!searchInput) return;
  const items = document.querySelectorAll('.dir-url-item');
  searchInput.addEventListener('input', function() {
    const query = this.value.toLowerCase();
    items.forEach(item => {
      item.style.display = item.textContent.toLowerCase().includes(query) ? '' : 'none';
    });
  });
}

// ── Esc closes overlays ───────────────────────────────────────────
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    closeVulnModal();
    closeScanDrawer();
    if (typeof closeToolDetail === 'function') closeToolDetail();
  }
});

// ── Theme Toggle ──────────────────────────────────────────────────
function initThemeToggle() {
  const toggle = document.getElementById('theme-toggle');
  if (!toggle) return;
  const savedTheme = localStorage.getItem('dark-recon-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  toggle.addEventListener('click', function() {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('dark-recon-theme', next);
  });
}

// ── Active Scans Badge (topbar) ───────────────────────────────────
async function pollActiveScans() {
  try {
    const resp = await fetch('/api/scans/active');
    const data = await resp.json();
    const scans = data.scans || [];
    const badge = document.getElementById('active-scans-badge');
    const count = document.getElementById('active-scans-count');
    if (badge && count) {
      if (scans.length > 0) {
        count.textContent = scans.length;
        badge.style.display = 'block';
      } else {
        badge.style.display = 'none';
      }
    }
  } catch (e) { /* silent */ }
}

// ── Sidebar Target List Refresh ───────────────────────────────────
async function refreshTargetList() {
  try {
    const resp = await fetch('/api/targets');
    const data = await resp.json();
    const targets = data.targets || [];
    const list = document.getElementById('target-list');
    if (!list) return;
    if (targets.length === 0) {
      const resp2 = await fetch('/api/scans/active');
      const data2 = await resp2.json();
      const scans = data2.scans || [];
      if (scans.length > 0) {
        list.innerHTML = scans.map(s =>
          `<a href="/target/${s.target}">${s.target} <span class="status-badge status-running">Running</span></a>`
        ).join('');
      } else {
        list.innerHTML = '<p class="text-muted">No targets yet</p>';
      }
    } else {
      list.innerHTML = targets.map(t => {
        const vulnCount = (t.critical || 0) + (t.high || 0) + (t.medium || 0) + (t.low || 0);
        const badge = vulnCount > 0
          ? `<span class="sev-badge sev-badge-${vulnCount > 5 ? 'critical' : 'high'}">${vulnCount}</span>`
          : '';
        return `<a href="/target/${t.name}">${t.name} ${badge}</a>`;
      }).join('');
    }
  } catch (e) {
    console.error('Failed to refresh target list', e);
  }
}

// ── Init on DOM Ready ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
  injectTopbar();
  initThemeToggle();
  initScanDrawer();
  initTargetsDropdown();
  loadTargetList();
  initCollapsibleSections();
  initVulnExpandableRows();
  initVulnFilter();
  initDirFilter();

  pollActiveScans();
  setInterval(pollActiveScans, 10000);
  setInterval(refreshTargetList, 5000);
});
