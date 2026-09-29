// IOC Scanner - Threat Intelligence Platform - Frontend JavaScript

let currentPage = 'dashboard';
let sseSource = null;
let currentIncidentId = null;

// --- Authentication --------------------------------------------------------
// The server requires a credential on every /api/* call. Rather than touching
// every call site, route all of them through apiFetch() below, which attaches the
// session cookie and surfaces a 401 by showing the login gate. EventSource cannot
// set headers at all, which is the reason the session is cookie-based.
function apiFetch(path, options) {
    const opts = Object.assign({ credentials: 'same-origin' }, options || {});
    return fetch(path, opts).then(res => {
        if (res.status === 401) {
            showLoginGate('Session expired or not authenticated.');
            throw new Error('unauthorized');
        }
        return res;
    });
}

function showLoginGate(message) {
    const gate = document.getElementById('login-gate');
    const app = document.getElementById('app');
    if (gate) gate.style.display = 'flex';
    if (app) app.style.display = 'none';
    const err = document.getElementById('login-error');
    if (err) err.textContent = message || '';
}

function hideLoginGate() {
    const gate = document.getElementById('login-gate');
    const app = document.getElementById('app');
    if (gate) gate.style.display = 'none';
    if (app) app.style.display = '';
}

async function login(key) {
    const res = await fetch('/api/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key })
    });
    if (!res.ok) throw new Error('Invalid session key');
    return true;
}

function initLogin() {
    const form = document.getElementById('login-form');
    if (!form) return;
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const input = document.getElementById('login-key');
        const err = document.getElementById('login-error');
        try {
            await login(input.value.trim());
            err.textContent = '';
            hideLoginGate();
            bootstrap();
        } catch (ex) {
            err.textContent = ex.message;
        }
    });
}

// Everything requiring a live connection, run only after a successful login.
function bootstrap() {
    initNavigation();
    initSSE();
    loadStats();
    loadInventory();
    loadDatabases();
    loadReports();
    updateTime();
    setInterval(updateTime, 1000);
    setTimeout(loadRecentIncidents, 500);
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initLogin();
    // The session cookie is HttpOnly, so JS cannot read it to check for a session.
    // Probe one cheap endpoint instead and show the gate on 401.
    apiFetch('/api/status')
        .then(() => { hideLoginGate(); bootstrap(); })
        .catch(err => {
            if (err.message === 'unauthorized') showLoginGate();
            else showLoginGate('Cannot reach the platform server.');
        });
});

// Navigation
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            const page = item.dataset.page;
            showPage(page);
        });
    });

    document.getElementById('refresh-btn').addEventListener('click', () => {
        loadStats();
        loadRecentIncidents();
        loadInventory();
        loadDatabases();
        loadReports();
    });
}

function showPage(page) {
    currentPage = page;
    
    // Update nav
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });

    // Update pages
    document.querySelectorAll('.page').forEach(p => {
        p.classList.toggle('active', p.id === `page-${page}`);
    });

    // Update title
    const titles = {
        dashboard: 'Dashboard',
        scanner: 'Scanner',
        inventory: 'Endpoint Inventory',
        incidents: 'Incidents & Alarms',
        databases: 'IOC Databases',
        reports: 'Reports',
        agents: 'Agent Setup'
    };
    document.getElementById('page-title').textContent = titles[page] || page;

    // Refresh data for page
    if (page === 'inventory') loadInventory();
    if (page === 'incidents') loadIncidents();
    if (page === 'databases') loadDatabases();
    if (page === 'reports') loadReports();
}

// SSE Connection
function initSSE() {
    sseSource = new EventSource('/api/events');

    sseSource.addEventListener('connected', (e) => {
        const data = JSON.parse(e.data);
        updateScanUI(data);
    });

    sseSource.addEventListener('scan_start', (e) => {
        const data = JSON.parse(e.data);
        updateScanUI(data);
        addLog('Scan started', 'info');
    });

    sseSource.addEventListener('progress', (e) => {
        const data = JSON.parse(e.data);
        updateScanUI(data);
    });

    sseSource.addEventListener('scan_complete', (e) => {
        const data = JSON.parse(e.data);
        updateScanUI(data);
        addLog('Scan completed', 'success');
        loadStats();
        loadIncidents();
    });

    sseSource.addEventListener('scan_stopped', (e) => {
        addLog('Scan stopped', 'warning');
    });

    sseSource.addEventListener('new_incident', (e) => {
        loadStats();
        loadRecentIncidents();
        loadIncidents();
    });

    sseSource.onerror = () => {
        console.log('SSE connection lost, retrying...');
    };
}

// Load Stats
async function loadStats() {
    try {
        const res = await apiFetch('/api/stats');
        const stats = await res.json();

        document.getElementById('stat-endpoints').textContent = stats.endpoints || 0;
        document.getElementById('stat-online').textContent = stats.endpoints_online || 0;
        document.getElementById('stat-threats').textContent = stats.threats_total || 0;
        document.getElementById('stat-incidents').textContent = stats.incidents_open || 0;
        document.getElementById('stat-critical').textContent = stats.incidents_critical || 0;
        document.getElementById('stat-scans').textContent = stats.scans_total || 0;

        document.getElementById('endpoint-count').textContent = stats.endpoints || 0;
        document.getElementById('incident-count').textContent = stats.incidents_open || 0;
    } catch (e) {
        console.error('Failed to load stats:', e);
    }
}

// Load Recent Incidents
async function loadRecentIncidents() {
    try {
        const res = await apiFetch('/api/incidents/recent');
        const data = await res.json();
        const container = document.getElementById('recent-incidents');

        if (!data.incidents || data.incidents.length === 0) {
            container.innerHTML = '<div class="empty-state">No incidents</div>';
            return;
        }

        container.innerHTML = data.incidents.slice(0, 5).map(inc => `
            <div class="incident-item" onclick="showIncidentDetail('${inc.id}')">
                <span class="badge badge-${inc.severity}">${inc.severity}</span>
                <span class="incident-title">${escapeHtml(inc.title)}</span>
                <span class="incident-time">${formatTime(inc.created)}</span>
            </div>
        `).join('');
    } catch (e) {
        console.error('Failed to load incidents:', e);
    }
}

// Load Inventory
async function loadInventory() {
    try {
        const res = await apiFetch('/api/inventory');
        const data = await res.json();
        const tbody = document.getElementById('inventory-body');

        if (!data.endpoints || data.endpoints.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="empty-state">No endpoints registered</td></tr>';
            return;
        }

        tbody.innerHTML = data.endpoints.map(ep => `
            <tr>
                <td>${ep.id}</td>
                <td>${escapeHtml(ep.hostname)}</td>
                <td>${ep.ip}</td>
                <td>${escapeHtml(ep.os)}</td>
                <td><span class="badge badge-${ep.status}">${ep.status}</span></td>
                <td>${formatTime(ep.last_seen)}</td>
                <td>${ep.scan_count || 0}</td>
                <td>${ep.threats_found || 0}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="scanEndpoint('${ep.id}')">Scan</button>
                </td>
            </tr>
        `).join('');

        // Update agent dropdown
        const select = document.getElementById('scan-agent');
        select.innerHTML = '<option value="">Local Machine</option>' +
            data.endpoints.map(ep => `<option value="${ep.id}">${escapeHtml(ep.hostname)} (${ep.ip})</option>`).join('');
    } catch (e) {
        console.error('Failed to load inventory:', e);
    }
}

function refreshInventory() {
    loadInventory();
    loadStats();
}

// Load Incidents
async function loadIncidents() {
    try {
        const res = await apiFetch('/api/incidents');
        const data = await res.json();
        const tbody = document.getElementById('incidents-body');

        if (!data.incidents || data.incidents.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No incidents</td></tr>';
            return;
        }

        tbody.innerHTML = data.incidents.map(inc => `
            <tr>
                <td>${inc.id}</td>
                <td>${formatTime(inc.created)}</td>
                <td><span class="badge badge-${inc.severity}">${inc.severity}</span></td>
                <td>${escapeHtml(inc.title)}</td>
                <td>${escapeHtml(inc.source)}</td>
                <td>${inc.type}</td>
                <td><span class="badge badge-${inc.status}">${inc.status}</span></td>
                <td>
                    <button class="btn btn-sm" onclick="showIncidentDetail('${inc.id}')">View</button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Failed to load incidents:', e);
    }
}

function filterIncidents() {
    const filter = document.getElementById('incident-filter').value;
    const rows = document.querySelectorAll('#incidents-body tr');
    
    rows.forEach(row => {
        if (row.querySelector('.empty-state')) return;
        
        const severity = row.querySelector('.badge-critical, .badge-high, .badge-medium, .badge-low')?.textContent || '';
        const status = row.querySelector('.badge-open, .badge-resolved, .badge-investigating')?.textContent || '';
        
        let show = true;
        if (filter === 'open') show = status === 'open';
        else if (filter === 'critical') show = severity === 'critical';
        else if (filter === 'high') show = severity === 'high';
        else if (filter === 'resolved') show = status === 'resolved';
        
        row.style.display = show ? '' : 'none';
    });
}

// Load Databases
async function loadDatabases() {
    try {
        const res = await apiFetch('/api/databases');
        const data = await res.json();
        const tbody = document.getElementById('databases-body');

        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No databases</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(db => `
            <tr>
                <td>${escapeHtml(db.name)}</td>
                <td>${db.entries}</td>
                <td>${formatBytes(db.size)}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="deleteDatabase('${escapeHtml(db.name)}')">Delete</button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Failed to load databases:', e);
    }
}

// Load Reports
async function loadReports() {
    try {
        const res = await apiFetch('/api/reports');
        const data = await res.json();
        const tbody = document.getElementById('reports-body');

        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No reports</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(r => `
            <tr>
                <td>${escapeHtml(r.name)}</td>
                <td>${formatBytes(r.size)}</td>
                <td>${formatTime(r.modified)}</td>
                <td>
                    <button class="btn btn-sm" onclick="viewReport('${escapeHtml(r.name)}')">View</button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Failed to load reports:', e);
    }
}

// Scan Control
async function startScan() {
    const path = document.getElementById('scan-path').value || '/';
    const agentId = document.getElementById('scan-agent').value;
    const mode = document.getElementById('scan-mode').value;
    const quick = mode === 'quick';

    try {
        const res = await apiFetch('/api/scan/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path, quick, agent_id: agentId || undefined })
        });
        const data = await res.json();
        if (data.started) {
            addLog(`Starting ${mode} scan of ${path}${agentId ? ' via agent ' + agentId : ''}`, 'info');
        } else {
            addLog('Failed to start scan: ' + (data.error || 'Unknown error'), 'error');
        }
    } catch (e) {
        addLog('Error starting scan: ' + e.message, 'error');
    }
}

async function stopScan() {
    try {
        await apiFetch('/api/scan/stop', { method: 'POST' });
        addLog('Scan stopped', 'warning');
    } catch (e) {
        addLog('Error stopping scan: ' + e.message, 'error');
    }
}

async function scanEndpoint(agentId) {
    const path = prompt('Enter path to scan:', '/');
    if (!path) return;

    try {
        const res = await apiFetch('/api/agent/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ agent_id: agentId, path, quick: false })
        });
        const data = await res.json();
        if (data.started) {
            showPage('scanner');
            addLog(`Scan started on agent ${agentId}`, 'info');
        } else {
            alert('Failed to start scan: ' + (data.error || 'Unknown error'));
        }
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

// Update Scan UI
function updateScanUI(data) {
    const statusEl = document.getElementById('scan-status');
    const progressEl = document.getElementById('scan-progress');
    const startBtn = document.getElementById('start-scan-btn');
    const stopBtn = document.getElementById('stop-scan-btn');

    // Update status
    statusEl.textContent = data.status;
    statusEl.className = 'scan-status ' + data.status;

    // Update progress
    const progress = data.progress || 0;
    progressEl.style.width = progress + '%';

    // Update stats
    document.getElementById('scan-files').textContent = data.files_scanned || 0;
    document.getElementById('scan-dirs').textContent = data.dirs_scanned || 0;
    document.getElementById('scan-threats').textContent = data.threats_found || 0;
    document.getElementById('scan-errors').textContent = data.errors || 0;

    // Update current file
    if (data.current_file) {
        document.getElementById('current-file').textContent = data.current_file;
    }

    // Update buttons
    startBtn.disabled = data.running;
    stopBtn.disabled = !data.running;

    // Update threats list
    if (data.threats && data.threats.length > 0) {
        const container = document.getElementById('threats-list');
        container.innerHTML = data.threats.filter(t => t.file).map(t => `
            <div class="threat-item">
                <div class="threat-file">${escapeHtml(t.file)}</div>
                <div class="threat-meta">
                    <span class="threat-family">${escapeHtml(t.family || 'Unknown')}</span>
                    <span>${escapeHtml(t.type || '')}</span>
                    <span>${escapeHtml(t.details || '')}</span>
                </div>
            </div>
        `).join('');
    }
}

// Logging
function addLog(message, type = 'info') {
    const log = document.getElementById('scan-log');
    const entry = document.createElement('div');
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;
}

// Incident Detail
async function showIncidentDetail(id) {
    currentIncidentId = id;
    try {
        const res = await apiFetch('/api/incidents');
        const data = await res.json();
        const inc = data.incidents.find(i => i.id === id);
        if (!inc) return;

        document.getElementById('modal-title').textContent = inc.id + ' - ' + inc.title;
        document.getElementById('modal-body').innerHTML = `
            <div class="incident-detail">
                <p><strong>Severity:</strong> <span class="badge badge-${inc.severity}">${inc.severity}</span></p>
                <p><strong>Status:</strong> <span class="badge badge-${inc.status}">${inc.status}</span></p>
                <p><strong>Source:</strong> ${escapeHtml(inc.source)}</p>
                <p><strong>Type:</strong> ${inc.type}</p>
                <p><strong>Created:</strong> ${formatTime(inc.created)}</p>
                <p><strong>Description:</strong> ${escapeHtml(inc.description)}</p>
                ${inc.details ? `<p><strong>Details:</strong><br><pre>${escapeHtml(JSON.stringify(inc.details, null, 2))}</pre></p>` : ''}
                ${inc.notes ? `<p><strong>Notes:</strong></p><ul>${inc.notes.map(n => `<li>${escapeHtml(n.text)} - ${formatTime(n.time)}</li>`).join('')}</ul>` : ''}
            </div>
        `;
        document.getElementById('incident-modal').classList.add('active');
    } catch (e) {
        console.error('Failed to load incident:', e);
    }
}

function closeModal() {
    document.getElementById('incident-modal').classList.remove('active');
    currentIncidentId = null;
}

async function resolveIncident() {
    if (!currentIncidentId) return;
    try {
        await apiFetch('/api/incidents/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: currentIncidentId, status: 'resolved', note: 'Marked resolved from web UI' })
        });
        closeModal();
        loadIncidents();
        loadStats();
    } catch (e) {
        console.error('Failed to resolve incident:', e);
    }
}

// Utilities
function updateTime() {
    document.getElementById('header-time').textContent = new Date().toLocaleString();
}

function formatTime(iso) {
    if (!iso) return '-';
    const d = new Date(iso);
    return d.toLocaleString();
}

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function copyAgentCode() {
    const code = document.getElementById('agent-install-curl').textContent;
    navigator.clipboard.writeText(code).then(() => {
        alert('Copied to clipboard!');
    });
}

function showAddDatabase() {
    const name = prompt('Database name:');
    if (!name) return;
    const type = prompt('Type (hash/pattern):', 'hash');
    if (!type) return;
    
    const filename = `${name}_${type}.csv`;
    const content = type === 'hash' ? '# SHA-256 Hash,Family,Description\n' : '# Pattern,Family,Description,IsExtension\n';
    
    apiFetch('/api/databases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: filename, content })
    }).then(() => loadDatabases());
}

function deleteDatabase(name) {
    if (!confirm(`Delete database "${name}"?`)) return;
    apiFetch('/api/databases/' + encodeURIComponent(name), { method: 'DELETE' })
        .then(() => loadDatabases());
}

function viewReport(name) {
    apiFetch('/api/reports/' + encodeURIComponent(name))
        .then(r => r.text())
        .then(text => {
            const w = window.open('', '_blank');
            w.document.write('<pre>' + escapeHtml(text) + '</pre>');
        });
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
    if (e.ctrlKey && e.key === 'Enter') {
        if (currentPage === 'scanner') startScan();
    }
});
