// Fallback to localhost if running locally, otherwise use the cloud backend URL (set this to your real backend IP/domain after deploying)
const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.protocol === 'file:';
const CLOUD_BACKEND_IP = 'YOUR_CLOUD_VM_IP_HERE'; // <-- Update this before cloud launch!
const API_BASE = isLocal ? 'http://127.0.0.1:8000' : `http://${CLOUD_BACKEND_IP}:8000`;
const WS_URL = isLocal ? 'ws://127.0.0.1:8000/ws' : `ws://${CLOUD_BACKEND_IP}:8000/ws`;

let ws = null;
let attackDistChart = null;
let severityChart = null;
let currentIncidentId = null;
let authToken = null;

// ══════════════════════════════════════════════════════════════
//  INITIALIZATION
// ══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    initLogin();
    initNavigation();
    initModal();
    initChat();

    // Check if already logged in
    const saved = localStorage.getItem('soc_token');
    if (saved) {
        authToken = saved;
        hideLogin();
        initWebSocket();
        fetchAllData();
    }
});

// ══════════════════════════════════════════════════════════════
//  AUTH / LOGIN
// ══════════════════════════════════════════════════════════════

function initLogin() {
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;
        const errorEl = document.getElementById('login-error');
        errorEl.textContent = '';

        try {
            const res = await fetch(`${API_BASE}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            if (!res.ok) {
                errorEl.textContent = 'Invalid credentials';
                return;
            }
            const data = await res.json();
            authToken = data.token;
            localStorage.setItem('soc_token', authToken);
            document.getElementById('user-name').textContent = data.username;
            document.getElementById('user-role').textContent = data.role;
            hideLogin();
            initWebSocket();
            fetchAllData();
        } catch (err) {
            errorEl.textContent = 'Connection failed — is the backend running?';
        }
    });

    document.getElementById('logout-btn').addEventListener('click', () => {
        authToken = null;
        localStorage.removeItem('soc_token');
        showLogin();
    });
}

function hideLogin() {
    document.getElementById('login-overlay').style.display = 'none';
}

function showLogin() {
    document.getElementById('login-overlay').style.display = 'flex';
}

function authHeaders() {
    const h = { 'Content-Type': 'application/json' };
    if (authToken) h['Authorization'] = `Bearer ${authToken}`;
    return h;
}

// ══════════════════════════════════════════════════════════════
//  NAVIGATION
// ══════════════════════════════════════════════════════════════

function initNavigation() {
    document.querySelectorAll('#main-nav li').forEach(li => {
        li.addEventListener('click', () => {
            document.querySelectorAll('#main-nav li').forEach(l => l.classList.remove('active'));
            li.classList.add('active');
            document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
            document.getElementById(`view-${li.dataset.view}`).classList.add('active');
        });
    });
}

// ══════════════════════════════════════════════════════════════
//  WEBSOCKET
// ══════════════════════════════════════════════════════════════

function initWebSocket() {
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {
        document.getElementById('ws-status').innerHTML = '<span class="ws-dot connected"></span> Connected';
    };
    ws.onclose = () => {
        document.getElementById('ws-status').innerHTML = '<span class="ws-dot disconnected"></span> Disconnected';
        setTimeout(initWebSocket, 3000);
    };
    ws.onerror = () => {
        document.getElementById('ws-status').innerHTML = '<span class="ws-dot disconnected"></span> Error';
    };
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'new_alert') {
            addLiveFeedEvent('alert', `ALERT: ${data.alert.title} from ${data.alert.attacker_ip} [${data.alert.severity}]`);
            fetchAllData();
        } else if (data.type === 'new_log') {
            addLiveFeedEvent('log', `${data.log.event_type} | IP: ${data.log.source_ip} | User: ${data.log.user_id || '-'} | ${data.log.status}`);
        } else if (data.type === 'approval_needed') {
            addLiveFeedEvent('approval', `⚠️ APPROVAL NEEDED: ${data.approval.action_type} → ${data.approval.target}`);
            fetchAllData();
        } else if (data.type === 'approval_processed') {
            fetchAllData();
        }
    };
}

function addLiveFeedEvent(type, message) {
    const feed = document.getElementById('live-feed');
    const time = new Date().toLocaleTimeString();
    const div = document.createElement('div');
    div.className = `feed-event type-${type}`;
    div.innerHTML = `<span class="feed-time">${time}</span><span class="feed-type">${type.toUpperCase()}</span><span>${message}</span>`;
    feed.insertBefore(div, feed.firstChild);
    if (feed.children.length > 200) feed.removeChild(feed.lastChild);
}

// ══════════════════════════════════════════════════════════════
//  FETCH ALL DATA
// ══════════════════════════════════════════════════════════════

async function fetchAllData() {
    try {
        const [statsRes, alertsRes, responsesRes, incidentsRes, approvalsRes, blocksRes, emailsRes, auditRes] = await Promise.all([
            fetch(`${API_BASE}/stats`),
            fetch(`${API_BASE}/alerts`),
            fetch(`${API_BASE}/responses`),
            fetch(`${API_BASE}/incidents`),
            fetch(`${API_BASE}/approvals`),
            fetch(`${API_BASE}/blocks`),
            fetch(`${API_BASE}/email-drafts`),
            fetch(`${API_BASE}/audit-log`),
        ]);
        const stats = await statsRes.json();
        const alerts = await alertsRes.json();
        const responses = await responsesRes.json();
        const incidents = await incidentsRes.json();
        const approvals = await approvalsRes.json();
        const blocks = await blocksRes.json();
        const emails = await emailsRes.json();
        const audit = await auditRes.json();

        updateStats(stats);
        updateCharts(stats, alerts);
        updateAlertsTable(alerts);
        updateAllAlertsTable(alerts);
        updateAllIncidentsTable(incidents);
        updateResponseTimeline(responses);
        updateApprovalsTable(approvals);
        updateBlocksTable(blocks);
        updateEmailsTable(emails);
        updateAuditTable(audit);
    } catch (error) {
        console.error("Fetch error:", error);
    }
}

// ══════════════════════════════════════════════════════════════
//  STATS
// ══════════════════════════════════════════════════════════════

function updateStats(stats) {
    animateCounter('total-incidents', stats.total_incidents || 0);
    animateCounter('total-alerts', stats.total_alerts || 0);
    animateCounter('total-blocked', stats.total_blocked || 0);
    animateCounter('total-pending', stats.pending_approvals || 0);
    animateCounter('total-logs', stats.total_logs || 0);
    document.getElementById('nav-alert-count').innerText = stats.total_alerts || 0;
    document.getElementById('nav-incident-count').innerText = stats.total_incidents || 0;
    document.getElementById('nav-approval-count').innerText = stats.pending_approvals || 0;
    document.getElementById('nav-email-count').innerText = stats.draft_emails || 0;
}

function animateCounter(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const current = parseInt(el.innerText) || 0;
    if (current === target) return;
    const diff = target - current;
    const step = Math.max(1, Math.abs(Math.ceil(diff / 10)));
    let val = current;
    const interval = setInterval(() => {
        val += diff > 0 ? step : -step;
        if ((diff > 0 && val >= target) || (diff < 0 && val <= target)) {
            val = target;
            clearInterval(interval);
        }
        el.innerText = val;
    }, 30);
}

// ══════════════════════════════════════════════════════════════
//  CHARTS
// ══════════════════════════════════════════════════════════════

function updateCharts(stats, alerts) {
    const dist = stats.attack_distribution || {};
    const chartColors = ['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#10b981', '#2dd4bf'];

    const distCtx = document.getElementById('attack-dist-chart');
    if (attackDistChart) attackDistChart.destroy();
    attackDistChart = new Chart(distCtx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(dist).map(k => k.replace(/_/g, ' ')),
            datasets: [{ data: Object.values(dist), backgroundColor: chartColors.slice(0, Object.keys(dist).length), borderWidth: 0, hoverOffset: 8 }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#94a3b8', font: { family: 'Inter', size: 12 }, padding: 16 } } }, cutout: '65%' }
    });

    const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    alerts.forEach(a => { if (sevCounts[a.severity] !== undefined) sevCounts[a.severity]++; });
    const sevCtx = document.getElementById('severity-chart');
    if (severityChart) severityChart.destroy();
    severityChart = new Chart(sevCtx, {
        type: 'bar',
        data: {
            labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            datasets: [{ label: 'Alerts', data: [sevCounts.CRITICAL, sevCounts.HIGH, sevCounts.MEDIUM, sevCounts.LOW], backgroundColor: ['rgba(220,38,38,0.6)', 'rgba(239,68,68,0.6)', 'rgba(245,158,11,0.6)', 'rgba(45,212,191,0.6)'], borderColor: ['#dc2626', '#ef4444', '#f59e0b', '#2dd4bf'], borderWidth: 1, borderRadius: 6 }]
        },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { color: '#64748b', stepSize: 1 }, grid: { color: 'rgba(51,65,85,0.3)' } }, x: { ticks: { color: '#64748b' }, grid: { display: false } } }, plugins: { legend: { display: false } } }
    });
}

// ══════════════════════════════════════════════════════════════
//  TABLES
// ══════════════════════════════════════════════════════════════

function updateAlertsTable(alerts) {
    const tbody = document.querySelector('#alerts-table tbody');
    tbody.innerHTML = '';
    alerts.slice(0, 10).forEach(alert => {
        const tr = document.createElement('tr');
        const time = new Date(alert.timestamp).toLocaleTimeString();
        const conf = alert.confidence_score || 80;
        const confColor = conf >= 80 ? 'var(--accent-red)' : conf >= 60 ? 'var(--accent-amber)' : 'var(--accent-green)';
        tr.innerHTML = `
            <td>${time}</td>
            <td><strong>${alert.title}</strong></td>
            <td><span class="attack-type-badge">${alert.attack_type || 'N/A'}</span></td>
            <td style="font-family:monospace;color:var(--primary);">${alert.attacker_ip}</td>
            <td><span class="severity-badge severity-${alert.severity}">${alert.severity}</span></td>
            <td><span class="confidence-score" style="color:${confColor}">${conf}%</span></td>
            <td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${alert.llm_summary || ''}</td>
            <td><button class="btn-investigate" onclick="openInvestigation(${alert.incident_id || alert.id})">Investigate</button></td>
        `;
        tbody.appendChild(tr);
    });
}

function updateAllAlertsTable(alerts) {
    const tbody = document.querySelector('#all-alerts-table tbody');
    tbody.innerHTML = '';
    alerts.forEach(alert => {
        const tr = document.createElement('tr');
        const time = new Date(alert.timestamp).toLocaleString();
        const vc = alert.verdict === 'TRUE_POSITIVE' ? 'color:var(--accent-green)' : alert.verdict === 'FALSE_POSITIVE' ? 'color:var(--accent-red)' : 'color:var(--text-muted)';
        const conf = alert.confidence_score || 80;
        tr.innerHTML = `
            <td>${alert.id}</td><td>${time}</td>
            <td><strong>${alert.title}</strong></td>
            <td><span class="attack-type-badge">${alert.attack_type || 'N/A'}</span></td>
            <td style="font-family:monospace;color:var(--primary);">${alert.attacker_ip}</td>
            <td><span class="severity-badge severity-${alert.severity}">${alert.severity}</span></td>
            <td><span class="confidence-score">${conf}%</span></td>
            <td style="${vc};font-weight:600;">${alert.verdict || 'PENDING'}</td>
            <td><button class="btn-investigate" onclick="openInvestigation(${alert.incident_id || alert.id})">Investigate</button></td>
        `;
        tbody.appendChild(tr);
    });
}

function updateAllIncidentsTable(incidents) {
    const tbody = document.querySelector('#all-incidents-table tbody');
    tbody.innerHTML = '';
    incidents.forEach(inc => {
        const tr = document.createElement('tr');
        const time = new Date(inc.timestamp).toLocaleString();
        const vc = inc.verdict === 'TRUE_POSITIVE' ? 'color:var(--accent-green)' : inc.verdict === 'FALSE_POSITIVE' ? 'color:var(--accent-red)' : 'color:var(--text-muted)';
        tr.innerHTML = `
            <td>${inc.id}</td><td>${time}</td>
            <td><strong>${inc.title}</strong></td>
            <td><span class="severity-badge severity-${inc.severity}">${inc.severity}</span></td>
            <td style="font-family:monospace;color:var(--primary);">${inc.correlation_key}</td>
            <td><span class="attack-type-badge" style="background:rgba(59,130,246,0.12);color:var(--primary);">${inc.status}</span></td>
            <td style="${vc};font-weight:600;">${inc.verdict || 'PENDING'}</td>
            <td><button class="btn-investigate" onclick="openInvestigation(${inc.id})">Investigate</button></td>
        `;
        tbody.appendChild(tr);
    });
}

function updateApprovalsTable(approvals) {
    const tbody = document.querySelector('#approvals-table tbody');
    tbody.innerHTML = '';
    approvals.forEach(a => {
        const tr = document.createElement('tr');
        const time = new Date(a.timestamp).toLocaleString();
        const isPending = a.status === 'PENDING';
        const statusClass = isPending ? 'approval-pending' : a.status === 'APPROVED' ? 'approval-approved' : 'approval-rejected';
        tr.className = isPending ? 'row-highlight' : '';
        tr.innerHTML = `
            <td>${a.id}</td><td>${time}</td>
            <td><strong>${a.action_type}</strong></td>
            <td><span class="tier-badge tier-${a.response_tier}">Tier ${a.response_tier}</span></td>
            <td style="font-family:monospace;color:var(--primary);">${a.target}</td>
            <td>${a.alert_id || '-'}</td>
            <td><span class="approval-status ${statusClass}">${a.status}</span></td>
            <td>${isPending ? `
                <button class="btn-approve" onclick="approveAction(${a.id})">✓ Approve</button>
                <button class="btn-reject" onclick="rejectAction(${a.id})">✗ Reject</button>
            ` : `<span style="color:var(--text-muted);">${a.reviewed_by || '-'}</span>`}</td>
        `;
        tbody.appendChild(tr);
    });
}

function updateBlocksTable(blocks) {
    const tbody = document.querySelector('#blocks-table tbody');
    tbody.innerHTML = '';
    blocks.forEach(b => {
        const tr = document.createElement('tr');
        const time = new Date(b.timestamp).toLocaleString();
        const expires = b.expires_at ? new Date(b.expires_at).toLocaleString() : 'Never';
        tr.innerHTML = `
            <td>${b.id}</td><td>${time}</td>
            <td><strong>${b.action_type}</strong></td>
            <td><span class="tier-badge tier-${b.response_tier}">Tier ${b.response_tier}</span></td>
            <td style="font-family:monospace;color:var(--primary);">${b.target}</td>
            <td>${expires}</td>
            <td><span class="approval-status">${b.approval_status || 'AUTO'}</span></td>
            <td><button class="btn-reject" onclick="unblockTarget(${b.id})">Unblock</button></td>
        `;
        tbody.appendChild(tr);
    });
}

function updateEmailsTable(emails) {
    const tbody = document.querySelector('#emails-table tbody');
    tbody.innerHTML = '';
    emails.forEach(e => {
        const tr = document.createElement('tr');
        const time = new Date(e.timestamp).toLocaleString();
        const isDraft = e.status === 'DRAFT';
        tr.innerHTML = `
            <td>${e.id}</td><td>${time}</td>
            <td style="font-family:monospace;color:var(--primary);">${e.target_ip}</td>
            <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${e.subject || 'N/A'}</td>
            <td><span class="approval-status ${isDraft ? 'approval-pending' : e.status === 'SENT' ? 'approval-approved' : ''}">${e.status}</span></td>
            <td>${isDraft ? `
                <button class="btn-approve" onclick="approveEmail(${e.id})">✓ Send</button>
                <button class="btn-reject" onclick="rejectEmail(${e.id})">✗ Reject</button>
            ` : '-'}</td>
        `;
        tbody.appendChild(tr);
    });
}

function updateAuditTable(audit) {
    const tbody = document.querySelector('#audit-table tbody');
    tbody.innerHTML = '';
    audit.forEach(a => {
        const tr = document.createElement('tr');
        const time = new Date(a.timestamp).toLocaleString();
        const resultClass = a.execution_result === 'SUCCESS' ? 'color:var(--accent-green)' : a.execution_result === 'QUEUED' ? 'color:var(--accent-amber)' : 'color:var(--accent-red)';
        tr.innerHTML = `
            <td style="white-space:nowrap;">${time}</td>
            <td><strong>${a.action_type}</strong></td>
            <td>${a.response_tier != null ? `<span class="tier-badge tier-${a.response_tier}">T${a.response_tier}</span>` : '-'}</td>
            <td style="font-family:monospace;color:var(--primary);">${a.target}</td>
            <td>${a.triggered_by || 'SYSTEM'}</td>
            <td>${a.approval_status || '-'}</td>
            <td style="${resultClass};font-weight:600;">${a.execution_result || '-'}</td>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-muted);">${a.notes || '-'}</td>
        `;
        tbody.appendChild(tr);
    });
}

// ══════════════════════════════════════════════════════════════
//  RESPONSE TIMELINE
// ══════════════════════════════════════════════════════════════

function updateResponseTimeline(responses) {
    const timeline = document.getElementById('response-timeline');
    timeline.innerHTML = '';
    responses.forEach(resp => {
        const item = document.createElement('div');
        item.className = `timeline-item action-${resp.action_type}`;
        const time = new Date(resp.timestamp).toLocaleString();
        let detailsHtml = resp.action_type === 'SEND_EMAIL' || resp.action_type === 'DRAFT_EMAIL'
            ? `<div class="email-block">${escapeHtml(resp.details)}</div>`
            : `<div>${escapeHtml(resp.details)}</div>`;
        const tierBadge = resp.response_tier ? `<span class="tier-badge tier-${resp.response_tier}">Tier ${resp.response_tier}</span>` : '';
        item.innerHTML = `
            <div class="timeline-time">${time} — <strong>${resp.action_type}</strong> ${tierBadge}
                <span class="approval-status" style="font-size:0.7rem;margin-left:8px;">${resp.approval_status || 'AUTO'}</span>
            </div>
            <div class="timeline-content">Target: <span style="color:var(--primary);font-family:monospace;">${resp.target}</span>${detailsHtml}</div>
        `;
        timeline.appendChild(item);
    });
}

// ══════════════════════════════════════════════════════════════
//  ACTION HANDLERS
// ══════════════════════════════════════════════════════════════

async function approveAction(id) {
    await fetch(`${API_BASE}/approvals/${id}/approve`, { method: 'POST', headers: authHeaders() });
    fetchAllData();
}

async function rejectAction(id) {
    await fetch(`${API_BASE}/approvals/${id}/reject`, { method: 'POST', headers: authHeaders() });
    fetchAllData();
}

async function unblockTarget(id) {
    await fetch(`${API_BASE}/blocks/${id}/unblock`, { method: 'POST', headers: authHeaders() });
    fetchAllData();
}

async function approveEmail(id) {
    await fetch(`${API_BASE}/email-drafts/${id}/approve`, { method: 'POST', headers: authHeaders() });
    fetchAllData();
}

async function rejectEmail(id) {
    await fetch(`${API_BASE}/email-drafts/${id}/reject`, { method: 'POST', headers: authHeaders() });
    fetchAllData();
}

// ══════════════════════════════════════════════════════════════
//  INVESTIGATION MODAL
// ══════════════════════════════════════════════════════════════

function initModal() {
    document.getElementById('modal-close').addEventListener('click', closeModal);
    document.getElementById('modal-overlay').addEventListener('click', (e) => {
        if (e.target === document.getElementById('modal-overlay')) closeModal();
    });
    document.querySelectorAll('.modal-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.modal-tab-content').forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
        });
    });
    document.querySelectorAll('.verdict-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            if (!currentIncidentId) return;
            document.querySelectorAll('.verdict-btn').forEach(b => b.classList.remove('selected'));
            btn.classList.add('selected');
            fetch(`${API_BASE}/incidents/${currentIncidentId}/verdict`, {
                method: 'POST',
                headers: authHeaders(),
                body: JSON.stringify({ verdict: btn.dataset.verdict })
            }).then(() => fetchAllData());
        });
    });
    document.getElementById('btn-download-pdf').addEventListener('click', () => {
        if (!currentIncidentId) return;
        window.open(`${API_BASE}/alerts/${currentIncidentId}/report.pdf`, '_blank');
    });
}

async function openInvestigation(incidentId) {
    currentIncidentId = incidentId;
    try {
        const res = await fetch(`${API_BASE}/incidents/${incidentId}/details`);
        const data = await res.json();
        renderInvestigation(data);
        document.getElementById('modal-overlay').classList.add('active');
    } catch (err) {
        console.error("Failed to load investigation:", err);
    }
}

function closeModal() {
    document.getElementById('modal-overlay').classList.remove('active');
    currentIncidentId = null;
}

function renderInvestigation(data) {
    const { incident, alerts, related_logs, related_responses, enrichment } = data;

    document.getElementById('modal-title').innerText = `Incident: ${incident.title} (Entity: ${incident.correlation_key})`;

    // Reset to first tab
    document.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.modal-tab-content').forEach(c => c.classList.remove('active'));
    document.querySelector('.modal-tab[data-tab="timeline"]').classList.add('active');
    document.getElementById('tab-timeline').classList.add('active');

    // Timeline
    const timeline = document.getElementById('investigation-timeline');
    timeline.innerHTML = '';
    related_logs.forEach(log => {
        const div = document.createElement('div');
        div.className = `inv-event status-${log.status}`;
        div.innerHTML = `<span class="inv-time">${log.timestamp}</span><span class="inv-type">${log.event_type}</span><span class="inv-detail">IP: ${log.source_ip} | User: ${log.user_id || '-'} | FP: ${log.device_fingerprint || '-'} | Status: ${log.status} | UA: ${log.user_agent || '-'}</span>`;
        timeline.appendChild(div);
    });

    // Evidence
    const graph = document.getElementById('evidence-graph');
    graph.innerHTML = '';
    const nodes = [
        { label: 'Correlation Key', value: incident.correlation_key },
        { label: 'Severity', value: incident.severity },
        { label: 'Total Alerts', value: alerts.length },
        { label: 'Logs Analyzed', value: related_logs.length },
    ];
    const userIds = [...new Set(alerts.flatMap(a => { try { return JSON.parse(a.evidence || '{}').user_ids || []; } catch { return []; } }))];
    const deviceFps = [...new Set(alerts.flatMap(a => { try { return [JSON.parse(a.evidence || '{}').device_fingerprint || '']; } catch { return []; } }))].filter(Boolean);
    if (userIds.length) nodes.push({ label: 'Targeted Users', value: userIds.join(', ') });
    if (deviceFps.length) nodes.push({ label: 'Device FPs', value: deviceFps.join(', ') });
    nodes.push({ label: 'Mitigations', value: related_responses.length });
    nodes.forEach(n => {
        const node = document.createElement('div');
        node.className = 'evidence-node';
        node.innerHTML = `<div class="evidence-node-label">${n.label}</div><div class="evidence-node-value">${n.value || '-'}</div>`;
        graph.appendChild(node);
    });

    // Citations
    const citationsEl = document.getElementById('citations-content');
    citationsEl.innerHTML = '';
    const firstAlert = alerts[0] || {};
    let citations = [];
    try { citations = JSON.parse(firstAlert.evidence_citations || '[]'); } catch {}
    if (citations.length) {
        citations.forEach(c => {
            const card = document.createElement('div');
            card.className = 'citation-card';
            card.innerHTML = `
                <div class="citation-id">LOG-${c.log_id}</div>
                <div class="citation-detail">${c.timestamp}</div>
                <div class="citation-detail">${c.event_type} | ${c.source_ip} | ${c.status}</div>
                <div class="citation-detail">User: ${c.user_id || '-'}</div>
            `;
            citationsEl.appendChild(card);
        });
    } else {
        citationsEl.innerHTML = '<p style="color:var(--text-muted);">No specific evidence citations available.</p>';
    }

    // Threat Intel
    const intel = document.getElementById('intel-content');
    intel.innerHTML = '';
    if (enrichment) {
        const scoreColor = enrichment.abuse_score >= 70 ? '#ef4444' : enrichment.abuse_score >= 40 ? '#f59e0b' : '#10b981';
        intel.innerHTML = `
            <div class="intel-grid">
                <div class="intel-card"><div class="intel-card-flag">${enrichment.flag || ''}</div><div class="intel-card-label">Country</div><div class="intel-card-value">${enrichment.country || 'Unknown'}</div></div>
                <div class="intel-card"><div class="intel-card-label">ISP</div><div class="intel-card-value">${enrichment.isp || 'Unknown'}</div></div>
                <div class="intel-card"><div class="intel-card-label">Abuse Score</div><div class="intel-card-value" style="color:${scoreColor};font-size:1.5rem;">${enrichment.abuse_score}/100</div><div class="abuse-score-bar"><div class="abuse-score-fill" style="width:${enrichment.abuse_score}%;background:${scoreColor};"></div></div></div>
                <div class="intel-card"><div class="intel-card-label">Usage Type</div><div class="intel-card-value">${enrichment.usage_type || 'Unknown'}</div></div>
                <div class="intel-card"><div class="intel-card-label">Source</div><div class="intel-card-value">${enrichment.source || 'N/A'}</div></div>
                <div class="intel-card"><div class="intel-card-label">IP Address</div><div class="intel-card-value" style="font-family:monospace;">${enrichment.ip}</div></div>
            </div>`;
    } else {
        intel.innerHTML = '<p style="color:var(--text-muted);">No threat intelligence data available.</p>';
    }

    // Reports
    document.getElementById('report-content').innerText = firstAlert.attacker_report || 'No report available.';
    const emailResp = related_responses.find(r => r.action_type === 'SEND_EMAIL' || r.action_type === 'DRAFT_EMAIL');
    document.getElementById('email-preview').innerText = emailResp ? emailResp.details : 'No deterrence email found.';

    // Verdict
    document.querySelectorAll('.verdict-btn').forEach(b => b.classList.remove('selected'));
    if (incident.verdict && incident.verdict !== 'PENDING') {
        const btn = document.querySelector(`.verdict-btn[data-verdict="${incident.verdict}"]`);
        if (btn) btn.classList.add('selected');
    }
}

// ══════════════════════════════════════════════════════════════
//  AI CHAT
// ══════════════════════════════════════════════════════════════

function initChat() {
    const toggle = document.getElementById('chat-toggle');
    const panel = document.getElementById('chat-panel');
    const input = document.getElementById('chat-input');
    const sendBtn = document.getElementById('chat-send');

    toggle.addEventListener('click', () => panel.classList.toggle('minimized'));

    const sendMessage = async () => {
        const query = input.value.trim();
        if (!query) return;
        addChatMessage('user', query);
        input.value = '';

        try {
            const res = await fetch(`${API_BASE}/chat`, {
                method: 'POST',
                headers: authHeaders(),
                body: JSON.stringify({ query })
            });
            const data = await res.json();
            let answer = data.answer;
            if (data.sql_generated) {
                answer += `\n\n📊 SQL: ${data.sql_generated}`;
            }
            addChatMessage('ai', answer);
        } catch (err) {
            addChatMessage('ai', 'Sorry, I encountered an error. Please try again.');
        }
    };

    sendBtn.addEventListener('click', sendMessage);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendMessage(); });
}

function addChatMessage(role, text) {
    const messages = document.getElementById('chat-messages');
    const div = document.createElement('div');
    div.className = `chat-msg chat-${role}`;
    div.innerText = text;
    messages.appendChild(div);
    messages.scrollTop = messages.scrollHeight;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.innerText = text;
    return div.innerHTML;
}

// Fallback polling
setInterval(fetchAllData, 5000);
