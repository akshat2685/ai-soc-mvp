const API_BASE = 'http://127.0.0.1:8000';
const WS_URL = 'ws://127.0.0.1:8000/ws';

let ws = null;
let attackDistChart = null;
let severityChart = null;
let currentIncidentId = null;

// ── Initialize ──
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initModal();
    initWebSocket();
    initChat();
    fetchAllData();
});

// ── Navigation ──
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

// ── WebSocket ──
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

// ── Fetch All Data ──
async function fetchAllData() {
    try {
        const [statsRes, alertsRes, responsesRes, incidentsRes] = await Promise.all([
            fetch(`${API_BASE}/stats`),
            fetch(`${API_BASE}/alerts`),
            fetch(`${API_BASE}/responses`),
            fetch(`${API_BASE}/incidents`)
        ]);
        const stats = await statsRes.json();
        const alerts = await alertsRes.json();
        const responses = await responsesRes.json();
        const incidents = await incidentsRes.json();

        updateStats(stats);
        updateCharts(stats, alerts);
        updateAlertsTable(alerts);
        updateAllAlertsTable(alerts);
        updateAllIncidentsTable(incidents);
        updateResponseTimeline(responses);
    } catch (error) {
        console.error("Fetch error:", error);
    }
}

// ── Stats ──
function updateStats(stats) {
    animateCounter('total-incidents', stats.total_incidents || 0);
    animateCounter('total-alerts', stats.total_alerts || 0);
    animateCounter('total-blocked', stats.total_blocked || 0);
    animateCounter('total-emails', stats.total_emails || 0);
    animateCounter('total-logs', stats.total_logs || 0);
    document.getElementById('nav-alert-count').innerText = stats.total_alerts || 0;
    document.getElementById('nav-incident-count').innerText = stats.total_incidents || 0;
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

// ── Charts ──
function updateCharts(stats, alerts) {
    const dist = stats.attack_distribution || {};
    const chartColors = ['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#10b981'];

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

    const sevCounts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    alerts.forEach(a => { if (sevCounts[a.severity] !== undefined) sevCounts[a.severity]++; });
    const sevCtx = document.getElementById('severity-chart');
    if (severityChart) severityChart.destroy();
    severityChart = new Chart(sevCtx, {
        type: 'bar',
        data: {
            labels: ['HIGH', 'MEDIUM', 'LOW'],
            datasets: [{ label: 'Alerts', data: [sevCounts.HIGH, sevCounts.MEDIUM, sevCounts.LOW], backgroundColor: ['rgba(239,68,68,0.6)', 'rgba(245,158,11,0.6)', 'rgba(45,212,191,0.6)'], borderColor: ['#ef4444', '#f59e0b', '#2dd4bf'], borderWidth: 1, borderRadius: 6 }]
        },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { color: '#64748b', stepSize: 1 }, grid: { color: 'rgba(51,65,85,0.3)' } }, x: { ticks: { color: '#64748b' }, grid: { display: false } } }, plugins: { legend: { display: false } } }
    });
}

// ── Alerts & Incidents Tables ──
function updateAlertsTable(alerts) {
    const tbody = document.querySelector('#alerts-table tbody');
    tbody.innerHTML = '';
    alerts.slice(0, 10).forEach(alert => {
        const tr = document.createElement('tr');
        const time = new Date(alert.timestamp).toLocaleTimeString();
        tr.innerHTML = `
            <td>${time}</td>
            <td><strong>${alert.title}</strong></td>
            <td><span class="attack-type-badge">${alert.attack_type || 'N/A'}</span></td>
            <td style="font-family:monospace;color:var(--primary);">${alert.attacker_ip}</td>
            <td><span class="severity-badge severity-${alert.severity}">${alert.severity}</span></td>
            <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${alert.llm_summary}</td>
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
        tr.innerHTML = `
            <td>${alert.id}</td><td>${time}</td>
            <td><strong>${alert.title}</strong></td>
            <td><span class="attack-type-badge">${alert.attack_type || 'N/A'}</span></td>
            <td style="font-family:monospace;color:var(--primary);">${alert.attacker_ip}</td>
            <td><span class="severity-badge severity-${alert.severity}">${alert.severity}</span></td>
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
            <td>${inc.id}</td>
            <td>${time}</td>
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

// ── Response Timeline ──
function updateResponseTimeline(responses) {
    const timeline = document.getElementById('response-timeline');
    timeline.innerHTML = '';
    responses.forEach(resp => {
        const item = document.createElement('div');
        item.className = `timeline-item action-${resp.action_type}`;
        const time = new Date(resp.timestamp).toLocaleString();
        let detailsHtml = resp.action_type === 'SEND_EMAIL' ? `<div class="email-block">${escapeHtml(resp.details)}</div>` : `<div>${escapeHtml(resp.details)}</div>`;
        item.innerHTML = `
            <div class="timeline-time">${time} - <strong>${resp.action_type}</strong></div>
            <div class="timeline-content">Target: <span style="color:var(--primary);font-family:monospace;">${resp.target}</span>${detailsHtml}</div>
        `;
        timeline.appendChild(item);
    });
}

// ── Investigation Modal ──
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
            fetch(`${API_BASE}/incidents/${currentIncidentId}/verdict?verdict=${btn.dataset.verdict}`, { method: 'POST' }).then(() => fetchAllData());
        });
    });
    document.getElementById('btn-download-pdf').addEventListener('click', () => {
        if (!currentIncidentId) return;
        // Map to first alert ID in that incident if needed, or get report.pdf
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

    document.getElementById('modal-title').innerText = `Incident Investigation: ${incident.title} (Entity: ${incident.correlation_key})`;

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
        { label: 'Total Child Alerts', value: alerts.length },
        { label: 'Logs Analyzed', value: related_logs.length },
    ];
    
    // Aggregate user IDs and IPs
    const userIds = [...new Set(alerts.flatMap(a => JSON.parse(a.evidence || '{}').user_ids || []))];
    const deviceFps = [...new Set(alerts.flatMap(a => JSON.parse(a.evidence || '{}').device_fingerprint || []))].filter(Boolean);
    
    if (userIds.length) nodes.push({ label: 'Targeted Users', value: userIds.join(', ') });
    if (deviceFps.length) nodes.push({ label: 'Device Fingerprints', value: deviceFps.join(', ') });
    nodes.push({ label: 'Mitigations Executed', value: related_responses.length });
    
    nodes.forEach(n => {
        const node = document.createElement('div');
        node.className = 'evidence-node';
        node.innerHTML = `<div class="evidence-node-label">${n.label}</div><div class="evidence-node-value">${n.value || '-'}</div>`;
        graph.appendChild(node);
    });

    // Threat Intel
    const intel = document.getElementById('intel-content');
    intel.innerHTML = '';
    if (enrichment) {
        const scoreColor = enrichment.abuse_score >= 70 ? '#ef4444' : enrichment.abuse_score >= 40 ? '#f59e0b' : '#10b981';
        intel.innerHTML = `
            <div class="intel-grid">
                <div class="intel-card">
                    <div class="intel-card-flag">${enrichment.flag || ''}</div>
                    <div class="intel-card-label">Country</div>
                    <div class="intel-card-value">${enrichment.country || 'Unknown'}</div>
                </div>
                <div class="intel-card">
                    <div class="intel-card-label">ISP</div>
                    <div class="intel-card-value">${enrichment.isp || 'Unknown'}</div>
                </div>
                <div class="intel-card">
                    <div class="intel-card-label">Abuse Confidence Score</div>
                    <div class="intel-card-value" style="color:${scoreColor};font-size:1.5rem;">${enrichment.abuse_score}/100</div>
                    <div class="abuse-score-bar"><div class="abuse-score-fill" style="width:${enrichment.abuse_score}%;background:${scoreColor};"></div></div>
                </div>
                <div class="intel-card">
                    <div class="intel-card-label">Usage Type</div>
                    <div class="intel-card-value">${enrichment.usage_type || 'Unknown'}</div>
                </div>
                <div class="intel-card">
                    <div class="intel-card-label">Source</div>
                    <div class="intel-card-value">${enrichment.source || 'N/A'}</div>
                </div>
                <div class="intel-card">
                    <div class="intel-card-label">IP Address</div>
                    <div class="intel-card-value" style="font-family:monospace;">${enrichment.ip}</div>
                </div>
            </div>`;
    } else {
        intel.innerHTML = '<p style="color:var(--text-muted);">No threat intelligence data available for correlation key.</p>';
    }

    // Reports & Deterrence preview from the first child alert
    const firstAlert = alerts[0] || {};
    document.getElementById('report-content').innerText = firstAlert.attacker_report || 'No report available.';
    const emailResp = related_responses.find(r => r.action_type === 'SEND_EMAIL');
    document.getElementById('email-preview').innerText = emailResp ? emailResp.details : 'No deterrence email found.';

    // Verdict
    document.querySelectorAll('.verdict-btn').forEach(b => b.classList.remove('selected'));
    if (incident.verdict && incident.verdict !== 'PENDING') {
        const btn = document.querySelector(`.verdict-btn[data-verdict="${incident.verdict}"]`);
        if (btn) btn.classList.add('selected');
    }
}

// ── AI Chat ──
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
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query })
            });
            const data = await res.json();
            addChatMessage('ai', data.answer);
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
