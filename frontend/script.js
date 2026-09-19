// ═══════════════════════════════════════════════════════════
// NetSentinel Dashboard  v3.0
// ═══════════════════════════════════════════════════════════

const API_BASE  = "";
const PAGE_SIZE = 25;

let allEvents     = [];
let currentPage   = 0;
let lastEventId   = 0;     // track newest event for new-event toasts
let currentSection = "overview";

let trafficChart = null;


// ═══════════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════════

document.addEventListener("DOMContentLoaded", () => {

    initNav();
    loadDashboard();

    // Poll every 5 seconds
    setInterval(loadDashboard, 5000);

});


// ═══════════════════════════════════════════════════════════
// SIDEBAR NAVIGATION
// ═══════════════════════════════════════════════════════════

function initNav() {

    document.querySelectorAll(".nav-item").forEach(item => {

        item.addEventListener("click", e => {

            e.preventDefault();

            const section = item.dataset.section;

            document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
            item.classList.add("active");

            document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));

            const pageMap = {
                overview:  "page-overview",
                traffic:   "page-overview",
                events:    "page-events",
                attackers: "page-attackers",
            };

            const targetPage = document.getElementById(pageMap[section]);
            if (targetPage) targetPage.classList.add("active");

            // Scroll to sub-section
            const anchor = document.getElementById(section);
            if (anchor) {
                setTimeout(() => anchor.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
            }

            currentSection = section;

            document.getElementById("page-title").textContent =
                item.textContent.trim().replace(/^[◈⬡◉⚠]\s*/, "");

        });

    });

}


// ═══════════════════════════════════════════════════════════
// MAIN DASHBOARD LOAD
// ═══════════════════════════════════════════════════════════

async function loadDashboard() {

    spinRefresh(true);

    try {

        await Promise.all([
            loadStats(),
            loadEvents(),
            loadTraffic(),
        ]);

        setConnected(true);

        document.getElementById("last-refresh").textContent =
            "Last refresh: " + new Date().toLocaleTimeString();

    } catch (err) {

        console.error("Dashboard error:", err);
        setConnected(false);

    } finally {

        spinRefresh(false);

    }

}


// ═══════════════════════════════════════════════════════════
// STATS
// ═══════════════════════════════════════════════════════════

async function loadStats() {

    const res  = await fetch(`${API_BASE}/api/stats`);
    const data = await res.json();

    animateCount("total-events", data.total_events || 0);
    animateCount("port-scans",   data.port_scans   || 0);
    animateCount("syn-floods",   data.syn_floods    || 0);
    animateCount("icmp-floods",  data.icmp_floods   || 0);

    updateThreatLevel(data.threat_level || "LOW");

    // Also load top attackers in background
    loadTopIPs();

}


// ═══════════════════════════════════════════════════════════
// ANIMATED COUNTER
// ═══════════════════════════════════════════════════════════

const _prevCounts = {};

function animateCount(id, target) {

    const el  = document.getElementById(id);
    if (!el) return;

    const prev = _prevCounts[id] || 0;

    if (prev === target) {
        el.textContent = target.toLocaleString();
        return;
    }

    const diff     = target - prev;
    const steps    = 20;
    const interval = 40;
    let   step     = 0;

    const timer = setInterval(() => {

        step++;
        const val = Math.round(prev + (diff * step / steps));
        el.textContent = val.toLocaleString();

        if (step >= steps) {
            clearInterval(timer);
            el.textContent = target.toLocaleString();
            _prevCounts[id] = target;
        }

    }, interval);

}


// ═══════════════════════════════════════════════════════════
// THREAT LEVEL
// ═══════════════════════════════════════════════════════════

function updateThreatLevel(level) {

    const pill   = document.getElementById("threat-pill");
    const label  = document.getElementById("threat-label");
    const ring   = document.getElementById("threat-ring");
    const text   = document.getElementById("threat-level-text");

    const cls    = "tl-" + level.toLowerCase();

    // Pill
    pill.className = "threat-pill " + cls;
    label.textContent = "Threat: " + level;

    // Ring
    ring.className = "threat-ring " + cls;

    // Text
    text.textContent = level;
    text.className   = "threat-level-text";

    // Highlight active level item
    document.querySelectorAll(".tl-item").forEach(item => {
        item.classList.toggle("active-level", item.classList.contains(level.toLowerCase()));
    });

}


// ═══════════════════════════════════════════════════════════
// EVENTS
// ═══════════════════════════════════════════════════════════

async function loadEvents() {

    setLoading("events-loading", true);

    try {

        const res  = await fetch(`${API_BASE}/api/events?limit=500&offset=0`);
        const data = await res.json();
        const events = data.events || [];

        // Detect new events and toast them
        if (events.length > 0) {
            const newestId = events[0].id;
            if (lastEventId > 0 && newestId > lastEventId) {
                const newOnes = events.filter(e => e.id > lastEventId);
                newOnes.slice(0, 3).forEach(e => {
                    showToast(e.alert_type, e.source_ip, e.severity);
                });
            }
            lastEventId = newestId;
        }

        allEvents   = events;
        currentPage = 0;

        applyFilters();

        const upd = document.getElementById("events-updated");
        if (upd) upd.textContent = "Last updated: " + new Date().toLocaleTimeString();

    } finally {
        setLoading("events-loading", false);
    }

}


// ═══════════════════════════════════════════════════════════
// FILTERS
// ═══════════════════════════════════════════════════════════

function applyFilters() {

    const typeF = (document.getElementById("filter-type")?.value     || "").toUpperCase();
    const sevF  = (document.getElementById("filter-severity")?.value || "").toUpperCase();

    let filtered = allEvents;
    if (typeF) filtered = filtered.filter(e => e.alert_type === typeF);
    if (sevF)  filtered = filtered.filter(e => e.severity   === sevF);

    const badge = document.getElementById("events-count");
    if (badge) badge.textContent = filtered.length + " event" + (filtered.length !== 1 ? "s" : "");

    renderEventsPage(filtered, currentPage);

}

function renderEventsPage(events, page) {

    const start = page * PAGE_SIZE;
    renderEvents(events.slice(start, start + PAGE_SIZE));

    const total      = events.length;
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

    const prev  = document.getElementById("btn-prev");
    const next  = document.getElementById("btn-next");
    const info  = document.getElementById("page-info");

    if (prev)  prev.disabled  = page <= 0;
    if (next)  next.disabled  = start + PAGE_SIZE >= total;
    if (info)  info.textContent = `Page ${page + 1} of ${totalPages}`;

}

function prevPage() {
    if (currentPage > 0) { currentPage--; applyFilters(); }
}

function nextPage() {
    currentPage++;
    applyFilters();
}

function renderEvents(events) {

    const tbody = document.getElementById("events-body");
    if (!tbody) return;

    if (!events || events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">No security events detected</td></tr>`;
        return;
    }

    tbody.innerHTML = "";

    events.forEach(ev => {

        const row      = document.createElement("tr");
        const severity = ev.severity || "LOW";

        if (severity === "CRITICAL") row.classList.add("row-critical");
        else if (severity === "HIGH") row.classList.add("row-high");

        row.innerHTML = `
            <td>${escHtml(ev.id)}</td>
            <td>${escHtml(fmtTime(ev.timestamp))}</td>
            <td><span class="badge ${alertBadge(ev.alert_type)}">${escHtml(ev.alert_type)}</span></td>
            <td>${escHtml(ev.source_ip)}</td>
            <td><span class="risk-num ${riskClass(severity)}">${ev.risk_score ?? 0}</span></td>
            <td><span class="badge ${sevBadge(severity)}">${escHtml(severity)}</span></td>
            <td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(ev.details)}</td>
        `;

        tbody.appendChild(row);

    });

}


// ═══════════════════════════════════════════════════════════
// TRAFFIC
// ═══════════════════════════════════════════════════════════

async function loadTraffic() {

    const res     = await fetch(`${API_BASE}/api/traffic`);
    const traffic = await res.json();

    setText("total-packets",      fmtNum(traffic.total_packets));
    setText("tcp-packets",        fmtNum(traffic.tcp_packets));
    setText("udp-packets",        fmtNum(traffic.udp_packets));
    setText("icmp-packets",       fmtNum(traffic.icmp_packets  || 0));
    setText("packets-per-second", fmtNum(traffic.packets_per_second || 0));
    setText("total-bytes",        fmtBytes(traffic.total_bytes));

    updateChart(traffic.history || []);

}


// ═══════════════════════════════════════════════════════════
// CHART
// ═══════════════════════════════════════════════════════════

function updateChart(history) {

    const canvas = document.getElementById("traffic-chart");
    if (!canvas || typeof Chart === "undefined") return;

    const labels = history.map(h => h.time || "");
    const values = history.map(h => h.packets_per_second || 0);

    if (trafficChart) {
        trafficChart.data.labels           = labels;
        trafficChart.data.datasets[0].data = values;
        trafficChart.update("active");
        return;
    }

    const ctx = canvas.getContext("2d");

    const gradient = ctx.createLinearGradient(0, 0, 0, 180);
    gradient.addColorStop(0,   "rgba(56, 189, 248, 0.35)");
    gradient.addColorStop(0.6, "rgba(56, 189, 248, 0.08)");
    gradient.addColorStop(1,   "rgba(56, 189, 248, 0)");

    trafficChart = new Chart(canvas, {
        type: "line",
        data: {
            labels,
            datasets: [{
                label:            "Packets/sec",
                data:             values,
                borderColor:      "#38bdf8",
                backgroundColor:  gradient,
                borderWidth:      2,
                tension:          0.45,
                fill:             true,
                pointRadius:      0,
                pointHoverRadius: 5,
                pointHoverBackgroundColor: "#38bdf8",
            }]
        },
        options: {
            responsive:          true,
            maintainAspectRatio: false,
            animation:           { duration: 300 },
            interaction:         { intersect: false, mode: "index" },
            scales: {
                x: {
                    ticks: { color: "#475569", maxTicksLimit: 8, font: { size: 10 } },
                    grid:  { color: "rgba(255,255,255,0.03)" }
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: "#475569", font: { size: 10 } },
                    grid:  { color: "rgba(255,255,255,0.04)" }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "rgba(8, 14, 24, 0.95)",
                    borderColor:     "rgba(56, 189, 248, 0.3)",
                    borderWidth:     1,
                    titleColor:      "#94a3b8",
                    bodyColor:       "#38bdf8",
                    padding:         10,
                }
            }
        }
    });

}


// ═══════════════════════════════════════════════════════════
// TOP ATTACKERS
// ═══════════════════════════════════════════════════════════

async function loadTopIPs() {

    setLoading("attackers-loading", true);

    try {

        const res  = await fetch(`${API_BASE}/api/top-ips`);
        const data = await res.json();

        const tbody = document.getElementById("attackers-body");
        if (!tbody) return;

        if (!data || data.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">No attackers detected yet</td></tr>`;
            return;
        }

        tbody.innerHTML = "";

        data.forEach((ip, i) => {

            const row = document.createElement("tr");

            row.innerHTML = `
                <td><span class="rank-num">${i + 1}</span></td>
                <td style="color: var(--red); font-weight: 700;">${escHtml(ip.source_ip)}</td>
                <td style="color: var(--text); font-weight: 700;">${ip.total}</td>
                <td>${ip.port_scans  || 0}</td>
                <td>${ip.syn_floods  || 0}</td>
                <td>${ip.icmp_floods || 0}</td>
                <td style="color: var(--text-muted)">${escHtml(fmtTime(ip.last_seen))}</td>
            `;

            tbody.appendChild(row);

        });

    } finally {
        setLoading("attackers-loading", false);
    }

}


// ═══════════════════════════════════════════════════════════
// TOAST NOTIFICATIONS
// ═══════════════════════════════════════════════════════════

function showToast(alertType, sourceIp, severity) {

    const container = document.getElementById("toast-container");
    if (!container) return;

    const iconMap = {
        PORT_SCAN:  "🔍",
        SYN_FLOOD:  "⚡",
        ICMP_FLOOD: "📡",
    };

    const classMap = {
        CRITICAL: "toast-danger",
        HIGH:     "toast-danger",
        MEDIUM:   "toast-warning",
        LOW:      "toast-info",
    };

    const icon  = iconMap[alertType]   || "⚠️";
    const cls   = classMap[severity]   || "toast-info";
    const label = alertType.replace(/_/g, " ");

    const toast = document.createElement("div");
    toast.className = `toast ${cls}`;

    toast.innerHTML = `
        <span class="toast-icon">${icon}</span>
        <div class="toast-body">
            <div class="toast-title">🚨 ${label} Detected</div>
            <div class="toast-msg">Source: ${escHtml(sourceIp)} &nbsp;|&nbsp; ${severity}</div>
        </div>
        <button class="toast-close" onclick="this.closest('.toast').remove()">✕</button>
    `;

    container.appendChild(toast);

    // Auto-dismiss after 6 seconds
    setTimeout(() => {
        toast.style.animation = "toast-out 0.3s ease forwards";
        setTimeout(() => toast.remove(), 300);
    }, 6000);

}


// ═══════════════════════════════════════════════════════════
// EXPORT / CLEAR
// ═══════════════════════════════════════════════════════════

function refreshEvents() { loadDashboard(); }

function exportCSV() {
    window.location.href = `${API_BASE}/api/events/export`;
}

async function clearEvents() {

    if (!confirm("Delete ALL security events? This cannot be undone.")) return;

    try {

        const res = await fetch(`${API_BASE}/api/events`, { method: "DELETE" });
        if (!res.ok) throw new Error("Failed");

        allEvents   = [];
        currentPage = 0;
        lastEventId = 0;
        renderEvents([]);
        loadStats();

    } catch {
        alert("Failed to clear events.");
    }

}


// ═══════════════════════════════════════════════════════════
// UI HELPERS
// ═══════════════════════════════════════════════════════════

function setConnected(online) {

    const dot  = document.querySelector(".conn-dot");
    const span = document.querySelector(".connection-status span:last-child");

    if (!dot || !span) return;

    if (online) {
        dot.classList.remove("offline");
        span.textContent = "Connected";
    } else {
        dot.classList.add("offline");
        span.textContent = "Offline";
    }

}

function spinRefresh(on) {

    const btn = document.querySelector(".refresh-btn");
    if (btn) btn.classList.toggle("spinning", on);

}

function setLoading(id, visible) {

    const el = document.getElementById(id);
    if (el) el.style.display = visible ? "flex" : "none";

}

function setText(id, value) {

    const el = document.getElementById(id);
    if (el) el.textContent = value;

}


// ═══════════════════════════════════════════════════════════
// BADGE HELPERS
// ═══════════════════════════════════════════════════════════

function alertBadge(type) {
    if (!type) return "";
    switch (type.toUpperCase()) {
        case "PORT_SCAN":  return "badge-port";
        case "SYN_FLOOD":  return "badge-syn";
        case "ICMP_FLOOD": return "badge-icmp";
        default:           return "";
    }
}

function sevBadge(sev) {
    if (!sev) return "";
    switch (sev.toUpperCase()) {
        case "LOW":      return "sev-low";
        case "MEDIUM":   return "sev-medium";
        case "HIGH":     return "sev-high";
        case "CRITICAL": return "sev-critical";
        default:         return "";
    }
}

function riskClass(sev) {
    if (!sev) return "risk-low";
    return "risk-" + sev.toLowerCase();
}


// ═══════════════════════════════════════════════════════════
// FORMAT HELPERS
// ═══════════════════════════════════════════════════════════

function fmtTime(ts) {

    if (!ts) return "-";

    const d = new Date(ts.replace(" ", "T"));
    if (isNaN(d.getTime())) return ts;

    return d.toLocaleString(undefined, {
        month:  "short",
        day:    "2-digit",
        hour:   "2-digit",
        minute: "2-digit",
        second: "2-digit",
    });

}

function fmtBytes(b) {

    if (!b || b <= 0) return "0 B";

    const u = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), u.length - 1);

    return (b / Math.pow(1024, i)).toFixed(1) + " " + u[i];

}

function fmtNum(n) {
    return Number(n || 0).toLocaleString();
}

function escHtml(v) {

    if (v === null || v === undefined) return "";

    return String(v)
        .replace(/&/g,  "&amp;")
        .replace(/</g,  "&lt;")
        .replace(/>/g,  "&gt;")
        .replace(/"/g,  "&quot;")
        .replace(/'/g,  "&#039;");

}