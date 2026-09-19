// ============================================================
// NetSentinel Dashboard  v2.0
// ============================================================

const API_BASE = "";

// Pagination state
const PAGE_SIZE = 25;
let currentPage = 0;
let allEvents   = [];


// ============================================================
// PAGE INITIALIZATION
// ============================================================

document.addEventListener("DOMContentLoaded", () => {

    loadDashboard();

    // Refresh dashboard every 5 seconds
    setInterval(loadDashboard, 5000);

});


// ============================================================
// LOAD COMPLETE DASHBOARD
// ============================================================

async function loadDashboard() {

    try {

        await Promise.all([
            loadStats(),
            loadEvents(),
            loadTraffic()
        ]);

        updateSystemStatus(true);

    } catch (error) {

        console.error("Dashboard error:", error);

        updateSystemStatus(false);

    }

}


// ============================================================
// SYSTEM STATUS
// ============================================================

function updateSystemStatus(online) {

    const el = document.getElementById("system-status");

    if (!el) return;

    el.innerHTML = online
        ? '<span class="status-dot online"></span> System Online'
        : '<span class="status-dot offline"></span> System Offline';

}


// ============================================================
// LOAD STATISTICS
// ============================================================

async function loadStats() {

    const response = await fetch(`${API_BASE}/api/stats`);

    if (!response.ok) {
        throw new Error("Failed to load statistics");
    }

    const stats = await response.json();

    setText("total-events", stats.total_events);
    setText("port-scans",   stats.port_scans);
    setText("syn-floods",   stats.syn_floods);
    setText("icmp-floods",  stats.icmp_floods);

}


// ============================================================
// LOAD SECURITY EVENTS  (all, cached for client-side filtering)
// ============================================================

async function loadEvents() {

    setLoading(true);

    try {

        // Fetch without pagination — we paginate client-side
        // so filters can apply over the full dataset
        const response = await fetch(
            `${API_BASE}/api/events?limit=500&offset=0`
        );

        if (!response.ok) {
            throw new Error("Failed to load security events");
        }

        const data   = await response.json();
        allEvents    = data.events || [];
        currentPage  = 0;

        applyFilters();

        const updated = document.getElementById("events-updated");

        if (updated) {
            updated.textContent = "Last updated: " + formatTimestamp(new Date().toISOString());
        }

    } finally {

        setLoading(false);

    }

}


// ============================================================
// APPLY FILTERS + RE-RENDER
// ============================================================

function applyFilters() {

    const typeFilter     = (document.getElementById("filter-type")?.value     || "").toUpperCase();
    const severityFilter = (document.getElementById("filter-severity")?.value || "").toUpperCase();

    let filtered = allEvents;

    if (typeFilter) {
        filtered = filtered.filter(e => e.alert_type === typeFilter);
    }

    if (severityFilter) {
        filtered = filtered.filter(e => e.severity === severityFilter);
    }

    const countEl = document.getElementById("events-count");
    if (countEl) {
        countEl.textContent = `${filtered.length} event${filtered.length !== 1 ? "s" : ""}`;
    }

    renderPage(filtered, currentPage);

}


// ============================================================
// RENDER ONE PAGE OF EVENTS
// ============================================================

function renderPage(events, page) {

    const start    = page * PAGE_SIZE;
    const pageData = events.slice(start, start + PAGE_SIZE);
    const total    = events.length;

    renderEvents(pageData);

    // Update pagination controls
    const prevBtn  = document.getElementById("btn-prev");
    const nextBtn  = document.getElementById("btn-next");
    const pageInfo = document.getElementById("page-info");

    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

    if (prevBtn)  prevBtn.disabled  = (page <= 0);
    if (nextBtn)  nextBtn.disabled  = (start + PAGE_SIZE >= total);
    if (pageInfo) pageInfo.textContent = `Page ${page + 1} of ${totalPages}`;

}


// ============================================================
// PAGINATION CONTROLS
// ============================================================

function prevPage() {

    if (currentPage > 0) {

        currentPage--;
        applyFilters();

        window.scrollTo({
            top:      document.querySelector(".events-panel")?.offsetTop || 0,
            behavior: "smooth"
        });

    }

}


function nextPage() {

    const typeFilter     = (document.getElementById("filter-type")?.value     || "").toUpperCase();
    const severityFilter = (document.getElementById("filter-severity")?.value || "").toUpperCase();

    let filtered = allEvents;
    if (typeFilter)     filtered = filtered.filter(e => e.alert_type === typeFilter);
    if (severityFilter) filtered = filtered.filter(e => e.severity   === severityFilter);

    if ((currentPage + 1) * PAGE_SIZE < filtered.length) {

        currentPage++;
        applyFilters();

    }

}


// ============================================================
// RENDER SECURITY EVENTS TABLE
// ============================================================

function renderEvents(events) {

    const tableBody = document.getElementById("events-body");

    if (!tableBody) return;

    if (!events || events.length === 0) {

        tableBody.innerHTML = `
            <tr>
                <td colspan="7" class="empty-state">
                    No security events detected
                </td>
            </tr>
        `;

        return;

    }

    tableBody.innerHTML = "";

    events.forEach(event => {

        const row          = document.createElement("tr");
        const severity     = event.severity     || "UNKNOWN";
        const score        = event.risk_score    ?? 0;
        const severityClass = getSeverityClass(severity);

        row.innerHTML = `
            <td>${escapeHtml(event.id)}</td>
            <td>${escapeHtml(formatTimestamp(event.timestamp))}</td>
            <td>
                <span class="alert-badge ${getAlertClass(event.alert_type)}">
                    ${escapeHtml(event.alert_type)}
                </span>
            </td>
            <td>${escapeHtml(event.source_ip)}</td>
            <td>
                <span class="risk-score ${severityClass}">
                    ${score}
                </span>
            </td>
            <td>
                <span class="severity-badge ${severityClass}">
                    ${escapeHtml(severity)}
                </span>
            </td>
            <td class="details-cell">${escapeHtml(event.details)}</td>
        `;

        tableBody.appendChild(row);

    });

}


// ============================================================
// LOADING SPINNER
// ============================================================

function setLoading(visible) {

    const spinner = document.getElementById("events-loading");

    if (spinner) {
        spinner.style.display = visible ? "flex" : "none";
    }

}


// ============================================================
// LOAD LIVE TRAFFIC
// ============================================================

async function loadTraffic() {

    const response = await fetch(`${API_BASE}/api/traffic`);

    if (!response.ok) {
        throw new Error("Failed to load traffic");
    }

    const traffic = await response.json();

    setText("total-packets",      formatNumber(traffic.total_packets));
    setText("tcp-packets",        formatNumber(traffic.tcp_packets));
    setText("udp-packets",        formatNumber(traffic.udp_packets));
    setText("icmp-packets",       formatNumber(traffic.icmp_packets  || 0));
    setText("packets-per-second", formatNumber(traffic.packets_per_second || 0));
    setText("total-bytes",        formatBytes(traffic.total_bytes));

    const updatedEl = document.getElementById("traffic-updated");
    if (updatedEl) {
        updatedEl.textContent = "Updated: " + new Date().toLocaleTimeString();
    }

    updateTrafficChart(traffic.history || []);

}


// ============================================================
// TRAFFIC CHART
// ============================================================

let trafficChart = null;


function updateTrafficChart(history) {

    const canvas = document.getElementById("traffic-chart");

    if (!canvas) return;

    if (typeof Chart === "undefined") {
        console.warn("Chart.js is not loaded.");
        return;
    }

    const labels = history.map(item => item.time || "");
    const values = history.map(item => item.packets_per_second || 0);

    if (trafficChart) {

        trafficChart.data.labels           = labels;
        trafficChart.data.datasets[0].data = values;
        trafficChart.update();

        return;

    }

    const ctx = canvas.getContext("2d");

    // Gradient fill
    const gradient = ctx.createLinearGradient(0, 0, 0, 200);
    gradient.addColorStop(0,   "rgba(56, 189, 248, 0.4)");
    gradient.addColorStop(1,   "rgba(56, 189, 248, 0.0)");

    trafficChart = new Chart(canvas, {

        type: "line",

        data: {

            labels: labels,

            datasets: [{

                label:            "Packets per Second",
                data:             values,
                borderColor:      "#38bdf8",
                backgroundColor:  gradient,
                borderWidth:      2,
                tension:          0.4,
                fill:             true,
                pointRadius:      3,
                pointBackgroundColor: "#38bdf8"

            }]

        },

        options: {

            responsive:          true,
            maintainAspectRatio: false,
            animation:           { duration: 300 },

            scales: {

                x: {
                    ticks: { color: "#94a3b8", maxTicksLimit: 10 },
                    grid:  { color: "rgba(255,255,255,0.05)" }
                },

                y: {
                    beginAtZero: true,
                    ticks:       { color: "#94a3b8" },
                    grid:        { color: "rgba(255,255,255,0.05)" }
                }

            },

            plugins: {
                legend: { display: false }
            }

        }

    });

}


// ============================================================
// REFRESH BUTTON
// ============================================================

function refreshEvents() {
    loadDashboard();
}


// ============================================================
// EXPORT CSV
// ============================================================

function exportCSV() {
    window.location.href = `${API_BASE}/api/events/export`;
}


// ============================================================
// CLEAR ALL EVENTS
// ============================================================

async function clearEvents() {

    const confirmed = confirm(
        "Are you sure you want to delete ALL security events? This cannot be undone."
    );

    if (!confirmed) return;

    try {

        const response = await fetch(`${API_BASE}/api/events`, {
            method: "DELETE"
        });

        if (!response.ok) {
            throw new Error("Failed to clear events");
        }

        allEvents   = [];
        currentPage = 0;
        renderEvents([]);
        loadStats();

    } catch (error) {

        console.error("Clear events error:", error);
        alert("Failed to clear events. Please try again.");

    }

}


// ============================================================
// ALERT TYPE CSS CLASS
// ============================================================

function getAlertClass(alertType) {

    if (!alertType) return "";

    switch (alertType.toUpperCase()) {

        case "SYN_FLOOD":  return "alert-danger";
        case "PORT_SCAN":  return "alert-warning";
        case "ICMP_FLOOD": return "alert-icmp";
        default:           return "alert-normal";

    }

}


// ============================================================
// SEVERITY CSS CLASS
// ============================================================

function getSeverityClass(severity) {

    if (!severity) return "severity-unknown";

    switch (severity.toUpperCase()) {

        case "LOW":      return "severity-low";
        case "MEDIUM":   return "severity-medium";
        case "HIGH":     return "severity-high";
        case "CRITICAL": return "severity-critical";
        default:         return "severity-unknown";

    }

}


// ============================================================
// FORMAT TIMESTAMP
// ============================================================

function formatTimestamp(timestamp) {

    if (!timestamp) return "-";

    // Handle ISO strings and "YYYY-MM-DD HH:MM:SS" DB format
    const normalized = timestamp.replace(" ", "T");
    const d = new Date(normalized);

    if (isNaN(d.getTime())) return timestamp;

    return d.toLocaleString(undefined, {
        year:   "numeric",
        month:  "short",
        day:    "2-digit",
        hour:   "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });

}


// ============================================================
// FORMAT BYTES
// ============================================================

function formatBytes(bytes) {

    if (!bytes || bytes <= 0) return "0 B";

    const units    = ["B", "KB", "MB", "GB", "TB"];
    const index    = Math.min(
        Math.floor(Math.log(bytes) / Math.log(1024)),
        units.length - 1
    );
    const value    = bytes / Math.pow(1024, index);

    return `${value.toFixed(1)} ${units[index]}`;

}


// ============================================================
// FORMAT NUMBERS
// ============================================================

function formatNumber(number) {
    return Number(number || 0).toLocaleString();
}


// ============================================================
// SET TEXT SAFELY
// ============================================================

function setText(id, value) {

    const el = document.getElementById(id);

    if (el) {
        el.textContent = value;
    }

}


// ============================================================
// ESCAPE HTML
// ============================================================

function escapeHtml(value) {

    if (value === null || value === undefined) return "";

    return String(value)
        .replace(/&/g,  "&amp;")
        .replace(/</g,  "&lt;")
        .replace(/>/g,  "&gt;")
        .replace(/"/g,  "&quot;")
        .replace(/'/g,  "&#039;");

}