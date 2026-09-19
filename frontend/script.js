// ============================================================
// NetSentinel Dashboard
// ============================================================

const API_BASE = "";


// ============================================================
// PAGE INITIALIZATION
// ============================================================

document.addEventListener("DOMContentLoaded", () => {

    loadDashboard();

    // Refresh dashboard every 3 seconds
    setInterval(loadDashboard, 3000);

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

    const statusElement =
        document.getElementById("system-status");

    if (!statusElement) {
        return;
    }

    if (online) {

        statusElement.innerHTML =
            '<span class="status-dot online"></span> System Online';

    } else {

        statusElement.innerHTML =
            '<span class="status-dot offline"></span> System Offline';

    }

}


// ============================================================
// LOAD STATISTICS
// ============================================================

async function loadStats() {

    const response =
        await fetch(`${API_BASE}/api/stats`);

    if (!response.ok) {

        throw new Error(
            "Failed to load statistics"
        );

    }

    const stats =
        await response.json();


    // Total events

    setText(
        "total-events",
        stats.total_events
    );


    // Port scans

    setText(
        "port-scans",
        stats.port_scans
    );


    // SYN floods

    setText(
        "syn-floods",
        stats.syn_floods
    );

}


// ============================================================
// LOAD SECURITY EVENTS
// ============================================================

async function loadEvents() {

    const response =
        await fetch(`${API_BASE}/api/events`);

    if (!response.ok) {

        throw new Error(
            "Failed to load security events"
        );

    }

    const events =
        await response.json();

    renderEvents(events);

}


// ============================================================
// RENDER SECURITY EVENTS
// ============================================================

function renderEvents(events) {

    const tableBody =
        document.getElementById("events-body");

    if (!tableBody) {
        return;
    }


    // No events

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

        const row =
            document.createElement("tr");


        const severity =
            event.severity || "UNKNOWN";


        const score =
            event.risk_score ?? 0;


        const severityClass =
            getSeverityClass(severity);


        row.innerHTML = `

            <td>
                ${escapeHtml(event.id)}
            </td>

            <td>
                ${escapeHtml(
                    formatTimestamp(event.timestamp)
                )}
            </td>

            <td>
                <span class="alert-badge ${getAlertClass(event.alert_type)}">
                    ${escapeHtml(event.alert_type)}
                </span>
            </td>

            <td>
                ${escapeHtml(event.source_ip)}
            </td>

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

            <td>
                ${escapeHtml(event.details)}
            </td>

        `;


        tableBody.appendChild(row);

    });

}


// ============================================================
// LOAD LIVE TRAFFIC
// ============================================================

async function loadTraffic() {

    const response =
        await fetch(`${API_BASE}/api/traffic`);

    if (!response.ok) {

        throw new Error(
            "Failed to load traffic"
        );

    }

    const traffic =
        await response.json();


    setText(
        "total-packets",
        formatNumber(traffic.total_packets)
    );


    setText(
        "tcp-packets",
        formatNumber(traffic.tcp_packets)
    );


    setText(
        "udp-packets",
        formatNumber(traffic.udp_packets)
    );


    setText(
        "packets-per-second",
        formatNumber(traffic.packets_per_second || 0)
    );


    setText(
        "total-bytes",
        formatBytes(traffic.total_bytes)
    );


    updateTrafficChart(
        traffic.history || []
    );

}


// ============================================================
// TRAFFIC CHART
// ============================================================

let trafficChart = null;


function updateTrafficChart(history) {

    const canvas =
        document.getElementById("traffic-chart");

    if (!canvas) {
        return;
    }


    // Chart.js must be loaded
    if (typeof Chart === "undefined") {

        console.warn(
            "Chart.js is not loaded."
        );

        return;

    }


    const labels =
        history.map(item =>
            item.time || ""
        );


    const values =
        history.map(item =>
            item.packets_per_second || 0
        );


    if (trafficChart) {

        trafficChart.data.labels =
            labels;

        trafficChart.data.datasets[0].data =
            values;

        trafficChart.update();

        return;

    }


    trafficChart =
        new Chart(canvas, {

            type: "line",

            data: {

                labels: labels,

                datasets: [{

                    label: "Packets per Second",

                    data: values,

                    borderWidth: 2,

                    tension: 0.3,

                    fill: false,

                    pointRadius: 3

                }]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                scales: {

                    y: {

                        beginAtZero: true

                    }

                },

                plugins: {

                    legend: {

                        display: false

                    }

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
// ALERT TYPE CSS CLASS
// ============================================================

function getAlertClass(alertType) {

    if (!alertType) {
        return "";
    }


    const type =
        alertType.toUpperCase();


    if (type === "SYN_FLOOD") {

        return "alert-danger";

    }


    if (type === "PORT_SCAN") {

        return "alert-warning";

    }


    return "alert-normal";

}


// ============================================================
// SEVERITY CSS CLASS
// ============================================================

function getSeverityClass(severity) {

    if (!severity) {
        return "severity-unknown";
    }


    switch (
        severity.toUpperCase()
    ) {

        case "LOW":
            return "severity-low";

        case "MEDIUM":
            return "severity-medium";

        case "HIGH":
            return "severity-high";

        case "CRITICAL":
            return "severity-critical";

        default:
            return "severity-unknown";

    }

}


// ============================================================
// FORMAT TIMESTAMP
// ============================================================

function formatTimestamp(timestamp) {

    if (!timestamp) {
        return "-";
    }

    return timestamp;

}


// ============================================================
// FORMAT BYTES
// ============================================================

function formatBytes(bytes) {

    if (!bytes || bytes <= 0) {

        return "0 B";

    }


    const units = [
        "B",
        "KB",
        "MB",
        "GB"
    ];


    const index =
        Math.floor(
            Math.log(bytes) /
            Math.log(1024)
        );


    const safeIndex =
        Math.min(
            index,
            units.length - 1
        );


    const value =
        bytes /
        Math.pow(
            1024,
            safeIndex
        );


    return `${value.toFixed(1)} ${units[safeIndex]}`;

}


// ============================================================
// FORMAT NUMBERS
// ============================================================

function formatNumber(number) {

    return Number(number || 0)
        .toLocaleString();

}


// ============================================================
// SET TEXT SAFELY
// ============================================================

function setText(id, value) {

    const element =
        document.getElementById(id);

    if (element) {

        element.textContent =
            value;

    }

}


// ============================================================
// ESCAPE HTML
// ============================================================

function escapeHtml(value) {

    if (value === null ||
        value === undefined) {

        return "";

    }


    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}