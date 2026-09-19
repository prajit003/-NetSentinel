import csv
import io
import sqlite3
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .database import DATABASE, create_database
from .risk import calculate_risk
from .traffic import get_traffic_stats, start_capture


# ============================================================
# PATHS
# ============================================================

BASE_DIR     = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
INDEX_FILE   = FRONTEND_DIR / "index.html"
LOGS_DIR     = BASE_DIR / "logs"


# ============================================================
# CAPTURE THREAD
# ============================================================

capture_thread = None


def _start_network_capture():
    """Start the packet capture daemon thread (idempotent)."""

    global capture_thread

    if capture_thread is not None and capture_thread.is_alive():
        return

    capture_thread = threading.Thread(
        target=start_capture,
        daemon=True
    )

    capture_thread.start()

    print("==========================================")
    print("NetSentinel Network Monitor")
    print("==========================================")
    print("Network packet capture started.")
    print("Traffic statistics are now being collected.")
    print("==========================================")


# ============================================================
# LIFESPAN  (replaces deprecated @app.on_event)
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup / shutdown lifecycle."""

    # ── Startup ──────────────────────────────────────────
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    create_database()
    _start_network_capture()

    yield

    # ── Shutdown ─────────────────────────────────────────
    print("NetSentinel shutting down.")


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="NetSentinel API",
    description="Network Security Monitoring API",
    version="2.0",
    lifespan=lifespan
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# ============================================================
# STATIC FRONTEND FILES
# ============================================================

app.mount(
    "/static",
    StaticFiles(directory=FRONTEND_DIR),
    name="static"
)


# ============================================================
# DATABASE CONNECTION HELPER
# ============================================================

def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# ============================================================
# HELPER: PARSE COUNT FROM DETAILS STRING
# ============================================================

def _parse_count(details: str, alert_type: str) -> int:
    """Extract the numeric count embedded in the event details string."""

    key_map = {
        "PORT_SCAN":  "PORT_COUNT=",
        "SYN_FLOOD":  "SYN_COUNT=",
        "ICMP_FLOOD": "ICMP_COUNT=",
    }

    key = key_map.get(alert_type)

    if key and key in details:

        try:
            return int(details.split(key, 1)[1].split()[0])
        except (ValueError, IndexError):
            pass

    return 0


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():
    if INDEX_FILE.exists():
        return FileResponse(INDEX_FILE)
    return {"message": "NetSentinel API is running"}


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/api/health")
def health():
    return {
        "status":   "online",
        "service":  "NetSentinel",
        "version":  "2.0",
        "database": Path(DATABASE).exists(),
        "frontend": INDEX_FILE.exists()
    }


# ============================================================
# SECURITY STATISTICS
# ============================================================

@app.get("/api/stats")
def get_stats():

    connection = get_connection()
    cursor     = connection.cursor()

    total_events = 0
    port_scans   = 0
    syn_floods   = 0
    icmp_floods  = 0
    high_severity = 0

    try:

        cursor.execute("SELECT COUNT(*) FROM security_events")
        total_events = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM security_events WHERE alert_type = ?",
            ("PORT_SCAN",)
        )
        port_scans = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM security_events WHERE alert_type = ?",
            ("SYN_FLOOD",)
        )
        syn_floods = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM security_events WHERE alert_type = ?",
            ("ICMP_FLOOD",)
        )
        icmp_floods = cursor.fetchone()[0]

    except sqlite3.OperationalError:
        pass

    finally:
        connection.close()

    return {
        "total_events": total_events,
        "port_scans":   port_scans,
        "syn_floods":   syn_floods,
        "icmp_floods":  icmp_floods,
    }


# ============================================================
# SECURITY EVENTS  (with pagination)
# ============================================================

@app.get("/api/events")
def get_events(
    limit:      int = Query(default=50,  ge=1, le=500),
    offset:     int = Query(default=0,   ge=0),
    alert_type: str = Query(default="",  description="Filter by alert type"),
    severity:   str = Query(default="",  description="Filter by severity")
):
    """
    Return security events with optional filtering and pagination.

    Query parameters
    ----------------
    limit       : Max events to return (default 50, max 500)
    offset      : Pagination offset
    alert_type  : Optional filter: PORT_SCAN | SYN_FLOOD | ICMP_FLOOD
    severity    : Optional filter: LOW | MEDIUM | HIGH | CRITICAL
    """

    connection = get_connection()
    cursor     = connection.cursor()
    rows       = []

    try:

        cursor.execute("""
            SELECT id, timestamp, alert_type, source_ip, details
            FROM security_events
            ORDER BY id DESC
        """)

        rows = cursor.fetchall()

    except sqlite3.OperationalError:
        rows = []

    finally:
        connection.close()

    # Build event objects (with risk + severity)
    events = []

    for row in rows:

        event_id   = row["id"]
        timestamp  = row["timestamp"]
        atype      = row["alert_type"]
        source_ip  = row["source_ip"]
        details    = row["details"] or ""

        count = _parse_count(details, atype)
        risk  = calculate_risk(atype, count)

        events.append({
            "id":         event_id,
            "timestamp":  timestamp,
            "alert_type": atype,
            "source_ip":  source_ip,
            "details":    details,
            "risk_score": risk["score"],
            "severity":   risk["severity"]
        })

    # Apply filters
    if alert_type:
        events = [e for e in events if e["alert_type"] == alert_type.upper()]

    if severity:
        events = [e for e in events if e["severity"] == severity.upper()]

    # Paginate
    total  = len(events)
    events = events[offset: offset + limit]

    return {
        "total":  total,
        "limit":  limit,
        "offset": offset,
        "events": events
    }


# ============================================================
# EXPORT EVENTS AS CSV
# ============================================================

@app.get("/api/events/export")
def export_events():
    """Download all security events as a CSV file."""

    connection = get_connection()
    cursor     = connection.cursor()
    rows       = []

    try:
        cursor.execute("""
            SELECT id, timestamp, alert_type, source_ip, details
            FROM security_events
            ORDER BY id DESC
        """)
        rows = cursor.fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        connection.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["ID", "Timestamp", "Alert Type",
                     "Source IP", "Risk Score", "Severity", "Details"])

    for row in rows:

        details = row["details"] or ""
        count   = _parse_count(details, row["alert_type"])
        risk    = calculate_risk(row["alert_type"], count)

        writer.writerow([
            row["id"],
            row["timestamp"],
            row["alert_type"],
            row["source_ip"],
            risk["score"],
            risk["severity"],
            details
        ])

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=netsentinel_events.csv"
        }
    )


# ============================================================
# CLEAR ALL EVENTS
# ============================================================

@app.delete("/api/events")
def clear_events():
    """Delete all security events from the database."""

    from .database import clear_all_events
    clear_all_events()

    return {"message": "All security events cleared."}


# ============================================================
# LIVE TRAFFIC
# ============================================================

@app.get("/api/traffic")
def get_traffic():
    return get_traffic_stats()