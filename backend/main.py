from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from pathlib import Path
import sqlite3
import threading

from .traffic import get_traffic_stats, start_capture
from .risk import calculate_risk


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="NetSentinel API",
    description="Network Security Monitoring API",
    version="1.0"
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
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_PATH = BASE_DIR / "logs" / "netsentinel.db"

FRONTEND_DIR = BASE_DIR / "frontend"

INDEX_FILE = FRONTEND_DIR / "index.html"


# ============================================================
# STATIC FRONTEND FILES
# ============================================================

app.mount(
    "/static",
    StaticFiles(directory=FRONTEND_DIR),
    name="static"
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# START NETWORK TRAFFIC CAPTURE
# ============================================================

capture_thread = None


def start_network_capture():

    global capture_thread

    # Prevent starting multiple capture threads
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
# APPLICATION STARTUP
# ============================================================

@app.on_event("startup")
def startup_event():

    start_network_capture()


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    if INDEX_FILE.exists():

        return FileResponse(
            INDEX_FILE
        )

    return {
        "message": "NetSentinel API is running"
    }


# ============================================================
# SECURITY EVENTS
# ============================================================

@app.get("/api/events")
def get_events():

    connection = get_connection()

    cursor = connection.cursor()

    rows = []

    try:

        cursor.execute("""
            SELECT
                id,
                timestamp,
                alert_type,
                source_ip,
                details
            FROM security_events
            ORDER BY id DESC
        """)

        rows = cursor.fetchall()

    except sqlite3.OperationalError:

        rows = []

    finally:

        connection.close()


    events = []


    for row in rows:

        event_id = row["id"]

        timestamp = row["timestamp"]

        alert_type = row["alert_type"]

        source_ip = row["source_ip"]

        details = row["details"] or ""


        # ----------------------------------------------------
        # Extract attack count
        # ----------------------------------------------------

        count = 0


        if "PORT_COUNT=" in details:

            try:

                count_text = details.split(
                    "PORT_COUNT=",
                    1
                )[1]

                count = int(
                    count_text.split()[0]
                )

            except (ValueError, IndexError):

                count = 0


        elif "SYN_COUNT=" in details:

            try:

                count_text = details.split(
                    "SYN_COUNT=",
                    1
                )[1]

                count = int(
                    count_text.split()[0]
                )

            except (ValueError, IndexError):

                count = 0


        # ----------------------------------------------------
        # Calculate risk
        # ----------------------------------------------------

        risk = calculate_risk(
            alert_type,
            count
        )


        # ----------------------------------------------------
        # Create event object
        # ----------------------------------------------------

        events.append({

            "id": event_id,

            "timestamp": timestamp,

            "alert_type": alert_type,

            "source_ip": source_ip,

            "details": details,

            "risk_score": risk["score"],

            "severity": risk["severity"]

        })


    return events


# ============================================================
# SECURITY STATISTICS
# ============================================================

@app.get("/api/stats")
def get_stats():

    connection = get_connection()

    cursor = connection.cursor()

    total_events = 0

    port_scans = 0

    syn_floods = 0


    try:

        # ----------------------------------------------------
        # Total security events
        # ----------------------------------------------------

        cursor.execute("""
            SELECT COUNT(*)
            FROM security_events
        """)

        total_events = cursor.fetchone()[0]


        # ----------------------------------------------------
        # Port scan events
        # ----------------------------------------------------

        cursor.execute("""
            SELECT COUNT(*)
            FROM security_events
            WHERE alert_type = 'PORT_SCAN'
        """)

        port_scans = cursor.fetchone()[0]


        # ----------------------------------------------------
        # SYN flood events
        # ----------------------------------------------------

        cursor.execute("""
            SELECT COUNT(*)
            FROM security_events
            WHERE alert_type = 'SYN_FLOOD'
        """)

        syn_floods = cursor.fetchone()[0]


    except sqlite3.OperationalError:

        total_events = 0

        port_scans = 0

        syn_floods = 0


    finally:

        connection.close()


    return {

        "total_events": total_events,

        "port_scans": port_scans,

        "syn_floods": syn_floods

    }


# ============================================================
# LIVE TRAFFIC
# ============================================================

@app.get("/api/traffic")
def get_traffic():

    return get_traffic_stats()


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/api/health")
def health():

    return {

        "status": "online",

        "service": "NetSentinel",

        "database": DATABASE_PATH.exists(),

        "frontend": INDEX_FILE.exists()

    }