import sqlite3
from datetime import datetime
from pathlib import Path


# ============================================================
# DATABASE PATH (always relative to this file, not CWD)
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

LOGS_DIR = BASE_DIR / "logs"

DATABASE = str(LOGS_DIR / "netsentinel.db")


def _ensure_logs_dir():
    """Create the logs directory if it does not exist."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def create_database():
    """
    Create the security_events table and indexes if they do not exist.
    Also ensures the logs/ directory exists.
    """

    _ensure_logs_dir()

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            alert_type  TEXT    NOT NULL,
            source_ip   TEXT    NOT NULL,
            details     TEXT
        )
    """)

    # Index for fast per-type COUNT queries used by /api/stats
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_type
        ON security_events (alert_type)
    """)

    connection.commit()
    connection.close()


def save_security_event(alert_type, source_ip, details):
    """
    Save a security event to the database.
    """

    _ensure_logs_dir()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO security_events
        (timestamp, alert_type, source_ip, details)
        VALUES (?, ?, ?, ?)
    """, (
        timestamp,
        alert_type,
        source_ip,
        details
    ))

    connection.commit()
    connection.close()


def get_security_events():
    """
    Retrieve all security events ordered newest first.
    """

    _ensure_logs_dir()

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, timestamp, alert_type, source_ip, details
        FROM security_events
        ORDER BY id DESC
    """)

    events = cursor.fetchall()

    connection.close()

    return events


def clear_all_events():
    """
    Delete all security events from the database.
    """

    _ensure_logs_dir()

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("DELETE FROM security_events")

    connection.commit()
    connection.close()