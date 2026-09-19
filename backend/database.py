import sqlite3
from datetime import datetime


DATABASE = "logs/netsentinel.db"


def create_database():
    """
    Create the security_events table if it does not exist.
    """

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            details TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_security_event(alert_type, source_ip, details):
    """
    Save a security event to the database.
    """

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
    Retrieve all security events.
    """

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