from collections import defaultdict
import time
import threading

from .database import create_database, save_security_event


# Create the database when the detector module is first loaded
create_database()


# ============================================================
# CONFIGURABLE THRESHOLDS
# ============================================================

PORT_SCAN_PORT_THRESHOLD  = 10   # distinct ports within window
PORT_SCAN_TIME_WINDOW     = 10   # seconds

SYN_FLOOD_COUNT_THRESHOLD = 20   # SYN packets within window
SYN_FLOOD_TIME_WINDOW     = 5    # seconds

ICMP_FLOOD_COUNT_THRESHOLD = 30  # ICMP packets within window
ICMP_FLOOD_TIME_WINDOW     = 5   # seconds


# ============================================================
# THREAD-SAFE SHARED STATE
# ============================================================

_lock = threading.Lock()


# --------------------------------------------------
# Port Scan Tracking
# --------------------------------------------------

_connections  = defaultdict(set)
_ps_start     = {}


# --------------------------------------------------
# SYN Flood Tracking
# --------------------------------------------------

_syn_count = defaultdict(int)
_syn_start = {}


# --------------------------------------------------
# ICMP Flood Tracking
# --------------------------------------------------

_icmp_count = defaultdict(int)
_icmp_start = {}


# ============================================================
# INTERNAL HELPERS
# ============================================================

def _log_alert(alert_type, source_ip, details):
    """Persist a security alert to the database."""
    save_security_event(alert_type, source_ip, details)


# ============================================================
# PORT SCAN DETECTION
# ============================================================

def detect_port_scan(source_ip, destination_port):
    """
    Detect a possible TCP port scan.

    Triggers when a single source IP contacts
    PORT_SCAN_PORT_THRESHOLD or more distinct destination ports
    within PORT_SCAN_TIME_WINDOW seconds.
    """

    current_time = time.time()

    with _lock:

        if source_ip not in _ps_start:
            _ps_start[source_ip] = current_time

        _connections[source_ip].add(destination_port)

        elapsed = current_time - _ps_start[source_ip]

        if elapsed <= PORT_SCAN_TIME_WINDOW:

            num_ports = len(_connections[source_ip])

            if num_ports >= PORT_SCAN_PORT_THRESHOLD:

                ports = sorted(_connections[source_ip])

                print("\n" + "=" * 50)
                print("SECURITY ALERT: PORT SCAN")
                print("=" * 50)
                print(f"Source IP       : {source_ip}")
                print(f"Ports contacted : {num_ports}")
                print(f"Ports           : {ports}")
                print("=" * 50 + "\n")

                _log_alert(
                    "PORT_SCAN",
                    source_ip,
                    f"PORT_COUNT={num_ports} PORTS={ports}"
                )

                # Reset window
                _connections[source_ip].clear()
                _ps_start[source_ip] = current_time

        else:

            # Window expired — start fresh
            _connections[source_ip] = {destination_port}
            _ps_start[source_ip] = current_time


# ============================================================
# SYN FLOOD DETECTION
# ============================================================

def detect_syn_flood(source_ip):
    """
    Detect repeated TCP SYN packets (SYN flood).

    Triggers when SYN_FLOOD_COUNT_THRESHOLD or more SYN packets
    are received from one IP within SYN_FLOOD_TIME_WINDOW seconds.
    """

    current_time = time.time()

    with _lock:

        if source_ip not in _syn_start:
            _syn_start[source_ip] = current_time

        _syn_count[source_ip] += 1

        elapsed = current_time - _syn_start[source_ip]

        if elapsed <= SYN_FLOOD_TIME_WINDOW:

            count = _syn_count[source_ip]

            if count >= SYN_FLOOD_COUNT_THRESHOLD:

                print("\n" + "=" * 50)
                print("SECURITY ALERT: SYN FLOOD")
                print("=" * 50)
                print(f"Source IP : {source_ip}")
                print(f"SYN Count : {count}")
                print(f"Window    : {SYN_FLOOD_TIME_WINDOW} seconds")
                print("=" * 50 + "\n")

                _log_alert(
                    "SYN_FLOOD",
                    source_ip,
                    f"SYN_COUNT={count} WINDOW={SYN_FLOOD_TIME_WINDOW}_SECONDS"
                )

                # Reset window
                _syn_count[source_ip] = 0
                _syn_start[source_ip] = current_time

        else:

            # Window expired — start fresh
            _syn_count[source_ip] = 1
            _syn_start[source_ip] = current_time


# ============================================================
# ICMP FLOOD DETECTION
# ============================================================

def detect_icmp_flood(source_ip):
    """
    Detect an ICMP ping flood.

    Triggers when ICMP_FLOOD_COUNT_THRESHOLD or more ICMP packets
    are received from one IP within ICMP_FLOOD_TIME_WINDOW seconds.
    """

    current_time = time.time()

    with _lock:

        if source_ip not in _icmp_start:
            _icmp_start[source_ip] = current_time

        _icmp_count[source_ip] += 1

        elapsed = current_time - _icmp_start[source_ip]

        if elapsed <= ICMP_FLOOD_TIME_WINDOW:

            count = _icmp_count[source_ip]

            if count >= ICMP_FLOOD_COUNT_THRESHOLD:

                print("\n" + "=" * 50)
                print("SECURITY ALERT: ICMP FLOOD")
                print("=" * 50)
                print(f"Source IP   : {source_ip}")
                print(f"ICMP Count  : {count}")
                print(f"Window      : {ICMP_FLOOD_TIME_WINDOW} seconds")
                print("=" * 50 + "\n")

                _log_alert(
                    "ICMP_FLOOD",
                    source_ip,
                    f"ICMP_COUNT={count} WINDOW={ICMP_FLOOD_TIME_WINDOW}_SECONDS"
                )

                # Reset window
                _icmp_count[source_ip] = 0
                _icmp_start[source_ip] = current_time

        else:

            # Window expired — start fresh
            _icmp_count[source_ip] = 1
            _icmp_start[source_ip] = current_time