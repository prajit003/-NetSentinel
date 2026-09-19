from collections import defaultdict
import time

from .database import create_database
from .database import save_security_event


# Create the database when the detector starts
create_database()


# --------------------------------------------------
# Port Scan Tracking
# --------------------------------------------------

connections = defaultdict(set)

start_time = {}


# --------------------------------------------------
# SYN Flood Tracking
# --------------------------------------------------

syn_count = defaultdict(int)

syn_start_time = {}


def log_security_alert(alert_type, source_ip, details):
    """
    Save a security alert to the database.
    """

    save_security_event(
        alert_type,
        source_ip,
        details
    )


def detect_port_scan(source_ip, destination_port):
    """
    Detect a possible TCP port scan.

    10 or more different destination ports
    within 10 seconds triggers an alert.
    """

    current_time = time.time()

    # Start tracking a new IP
    if source_ip not in start_time:
        start_time[source_ip] = current_time

    # Add destination port
    connections[source_ip].add(destination_port)

    elapsed_time = current_time - start_time[source_ip]

    # 10-second detection window
    if elapsed_time <= 10:

        number_of_ports = len(connections[source_ip])

        if number_of_ports >= 10:

            ports = connections[source_ip].copy()

            print("\n" + "=" * 50)
            print("SECURITY ALERT")
            print("=" * 50)
            print("Possible TCP port scan detected")
            print(f"Source IP       : {source_ip}")
            print(f"Ports contacted : {number_of_ports}")
            print(f"Ports           : {sorted(ports)}")
            print("=" * 50 + "\n")

            # Save to database
            log_security_alert(
                "PORT_SCAN",
                source_ip,
                f"PORT_COUNT={len(ports)} PORTS={sorted(ports)}"
            )

            # Reset
            connections[source_ip].clear()
            start_time[source_ip] = current_time

    else:

        connections[source_ip].clear()
        connections[source_ip].add(destination_port)
        start_time[source_ip] = current_time


def detect_syn_flood(source_ip):
    """
    Detect repeated TCP SYN packets.

    20 or more SYN packets within 5 seconds
    triggers an alert.
    """

    current_time = time.time()

    # Start tracking a new IP
    if source_ip not in syn_start_time:
        syn_start_time[source_ip] = current_time

    # Increase SYN counter
    syn_count[source_ip] += 1

    elapsed_time = current_time - syn_start_time[source_ip]

    # 5-second detection window
    if elapsed_time <= 5:

        if syn_count[source_ip] >= 20:

            count = syn_count[source_ip]

            print("\n" + "=" * 50)
            print("SECURITY ALERT")
            print("=" * 50)
            print("Possible SYN flooding detected")
            print(f"Source IP : {source_ip}")
            print(f"SYN Count : {count}")
            print("Time      : 5 seconds")
            print("=" * 50 + "\n")

            # Save to database
            log_security_alert(
                "SYN_FLOOD",
                source_ip,
                f"SYN_COUNT={count} WINDOW=5_SECONDS"
            )

            # Reset
            syn_count[source_ip] = 0
            syn_start_time[source_ip] = current_time

    else:

        syn_count[source_ip] = 1
        syn_start_time[source_ip] = current_time