import time
from collections import deque
from threading import Lock

from scapy.all import sniff, IP, TCP, UDP, ICMP


# ============================================================
# TRAFFIC DATA
# ============================================================

total_packets = 0
tcp_packets   = 0
udp_packets   = 0
icmp_packets  = 0
total_bytes   = 0

packet_times = deque(maxlen=300)

history = deque(maxlen=60)   # keep 60 one-second data points

lock = Lock()

capture_started = False


# ============================================================
# PACKET RECORDING  (called from packet_capture.py)
# ============================================================

def record_packet(protocol, packet_size):
    """
    Record a single packet into the shared traffic counters.

    Parameters
    ----------
    protocol    : str   One of "TCP", "UDP", "ICMP", "OTHER"
    packet_size : int   Size of the packet in bytes
    """

    global total_packets, tcp_packets, udp_packets, icmp_packets, total_bytes

    current_time = time.time()

    with lock:

        total_packets += 1
        total_bytes   += packet_size
        packet_times.append(current_time)

        if protocol == "TCP":
            tcp_packets  += 1

        elif protocol == "UDP":
            udp_packets  += 1

        elif protocol == "ICMP":
            icmp_packets += 1


# ============================================================
# PACKET PROCESSING  (used when traffic.py runs capture itself)
# ============================================================

def process_packet(packet):
    """Process a packet captured directly by this module."""

    global total_packets, tcp_packets, udp_packets, icmp_packets, total_bytes

    if IP not in packet:
        return

    current_time = time.time()

    with lock:

        total_packets += 1
        total_bytes   += len(packet)
        packet_times.append(current_time)

        if TCP in packet:
            tcp_packets  += 1

        elif UDP in packet:
            udp_packets  += 1

        elif ICMP in packet:
            icmp_packets += 1


# ============================================================
# CALCULATE PACKETS PER SECOND
# ============================================================

def calculate_packets_per_second():
    """Return the number of packets captured in the last second."""

    current_time  = time.time()
    one_second_ago = current_time - 1

    with lock:

        count = sum(
            1
            for timestamp in packet_times
            if timestamp >= one_second_ago
        )

    return count


# ============================================================
# UPDATE HISTORY RING BUFFER
# ============================================================

def update_history():
    """Append a new data point to the packets-per-second history."""

    pps = calculate_packets_per_second()

    point = {
        "time":               time.strftime("%H:%M:%S"),
        "packets_per_second": pps
    }

    with lock:
        history.append(point)


# ============================================================
# GET TRAFFIC STATISTICS
# ============================================================

def get_traffic_stats():
    """Return a snapshot of current traffic statistics."""

    pps = calculate_packets_per_second()

    update_history()

    with lock:

        stats = {
            "total_packets":      total_packets,
            "tcp_packets":        tcp_packets,
            "udp_packets":        udp_packets,
            "icmp_packets":       icmp_packets,
            "total_bytes":        total_bytes,
            "packets_per_second": pps,
            "history":            list(history)
        }

    return stats


# ============================================================
# START PACKET CAPTURE  (standalone mode)
# ============================================================

def start_capture():
    """
    Start sniffing packets using Scapy.
    Intended to run in a background daemon thread.
    """

    global capture_started

    if capture_started:
        return

    capture_started = True

    print("=" * 45)
    print("NetSentinel Traffic Monitor")
    print("=" * 45)
    print("Starting packet capture...")
    print("Press CTRL+C to stop.")
    print()

    sniff(
        filter="ip",          # only IP packets
        prn=process_packet,
        store=False
    )


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    print("Testing traffic module...")

    for i in range(10):

        fake_time = time.time()

        with lock:
            packet_times.append(fake_time)

        time.sleep(0.1)

    print(get_traffic_stats())