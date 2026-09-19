import time
from collections import deque
from threading import Lock

from scapy.all import sniff, IP, TCP, UDP


# ============================================================
# TRAFFIC DATA
# ============================================================

total_packets = 0
tcp_packets = 0
udp_packets = 0
total_bytes = 0

packet_times = deque(maxlen=300)

history = deque(maxlen=30)

lock = Lock()

capture_started = False


# ============================================================
# PACKET PROCESSING
# ============================================================

def process_packet(packet):
    global total_packets
    global tcp_packets
    global udp_packets
    global total_bytes

    if IP not in packet:
        return

    current_time = time.time()

    with lock:

        total_packets += 1

        total_bytes += len(packet)

        packet_times.append(current_time)

        if TCP in packet:
            tcp_packets += 1

        elif UDP in packet:
            udp_packets += 1


# ============================================================
# CALCULATE PACKETS PER SECOND
# ============================================================

def calculate_packets_per_second():

    current_time = time.time()

    one_second_ago = current_time - 1

    with lock:

        count = sum(
            1
            for timestamp in packet_times
            if timestamp >= one_second_ago
        )

    return count


# ============================================================
# CREATE HISTORY POINT
# ============================================================

def update_history():

    current_time = time.time()

    pps = calculate_packets_per_second()

    point = {
        "time": time.strftime("%H:%M:%S"),
        "packets_per_second": pps
    }

    with lock:
        history.append(point)


# ============================================================
# GET TRAFFIC STATISTICS
# ============================================================

def get_traffic_stats():

    global history

    pps = calculate_packets_per_second()

    # Add a new history point
    update_history()

    with lock:

        stats = {
            "total_packets": total_packets,
            "tcp_packets": tcp_packets,
            "udp_packets": udp_packets,
            "total_bytes": total_bytes,
            "packets_per_second": pps,
            "history": list(history)
        }

    return stats


# ============================================================
# START PACKET CAPTURE
# ============================================================

def start_capture():

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
        prn=process_packet,
        store=False
    )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("Testing traffic module...")

    for i in range(10):

        fake_packet_time = time.time()

        with lock:
            packet_times.append(fake_packet_time)

        time.sleep(0.1)

    print(get_traffic_stats())