from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

from .detector import detect_port_scan, detect_syn_flood, detect_icmp_flood
from .traffic import record_packet


# ============================================================
# PACKET PROCESSOR
# ============================================================

def process_packet(packet):
    """
    Analyse a single captured packet:
      1. Record it in the traffic statistics counters.
      2. Run security detectors as appropriate.
    """

    if IP not in packet:
        return

    source_ip   = packet[IP].src
    packet_size = len(packet)

    # --------------------------------------------------
    # Determine protocol
    # --------------------------------------------------

    if TCP in packet:
        protocol = "TCP"

    elif UDP in packet:
        protocol = "UDP"

    elif ICMP in packet:
        protocol = "ICMP"

    else:
        protocol = "OTHER"

    # --------------------------------------------------
    # Record traffic statistics
    # --------------------------------------------------

    record_packet(protocol, packet_size)

    # --------------------------------------------------
    # TCP-specific detections
    # --------------------------------------------------

    if TCP in packet:

        destination_port = packet[TCP].dport

        # Port scan detection
        detect_port_scan(source_ip, destination_port)

        # SYN flood detection (SYN without ACK)
        if packet[TCP].flags == "S":
            detect_syn_flood(source_ip)

    # --------------------------------------------------
    # ICMP flood detection
    # --------------------------------------------------

    elif ICMP in packet:
        detect_icmp_flood(source_ip)


# ============================================================
# START CAPTURE
# ============================================================

def start_capture():
    """
    Begin sniffing network traffic.
    Runs in a daemon thread started by main.py.
    """

    print("=================================")
    print("       NetSentinel Started")
    print("=================================")
    print("Monitoring network traffic...")
    print("Press CTRL+C to stop.")
    print()

    try:

        sniff(
            filter="ip",       # skip non-IP frames for efficiency
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:

        print()
        print("Stopping NetSentinel...")


# ============================================================
# STANDALONE ENTRY POINT
# ============================================================

if __name__ == "__main__":
    start_capture()