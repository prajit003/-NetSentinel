from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

from .detector import detect_port_scan, detect_syn_flood
from .traffic import record_packet


def process_packet(packet):

    # Make sure packet contains IP information
    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_size = len(packet)

    # Determine protocol
    if TCP in packet:
        protocol = "TCP"

    elif UDP in packet:
        protocol = "UDP"

    else:
        protocol = "OTHER"


    # ========================================
    # Record traffic statistics
    # ========================================

    record_packet(
        protocol,
        packet_size
    )


    # ========================================
    # Display packet information
    # ========================================

    print("----------------------------------------")

    print(
        f"Time        : "
        f"{datetime.now().strftime('%H:%M:%S')}"
    )

    print(
        f"Protocol    : {protocol}"
    )

    print(
        f"Source      : {source_ip}"
    )

    print(
        f"Destination : {destination_ip}"
    )

    print(
        f"Packet Size : {packet_size} bytes"
    )


    # ========================================
    # Port Scan Detection
    # ========================================

    if TCP in packet:

        destination_port = packet[TCP].dport

        detect_port_scan(
            source_ip,
            destination_port
        )


        # ====================================
        # SYN Flood Detection
        # ====================================

        flags = packet[TCP].flags

        # SYN packet without ACK
        if flags == "S":

            detect_syn_flood(
                source_ip
            )


def start_capture():

    print("=================================")
    print("       NetSentinel Started")
    print("=================================")

    print("Monitoring network traffic...")
    print("Press CTRL+C to stop.")
    print()


    try:

        sniff(
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:

        print()
        print("Stopping NetSentinel...")


if __name__ == "__main__":

    start_capture()