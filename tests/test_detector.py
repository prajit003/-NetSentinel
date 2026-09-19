from backend.detector import detect_port_scan
from backend.detector import detect_syn_flood


print("========================================")
print("   NetSentinel Detection Tests")
print("========================================")


# --------------------------------------------------
# TEST 1: Port Scan
# --------------------------------------------------

print("\n[TEST 1] Port Scan Detection")

source_ip = "192.168.1.100"

ports = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    443,
    445
]

for port in ports:

    print(f"Testing destination port: {port}")

    detect_port_scan(
        source_ip,
        port
    )


# --------------------------------------------------
# TEST 2: SYN Flood Detection
# --------------------------------------------------

print("\n[TEST 2] SYN Flood Detection")

source_ip = "192.168.1.200"

for i in range(20):

    print(f"Testing SYN packet: {i + 1}")

    detect_syn_flood(
        source_ip
    )


print("\n========================================")
print("       Tests Completed")
print("========================================")