# ============================================================
# NetSentinel Risk Engine
# ============================================================


# ============================================================
# SEVERITY LEVELS (score → label)
# ============================================================
#
#   CRITICAL  >=  95
#   HIGH      >=  80
#   MEDIUM    >=  50
#   LOW       >=   0
#

def get_severity(score):
    """Convert a numerical risk score into a severity label."""

    if score >= 95:
        return "CRITICAL"

    elif score >= 80:
        return "HIGH"

    elif score >= 50:
        return "MEDIUM"

    else:
        return "LOW"


# ============================================================
# PER-TYPE RISK CALCULATORS
# ============================================================

def calculate_port_scan_risk(port_count):
    """
    Calculate risk score for a port scan event.

    Parameters
    ----------
    port_count : int  Number of distinct ports contacted.
    """

    if port_count >= 50:
        return 98

    elif port_count >= 30:
        return 95

    elif port_count >= 20:
        return 90

    elif port_count >= 15:
        return 85

    elif port_count >= 10:
        return 70

    elif port_count >= 5:
        return 50

    else:
        return 30


def calculate_syn_flood_risk(syn_count):
    """
    Calculate risk score for a SYN flood event.

    Parameters
    ----------
    syn_count : int  Number of SYN packets in the detection window.
    """

    if syn_count >= 200:
        return 100

    elif syn_count >= 100:
        return 97

    elif syn_count >= 50:
        return 90

    elif syn_count >= 20:
        return 80

    elif syn_count >= 10:
        return 65

    else:
        return 40


def calculate_icmp_flood_risk(icmp_count):
    """
    Calculate risk score for an ICMP flood event.

    Parameters
    ----------
    icmp_count : int  Number of ICMP packets in the detection window.
    """

    if icmp_count >= 200:
        return 98

    elif icmp_count >= 100:
        return 90

    elif icmp_count >= 50:
        return 80

    elif icmp_count >= 30:
        return 65

    else:
        return 40


# ============================================================
# MAIN RISK CALCULATION ENTRY POINT
# ============================================================

def calculate_risk(alert_type, count):
    """
    Calculate a risk score and severity for a given alert.

    Parameters
    ----------
    alert_type : str  "PORT_SCAN", "SYN_FLOOD", or "ICMP_FLOOD"
    count      : int  The raw count extracted from the event details
    """

    if alert_type == "PORT_SCAN":
        score = calculate_port_scan_risk(count)

    elif alert_type == "SYN_FLOOD":
        score = calculate_syn_flood_risk(count)

    elif alert_type == "ICMP_FLOOD":
        score = calculate_icmp_flood_risk(count)

    else:
        score = 20

    severity = get_severity(score)

    return {
        "score":    score,
        "severity": severity
    }