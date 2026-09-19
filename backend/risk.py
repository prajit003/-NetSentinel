# ========================================
# NetSentinel Risk Engine
# ========================================


def calculate_port_scan_risk(port_count):
    """
    Calculate risk score for a port scan.
    """

    if port_count >= 20:
        score = 95

    elif port_count >= 15:
        score = 85

    elif port_count >= 10:
        score = 70

    elif port_count >= 5:
        score = 50

    else:
        score = 30


    return score


def calculate_syn_flood_risk(syn_count):
    """
    Calculate risk score for SYN flooding.
    """

    if syn_count >= 100:
        score = 100

    elif syn_count >= 50:
        score = 90

    elif syn_count >= 20:
        score = 80

    elif syn_count >= 10:
        score = 65

    else:
        score = 40


    return score


def get_severity(score):
    """
    Convert numerical risk score into severity.
    """

    if score >= 80:

        return "HIGH"

    elif score >= 50:

        return "MEDIUM"

    else:

        return "LOW"


def calculate_risk(alert_type, count):
    """
    Main risk calculation function.
    """

    if alert_type == "PORT_SCAN":

        score = calculate_port_scan_risk(
            count
        )


    elif alert_type == "SYN_FLOOD":

        score = calculate_syn_flood_risk(
            count
        )


    else:

        score = 20


    severity = get_severity(score)


    return {
        "score": score,
        "severity": severity
    }