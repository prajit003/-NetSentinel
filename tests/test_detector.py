"""
NetSentinel — Detection & Risk Engine Tests
============================================
Run with:  pytest tests/ -v
"""

import time
import pytest

from backend.detector import (
    detect_port_scan,
    detect_syn_flood,
    detect_icmp_flood,
    PORT_SCAN_PORT_THRESHOLD,
    PORT_SCAN_TIME_WINDOW,
    SYN_FLOOD_COUNT_THRESHOLD,
    SYN_FLOOD_TIME_WINDOW,
    ICMP_FLOOD_COUNT_THRESHOLD,
    ICMP_FLOOD_TIME_WINDOW,
    _connections,
    _ps_start,
    _syn_count,
    _syn_start,
    _icmp_count,
    _icmp_start,
)

from backend.risk import (
    calculate_risk,
    get_severity,
    calculate_port_scan_risk,
    calculate_syn_flood_risk,
    calculate_icmp_flood_risk,
)


# ============================================================
# FIXTURES
# ============================================================

@pytest.fixture(autouse=True)
def reset_detector_state():
    """Clear shared detector state before every test."""

    _connections.clear()
    _ps_start.clear()
    _syn_count.clear()
    _syn_start.clear()
    _icmp_count.clear()
    _icmp_start.clear()

    yield


# ============================================================
# PORT SCAN DETECTION
# ============================================================

class TestPortScanDetection:

    def test_below_threshold_no_alert(self, capsys):
        """Fewer than PORT_SCAN_PORT_THRESHOLD ports should not fire an alert."""

        ip = "10.0.0.1"

        for port in range(1, PORT_SCAN_PORT_THRESHOLD):
            detect_port_scan(ip, port)

        captured = capsys.readouterr()
        assert "PORT SCAN" not in captured.out

    def test_at_threshold_fires_alert(self, capsys):
        """Exactly PORT_SCAN_PORT_THRESHOLD distinct ports fires an alert."""

        ip = "10.0.0.2"

        for port in range(1, PORT_SCAN_PORT_THRESHOLD + 1):
            detect_port_scan(ip, port)

        captured = capsys.readouterr()
        assert "PORT SCAN" in captured.out

    def test_duplicate_ports_not_counted(self, capsys):
        """Duplicate destination ports must not trigger a false alert."""

        ip = "10.0.0.3"

        # Send 20 packets all to port 80 — only 1 unique port
        for _ in range(20):
            detect_port_scan(ip, 80)

        captured = capsys.readouterr()
        assert "PORT SCAN" not in captured.out

    def test_window_reset_after_expiry(self, capsys):
        """
        Ports contacted after the time window expires should start
        a new window and NOT be combined with old contacts.
        """

        ip = "10.0.0.4"

        # Hit (threshold - 1) ports
        for port in range(1, PORT_SCAN_PORT_THRESHOLD):
            detect_port_scan(ip, port)

        # Manually expire the window
        _ps_start[ip] -= (PORT_SCAN_TIME_WINDOW + 1)

        # Send one more port — window has expired, counter resets
        detect_port_scan(ip, 9999)

        captured = capsys.readouterr()
        assert "PORT SCAN" not in captured.out


# ============================================================
# SYN FLOOD DETECTION
# ============================================================

class TestSynFloodDetection:

    def test_below_threshold_no_alert(self, capsys):
        """Fewer than SYN_FLOOD_COUNT_THRESHOLD SYN packets should not alert."""

        ip = "192.168.1.1"

        for _ in range(SYN_FLOOD_COUNT_THRESHOLD - 1):
            detect_syn_flood(ip)

        captured = capsys.readouterr()
        assert "SYN FLOOD" not in captured.out

    def test_at_threshold_fires_alert(self, capsys):
        """SYN_FLOOD_COUNT_THRESHOLD packets fires an alert."""

        ip = "192.168.1.2"

        for _ in range(SYN_FLOOD_COUNT_THRESHOLD):
            detect_syn_flood(ip)

        captured = capsys.readouterr()
        assert "SYN FLOOD" in captured.out

    def test_counter_resets_after_alert(self, capsys):
        """Counter is reset to zero after an alert fires."""

        ip = "192.168.1.3"

        for _ in range(SYN_FLOOD_COUNT_THRESHOLD):
            detect_syn_flood(ip)

        # After alert the counter should have been zeroed
        assert _syn_count[ip] == 0

    def test_window_reset_after_expiry(self, capsys):
        """Counter resets when the time window expires."""

        ip = "192.168.1.4"

        for _ in range(SYN_FLOOD_COUNT_THRESHOLD - 1):
            detect_syn_flood(ip)

        # Expire the window
        _syn_start[ip] -= (SYN_FLOOD_TIME_WINDOW + 1)

        detect_syn_flood(ip)

        captured = capsys.readouterr()
        assert "SYN FLOOD" not in captured.out
        assert _syn_count[ip] == 1   # fresh counter


# ============================================================
# ICMP FLOOD DETECTION
# ============================================================

class TestIcmpFloodDetection:

    def test_below_threshold_no_alert(self, capsys):
        """Fewer than ICMP_FLOOD_COUNT_THRESHOLD packets should not alert."""

        ip = "172.16.0.1"

        for _ in range(ICMP_FLOOD_COUNT_THRESHOLD - 1):
            detect_icmp_flood(ip)

        captured = capsys.readouterr()
        assert "ICMP FLOOD" not in captured.out

    def test_at_threshold_fires_alert(self, capsys):
        """ICMP_FLOOD_COUNT_THRESHOLD packets fires an alert."""

        ip = "172.16.0.2"

        for _ in range(ICMP_FLOOD_COUNT_THRESHOLD):
            detect_icmp_flood(ip)

        captured = capsys.readouterr()
        assert "ICMP FLOOD" in captured.out

    def test_counter_resets_after_alert(self, capsys):
        """Counter is reset to zero after an ICMP flood alert fires."""

        ip = "172.16.0.3"

        for _ in range(ICMP_FLOOD_COUNT_THRESHOLD):
            detect_icmp_flood(ip)

        assert _icmp_count[ip] == 0


# ============================================================
# RISK ENGINE
# ============================================================

class TestRiskEngine:

    # ── Severity mapping ─────────────────────────────────────

    def test_severity_critical(self):
        assert get_severity(95)  == "CRITICAL"
        assert get_severity(100) == "CRITICAL"

    def test_severity_high(self):
        assert get_severity(80) == "HIGH"
        assert get_severity(94) == "HIGH"

    def test_severity_medium(self):
        assert get_severity(50) == "MEDIUM"
        assert get_severity(79) == "MEDIUM"

    def test_severity_low(self):
        assert get_severity(0)  == "LOW"
        assert get_severity(49) == "LOW"

    # ── Port scan risk ────────────────────────────────────────

    def test_port_scan_risk_high_count(self):
        assert calculate_port_scan_risk(50) >= 95

    def test_port_scan_risk_mid_count(self):
        score = calculate_port_scan_risk(10)
        assert 50 <= score < 90

    def test_port_scan_risk_low_count(self):
        assert calculate_port_scan_risk(3) < 50

    # ── SYN flood risk ────────────────────────────────────────

    def test_syn_flood_risk_high_count(self):
        assert calculate_syn_flood_risk(100) >= 97

    def test_syn_flood_risk_mid_count(self):
        score = calculate_syn_flood_risk(20)
        assert 70 <= score <= 90

    # ── ICMP flood risk ───────────────────────────────────────

    def test_icmp_flood_risk_high_count(self):
        assert calculate_icmp_flood_risk(200) >= 95

    def test_icmp_flood_risk_low_count(self):
        assert calculate_icmp_flood_risk(5) < 70

    # ── calculate_risk integration ───────────────────────────

    def test_calculate_risk_port_scan(self):
        result = calculate_risk("PORT_SCAN", 20)
        assert "score"    in result
        assert "severity" in result
        assert result["score"] > 0

    def test_calculate_risk_syn_flood(self):
        result = calculate_risk("SYN_FLOOD", 50)
        assert result["severity"] in ("HIGH", "CRITICAL")

    def test_calculate_risk_icmp_flood(self):
        result = calculate_risk("ICMP_FLOOD", 30)
        assert result["score"] >= 60

    def test_calculate_risk_unknown_type(self):
        result = calculate_risk("UNKNOWN_ATTACK", 999)
        assert result["score"] == 20
        assert result["severity"] == "LOW"