# 🛡️ NetSentinel

**Network Security Monitoring System** — Real-time detection of port scans, SYN floods, and ICMP floods with a live dashboard.

Built with **Python 3.10+**, **FastAPI**, **Scapy**, and a vanilla JS/HTML/CSS frontend.

---

## Features

| Feature | Description |
|---|---|
| 🔍 **Port Scan Detection** | Alerts when 10+ distinct ports are contacted within 10 seconds |
| ⚡ **SYN Flood Detection** | Alerts on 20+ SYN packets from one IP within 5 seconds |
| 📡 **ICMP Flood Detection** | Alerts on 30+ ICMP packets from one IP within 5 seconds |
| 📊 **Live Traffic Chart** | Real-time packets-per-second line chart with gradient fill |
| 🎛️ **Filter & Paginate** | Filter events by alert type and severity; 25 events per page |
| ⬇️ **CSV Export** | Download all security events as a CSV file |
| 🗑️ **Clear Events** | One-click clearing of all logged events |
| 🟢 **Health Endpoint** | `/api/health` reports DB and frontend status |
| 📁 **Auto DB Setup** | `logs/` directory and SQLite database are created automatically |

---

## Architecture

```
NetSentinel/
├── backend/
│   ├── main.py           # FastAPI app, routes, lifespan
│   ├── detector.py       # Port scan / SYN flood / ICMP flood detection
│   ├── traffic.py        # Packet counter & history ring buffer
│   ├── packet_capture.py # Scapy sniff loop + detector dispatch
│   ├── database.py       # SQLite helpers (create, save, clear)
│   ├── risk.py           # Risk score + severity calculation
│   └── __init__.py
├── frontend/
│   ├── index.html        # Dashboard UI
│   ├── script.js         # API polling, chart, filters, pagination
│   └── style.css         # Dark-theme stylesheet
├── tests/
│   ├── test_detector.py  # pytest suite (detection + risk engine)
│   └── __init__.py
├── logs/                 # Auto-created; contains netsentinel.db
├── requirements.txt
└── README.md
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

> **Note:** Scapy requires administrator / root privileges to capture raw packets.

### 2. Run the server

```bash
# Windows (run as Administrator)
uvicorn backend.main:app --reload

# Linux / macOS (run as root)
sudo uvicorn backend.main:app --reload
```

The dashboard will be available at **http://localhost:8000**

### 3. Run the tests

```bash
pytest tests/ -v
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/` | Serve the dashboard |
| `GET`  | `/api/health` | Health check |
| `GET`  | `/api/stats` | Event counts by type |
| `GET`  | `/api/events` | Paginated + filtered events |
| `GET`  | `/api/events/export` | Download CSV |
| `DELETE` | `/api/events` | Clear all events |
| `GET`  | `/api/traffic` | Live traffic stats + history |

### `/api/events` Query Parameters

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 50 | Max events (1–500) |
| `offset` | int | 0 | Pagination offset |
| `alert_type` | str | _(all)_ | `PORT_SCAN` \| `SYN_FLOOD` \| `ICMP_FLOOD` |
| `severity` | str | _(all)_ | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |

---

## Detection Thresholds

| Attack | Threshold | Window |
|--------|-----------|--------|
| Port Scan | 10 distinct ports | 10 seconds |
| SYN Flood | 20 SYN packets | 5 seconds |
| ICMP Flood | 30 ICMP packets | 5 seconds |

---

## Risk Scoring

| Score | Severity |
|-------|----------|
| ≥ 95 | 🔴 **CRITICAL** |
| ≥ 80 | 🟠 **HIGH** |
| ≥ 50 | 🟡 **MEDIUM** |
| < 50 | 🟢 **LOW** |

---

## Requirements

- Python 3.10+
- Admin / root privileges (for raw packet capture with Scapy)
- Modern browser for the dashboard
