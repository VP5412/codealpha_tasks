# Task 3 — Nexus IDS: Real-Time Intrusion Detection System

Nexus IDS is a full-stack, real-time network intrusion detection system. A Python backend sniffs live network traffic, analyzes packets against threat heuristics, and streams alerts to a browser-based dashboard over WebSocket. The dashboard lets operators monitor traffic visually, review threat alerts, and block or unblock IP addresses — automatically or manually.

---

## Features

- **Live packet sniffing** using Scapy, running in a background thread
- **Real-time threat detection** with four heuristic rules:
  - High-volume traffic / DoS flooding
  - Rapid port scanning
  - Suspiciously large packets
  - Access to sensitive ports (SSH, Telnet, RDP, SMB)
- **WebSocket streaming** — alerts and traffic events pushed instantly to the browser
- **Traffic Radar** — animated radar visualization showing active network nodes
- **Threat Alert feed** — color-coded by severity (Critical / High / Medium / Low)
- **Active Defense panel** — manually block or unblock an IP, with command confirmation in the system log
- **Auto-Mitigation toggle** — automatically blocks High/Critical source IPs via OS firewall rules
- **Firewall integration** — uses `iptables` (Linux) or `netsh advfirewall` (Windows) to apply blocks
- **Attack simulation tool** (`test_attack.py`) for safe local testing

---

## Project Structure

```
Task 3/
├── backend/
│   ├── server.py       # FastAPI app, WebSocket endpoint, auto-mitigation logic
│   ├── sniffer.py      # Scapy-based packet sniffer with heuristic threat detection
│   └── mitigation.py   # OS-level IP blocking/unblocking engine
├── frontend/
│   ├── index.html      # Dashboard layout: radar, alerts feed, defense controls
│   ├── app.js          # WebSocket client, radar rendering, alert & log management
│   └── styles.css      # Dark glassmorphism theme for the dashboard
├── requirements.txt    # Python dependencies
└── test_attack.py      # Attack simulation script (port scan + DoS)
```

### Backend Components

| File | Role |
|---|---|
| `server.py` | FastAPI application; starts the sniffer on startup, manages WebSocket connections, routes `block_ip` / `unblock_ip` / `toggle_automitigate` commands, and auto-blocks High/Critical IPs when auto-mitigation is enabled |
| `sniffer.py` | `NexusSniffer` class; uses Scapy's `sniff()` in a daemon thread; evaluates each packet against four threat rules and pushes `traffic` and `alert` events onto a shared queue |
| `mitigation.py` | `MitigationEngine` class; executes OS firewall commands to block or unblock an IP address and maintains the set of currently blocked IPs |

### Frontend Components

| File | Role |
|---|---|
| `index.html` | Three-panel dashboard: Traffic Radar, Threat Alerts feed, Active Defense controls |
| `app.js` | Opens a WebSocket to the backend, renders traffic nodes on the radar canvas, populates the alerts feed, handles block/unblock button actions, and processes mitigation event confirmations |
| `styles.css` | Full dark-theme stylesheet with glassmorphism cards, animated radar sweep, severity color coding, and responsive layout |

---

## Requirements

- Python **3.9+**
- Linux or Windows (firewall integration is OS-specific)
- **Root / Administrator privileges** (required for packet sniffing and firewall rules)
- Python packages (install via `requirements.txt`):

```
fastapi
uvicorn
scapy
websockets
psutil
```

---

## Installation

```bash
cd "Task 3"
pip install -r requirements.txt
```

---

## Running the System

### 1. Start the backend server

```bash
cd backend
sudo python3 server.py
```

The API server starts on `http://localhost:8000`. The sniffer begins capturing immediately.

### 2. Open the dashboard

Open `frontend/index.html` in a modern browser (double-click or drag into browser).

The dashboard connects to `ws://localhost:8000/ws` automatically and begins receiving live events.

---

## Threat Detection Rules

| Rule | Trigger | Severity | Score |
|---|---|---|---|
| High Traffic Volume (DoS) | Source IP sends >50 packets within 1 second | Critical | 95 |
| Rapid Port Scanning | Source IP accesses >15 unique ports within 1 second | High | 85 |
| Anomalous Packet Size | Packet size exceeds 15,000 bytes | Medium | 60 |
| Sensitive Port Access | Destination port is 22, 23, 3389, or 445 | Low | 30 |

---

## Active Defense

**Manual control** — enter any IP address in the Active Defense panel and click:
- **Block Node** — adds a firewall rule to drop all inbound traffic from that IP
- **Unblock Node** — removes the firewall rule

**Auto-Mitigation** — toggle the switch in the header to enable automatic blocking of any IP that triggers a High or Critical alert.

All actions are confirmed in the on-screen System Log.

---

## Testing with the Attack Simulator

`test_attack.py` simulates port scanning and DoS traffic against a local or remote target so you can verify that the IDS detects and alerts correctly:

```bash
# Simulate both a port scan and a DoS against localhost
python3 test_attack.py 127.0.0.1 --attack both

# Simulate only a port scan
python3 test_attack.py 127.0.0.1 --attack scan

# Simulate only a DoS flood
python3 test_attack.py 127.0.0.1 --attack dos
```

> **Note:** Run the simulator on the same machine as the backend (or on a machine on the same network segment). Alerts should appear in the dashboard within seconds.

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Health check — returns `{"status": "Nexus IDS is active"}` |
| `WebSocket` | `/ws` | Bidirectional event stream for traffic data, alerts, and commands |

### WebSocket Message Types

**Incoming (server → client):**

| Type | Description |
|---|---|
| `traffic` | Every captured packet: `src_ip`, `dst_ip`, `protocol`, `dst_port`, `size`, `timestamp`, optional `alert` |
| `alert` | Threat alert with `severity`, `message`, `src_ip`, `dst_ip`, `score`, `timestamp` |
| `mitigation` | Auto-block confirmation: `action`, `ip` |

**Outgoing (client → server):**

| Command | Payload | Description |
|---|---|---|
| `block_ip` | `{"command": "block_ip", "ip": "..."}` | Block an IP via the firewall |
| `unblock_ip` | `{"command": "unblock_ip", "ip": "..."}` | Remove a firewall block |
| `toggle_automitigate` | `{"command": "toggle_automitigate", "state": true\|false}` | Enable or disable auto-mitigation |

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Python / FastAPI | REST + WebSocket backend |
| Uvicorn | ASGI server for FastAPI |
| Scapy | Low-level packet capture and parsing |
| HTML5 / CSS3 | Dashboard layout and dark glassmorphism styling |
| Vanilla JavaScript | WebSocket client, radar canvas rendering, UI interactions |
| iptables / netsh | OS-level firewall rule management |

---

## Screenshots

<img width="1582" height="759" alt="Nexus IDS — traffic radar and alerts feed" src="https://github.com/user-attachments/assets/d74b3d0c-3ab9-4377-b6ce-f4a49a4ee1ee" />

<img width="1574" height="768" alt="Nexus IDS — active defense panel" src="https://github.com/user-attachments/assets/afa4eb98-3113-4631-afbd-2a01c9012def" />

<img width="1574" height="762" alt="Nexus IDS — threat alert details" src="https://github.com/user-attachments/assets/a1706c37-4fe5-4cdf-886f-e421054eb9e3" />
