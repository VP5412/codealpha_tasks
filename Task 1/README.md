# Task 1 — NetSniff Pro v2.0: AI-Enhanced Network Packet Analyzer

NetSniff Pro is a command-line network packet analyzer built in Python. It captures raw network traffic directly from a network interface, decodes multiple protocols, detects anomalies in real time, and presents everything in a colorful, readable terminal UI.

---

## Features

- **Live packet capture** using raw sockets (no third-party capture libraries required)
- **Protocol detection & decoding**: TCP, UDP, ICMP, DNS, HTTP, TLS/SSL, ARP, DHCP, SSH
- **Anomaly detection** engine with alerts for:
  - Port scan activity (SYN floods to many ports)
  - DNS exfiltration (unusually long subdomain labels or high query rate)
  - ICMP flood detection
  - Large payloads on unusual ports
- **Hex dump** view of raw packet bytes, color-coded by protocol layer
- **Verbose mode** — shows TTL, TCP flags, and payload size per packet
- **JSON export** — save captured packets to a structured JSON file
- **Session statistics** — protocol breakdown bar chart, top talkers, top conversations
- A companion **web-based UI** (`netsniff_pro_cli.html`) for visualizing captures in the browser

---

## Project Structure

```
Task 1/
├── netsniff.py          # Main packet analyzer script
└── netsniff_pro_cli.html  # Browser-based UI / visualization companion
```

### Key Components inside `netsniff.py`

| Class / Function | Role |
|---|---|
| `C` | ANSI color constants for terminal output |
| `Packet` (dataclass) | Holds all parsed fields of a captured packet |
| `Stats` (dataclass) | Accumulates per-session counters and conversation tracking |
| `PacketParser` | Parses raw Ethernet frames into `Packet` objects (IPv4, ARP, TCP, UDP, ICMP, DNS, HTTP, TLS) |
| `AnomalyDetector` | Inspects each packet for suspicious patterns and returns alert strings |
| `hexdump()` | Renders raw bytes as a color-coded hex + ASCII dump |
| `CLI` | Handles all terminal output: banner, packet rows, stats panel, anomaly messages |
| `NetSniff` | Orchestrates the raw socket, packet loop, anomaly detection, and JSON output |
| `main()` | Entry point; parses CLI arguments and starts `NetSniff` |

---

## Requirements

- Python **3.8+**
- Linux OS (uses `AF_PACKET` raw sockets — Linux only)
- **Root / sudo privileges** (required to open raw sockets)
- No external Python packages required

---

## Usage

### Basic capture (all interfaces)
```bash
sudo python3 netsniff.py
```

### Capture on a specific interface
```bash
sudo python3 netsniff.py -i eth0
```

### Capture a fixed number of packets
```bash
sudo python3 netsniff.py -i eth0 -c 100
```

### Verbose output with hex dump
```bash
sudo python3 netsniff.py -v --hex
```

### Save output as JSON
```bash
sudo python3 netsniff.py --json -o capture.json
```

### Show only anomaly alerts
```bash
sudo python3 netsniff.py -i wlan0 --anomaly-only
```

### Full argument reference
```
usage: netsniff.py [-h] [-i IFACE] [-c COUNT] [-f FILTER] [-v] [--hex]
                   [--json] [-o OUTPUT] [--anomaly-only] [--stats-interval N]

optional arguments:
  -i, --iface        Network interface to listen on (default: all)
  -c, --count        Stop after N packets (default: unlimited)
  -f, --filter       Simple protocol keyword filter (e.g. tcp, udp, dns)
  -v, --verbose      Show TTL, flags, and payload size for each packet
  --hex              Print a hex dump of each packet's raw bytes
  --json             Serialize captured packets to JSON
  -o, --output       File path to save JSON output
  --anomaly-only     Only print anomaly/alert lines (suppress normal packets)
  --stats-interval   Print session stats every N seconds
```

---

## How It Works

1. A raw `AF_PACKET` socket is opened to receive every Ethernet frame on the chosen interface.
2. Each frame is passed to `PacketParser`, which strips the Ethernet header and dispatches to the appropriate protocol handler.
3. The parsed `Packet` is printed as a formatted row in the terminal by `CLI`.
4. `AnomalyDetector` checks each packet against heuristic rules and prints an alert if a threat is found.
5. Statistics (protocol counts, top talkers, conversations) are accumulated in `Stats`.
6. On `Ctrl+C`, the capture stops and the full session statistics panel is displayed.

---

## Anomaly Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| Port Scan | Single source sends SYN to >15 unique ports | `[ALERT]` |
| DNS Exfiltration | DNS label length >30 chars OR >20 queries in 5 s | `[WARN]` |
| ICMP Flood | >30 Echo Requests in a 2-second window | `[WARN]` |
| Large Payload on Unusual Port | TCP payload >8 KB on non-standard port | `[INFO]` |

---

## Web UI

Open `netsniff_pro_cli.html` in any modern browser to view a stylized, GitHub-dark-themed reference page for the tool's CLI output format and feature documentation.

---

## Screenshots

<img width="1029" height="691" alt="NetSniff Pro — packet capture output" src="https://github.com/user-attachments/assets/7ec8cd60-6fc2-4764-8262-82ded5fe0e86" />

<img width="956" height="348" alt="NetSniff Pro — session statistics panel" src="https://github.com/user-attachments/assets/278172ec-331e-47ec-b46a-4807827ed336" />

<img width="839" height="691" alt="NetSniff Pro — anomaly alert output" src="https://github.com/user-attachments/assets/a4b49df9-a568-4c4e-aeb8-95fd5158f449" />
