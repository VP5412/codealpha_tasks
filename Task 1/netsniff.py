#!/usr/bin/env python3
"""
NetSniff Pro v2.0 — AI-Enhanced Network Packet Analyzer
Author: Built for cybersecurity learning & research
"""

import sys, os, time, socket, struct, threading, json, argparse, signal
from collections import defaultdict, deque
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

# ─── ANSI Color Palette ────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[38;5;203m"
    GREEN   = "\033[38;5;71m"
    YELLOW  = "\033[38;5;179m"
    CYAN    = "\033[38;5;81m"
    BLUE    = "\033[38;5;111m"
    PURPLE  = "\033[38;5;183m"
    PINK    = "\033[38;5;211m"
    MUTED   = "\033[38;5;242m"
    WHITE   = "\033[38;5;253m"
    BG_DARK = "\033[48;5;233m"
    BG_BAR  = "\033[48;5;237m"

PROTO_COLORS = {
    "TCP":   C.BLUE,   "UDP":  C.PURPLE, "ICMP": C.YELLOW,
    "DNS":   C.GREEN,  "HTTP": C.PINK,   "TLS":  C.CYAN,
    "ARP":   C.RED,    "OTHER": C.MUTED,
}

# ─── Data Structures ───────────────────────────────────────────────────────────
@dataclass
class Packet:
    id:         int
    timestamp:  float
    src_ip:     str
    dst_ip:     str
    src_port:   Optional[int]
    dst_port:   Optional[int]
    proto:      str
    length:     int
    ttl:        int
    flags:      str
    payload:    bytes
    info:       str
    raw:        bytes

@dataclass
class Stats:
    total:     int = 0
    bytes:     int = 0
    proto_cnt: dict = field(default_factory=lambda: defaultdict(int))
    src_bytes:  dict = field(default_factory=lambda: defaultdict(int))
    dst_bytes:  dict = field(default_factory=lambda: defaultdict(int))
    conversations: dict = field(default_factory=lambda: defaultdict(lambda: {"bytes":0,"count":0}))
    port_scan_track: dict = field(default_factory=lambda: defaultdict(set))
    anomalies:  list = field(default_factory=list)

# ─── Packet Parser ─────────────────────────────────────────────────────────────
class PacketParser:
    TCP_FLAGS = {0x01:"FIN",0x02:"SYN",0x04:"RST",0x08:"PSH",0x10:"ACK",0x20:"URG"}

    def parse(self, raw: bytes, pkt_id: int) -> Optional[Packet]:
        try:
            # Ethernet header: 14 bytes
            if len(raw) < 14: return None
            eth_proto = struct.unpack("!H", raw[12:14])[0]

            # IPv4
            if eth_proto == 0x0800:
                return self._parse_ip(raw, raw[14:], pkt_id)
            # ARP
            elif eth_proto == 0x0806:
                return self._parse_arp(raw, raw[14:], pkt_id)
            return None
        except Exception:
            return None

    def _parse_ip(self, raw, ip_data, pkt_id):
        if len(ip_data) < 20: return None
        ver_ihl = ip_data[0]
        ihl     = (ver_ihl & 0x0F) * 4
        ttl     = ip_data[8]
        proto   = ip_data[9]
        src_ip  = socket.inet_ntoa(ip_data[12:16])
        dst_ip  = socket.inet_ntoa(ip_data[16:20])
        total_len = struct.unpack("!H", ip_data[2:4])[0]
        payload = ip_data[ihl:]

        if proto == 6:   return self._parse_tcp(raw, payload, src_ip, dst_ip, ttl, total_len, pkt_id)
        elif proto == 17: return self._parse_udp(raw, payload, src_ip, dst_ip, ttl, total_len, pkt_id)
        elif proto == 1:  return self._parse_icmp(raw, payload, src_ip, dst_ip, ttl, total_len, pkt_id)
        else:
            return Packet(pkt_id, time.time(), src_ip, dst_ip, None, None,
                         "OTHER", total_len, ttl, "", payload, f"Proto={proto}", raw)

    def _parse_tcp(self, raw, data, src_ip, dst_ip, ttl, length, pkt_id):
        if len(data) < 20: return None
        src_port, dst_port = struct.unpack("!HH", data[0:4])
        seq  = struct.unpack("!I", data[4:8])[0]
        data_off = (data[12] >> 4) * 4
        flag_byte = data[13]
        flags = " ".join(v for k,v in self.TCP_FLAGS.items() if flag_byte & k)
        payload = data[data_off:]

        # Protocol detection by port
        proto = "TCP"
        info = f"{src_port} → {dst_port} [{flags}] Seq={seq}"
        if dst_port == 443 or src_port == 443:
            proto = "TLS"
            info = self._detect_tls(payload, info)
        elif dst_port == 80 or src_port == 80:
            proto = "HTTP"
            info = self._detect_http(payload, info)
        elif dst_port == 22 or src_port == 22:
            proto = "SSH"
            info = f"SSH connection {src_ip}:{src_port}"

        return Packet(pkt_id, time.time(), src_ip, dst_ip, src_port, dst_port,
                     proto, length, ttl, flags, payload, info, raw)

    def _parse_udp(self, raw, data, src_ip, dst_ip, ttl, length, pkt_id):
        if len(data) < 8: return None
        src_port, dst_port, udp_len = struct.unpack("!HHH", data[0:6])
        payload = data[8:]
        proto, info = "UDP", f"{src_port} → {dst_port} Len={udp_len}"
        if dst_port == 53 or src_port == 53:
            proto = "DNS"
            info = self._detect_dns(payload, src_ip, dst_ip)
        elif dst_port == 67 or dst_port == 68:
            proto, info = "DHCP", "DHCP request/offer"
        return Packet(pkt_id, time.time(), src_ip, dst_ip, src_port, dst_port,
                     proto, length, ttl, "", payload, info, raw)

    def _parse_icmp(self, raw, data, src_ip, dst_ip, ttl, length, pkt_id):
        if len(data) < 4: return None
        t, code = data[0], data[1]
        ICMP_TYPES = {0:"Echo Reply",3:"Dest Unreachable",8:"Echo Request",11:"Time Exceeded"}
        info = f"{ICMP_TYPES.get(t, f'Type={t}')} code={code}"
        return Packet(pkt_id, time.time(), src_ip, dst_ip, None, None,
                     "ICMP", length, ttl, "", data[4:], info, raw)

    def _parse_arp(self, raw, data, pkt_id):
        if len(data) < 28: return None
        op = struct.unpack("!H", data[6:8])[0]
        sender_ip = socket.inet_ntoa(data[14:18])
        target_ip = socket.inet_ntoa(data[24:28])
        info = f"{'Request' if op==1 else 'Reply'}: {sender_ip} → {target_ip}"
        return Packet(pkt_id, time.time(), sender_ip, target_ip, None, None,
                     "ARP", len(raw), 0, "", b"", info, raw)

    def _detect_dns(self, data, src, dst):
        try:
            if len(data) < 12: return "DNS query"
            flags = struct.unpack("!H", data[2:4])[0]
            is_response = (flags >> 15) & 1
            qcount = struct.unpack("!H", data[4:6])[0]
            # Simple QNAME extraction
            pos = 12
            name_parts = []
            while pos < len(data) and data[pos] != 0:
                length = data[pos]; pos += 1
                name_parts.append(data[pos:pos+length].decode('ascii', errors='replace'))
                pos += length
            name = ".".join(name_parts) if name_parts else "?"
            rtype_map = {1:"A",2:"NS",5:"CNAME",15:"MX",16:"TXT",28:"AAAA"}
            if pos + 4 < len(data):
                rtype = struct.unpack("!H", data[pos+1:pos+3])[0]
                type_str = rtype_map.get(rtype, f"T={rtype}")
                return f"DNS {'Response' if is_response else 'Query'} {type_str} {name}"
            return f"DNS {'Response' if is_response else 'Query'} {name}"
        except: return "DNS packet"

    def _detect_tls(self, data, fallback):
        if len(data) > 5 and data[0] == 0x16:
            hs = {1:"ClientHello",2:"ServerHello",11:"Certificate",14:"ServerHelloDone",20:"Finished"}
            if len(data) > 9: return f"TLS {hs.get(data[5], 'Handshake')}"
            return "TLS Handshake"
        if len(data) > 0 and data[0] == 0x17: return "TLS Application Data"
        return fallback

    def _detect_http(self, data, fallback):
        try:
            text = data[:200].decode('utf-8', errors='replace')
            first_line = text.split('\r\n')[0]
            if any(first_line.startswith(m) for m in ['GET','POST','PUT','DELETE','HEAD','OPTIONS']):
                return first_line[:80]
            if first_line.startswith('HTTP/'):
                return first_line[:80]
        except: pass
        return fallback

# ─── Anomaly Detector ──────────────────────────────────────────────────────────
class AnomalyDetector:
    def __init__(self):
        self.syn_window   = deque(maxlen=200)  # (timestamp, src_ip, dst_port)
        self.dns_window   = deque(maxlen=100)
        self.icmp_window  = deque(maxlen=100)
        self.port_scan    = defaultdict(set)   # src_ip -> set of dst_ports
        self.dns_queries  = defaultdict(list)  # src_ip -> list of timestamps

    def check(self, pkt: Packet, stats: Stats) -> Optional[str]:
        now = time.time()

        # Port scan detection: many SYN to different ports from same source
        if pkt.proto == "TCP" and "SYN" in pkt.flags and "ACK" not in pkt.flags:
            self.port_scan[pkt.src_ip].add(pkt.dst_port)
            if len(self.port_scan[pkt.src_ip]) > 15:
                alert = f"[ALERT] Port scan: {pkt.src_ip} probed {len(self.port_scan[pkt.src_ip])} ports"
                self.port_scan[pkt.src_ip].clear()
                return alert

        # DNS exfiltration: unusually long subdomain queries
        if pkt.proto == "DNS" and "Query" in pkt.info:
            domain = pkt.info.split()[-1] if pkt.info.split() else ""
            labels = domain.split(".")
            if any(len(l) > 30 for l in labels):
                return f"[WARN] DNS exfil suspect: long label in {domain}"
            self.dns_queries[pkt.src_ip].append(now)
            recent = [t for t in self.dns_queries[pkt.src_ip] if now - t < 5]
            self.dns_queries[pkt.src_ip] = recent
            if len(recent) > 20:
                return f"[WARN] High DNS rate: {pkt.src_ip} sent {len(recent)} queries in 5s"

        # ICMP flood detection
        if pkt.proto == "ICMP" and "Echo Request" in pkt.info:
            self.icmp_window.append((now, pkt.src_ip))
            recent = [x for x in self.icmp_window if now - x[0] < 2]
            if len(recent) > 30:
                return f"[WARN] ICMP flood from {pkt.src_ip} — {len(recent)} pings/2s"

        # Large payload over unusual port
        if pkt.proto == "TCP" and len(pkt.payload) > 8000:
            if pkt.dst_port not in (80, 443, 8080, 8443, 22, 21):
                return f"[INFO] Large payload ({len(pkt.payload)}B) on unusual port {pkt.dst_port}"

        return None

# ─── Hex Dump ──────────────────────────────────────────────────────────────────
def hexdump(data: bytes, max_bytes=128):
    LAYER_COLORS = [C.YELLOW] * 14 + [C.CYAN] * 20 + [C.GREEN] * 94
    lines = []
    data = data[:max_bytes]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        offset = f"{C.MUTED}{i:04x}{C.RESET}  "
        hex_part = ""
        for j, byte in enumerate(chunk):
            color = LAYER_COLORS[i+j] if i+j < len(LAYER_COLORS) else C.WHITE
            hex_part += f"{color}{byte:02x}{C.RESET} "
            if j == 7: hex_part += " "
        hex_part = hex_part.ljust(50 + len(C.YELLOW)*16 + len(C.RESET)*16)
        ascii_part = f"{C.MUTED}│{C.RESET} " + "".join(
            f"{C.GREEN}{chr(b)}{C.RESET}" if 32 <= b < 127 else f"{C.MUTED}.{C.RESET}"
            for b in chunk
        )
        lines.append(f"  {offset}{hex_part} {ascii_part}")
    return "\n".join(lines)

# ─── CLI Display ───────────────────────────────────────────────────────────────
class CLI:
    WIDTH = 100

    def banner(self):
        print(f"""
{C.CYAN}{C.BOLD}
  ███╗   ██╗███████╗████████╗███████╗███╗  ██╗██╗███████╗███████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝████╗ ██║██║██╔════╝██╔════╝
  ██╔██╗ ██║█████╗     ██║   ███████╗██╔██╗██║██║█████╗  █████╗  
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║╚████║██║██╔══╝  ██╔══╝  
  ██║ ╚████║███████╗   ██║   ███████║██║ ╚███║██║██║     ██║     
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚══╝╚═╝╚═╝     ╚═╝    
{C.RESET}  {C.MUTED}NetSniff Pro v2.0  —  AI-Enhanced Packet Analyzer{C.RESET}
  {C.MUTED}github.com/VP5412 | vedpatel.tech{C.RESET}
""")

    def separator(self, char="─", label=""):
        if label:
            pad = (self.WIDTH - len(label) - 2) // 2
            print(f"{C.MUTED}{'─'*pad} {C.CYAN}{label}{C.RESET} {C.MUTED}{'─'*pad}{C.RESET}")
        else:
            print(f"{C.MUTED}{'─'*self.WIDTH}{C.RESET}")

    def format_packet(self, pkt: Packet, idx: int) -> str:
        proto_c = PROTO_COLORS.get(pkt.proto, C.WHITE)
        ts = datetime.fromtimestamp(pkt.timestamp).strftime("%H:%M:%S.%f")[:-3]
        proto_str = f"{proto_c}[{pkt.proto:>5}]{C.RESET}"
        src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else pkt.src_ip
        dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else pkt.dst_ip
        flags_str = f" {C.YELLOW}{pkt.flags}{C.RESET}" if pkt.flags else ""
        info = pkt.info[:55] + "…" if len(pkt.info) > 55 else pkt.info
        return (f"  {C.MUTED}{idx:>5}{C.RESET}  {C.MUTED}{ts}{C.RESET}  "
                f"{proto_str}  {C.WHITE}{src:<22}{C.RESET} {C.MUTED}→{C.RESET} "
                f"{C.WHITE}{dst:<22}{C.RESET}  {C.MUTED}{pkt.length:>5}B{C.RESET}"
                f"{flags_str}  {C.MUTED}{info}{C.RESET}")

    def header_row(self):
        print(f"  {C.MUTED}{'#':>5}  {'Time':>12}  {'Proto':>7}  {'Source':<22}   {'Destination':<22}  {'Len':>6}  {'Info'}{C.RESET}")
        self.separator()

    def anomaly(self, msg: str):
        color = C.RED if "ALERT" in msg else C.YELLOW if "WARN" in msg else C.BLUE
        print(f"\n  {color}{C.BOLD}{msg}{C.RESET}\n")

    def stats_panel(self, stats: Stats):
        self.separator(label="SESSION STATISTICS")
        protos = dict(sorted(stats.proto_cnt.items(), key=lambda x: -x[1]))
        max_cnt = max(protos.values(), default=1)
        BAR_W = 30
        for proto, cnt in protos.items():
            bar_len = int(cnt / max_cnt * BAR_W)
            color = PROTO_COLORS.get(proto, C.WHITE)
            bar = f"{color}{'█'*bar_len}{C.MUTED}{'░'*(BAR_W-bar_len)}{C.RESET}"
            print(f"  {color}{proto:<8}{C.RESET}  {bar}  {C.WHITE}{cnt:>6}{C.RESET}  {C.MUTED}pkts{C.RESET}")
        print()
        top_talkers = sorted(stats.src_bytes.items(), key=lambda x: -x[1])[:5]
        self.separator(label="TOP TALKERS")
        for ip, b in top_talkers:
            mb = b / 1024
            print(f"  {C.WHITE}{ip:<20}{C.RESET}  {C.CYAN}{mb:>8.1f} KB{C.RESET}")
        print()
        self.separator(label="CONVERSATIONS")
        top_convs = sorted(stats.conversations.items(), key=lambda x: -x[1]["bytes"])[:5]
        for conv, data in top_convs:
            a, b_ip = conv.split("<->")
            print(f"  {C.WHITE}{a:<22}{C.MUTED} ↔ {C.RESET}{C.WHITE}{b_ip:<22}{C.RESET}  {C.CYAN}{data['bytes']/1024:>8.1f} KB{C.RESET}  {C.MUTED}{data['count']} pkts{C.RESET}")
        print()

# ─── Main Sniffer ──────────────────────────────────────────────────────────────
class NetSniff:
    def __init__(self, iface, bpf_filter, count, verbose, show_hex, json_out, output_file):
        self.iface      = iface
        self.bpf_filter = bpf_filter
        self.count      = count
        self.verbose    = verbose
        self.show_hex   = show_hex
        self.json_out   = json_out
        self.output_file = output_file
        self.parser     = PacketParser()
        self.detector   = AnomalyDetector()
        self.stats      = Stats()
        self.cli        = CLI()
        self.pkt_id     = 0
        self.running    = True
        self.lock       = threading.Lock()
        self.json_packets = []

    def start(self):
        self.cli.banner()

        if os.geteuid() != 0:
            print(f"{C.RED}  [!] Root required. Run: sudo python3 netsniff.py{C.RESET}\n")
            sys.exit(1)

        iface_str = self.iface or "all interfaces"
        print(f"  {C.GREEN}[+]{C.RESET} Listening on {C.CYAN}{iface_str}{C.RESET}  filter: {C.YELLOW}{self.bpf_filter or 'none'}{C.RESET}  count: {C.WHITE}{self.count or '∞'}{C.RESET}")
        if self.output_file:
            print(f"  {C.GREEN}[+]{C.RESET} Saving to {C.CYAN}{self.output_file}{C.RESET}")
        print(f"  {C.MUTED}Press Ctrl+C to stop and show statistics{C.RESET}\n")

        signal.signal(signal.SIGINT, self._handle_exit)
        self.cli.header_row()

        try:
            # Raw socket — ETH_P_ALL = 0x0003
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            if self.iface:
                sock.bind((self.iface, 0))
        except PermissionError:
            print(f"{C.RED}  [!] Cannot open raw socket — need root{C.RESET}")
            sys.exit(1)
        except OSError as e:
            print(f"{C.RED}  [!] Socket error: {e}{C.RESET}")
            sys.exit(1)

        while self.running:
            try:
                raw, _ = sock.recvfrom(65536)
                self._process(raw)
                if self.count and self.pkt_id >= self.count:
                    break
            except Exception:
                if self.running: continue
                break

        sock.close()
        self._show_final_stats()

    def _process(self, raw: bytes):
        pkt = self.parser.parse(raw, self.pkt_id + 1)
        if not pkt: return
        with self.lock:
            self.pkt_id += 1
            self.stats.total += 1
            self.stats.bytes += pkt.length
            self.stats.proto_cnt[pkt.proto] += 1
            self.stats.src_bytes[pkt.src_ip] += pkt.length
            self.stats.dst_bytes[pkt.dst_ip] += pkt.length
            conv_key = "<->".join(sorted([pkt.src_ip, pkt.dst_ip]))
            self.stats.conversations[conv_key]["bytes"] += pkt.length
            self.stats.conversations[conv_key]["count"] += 1

            # Print packet line
            print(self.cli.format_packet(pkt, self.pkt_id))

            if self.verbose:
                print(f"    {C.MUTED}TTL={pkt.ttl}  Flags=[{pkt.flags}]  Payload={len(pkt.payload)}B{C.RESET}")

            if self.show_hex and pkt.raw:
                print(hexdump(pkt.raw))
                print()

            # Anomaly detection
            alert = self.detector.check(pkt, self.stats)
            if alert:
                self.cli.anomaly(alert)
                self.stats.anomalies.append({"time": pkt.timestamp, "alert": alert})

            # JSON output
            if self.json_out:
                self.json_packets.append({
                    "id": pkt.id, "time": pkt.timestamp, "src": pkt.src_ip,
                    "dst": pkt.dst_ip, "sport": pkt.src_port, "dport": pkt.dst_port,
                    "proto": pkt.proto, "len": pkt.length, "ttl": pkt.ttl,
                    "flags": pkt.flags, "info": pkt.info
                })
                if self.output_file:
                    with open(self.output_file, "w") as f:
                        json.dump({"packets": self.json_packets, "stats": {
                            "total": self.stats.total, "bytes": self.stats.bytes,
                            "protocols": dict(self.stats.proto_cnt)
                        }}, f, indent=2)

    def _handle_exit(self, sig, frame):
        print(f"\n\n  {C.YELLOW}[*] Stopping capture...{C.RESET}")
        self.running = False

    def _show_final_stats(self):
        print()
        self.cli.stats_panel(self.stats)
        if self.stats.anomalies:
            self.cli.separator(label="ANOMALIES DETECTED")
            for a in self.stats.anomalies:
                t = datetime.fromtimestamp(a["time"]).strftime("%H:%M:%S")
                print(f"  {C.MUTED}{t}{C.RESET}  {C.RED}{a['alert']}{C.RESET}")
        print()
        self.cli.separator()
        print(f"  {C.GREEN}Done.{C.RESET}  {self.stats.total} packets  {self.stats.bytes/1024:.1f} KB\n")

# ─── Entry Point ───────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description="NetSniff Pro — AI-Enhanced Network Packet Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  sudo python3 netsniff.py                          # capture all interfaces
  sudo python3 netsniff.py -i wlan0                 # specific interface
  sudo python3 netsniff.py -i eth0 -c 100           # capture 100 packets
  sudo python3 netsniff.py -v --hex                 # verbose + hex dump
  sudo python3 netsniff.py --json -o capture.json   # save as JSON
  sudo python3 netsniff.py -i wlan0 --anomaly-only  # show only anomalies
        """
    )
    p.add_argument("-i", "--iface",        default=None,  help="Network interface (default: all)")
    p.add_argument("-c", "--count",        type=int, default=0, help="Number of packets to capture (0=unlimited)")
    p.add_argument("-f", "--filter",       default="",    help="Simple protocol filter: tcp, udp, dns, etc.")
    p.add_argument("-v", "--verbose",      action="store_true", help="Show TTL, flags, payload size per packet")
    p.add_argument("--hex",                action="store_true", help="Show hex dump of each packet")
    p.add_argument("--json",               action="store_true", help="Output packets as JSON")
    p.add_argument("-o", "--output",       default=None,  help="Save JSON output to file")
    p.add_argument("--anomaly-only",       action="store_true", help="Only print anomaly alerts")
    p.add_argument("--stats-interval",     type=int, default=0, help="Print stats every N seconds")
    args = p.parse_args()

    sniffer = NetSniff(
        iface       = args.iface,
        bpf_filter  = args.filter,
        count       = args.count,
        verbose     = args.verbose,
        show_hex    = args.hex,
        json_out    = args.json,
        output_file = args.output,
    )
    sniffer.start()

if __name__ == "__main__":
    main()
