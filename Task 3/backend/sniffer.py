import threading
import time
import queue
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, conf

# Disable Scapy promiscuous mode warning
conf.sniff_promisc = False

class NexusSniffer:
    def __init__(self, alert_queue: queue.Queue):
        self.alert_queue = alert_queue
        self.running = False
        self.thread = None
        
        # State tracking for heuristics
        self.ip_packet_counts = defaultdict(int)
        self.ip_ports_accessed = defaultdict(set)
        self.last_reset = time.time()
        
        # Thresholds
        self.DOS_THRESHOLD = 50      # Packets per second
        self.PORT_SCAN_THRESHOLD = 15 # Unique ports per second

    def _reset_state(self):
        """Reset the tracker state every second."""
        now = time.time()
        if now - self.last_reset >= 1.0:
            self.ip_packet_counts.clear()
            self.ip_ports_accessed.clear()
            self.last_reset = now

    def process_packet(self, packet):
        if not self.running:
            return

        self._reset_state()

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "Other"
            dst_port = None
            src_port = None
            size = len(packet)

            if TCP in packet:
                protocol = "TCP"
                dst_port = packet[TCP].dport
                src_port = packet[TCP].sport
            elif UDP in packet:
                protocol = "UDP"
                dst_port = packet[UDP].dport
                src_port = packet[UDP].sport

            # Update State
            self.ip_packet_counts[src_ip] += 1
            if dst_port:
                self.ip_ports_accessed[src_ip].add(dst_port)

            # Heuristic Analysis
            alert = self._analyze_traffic(src_ip, dst_ip, protocol, dst_port, src_port, size)
            
            # Put network event into queue even if not an alert for the radar visualization
            event = {
                "type": "traffic",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "dst_port": dst_port,
                "size": size,
                "timestamp": time.time()
            }
            if alert:
                event["alert"] = alert
                self.alert_queue.put({"type": "alert", "data": alert})
                
            self.alert_queue.put({"type": "traffic", "data": event})


    def _analyze_traffic(self, src_ip, dst_ip, protocol, dst_port, src_port, size):
        # Allow localhost traffic without noisy alerts for typical Dev apps
        if src_ip == "127.0.0.1" and dst_ip == "127.0.0.1":
             pass # Maybe skip some analysis if needed
             
        # Rule 1: High Volume (Potential DoS / Flooding)
        if self.ip_packet_counts[src_ip] > self.DOS_THRESHOLD:
            return {
                "severity": "Critical",
                "message": "High Traffic Volume (Potential DoS)",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "score": 95,
                "timestamp": time.time()
            }

        # Rule 2: Port Scanning
        if len(self.ip_ports_accessed[src_ip]) > self.PORT_SCAN_THRESHOLD:
            return {
                "severity": "High",
                "message": "Rapid Port Scanning Detected",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "score": 85,
                "timestamp": time.time()
            }

        # Rule 3: Anomalous Packet Size
        if size > 15000: # Abnormally large packet (jumbo frame unlikely on internet)
            return {
                "severity": "Medium",
                "message": f"Suspiciously Large Packet ({size} bytes)",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "score": 60,
                "timestamp": time.time()
            }
            
        # Rule 4: Suspicious Port Access
        suspicious_ports = {22, 23, 3389, 445}
        if dst_port in suspicious_ports:
            return {
                "severity": "Low",
                "message": f"Access to Sensitive Port ({dst_port})",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "score": 30,
                "timestamp": time.time()
            }

        return None

    def _sniff_loop(self):
        # We start sniff, setting prn to our processing function
        # store=0 ensures we don't hold packets in memory forever
        sniff(prn=self.process_packet, store=0, stop_filter=lambda x: not self.running)

    def start(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
            self.thread.start()
            print("Sniffer started.")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2.0)
            print("Sniffer stopped.")
