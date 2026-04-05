import socket
import time
import argparse

def simulate_port_scan(target_ip, start_port=1, end_port=100, delay=0.01):
    print(f"[*] Simulating Rapid Port Scan against {target_ip}...")
    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((target_ip, port))
            s.close()
        except:
            pass
        time.sleep(delay)
    print("[+] Port scan simulation complete.")

def simulate_dos(target_ip, target_port=80, packet_count=200, delay=0.001):
    print(f"[*] Simulating High Volume Traffic (DoS) against {target_ip}:{target_port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"X" * 1024  # 1KB payload
        for _ in range(packet_count):
            s.sendto(payload, (target_ip, target_port))
            time.sleep(delay)
        s.close()
    except Exception as e:
        print(f"[-] Error during DoS: {e}")
    print("[+] DoS simulation complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nexus IDS - Attack Simulation Tool")
    parser.add_argument("target", help="Target IP address (e.g. 127.0.0.1)")
    parser.add_argument("--attack", choices=["scan", "dos", "both"], default="both", help="Type of attack to simulate")
    
    args = parser.parse_args()
    target = args.target
    
    if args.attack in ["scan", "both"]:
        simulate_port_scan(target)
        time.sleep(2)
        
    if args.attack in ["dos", "both"]:
        simulate_dos(target)
        
    print("[*] All simulations launched. Check your Nexus Dashboard.")
