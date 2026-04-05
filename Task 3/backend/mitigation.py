import subprocess
import platform
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MitigationEngine:
    def __init__(self):
        self.blocked_ips = set()
        self.auto_mitigate = False

    def toggle_auto_mitigate(self, state: bool):
        self.auto_mitigate = state
        logger.info(f"Auto-mitigation set to: {state}")
        return {"status": "success", "message": f"Auto-mitigation is now {'ON' if state else 'OFF'}"}

    def block_ip(self, ip_address: str):
        if ip_address in self.blocked_ips:
            return {"status": "warning", "message": f"IP {ip_address} is already blocked."}

        try:
            if platform.system() == "Windows":
                # Create a Windows Firewall rule to block inbound traffic from the IP
                rule_name = f"NexusIDS_Block_{ip_address}"
                command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
                subprocess.run(command, shell=True, check=True, capture_output=True)
                
            elif platform.system() == "Linux":
                # Fallback for Linux (iptables)
                command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
                subprocess.run(command, shell=True, check=True, capture_output=True)
                
            self.blocked_ips.add(ip_address)
            logger.info(f"Successfully blocked IP: {ip_address}")
            return {"status": "success", "message": f"Blocked IP: {ip_address}"}

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip_address}: {e.stderr}")
            return {"status": "error", "message": f"Failed to block IP. Require Admin privileges?"}


    def unblock_ip(self, ip_address: str):
        if ip_address not in self.blocked_ips:
            return {"status": "warning", "message": f"IP {ip_address} is not currently blocked."}

        try:
            if platform.system() == "Windows":
                rule_name = f"NexusIDS_Block_{ip_address}"
                command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                subprocess.run(command, shell=True, check=True, capture_output=True)
                
            elif platform.system() == "Linux":
                command = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
                subprocess.run(command, shell=True, check=True, capture_output=True)
                
            self.blocked_ips.remove(ip_address)
            logger.info(f"Successfully unblocked IP: {ip_address}")
            return {"status": "success", "message": f"Unblocked IP: {ip_address}"}

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock IP {ip_address}: {e.stderr}")
            return {"status": "error", "message": f"Failed to unblock IP."}
