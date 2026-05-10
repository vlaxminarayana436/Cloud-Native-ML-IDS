import time
import json
import requests
import random # <--- NEW: Import random
# Comment out Scapy imports since we are using simulation for reliable testing
# from scapy.all import sniff, IP, TCP, UDP 

# --- Configuration ---
# Target the FastAPI service name defined in docker-compose
BACKEND_URL = "http://backend-api:8000/api/v1/packets/process" 
INTERFACE = "eth0" 
print(f"Targeting automated malicious traffic at backend: {BACKEND_URL}")

# List of simulated malicious IPs
MALICIOUS_IPS = [
    "10.10.10.10", 
    "172.16.20.5", 
    "192.168.2.99",
    "45.23.100.12"
]

# Helper class to structure simulated data before sending to API
class PacketData:
    def __init__(self, timestamp, src_ip, dst_ip, protocol, length, src_port, dst_port):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.length = length
        self.src_port = src_port
        self.dst_port = dst_port
    
    def dict(self):
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "length": self.length,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
        }

if __name__ == "__main__":
    print("Starting automated malicious traffic generation...")
    
    # --- AUTOMATED MALICIOUS TRAFFIC LOOP ---
    while True:
        # 1. Randomly select an attacker IP
        attacker_ip = random.choice(MALICIOUS_IPS)
        
        # 2. Generate a random fluctuation in length (dictates confidence score)
        # Range 40-55 bytes (all still < 100, guaranteeing ML anomaly detection)
        fluctuation = random.randint(40, 55) 
        
        # Generate the packet that has the ML signature (small length, high entropy)
        malicious_data = PacketData(
            timestamp=time.time(), 
            src_ip=attacker_ip, # Dynamic attacker IP
            dst_ip="192.168.1.50",
            protocol="TCP", 
            length=fluctuation,             
            src_port=random.randint(40000, 65000), # Randomize ports slightly
            dst_port=2323
        )
        
        try:
            # Send the malicious packet to the FastAPI endpoint
            requests.post(BACKEND_URL, json=malicious_data.dict(), timeout=0.5)
        except requests.exceptions.RequestException:
            pass 
        
        # Send a packet every 1 second
        time.sleep(5)