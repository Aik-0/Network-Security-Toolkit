import socket
from datetime import datetime
import threading
import re
from collections import Counter
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# ==================== MODULE 1: PORT SCANNER ====================
def scan_port(target_ip, port, open_ports):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            print(f"[+] Port {port:<5} : OPEN")
            open_ports.append(port)
        s.close()
    except Exception:
        pass

def run_port_scanner():
    print("\n" + "=" * 60)
    print("--- 1. PORT SCANNER MODULE ---")
    print("=" * 60)
    
    target_host = input("Enter the IP address or host to scan (default: 127.0.0.1): ") or "127.0.0.1"
    
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print("\n[!] Error: Could not resolve target host.")
        return

    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
    open_ports = []
    threads = []

    print(f"Scanning Target: {target_ip}...")
    print(f"Scan Started At: {str(datetime.now())}")
    print("-" * 60)

    for port in common_ports:
        thread = threading.Thread(target=scan_port, args=(target_ip, port, open_ports))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("-" * 60)
    print(f"Scan completed! Total open ports found: {len(open_ports)}")

# ==================== MODULE 2: PACKET SNIFFER ====================
def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        proto_name = "OTHER"
        if packet.haslayer(TCP):
            proto_name = "TCP"
        elif packet.haslayer(UDP):
            proto_name = "UDP"

        print(f"[+] Packet: {src_ip}  --->  {dst_ip} | Protocol: {proto_name}")

def run_packet_sniffer():
    print("\n" + "=" * 60)
    print("--- 2. PACKET SNIFFER & TRAFFIC ANALYZER ---")
    print("=" * 60)
    
    try:
        count = int(input("Enter number of packets to capture (default: 10): ") or 10)
    except ValueError:
        count = 10

    print("Starting Packet Sniffer... Listening for traffic.")
    print("-" * 60)
    
    sniff(prn=process_packet, count=count, store=False)
    
    print("-" * 60)
    print("Sniffing completed!")

# ==================== MODULE 3: LOG & THREAT ANALYZER ====================
def run_log_analyzer():
    print("\n" + "=" * 60)
    print("--- 3. LOG & ATTACK ANALYSIS ENGINE ---")
    print("=" * 60)
    
    # Check if sample log exists, if not create it
    sample_log_name = "sample_security.log"
    dummy_logs = [
        "2026-10-21 10:00:01 - INFO - User admin logged in successfully from 192.168.1.10",
        "2026-10-21 10:05:12 - FAILED LOGIN - Invalid password from 203.0.113.50",
        "2026-10-21 10:05:15 - FAILED LOGIN - Invalid password from 203.0.113.50",
        "2026-10-21 10:05:18 - FAILED LOGIN - Unauthorized access from 203.0.113.50",
        "2026-10-21 10:10:22 - WARNING - Connection attempt to port 3389 from 198.51.100.15"
    ]
    
    with open(sample_log_name, 'w') as f:
        f.write("\n".join(dummy_logs))
    
    print(f"[*] Analyzing log file '{sample_log_name}'...\n")

    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    failed_attempts_ips = []
    suspicious_ports = [21, 23, 3389]
    alert_count = 0

    with open(sample_log_name, 'r') as file:
        logs = file.readlines()

    for line_num, line in enumerate(logs, 1):
        if "FAILED" in line.upper() or "UNAUTHORIZED" in line.upper() or "ERROR" in line.upper():
            match = re.search(ip_pattern, line)
            if match:
                ip = match.group()
                failed_attempts_ips.append(ip)
                print(f"[!] ALERT [Line {line_num}]: Suspicious failed activity from IP: {ip}")
                alert_count += 1

        for port in suspicious_ports:
            if f"port {port}" in line.lower() or f":{port}" in line:
                match = re.search(ip_pattern, line)
                if match:
                    print(f"[!] WARNING [Line {line_num}]: Sensitive Port {port} accessed by IP: {match.group()}")
                    alert_count += 1

    print("-" * 60)
    print(f"Analysis completed! Total alerts found: {alert_count}")

    if failed_attempts_ips:
        ip_counts = Counter(failed_attempts_ips)
        print("\n--- Threat Intelligence Summary ---")
        for ip, count in ip_counts.items():
            if count >= 3:
                print(f"[x] CRITICAL: Potential Brute Force Attack detected from IP: {ip} ({count} failed attempts)")

# ==================== MAIN SUITE MENU ====================
def main():
    while True:
        print("\n" + "=" * 60)
        print("          ALL-IN-ONE SECURITY SUITE (AOSS)          ")
        print("=" * 60)
        print("1. Port Scanner (Network Discovery)")
        print("2. Packet Sniffer (Traffic Analysis)")
        print("3. Log & Attack Analysis Engine (Threat Detection)")
        print("4. Exit")
        print("=" * 60)
        
        choice = input("Select an option (1-4): ")
        
        if choice == '1':
            run_port_scanner()
        elif choice == '2':
            run_packet_sniffer()
        elif choice == '3':
            run_log_analyzer()
        elif choice == '4':
            print("\nExiting Security Suite. Stay safe!")
            break
        else:
            print("\n[!] Invalid choice. Please select from 1 to 4.")

if __name__ == "__main__":
    main()