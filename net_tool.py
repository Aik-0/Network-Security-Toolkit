import socket
from datetime import datetime
import threading
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# ==================== PART 1: PORT SCANNER ====================
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
    print("\n" + "=" * 50)
    print("--- PORT SCANNER TOOL ---")
    print("=" * 50)
    
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
    print("-" * 50)

    for port in common_ports:
        thread = threading.Thread(target=scan_port, args=(target_ip, port, open_ports))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("-" * 50)
    print(f"Scan completed! Total open ports found: {len(open_ports)}")

# ==================== PART 2: PACKET SNIFFER ====================
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
    print("\n" + "=" * 50)
    print("--- PACKET SNIFFER TOOL ---")
    print("=" * 50)
    
    try:
        count = int(input("Enter number of packets to capture (default: 10): ") or 10)
    except ValueError:
        count = 10

    print("Starting Packet Sniffer... Listening for traffic.")
    print("-" * 50)
    
    sniff(prn=process_packet, count=count, store=False)
    
    print("-" * 50)
    print("Sniffing completed!")

# ==================== MAIN MENU ====================
def main():
    while True:
        print("\n" + "=" * 50)
        print("     NETWORK SECURITY TOOLKIT (NST)     ")
        print("=" * 50)
        print("1. Port Scanner")
        print("2. Packet Sniffer / Traffic Analyzer")
        print("3. Exit")
        print("=" * 50)
        
        choice = input("Select an option (1-3): ")
        
        if choice == '1':
            run_port_scanner()
        elif choice == '2':
            run_packet_sniffer()
        elif choice == '3':
            print("\nExiting toolkit. Stay safe!")
            break
        else:
            print("\n[!] Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
    