import socket
from datetime import datetime
import threading

def scan_port(target_ip, port, open_ports):
    """
    Function to scan a single port.
    """
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

def scan_ports(target_host, ports):
    """
    Function to scan multiple ports concurrently using threads.
    """
    print("=" * 50)
    print(f"Scanning Target: {target_host}")
    print(f"Scan Started At: {str(datetime.now())}")
    print("=" * 50)

    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print("\n[!] Error: Could not resolve target host.")
        return

    open_ports = []
    threads = []

    # Create a thread for each port to scan them simultaneously
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(target_ip, port, open_ports))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    print("-" * 50)
    print(f"Scan completed! Total open ports found: {len(open_ports)}")

if __name__ == "__main__":
    # Expanded list of common ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
    
    target = input("Enter the IP address or host to scan (default: 127.0.0.1): ") or "127.0.0.1"
    
    scan_ports(target, common_ports)