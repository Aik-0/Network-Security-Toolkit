import re
from collections import Counter

def analyze_logs(log_file_path):
    """
    Function to analyze a log file for potential security threats.
    """
    print("=" * 60)
    print("--- SECURITY LOG & THREAT ANALYSIS ENGINE ---")
    print("=" * 60)

    # Regular expression to extract IP addresses from log lines
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    
    failed_attempts_ips = []
    suspicious_ports = [21, 23, 3389] # Sensitive ports like FTP, Telnet, RDP
    
    try:
        with open(log_file_path, 'r') as file:
            logs = file.readlines()
    except FileNotFoundError:
        print(f"[!] Error: The file '{log_file_path}' was not found.")
        return

    print(f"[*] Analyzing {len(logs)} log entries...\n")

    alert_count = 0

    for line_num, line in enumerate(logs, 1):
        # Check for failed login keywords
        if "FAILED" in line.upper() or "UNAUTHORIZED" in line.upper() or "ERROR" in line.upper():
            match = re.search(ip_pattern, line)
            if match:
                ip = match.group()
                failed_attempts_ips.append(ip)
                print(f"[!] ALERT [Line {line_num}]: Suspicious failed activity from IP: {ip}")
                alert_count += 1

        # Check for sensitive port access attempts
        for port in suspicious_ports:
            if f"port {port}" in line.lower() or f":{port}" in line:
                match = re.search(ip_pattern, line)
                if match:
                    print(f"[!] WARNING [Line {line_num}]: Sensitive Port {port} accessed by IP: {match.group()}")
                    alert_count += 1

    print("-" * 60)
    print(f"Analysis completed! Total alerts found: {alert_count}")

    # Check for Brute Force patterns (IP appearing too many times in failed attempts)
    if failed_attempts_ips:
        ip_counts = Counter(failed_attempts_ips)
        print("\n--- Threat Intelligence Summary ---")
        for ip, count in ip_counts.items():
            if count >= 3:
                print(f"[x] CRITICAL: Potential Brute Force Attack detected from IP: {ip} ({count} failed attempts)")

if __name__ == "__main__":
    # For testing, we can create a sample log file automatically if it doesn't exist
    sample_log_name = "sample_security.log"
    
    # Create a dummy log file for quick testing
    dummy_logs = [
        "2026-10-21 10:00:01 - INFO - User admin logged in successfully from 192.168.1.10",
        "2026-10-21 10:05:12 - FAILED LOGIN - Invalid password from 203.0.113.50",
        "2026-10-21 10:05:15 - FAILED LOGIN - Invalid password from 203.0.113.50",
        "2026-10-21 10:05:18 - FAILED LOGIN - Unauthorized access from 203.0.113.50",
        "2026-10-21 10:10:22 - WARNING - Connection attempt to port 3389 from 198.51.100.15"
    ]
    
    with open(sample_log_name, 'w') as f:
        f.write("\n".join(dummy_logs))
        
    print(f"[*] Created a sample log file '{sample_log_name}' for demonstration.")
    
    # Run the analyzer on our sample log file
    analyze_logs(sample_log_name)