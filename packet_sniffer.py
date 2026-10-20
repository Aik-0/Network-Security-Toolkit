from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def process_packet(packet):
    """
    Function to process each captured packet and extract basic info.
    """
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Determine protocol name
        proto_name = "OTHER"
        if packet.haslayer(TCP):
            proto_name = "TCP"
        elif packet.haslayer(UDP):
            proto_name = "UDP"

        print(f"[+] Packet: {src_ip}  --->  {dst_ip} | Protocol: {proto_name}")

def start_sniffer(packet_count=10):
    """
    Function to start sniffing packets on the network.
    """
    print("=" * 50)
    print("Starting Packet Sniffer... Listening for traffic.")
    print("=" * 50)
    
    # Sniff packets (count=10 means it will capture 10 packets then stop)
    sniff(prn=process_packet, count=packet_count, store=False)
    
    print("-" * 50)
    print("Sniffing completed!")

if __name__ == "__main__":
    # You can change the count of packets to capture
    try:
        count = int(input("Enter number of packets to capture (default: 10): ") or 10)
    except ValueError:
        count = 10

    start_sniffer(packet_count=count)