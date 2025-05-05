from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

# Log file ka path
LOG_FILE = "analysis_log.txt"

# Function to log messages both to console and file
def log_message(msg):
    print(msg)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

# Advanced packet analysis function
def advanced_packet_analysis(packet):
    # 1. Time Stamp Analysis:
    # packet.time me epoch time hota hai. Use convert kar dete hain readable format mein.
    timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
    log_message("Timestamp: " + timestamp)
    
    # 2. Packet Length:
    pkt_length = len(packet)
    log_message("Packet Length: " + str(pkt_length))
    
    # 3. IP Layer Analysis:
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        log_message("Source IP: " + ip_layer.src)
        log_message("Destination IP: " + ip_layer.dst)
    
    # 4. TCP Analysis:
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        log_message("TCP Source Port: " + str(tcp_layer.sport))
        log_message("TCP Destination Port: " + str(tcp_layer.dport))
        
        # Protocol-Specific Analysis: Agar TCP port 80 (HTTP) hai.
        if tcp_layer.sport == 80 or tcp_layer.dport == 80:
            if packet.haslayer(Raw):
                try:
                    # HTTP payload ko decode karte hain
                    http_payload = packet[Raw].load.decode("utf-8", errors="replace")
                    # First line extract karne ke liye:
                    request_line = http_payload.splitlines()[0]
                    log_message("HTTP Info: " + request_line)
                except Exception as e:
                    log_message("HTTP decode error: " + str(e))
    
    # 5. UDP Analysis:
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        log_message("UDP Source Port: " + str(udp_layer.sport))
        log_message("UDP Destination Port: " + str(udp_layer.dport))
    
    # Separator for clarity
    log_message("-" * 50)

# Main function to start sniffing packets with advanced analysis
def start_advanced_sniffing():
    # Log file ko clear karke starting header likh dein:
    with open(LOG_FILE, "w") as f:
        f.write("Advanced Packet Analysis Log\n\n")
    # 10 packets capture karne ke liye sniff function
    sniff(prn=advanced_packet_analysis, count=10)

if __name__ == "__main__":
    start_advanced_sniffing()
