from scapy.all import sniff, IP, TCP, UDP

def packet_analysis(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print("Source IP:", ip_layer.src)
        print("Destination IP:", ip_layer.dst)
        print("Protocol:", ip_layer.proto)
    
    # Agar packet TCP layer ko contain karta ho
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print("TCP Source Port:", tcp_layer.sport)
        print("TCP Destination Port:", tcp_layer.dport)
    
    # Agar packet UDP layer ko contain karta ho
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print("UDP Source Port:", udp_layer.sport)
        print("UDP Destination Port:", udp_layer.dport)

    # Agar aur data dekhna ho, to packet.show() use kar sakte ho
    print("-" * 50)  # separator for readability

# Packet sniffing: Capturing 5 packets for demonstration
sniff(prn=packet_analysis, count=5)
