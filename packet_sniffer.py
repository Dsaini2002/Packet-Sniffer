from scapy.all import sniff, wrpcap

def sniff_packets(count=10, iface=None):
    packets = sniff(count=count, iface=iface)  # Default to 10 packets if count isn't provided
    wrpcap("captured_packets.pcap", packets)
    print(f"{count} packets saved to captured_packets.pcap")

# Example of calling the function:
sniff_packets(count=20, iface="Ethernet")  # Or use the correct interface name
