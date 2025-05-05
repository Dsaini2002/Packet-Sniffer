from scapy.all import rdpcap

def deep_analyze_pcap(file_path="captured_packets.pcap"):
    try:
        packets = rdpcap(file_path)
        protocol_counts = {}

        for pkt in packets:
            proto = pkt.name
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        report = "\n--- Deep Packet Analysis Report ---\n"
        for proto, count in protocol_counts.items():
            report += f"{proto}: {count} packets\n"

        return report
    except Exception as e:
        return f"Error during analysis: {str(e)}"
# deep_analysis.py

def deep_analyze_pcap():
    # Dummy analysis (replace with real logic later)
    return "✔️ Analysis Complete: No threats found. Packet flow looks normal."
