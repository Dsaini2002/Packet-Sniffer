import tkinter as tk
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, DNSQR
from datetime import datetime
import threading
from collections import defaultdict
server_counter = defaultdict(int)
# Global variables
text_widget = None
current_filter = "all"  # Default filter: all packets
def process_packet(packet):
    # Check if packet contains DNS query (QR=0 for query)
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        domain = packet[DNSQR].qname.decode().rstrip('.')
        server_counter[domain] += 1
        update_server_list()
def update_server_list():
    """Update the server list box with the top contacted servers."""
    # Clear the list box
    server_listbox.delete(0, tk.END)
    
    # Sort servers by contact count and show top 10
    for domain, count in sorted(server_counter.items(), key=lambda x: x[1], reverse=True)[:10]:
        server_listbox.insert(tk.END, f"{domain:<40} {count}")


def log_to_gui(msg):
    """Append message to the Tkinter text widget."""
    global text_widget
    if text_widget:
        text_widget.insert(tk.END, msg + "\n")
        text_widget.see(tk.END)

def advanced_packet_analysis(packet):
    # Apply the filter: Only process if packet matches current_filter, or if filter is 'all'
    global current_filter
    if current_filter == "tcp" and not packet.haslayer(TCP):
        return
    if current_filter == "udp" and not packet.haslayer(UDP):
        return
    # You can add more protocol filters as needed

    # Get timestamp
    timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
    output = f"Timestamp: {timestamp}\n"
    
    # Packet Length
    output += f"Packet Length: {len(packet)}\n"
    
    # Check for IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        output += f"Source IP: {ip_layer.src}\n"
        output += f"Destination IP: {ip_layer.dst}\n"
    
    # TCP Analysis
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        output += f"TCP Source Port: {tcp_layer.sport}\n"
        output += f"TCP Destination Port: {tcp_layer.dport}\n"
        # HTTP analysis for port 80
        if tcp_layer.sport == 80 or tcp_layer.dport == 80:
            if packet.haslayer(Raw):
                try:
                    http_payload = packet[Raw].load.decode("utf-8", errors="replace")
                    request_line = http_payload.splitlines()[0]
                    output += f"HTTP Info: {request_line}\n"
                except Exception as e:
                    output += f"HTTP decode error: {e}\n"
    
    # UDP Analysis
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        output += f"UDP Source Port: {udp_layer.sport}\n"
        output += f"UDP Destination Port: {udp_layer.dport}\n"
    
    output += "-" * 50
    log_to_gui(output)

def start_sniffing():
    # Capture continuously until the GUI is closed.
    sniff(prn=advanced_packet_analysis)

def start_sniffing_thread():
    # Start sniffing on a separate thread to avoid blocking the GUI.
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

def update_filter(new_filter):
    global current_filter
    current_filter = new_filter
    log_to_gui(f"Filter updated to: {current_filter}")

# GUI Setup using Tkinter with Filter Options
def create_gui():
    global text_widget
    root = tk.Tk()
    root.title("Live Packet Analysis with Filter")
    
    # Top frame for filter controls
    top_frame = tk.Frame(root)
    top_frame.pack(side=tk.TOP, fill=tk.X)
    
    # Label and OptionMenu for filter selection
    filter_label = tk.Label(top_frame, text="Select Protocol Filter:")
    filter_label.pack(side=tk.LEFT, padx=5, pady=5)
    
    filter_options = ["all", "tcp", "udp"]
    selected_filter = tk.StringVar(value="all")
    
    def on_filter_change(*args):
        # Update the filter when the selection changes
        update_filter(selected_filter.get())
    
    selected_filter.trace("w", on_filter_change)
    filter_menu = tk.OptionMenu(top_frame, selected_filter, *filter_options)
    filter_menu.pack(side=tk.LEFT, padx=5, pady=5)
    
    # Create a Text widget with vertical scrollbar for packet details
    text_widget = tk.Text(root, wrap='word', height=25, width=80)
    text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    scrollbar = tk.Scrollbar(root, command=text_widget.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    text_widget.config(yscrollcommand=scrollbar.set)
    
    # Start packet sniffing in a separate thread
    start_sniffing_thread()
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()