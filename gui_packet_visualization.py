import tkinter as tk
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time

# Global variables for Tkinter text widget and packet counts
text_widget = None
current_filter = "all"  # For filtering, as defined earlier
protocol_counts = {"tcp": 0, "udp": 0, "other": 0}

def log_to_gui(msg):
    """Append message to the Tkinter text widget."""
    global text_widget
    if text_widget:
        text_widget.insert(tk.END, msg + "\n")
        text_widget.see(tk.END)

def advanced_packet_analysis(packet):
    global protocol_counts, current_filter

    # Filtering logic (already defined in previous step)
    if current_filter == "tcp" and not packet.haslayer(TCP):
        return
    if current_filter == "udp" and not packet.haslayer(UDP):
        return

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
        protocol_counts["tcp"] += 1
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
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        output += f"UDP Source Port: {udp_layer.sport}\n"
        output += f"UDP Destination Port: {udp_layer.dport}\n"
        protocol_counts["udp"] += 1
    
    else:
        protocol_counts["other"] += 1

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

def update_chart(canvas, ax, figure):
    # Function to update the matplotlib chart periodically
    while True:
        # Clear the current axis
        ax.clear()
        # Prepare data for the pie chart
        labels = []
        sizes = []
        for proto, count in protocol_counts.items():
            if count > 0:
                labels.append(proto.upper())
                sizes.append(count)
        # Draw pie chart only if data is available
        if sizes:
            ax.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
            ax.set_title("Protocol Distribution")
        figure.canvas.draw()
        time.sleep(2)  # Update chart every 2 seconds

# GUI Setup using Tkinter with Filter Options and Visualization
def create_gui():
    global text_widget
    root = tk.Tk()
    root.title("Live Packet Analysis with Visualization")
    
    # Top frame for filter controls
    top_frame = tk.Frame(root)
    top_frame.pack(side=tk.TOP, fill=tk.X)
    
    # Label and OptionMenu for filter selection
    filter_label = tk.Label(top_frame, text="Select Protocol Filter:")
    filter_label.pack(side=tk.LEFT, padx=5, pady=5)
    
    filter_options = ["all", "tcp", "udp"]
    selected_filter = tk.StringVar(value="all")
    
    def on_filter_change(*args):
        update_filter(selected_filter.get())
    
    selected_filter.trace("w", on_filter_change)
    filter_menu = tk.OptionMenu(top_frame, selected_filter, *filter_options)
    filter_menu.pack(side=tk.LEFT, padx=5, pady=5)
    
    # Middle frame for Text widget (packet details)
    middle_frame = tk.Frame(root)
    middle_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    
    text_widget = tk.Text(middle_frame, wrap='word', height=20, width=80)
    text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    scrollbar = tk.Scrollbar(middle_frame, command=text_widget.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    text_widget.config(yscrollcommand=scrollbar.set)
    
    # Bottom frame for visualization (Matplotlib chart)
    bottom_frame = tk.Frame(root)
    bottom_frame.pack(side=tk.BOTTOM, fill=tk.BOTH)
    
    # Create a Matplotlib figure
    figure = plt.Figure(figsize=(4, 3), dpi=100)
    ax = figure.add_subplot(111)
    
    canvas = FigureCanvasTkAgg(figure, master=bottom_frame)
    canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    
    # Start background thread for updating chart
    chart_thread = threading.Thread(target=update_chart, args=(canvas, ax, figure), daemon=True)
    chart_thread.start()
    
    # Start packet sniffing in a separate thread
    start_sniffing_thread()
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
