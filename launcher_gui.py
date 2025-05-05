import tkinter as tk
from tkinter import font, messagebox
import threading
import re
from scapy.all import sniff, get_if_list
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.dns import DNS
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter

# ================== Global Setup =====================
protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "Other": 0}
sensitive_keywords = ["password", "bank", "secret", "confidential"]
email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
credit_card_pattern = r"\b(?:\d[ -]*?){13,16}\b"

selected_iface = None  # Interface in use
text_widget = None     # For displaying packets
iface_var = None       # Dropdown variable
alert_panel = None     # Panel for displaying alerts
server_counter = Counter()  # Counter for DNS requests to track servers

# ================ Auto-Detect Function =================
def detect_working_interface(timeout=2, count=1):
    for iface in get_if_list():
        try:
            pkts = sniff(iface=iface, timeout=timeout, count=count)
            if pkts:
                return iface
        except Exception:
            continue
    return None

# ================ GUI Functions ======================
def create_gui():
    global text_widget, iface_var, alert_panel, server_listbox

    root = tk.Tk()
    root.title("NetScope++ Packet Sniffer")
    root.geometry("1100x550")
    root.configure(bg="#1e1e2f")

    title_font = font.Font(family="Helvetica", size=20, weight="bold")
    button_font = font.Font(family="Helvetica", size=12, weight="bold")
    text_font = font.Font(family="Courier", size=10)

    tk.Label(root, text="\U0001f6f0 NetScope++ Packet Sniffer", bg="#1e1e2f", fg="#00ffff", font=title_font).pack(pady=20)

    tk.Label(root, text="Select Network Interface:", bg="#1e1e2f", fg="white").pack()
    iface_var = tk.StringVar(root)
    iface_options = ["Auto-Detect"] + get_if_list()
    iface_var.set(iface_options[0])
    tk.OptionMenu(root, iface_var, *iface_options).pack(pady=5)

    button_frame = tk.Frame(root, bg="#1e1e2f")
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Start Sniffing", bg="#00bcd4", fg="white", font=button_font,
              command=start_sniffing, padx=20, pady=10).pack(side=tk.LEFT, padx=10)

    tk.Button(button_frame, text="Check for Data Leak", bg="#ff9800", fg="white", font=button_font,
              command=perform_data_leak_check, padx=20, pady=10).pack(side=tk.LEFT, padx=10)

    tk.Button(button_frame, text="Deep Analysis", bg="#8e44ad", fg="white", font=button_font,
              command=open_deep_analysis_window, padx=20, pady=10).pack(side=tk.LEFT, padx=10)

    main_frame = tk.Frame(root, bg="#1e1e2f")
    main_frame.pack(pady=20, padx=20, fill="both", expand=True)

    left_panel = tk.Frame(main_frame, bg="#1e1e2f")
    left_panel.pack(side=tk.LEFT, fill="both", expand=True)

    text_widget = tk.Text(left_panel, height=20, width=60, font=text_font, bg="#282a36", fg="#00bcd4",
                          insertbackground="white", bd=0, padx=10, pady=10)
    text_widget.pack(fill="both", expand=True)

    alert_panel = tk.Frame(main_frame, bg="#1e1e2f", width=200)
    alert_panel.pack(side=tk.LEFT, padx=10, fill="both", expand=False)

    alert_label = tk.Label(alert_panel, text="Detected Leaks", bg="#1e1e2f", fg="#ff9800", font=("Helvetica", 14, "bold"))
    alert_label.pack(pady=10)

    global alert_listbox
    alert_listbox = tk.Listbox(alert_panel, height=20, width=30, font=text_font, bg="#282a36", fg="#ff9800",
                               selectmode=tk.SINGLE)
    alert_listbox.pack(fill="both", expand=True)

    # Listbox for displaying top contacted servers
    server_listbox = tk.Listbox(root, height=25, width=40, font=text_font, bg="#282a36", fg="#00bcd4")
    server_listbox.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=10)

    root.mainloop()

# ============== Packet Sniffing ==================
def start_sniffing():
    global selected_iface
    choice = iface_var.get()
    if choice == "Auto-Detect":
        text_widget.insert(tk.END, "\U0001f50d Auto-detecting active interface...\n")
        text_widget.yview(tk.END)
        selected_iface = detect_working_interface()
        if not selected_iface:
            messagebox.showerror("Error", "No active interface found!")
            return
        text_widget.insert(tk.END, f"\u2705 Detected interface: {selected_iface}\n")
        text_widget.yview(tk.END)
    else:
        selected_iface = choice
        text_widget.insert(tk.END, f"\U0001f680 Sniffing on selected interface: {selected_iface}\n")
        text_widget.yview(tk.END)

    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.daemon = True
    sniff_thread.start()

def sniff_packets():
    try:
        sniff(prn=process_packet, iface=selected_iface, store=False)
    except Exception as e:
        text_widget.insert(tk.END, f"\u274c Error starting sniffing: {e}\n")
        text_widget.yview(tk.END)

# ========== Packet Processing & Leak Detection ============

def process_packet(packet):
    packet_data = str(packet)
    leak_info = check_data_leak(packet_data)

    # Update DNS servers list
    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        if dns_layer.qd:  # Question section
            queried_domain = dns_layer.qd.qname.decode('utf-8')
            server_counter[queried_domain] += 1
            update_server_list()

    if packet.haslayer(TCP):
        protocol_counts["TCP"] += 1
    elif packet.haslayer(UDP):
        protocol_counts["UDP"] += 1
    elif packet.haslayer(ICMP):
        protocol_counts["ICMP"] += 1
    elif packet.haslayer(DNS):
        protocol_counts["DNS"] += 1
    else:
        protocol_counts["Other"] += 1

    packet_info = ""
    if leak_info:
        packet_info += f"\u26a0\ufe0f Data Leak Found:\n"
        for leak in leak_info:
            packet_info += f"- {leak}\n"
        alert_listbox.insert(tk.END, f"\u26a0\ufe0f {', '.join(leak_info)}")
    else:
        packet_info += f"\U0001f4e6 {packet.summary()}\n"

    text_widget.insert(tk.END, packet_info)
    text_widget.yview(tk.END)

def check_data_leak(packet_data):
    leaks = []
    for keyword in sensitive_keywords:
        if keyword.lower() in packet_data.lower():
            leaks.append(f"Sensitive Keyword: {keyword}")
    if re.search(email_pattern, packet_data):
        leaks.append("Email Address Detected")
    if re.search(credit_card_pattern, packet_data):
        leaks.append("Credit Card Number Detected")
    return leaks

def perform_data_leak_check():
    messagebox.showinfo("Leak Check", "\u2714\ufe0f Leak check completed. See the packet details for any alerts.")

def update_server_list():
    """Update the listbox to show top contacted servers."""
    global server_counter
    # Sort the servers based on their count (most contacted)
    most_contacted_servers = server_counter.most_common(10)
    
    # Clear previous entries
    server_listbox.delete(0, tk.END)
    
    # Insert the top servers into the listbox
    for server, count in most_contacted_servers:
        server_listbox.insert(tk.END, f"{server}: {count} requests")

def open_deep_analysis_window():
    deep_window = tk.Toplevel()
    deep_window.title("Deep Analysis")
    deep_window.geometry("600x400")
    deep_window.configure(bg="#1e1e2f")

    tk.Label(deep_window, text="Deep Analysis", bg="#1e1e2f", fg="#00ffff", font=("Helvetica", 18, "bold")).pack(pady=20)

    fig1, ax1 = plt.subplots()
    line_canvas = FigureCanvasTkAgg(fig1, master=deep_window)
    line_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def update_line_chart():
        labels = list(protocol_counts.keys())
        values = list(protocol_counts.values())

        ax1.clear()
        ax1.plot(labels, values, marker='o', color='cyan')
        ax1.set_title("Protocol Distribution Over Time")
        ax1.set_ylabel("Packet Count")
        ax1.set_xlabel("Protocol")
        line_canvas.draw()

        deep_window.after(2000, update_line_chart)

    update_line_chart()

if __name__ == "__main__":
    create_gui()
