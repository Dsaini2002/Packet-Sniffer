# 🚀 NetScope++ Packet Sniffer

NetScope++ is a powerful real-time packet sniffer and network analysis tool built with Python, Tkinter, and Scapy. It provides live packet capture, sensitive data leak detection, and interactive protocol analytics with an intuitive GUI.

---

## 🔧 Features

- 🖥️ **Interface Selection** (Manual or Auto-detect)
- 📦 **Real-time Packet Sniffing**
- ⚠️ **Sensitive Data Leak Detection**
  - Keywords: password, bank, secret, confidential
  - Patterns: Email addresses and credit card numbers
- 🌐 **Top Contacted Servers** via DNS Tracking
- 📊 **Deep Protocol Analysis**
  - Line chart of protocol usage over time (TCP, UDP, ICMP, DNS, Others)
- 🧠 **Multithreaded Design** for seamless GUI experience

---

## 🖼️ GUI Overview

- **Left Panel:** Captured packet logs
- **Right Panel:** Top contacted domains (via DNS)
- **Alert Panel:** List of detected leaks
- **Buttons:**
  - `Start Sniffing` – Begin capturing network packets
  - `Check for Data Leak` – Run manual leak check
  - `Deep Analysis` – View graphical protocol trends

---

## 🛠️ Requirements

Make sure to install the following dependencies:

```bash
pip install scapy matplotlib
