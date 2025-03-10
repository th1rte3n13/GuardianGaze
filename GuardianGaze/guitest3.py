import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
from threading import Thread
from datetime import datetime

# Function to capture network packets
def capture_packets(interface, packet_count=100, callback=None):
    scapy.sniff(iface=interface, count=packet_count, prn=callback, store=False)

# Function to extract and format packet details for display in a table
def extract_packet_details(packet):
    try:
        packet_time = datetime.now().strftime('%H:%M:%S')  # Current time

        # Extract IP information
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto
            packet_length = len(packet)
        else:
            src_ip, dst_ip, protocol, packet_length = 'N/A', 'N/A', 'N/A', 'N/A'

        # Extract TCP/UDP ports if applicable
        src_port, dst_port, flags = 'N/A', 'N/A', 'N/A'
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            flags = packet.sprintf('%TCP.flags%')
            protocol = 'TCP'
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            protocol = 'UDP'

        return packet_time, src_ip, dst_ip, src_port, dst_port, protocol, packet_length, flags
    except Exception as e:
        return "Error", "Error", "Error", "Error", "Error", "Error", "Error", "Error"

# GUI for the Intrusion Detection System with real-time packet display in a table
class IDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")
        self.root.geometry("1000x600")
        
        # Start button
        self.start_button = tk.Button(root, text="Start Packet Capture", command=self.start_capture)
        self.start_button.pack(pady=10)
        
        # Stop button
        self.stop_button = tk.Button(root, text="Stop Packet Capture", command=self.stop_capture)
        self.stop_button.pack(pady=10)

        # Create a treeview widget to display packets in a table
        self.packet_table = ttk.Treeview(root, columns=("Time", "Source", "Destination", "Src Port", "Dst Port", "Protocol", "Length", "Flags"), show='headings')
        self.packet_table.heading("Time", text="Time")
        self.packet_table.heading("Source", text="Source IP")
        self.packet_table.heading("Destination", text="Destination IP")
        self.packet_table.heading("Src Port", text="Source Port")
        self.packet_table.heading("Dst Port", text="Destination Port")
        self.packet_table.heading("Protocol", text="Protocol")
        self.packet_table.heading("Length", text="Length")
        self.packet_table.heading("Flags", text="Flags")
        
        # Set column widths
        self.packet_table.column("Time", width=100)
        self.packet_table.column("Source", width=150)
        self.packet_table.column("Destination", width=150)
        self.packet_table.column("Src Port", width=80)
        self.packet_table.column("Dst Port", width=80)
        self.packet_table.column("Protocol", width=100)
        self.packet_table.column("Length", width=100)
        self.packet_table.column("Flags", width=100)

        self.packet_table.pack(fill=tk.BOTH, expand=True)

        # Status Label
        self.status_label = tk.Label(root, text="Status: Waiting to capture packets...", fg="blue")
        self.status_label.pack(pady=10)

        self.is_capturing = False
        self.capture_thread = None

    # Function to start packet capture
    def start_capture(self):
        self.is_capturing = True
        self.status_label.config(text="Status: Capturing packets...", fg="green")
        self.capture_thread = Thread(target=self.capture_and_display)
        self.capture_thread.start()

    # Function to stop packet capture
    def stop_capture(self):
        self.is_capturing = False
        self.status_label.config(text="Status: Packet capture stopped.", fg="red")

    # Function to capture and display packets in real time
    def capture_and_display(self):
        interface = '\\Device\\NPF_Loopback'  # Replace with your actual interface
        while self.is_capturing:
            capture_packets(interface, packet_count=10, callback=self.display_packet)

    # Function to display packet details in the table
    def display_packet(self, packet):
        packet_details = extract_packet_details(packet)
        print(packet_details)  # Debug: print packet info to the console
        self.packet_table.insert('', tk.END, values=packet_details)  # Insert packet details into the table

# Main function to run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()
