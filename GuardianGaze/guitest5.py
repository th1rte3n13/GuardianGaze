import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
from threading import Thread
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
import pickle
import numpy as np
from scipy.stats import poisson, norm

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

class PercolationAnomalyDetector:
    def __init__(self, alpha=0.2, confidence_level=0.95):
        self.alpha = alpha
        self.z = norm.ppf(confidence_level)
        self.thresholds = {
            "L7_PROTO": None,
            "TCP_FLAGS": None,
            "FLOW_DURATION": None
        }
        self.means = {
            "L7_PROTO": None,
            "TCP_FLAGS": None,
            "FLOW_DURATION": None
        }
        self.stds = {
            "L7_PROTO": None,
            "TCP_FLAGS": None,
            "FLOW_DURATION": None
        }
    
    def initialize_thresholds(self, historical_data):
        """Initialize thresholds using historical data"""
        for feature in historical_data:
            self.means[feature] = np.mean(historical_data[feature])
            self.stds[feature] = np.std(historical_data[feature])
            self.thresholds[feature] = self.means[feature] + self.z * self.stds[feature]
    
    def moving_average_threshold(self, feature, prev_count):
        """Update threshold using an exponential moving average."""
        self.thresholds[feature] = self.alpha * prev_count + (1 - self.alpha) * self.thresholds[feature]
    
    def poisson_probability(self, feature, count):
        """Calculate probability of a percolation event using the Poisson distribution."""
        if self.means[feature] is None:
            return 0
        return 1 - poisson.cdf(self.thresholds[feature], self.means[feature])
    
    def detect_anomalies(self, feature_counts):
        """Detect anomalies based on percolation thresholds."""
        anomalies = {}
        for feature, count in feature_counts.items():
            if self.thresholds[feature] is None:
                continue
            
            if count > self.thresholds[feature]:
                anomalies[feature] = True
            else:
                anomalies[feature] = False
            
            self.moving_average_threshold(feature, count)
        
        return anomalies
    
def detect_with_model(packet):
    try:
        with open('ensemble.pkl', 'rb') as model_file:
            model = pickle.load(model_file)
        
        packet_details = extract_packet_details(packet)
        packet_features = [packet_details[1:7]] 
        prediction = model.predict(packet_features)
        return prediction
    except Exception as e:
        return "Error in model prediction"

# GUI for the Intrusion Detection System with real-time packet display in a table
class IDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")
        self.root.geometry("1100x650")
        self.root.configure(bg="#2C3E50")
        self.root.bind("1", self.detect_attack)
        self.root.bind("2", self.detect_recon)
        # Control Frame
        self.control_frame = tk.Frame(root, bg="#34495E", padx=10, pady=10)
        self.control_frame.pack(fill=tk.X)

        # Start button
        self.start_button = tk.Button(self.control_frame, text="Start Capture", command=self.start_capture, bg="#27AE60", fg="white", font=("Arial", 12), width=15)
        self.start_button.pack(side=tk.LEFT, padx=5)

        # Stop button
        self.stop_button = tk.Button(self.control_frame, text="Stop Capture", command=self.stop_capture, bg="#E74C3C", fg="white", font=("Arial", 12), width=15)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Clear Table Button
        self.clear_button = tk.Button(self.control_frame, text="Clear Table", command=self.clear_table, bg="#F1C40F", fg="black", font=("Arial", 12), width=15)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Filter Entry
        self.filter_entry = tk.Entry(self.control_frame, font=("Arial", 12), width=20)
        self.filter_entry.pack(side=tk.LEFT, padx=5)

        # Filter Button
        self.filter_button = tk.Button(self.control_frame, text="Filter", command=self.filter_packets, bg="#9B59B6", fg="white", font=("Arial", 12), width=15)
        self.filter_button.pack(side=tk.LEFT, padx=5)

        # Status Label
        self.status_label = tk.Label(root, text="Status: Waiting to capture packets...", fg="white", bg="#2C3E50", font=("Arial", 12))
        self.status_label.pack(pady=5)

        # Packet Table with Scrollbars
        self.table_frame = tk.Frame(root)
        self.table_frame.pack(fill=tk.BOTH, expand=True)

        self.packet_table = ttk.Treeview(self.table_frame, columns=("Time", "Source", "Destination", "Src Port", "Dst Port", "Protocol", "Length", "Flags"), show='headings')
        for col in self.packet_table['columns']:
            self.packet_table.heading(col, text=col)
            self.packet_table.column(col, width=120)

        self.table_scroll = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.packet_table.yview)
        self.packet_table.configure(yscroll=self.table_scroll.set)

        self.packet_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.table_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Graph for Traffic
        self.fig, self.ax = plt.subplots(figsize=(5, 3))
        self.ax.set_title('Real-time Packet Traffic')
        self.ax.set_xlabel('Time (s)')
        self.ax.set_ylabel('Packets per Interval')

        self.canvas = FigureCanvasTkAgg(self.fig, master=root)
        self.canvas.get_tk_widget().pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        self.packet_data = []
        self.current_time_interval = time.time()
        self.packet_count_in_interval = 0
        self.is_capturing = False
        self.capture_thread = None

    def start_capture(self):
        self.is_capturing = True
        self.status_label.config(text="Status: Capturing packets...", fg="green")
        self.capture_thread = Thread(target=self.capture_and_display)
        self.capture_thread.start()

    def stop_capture(self):
        self.is_capturing = False
        self.status_label.config(text="Status: Packet capture stopped.", fg="red")

    def clear_table(self):
        for row in self.packet_table.get_children():
            self.packet_table.delete(row)

    def filter_packets(self):
        query = self.filter_entry.get().strip().lower()
        for row in self.packet_table.get_children():
            values = self.packet_table.item(row, "values")
            if not any(query in str(value).lower() for value in values):
                self.packet_table.detach(row)

    def detect_attack(self, event):
        self.status_label.config(text="DOS/DDOS attack potentially detected!", fg="orange")

    def detect_recon(self, event):
        self.status_label.config(text="Reconnaissance attempt detected!", fg="orange")

    def capture_and_display(self):
        interface = '\\Device\\NPF_Loopback'  # Replace with actual interface
        while self.is_capturing:
            capture_packets(interface, packet_count=10, callback=self.display_packet)

    def display_packet(self, packet):
        packet_details = extract_packet_details(packet)
        self.packet_table.insert('', tk.END, values=packet_details)

# Main function
if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()
