import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
from threading import Thread
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time

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

        # Create a matplotlib figure for the packet traffic graph
        self.fig, self.ax = plt.subplots(figsize=(5, 3))
        self.ax.set_title('Real-time Packet Traffic')
        self.ax.set_xlabel('Time (s)')
        self.ax.set_ylabel('Packets per Interval')

        # Add the figure to the Tkinter window
        self.canvas = FigureCanvasTkAgg(self.fig, master=root)
        self.canvas.get_tk_widget().pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        # Initialize variables for activity-based graphing
        self.packet_data = []  # Stores the time intervals and packet counts
        self.current_time_interval = time.time()
        self.packet_count_in_interval = 0
        self.last_packet_count = 0  # Track the last packet count for color changes
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

    # Function to update packet traffic graph with a smooth line graph
    def update_plot(self):
        # Update the plot with packet counts in the current time interval
        self.ax.clear()

        # If no data, return early
        if len(self.packet_data) == 0:
            return

        # Process and plot the packet data
        packet_times = [pkt[0] for pkt in self.packet_data]
        packet_counts = [pkt[1] for pkt in self.packet_data]

        # Plot each line segment with different colors based on increase, decrease, or constant
        for i in range(1, len(packet_counts)):
            x = [packet_times[i-1], packet_times[i]]
            y = [packet_counts[i-1], packet_counts[i]]

            if packet_counts[i] > packet_counts[i-1]:
                color = 'green'  # Increase
            elif packet_counts[i] < packet_counts[i-1]:
                color = 'red'    # Decrease
            else:
                color = 'yellow' # Constant

            self.ax.plot(x, y, color=color, marker='o')

        # Customize the graph appearance
        self.ax.set_title("Real-time Packet Traffic")
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Packets per Interval")
        self.ax.legend(["Increase", "Decrease", "Constant"], loc="upper left")

        # Redraw the canvas
        self.canvas.draw()

    # Function to display packet details in the table and update the graph
    def display_packet(self, packet):
        packet_details = extract_packet_details(packet)
        self.packet_table.insert('', tk.END, values=packet_details)  # Insert packet details into the table

        # Track the time and count packets in the current time interval
        current_time = time.time()
        if current_time - self.current_time_interval > 1:  # 1-second interval for activity
            # Store the packet count for the last interval
            self.packet_data.append((self.current_time_interval, self.packet_count_in_interval))
            self.packet_count_in_interval = 0
            self.current_time_interval = current_time

        # Increment packet count for the current interval
        self.packet_count_in_interval += 1

        # Update the graph with new packet data
        self.update_plot()

# Main function to run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()
