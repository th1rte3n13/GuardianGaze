import scapy.all as scapy
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread

# Function to capture network packets
def capture_packets(interface, packet_count=100, callback=None):
    # Callback is used to update the GUI with packet data in real time
    scapy.sniff(iface=interface, count=packet_count, prn=callback)

# Function to extract and format packet details for display
def format_packet(packet):
    try:
        packet_info = packet.summary()  # Summary of the packet for display
        return packet_info
    except Exception as e:
        return f"Error parsing packet: {e}"

# GUI for the Intrusion Detection System with real-time packet display
class IDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")
        self.root.geometry("800x600")
        
        # Start button
        self.start_button = tk.Button(root, text="Start Packet Capture", command=self.start_capture)
        self.start_button.pack(pady=10)
        
        # Stop button
        self.stop_button = tk.Button(root, text="Stop Packet Capture", command=self.stop_capture)
        self.stop_button.pack(pady=10)

        # Text widget to display captured packets
        self.packet_display = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=25, width=100)
        self.packet_display.pack(pady=10)
        
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

    # Function to display packet in the GUI
    def display_packet(self, packet):
        packet_info = format_packet(packet)
        self.packet_display.insert(tk.END, packet_info + '\n')  # Append packet info to the text display
        self.packet_display.see(tk.END)  # Auto-scroll to the latest packet

# Main function to run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()
