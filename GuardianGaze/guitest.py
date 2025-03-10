import scapy.all as scapy
import tkinter as tk
from tkinter import messagebox
from threading import Thread
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

interfacetest = '\\Device\\NPF_{A0BA4BDE-DA28-4D62-AED5-A96A124A8D7A}'  # Replace this with the correct one

# Packet sniffer function to capture network packets
def capture_packets(interface, packet_count=100):
    return scapy.sniff(iface=interface, count=packet_count)

# Dummy function to simulate intrusion detection
def predict_intrusion(packet):
    return 0  # Assuming 0 for normal traffic (You can adjust this as needed)

# GUI for the Intrusion Detection System
class IDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")
        self.root.geometry("600x400")
        
        # Start button
        self.start_button = tk.Button(root, text="Start Packet Capture", command=self.start_capture)
        self.start_button.pack(pady=20)
        
        # Stop button
        self.stop_button = tk.Button(root, text="Stop Packet Capture", command=self.stop_capture)
        self.stop_button.pack(pady=20)
        
        # Status Label
        self.status_label = tk.Label(root, text="Status: Waiting to capture packets...", fg="blue")
        self.status_label.pack(pady=20)

        # Setup a plot for real-time visualization
        self.figure, self.ax = plt.subplots(figsize=(5, 4))
        self.canvas = FigureCanvasTkAgg(self.figure, master=root)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)
        self.packet_data = []

        self.is_capturing = False

    # Function to start packet capture
    def start_capture(self):
        self.is_capturing = True
        self.status_label.config(text="Status: Capturing packets...", fg="green")
        self.capture_thread = Thread(target=self.capture_and_analyze)
        self.capture_thread.start()

    # Function to stop packet capture
    def stop_capture(self):
        self.is_capturing = False
        self.status_label.config(text="Status: Packet capture stopped.", fg="red")

    # Function to capture and analyze packets
    def capture_and_analyze(self):
        interface = interfacetest  # Replace with your network interface
        while self.is_capturing:
            packets = capture_packets(interface, packet_count=10)
            for packet in packets:
                prediction = predict_intrusion(packet)
                self.packet_data.append(prediction)
                self.update_plot()

    # Update the plot with real-time data
    def update_plot(self):
        self.ax.clear()
        self.ax.plot(self.packet_data[-50:], label='Packet Prediction (0=Normal, 1=Anomaly)', color='blue')
        self.ax.set_ylim([-0.5, 1.5])
        self.ax.set_xlabel("Packet Number")
        self.ax.set_ylabel("Prediction")
        self.ax.legend()
        self.canvas.draw()

# Main function to run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()
