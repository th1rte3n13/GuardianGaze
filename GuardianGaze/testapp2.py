import sys
import os
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem, QHBoxLayout
from PyQt5.QtGui import QFont  # Add this import
import scapy.all as scapy
import joblib  # Corrected import for joblib
import pandas as pd

# Suppress EUDC font warning (optional)
os.environ["QT_QPA_PLATFORM_PLUGIN_PATH"] = r"C:\Program Files\Python311\Lib\site-packages\PyQt5\Qt\plugins"

# Set a default font to avoid EUDC font warning
app = QApplication(sys.argv)
app.setFont(QFont("Arial", 10))  # Now QFont is defined

# Load models and label encoder
xgboost_model = joblib.load('xgb_model.joblib')
extratrees_model = joblib.load('et_model.joblib')
naive_bayes_model = joblib.load('nb_model.joblib')
random_forest_model = joblib.load('rf_model.joblib')
label_encoder = joblib.load('label_encoder.joblib')

# Selected features for prediction
selected_features = [
    'L7_PROTO', 'FLOW_DURATION_MILLISECONDS', 'MIN_IP_PKT_LEN',
    'SERVER_TCP_FLAGS', 'L4_SRC_PORT', 'MAX_IP_PKT_LEN',
    'CLIENT_TCP_FLAGS', 'TCP_FLAGS', 'TCP_WIN_MAX_OUT',
    'RETRANSMITTED_OUT_PKTS'
]

# Dummy list to store packet data for real-time plotting
packet_data = []

# Function to extract features from a packet
def extract_features(packet):
    if not packet.haslayer(scapy.IP):
        return None
    
    # Check if packet has a TCP layer
    if packet.haslayer(scapy.TCP):
        tcp_flags = int(packet[scapy.TCP].flags)
        l4_src_port = packet[scapy.TCP].sport
        tcp_win_max_out = packet[scapy.TCP].window
    else:
        tcp_flags = l4_src_port = tcp_win_max_out = 0  # Default values when no TCP layer exists
    
    features = {
        'L7_PROTO': packet[scapy.IP].proto if packet.haslayer(scapy.IP) else 0,
        'FLOW_DURATION_MILLISECONDS': 0,  # Placeholder for duration
        'MIN_IP_PKT_LEN': len(packet),
        'MAX_IP_PKT_LEN': len(packet),
        'SERVER_TCP_FLAGS': tcp_flags,
        'CLIENT_TCP_FLAGS': tcp_flags,
        'L4_SRC_PORT': l4_src_port,
        'TCP_FLAGS': tcp_flags,
        'TCP_WIN_MAX_OUT': tcp_win_max_out,
        'RETRANSMITTED_OUT_PKTS': 0  # Placeholder for retransmissions
    }
    return features


# Function to predict using the ensemble model
def predict_packet(packet):
    features = extract_features(packet)
    if features is None:
        return None
    input_features = pd.DataFrame([features], columns=selected_features)
    
    # Ensemble prediction (using majority voting)
    xgboost_pred = xgboost_model.predict(input_features)
    extratrees_pred = extratrees_model.predict(input_features)
    naive_bayes_pred = naive_bayes_model.predict(input_features)
    random_forest_pred = random_forest_model.predict(input_features)
    
    predictions = [xgboost_pred[0], extratrees_pred[0], naive_bayes_pred[0], random_forest_pred[0]]
    final_prediction = max(set(predictions), key=predictions.count)
    decoded_prediction = label_encoder.inverse_transform([final_prediction])[0]
    
    return decoded_prediction

# Function to handle packet sniffing and display data
def packet_callback(packet):
    # Predict and update table
    prediction = predict_packet(packet)
    if prediction:
        # Update the packet data list for real-time plotting
        packet_data.append((packet.time, prediction))
        if len(packet_data) > 100:  # Keep last 100 packets for the plot
            packet_data.pop(0)
        # Update the table with new packet information
        update_table(packet)

# Function to update the table with new packet data
def update_table(packet):
    row_position = window.table.rowCount()
    window.table.insertRow(row_position)
    
    # Add packet info to the table
    window.table.setItem(row_position, 0, QTableWidgetItem(str(packet.time)))
    window.table.setItem(row_position, 1, QTableWidgetItem(str(packet[scapy.IP].src)))
    window.table.setItem(row_position, 2, QTableWidgetItem(str(packet[scapy.IP].dst)))
    window.table.setItem(row_position, 3, QTableWidgetItem(str(predict_packet(packet))))

# Real-time packet traffic plotting class
class PlotWidget(FigureCanvas):
    def __init__(self, parent=None):
        self.fig, self.ax = plt.subplots(figsize=(5, 5))
        super().__init__(self.fig)
        self.setParent(parent)
        self.ax.set_title('Real-time Packet Traffic')
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Packet Count')
        self.times = []
        self.counts = []

    def update_plot(self):
        # Extract time and prediction data from packet_data
        if len(packet_data) > 0:
            self.times = [pkt[0] for pkt in packet_data]
            self.counts = [pkt[1] for pkt in packet_data]
        
        # Plot data
        self.ax.clear()
        self.ax.plot(self.times, self.counts, label='Traffic Count')
        self.ax.set_title('Real-time Packet Traffic')
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Packet Count')
        self.draw()

# GUI Application
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Intrusion Detection System")
        self.setGeometry(0, 0, 1920, 1080)  # Set resolution to 1920x1080
        
        # Create main layout and widgets
        layout = QHBoxLayout()

        # Left side: Real-time Packet Traffic Graph
        self.plot_widget = PlotWidget(self)
        layout.addWidget(self.plot_widget)

        # Right side: Table for packet details
        self.table = QTableWidget(self)
        self.table.setRowCount(0)
        self.table.setColumnCount(4)  # Time, Source IP, Destination IP, Prediction
        self.table.setHorizontalHeaderLabels(['Time', 'Source IP', 'Destination IP', 'Prediction'])
        layout.addWidget(self.table)

        # Central widget
        central_widget = QWidget(self)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Start packet sniffing in the background
        scapy.sniff(prn=packet_callback, store=0, iface='\\Device\\NPF_Loopback', filter="ip")

    def update_display(self):
        # Update plot
        self.plot_widget.update_plot()

# Main execution
if __name__ == '__main__':
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

    sys.exit(app.exec_())


