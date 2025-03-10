import scapy.all as scapy
import joblib
import numpy as np
from datetime import datetime
import pandas as pd

# Load pre-trained models
extratrees_model = joblib.load('et_model.joblib')
naive_bayes_model = joblib.load('nb_model.joblib')
xgboost_model = joblib.load('xgb_model.joblib')
random_forest_model = joblib.load('rf_model.joblib')

# Load the label encoder
label_encoder = joblib.load('label_encoder.joblib')

# Function to extract the necessary features from a Scapy packet
import scapy.all as scapy

# Function to extract the necessary features from a Scapy packet
def extract_features(packet):
    try:
        # Initialize features
        features = {}
        
        # Example: Extract L7 protocol (you may need specific logic for your use case)
        features['L7_PROTO'] = packet[scapy.IP].proto if packet.haslayer(scapy.IP) else 0

        # FLOW_DURATION_MILLISECONDS: You might have to implement custom logic to track flow times
        features['FLOW_DURATION_MILLISECONDS'] = 0  # Placeholder, you need to calculate this

        # MIN_IP_PKT_LEN and MAX_IP_PKT_LEN
        features['MIN_IP_PKT_LEN'] = min([len(pkt) for pkt in scapy.sniff(count=10)]) if packet else 0
        features['MAX_IP_PKT_LEN'] = max([len(pkt) for pkt in scapy.sniff(count=10)]) if packet else 0

        # SERVER_TCP_FLAGS and CLIENT_TCP_FLAGS (convert flag values to integers)
        features['SERVER_TCP_FLAGS'] = int(packet[scapy.TCP].flags) if packet.haslayer(scapy.TCP) else 0
        features['CLIENT_TCP_FLAGS'] = int(packet[scapy.TCP].flags) if packet.haslayer(scapy.TCP) else 0

        # L4_SRC_PORT
        features['L4_SRC_PORT'] = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else 0

        # TCP_FLAGS (convert flag values to integers)
        features['TCP_FLAGS'] = int(packet[scapy.TCP].flags) if packet.haslayer(scapy.TCP) else 0

        # TCP_WIN_MAX_OUT (TCP Window size)
        features['TCP_WIN_MAX_OUT'] = packet[scapy.TCP].window if packet.haslayer(scapy.TCP) else 0

        # RETRANSMITTED_OUT_PKTS (Placeholder as Scapy doesn't directly track retransmissions)
        features['RETRANSMITTED_OUT_PKTS'] = 0  # You can track retransmissions manually if required

        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

# Function to make predictions using the ensemble model
def predict_packet(packet):
    # Extract features from the packet
    features = extract_features(packet)
    if features is None:
        return None
    
    # Convert features into the appropriate format for model input (as a pandas DataFrame)
    selected_features = [
        'L7_PROTO', 'FLOW_DURATION_MILLISECONDS', 'MIN_IP_PKT_LEN',
        'SERVER_TCP_FLAGS', 'L4_SRC_PORT', 'MAX_IP_PKT_LEN',
        'CLIENT_TCP_FLAGS', 'TCP_FLAGS', 'TCP_WIN_MAX_OUT',
        'RETRANSMITTED_OUT_PKTS'
    ]
    
    # Create a pandas DataFrame with the correct feature names
    input_features = pd.DataFrame([features], columns=selected_features)
    
    # Make predictions using each model
    xgboost_pred = xgboost_model.predict(input_features)
    extratrees_pred = extratrees_model.predict(input_features)
    naive_bayes_pred = naive_bayes_model.predict(input_features)
    random_forest_pred = random_forest_model.predict(input_features)
    
    # Ensemble voting mechanism (Majority vote in this example)
    predictions = [xgboost_pred[0], extratrees_pred[0], naive_bayes_pred[0], random_forest_pred[0]]
    final_prediction = max(set(predictions), key=predictions.count)
    
    # Decode the final prediction label using the label encoder
    decoded_prediction = label_encoder.inverse_transform([final_prediction])[0]
    
    return decoded_prediction


# Function to sniff and predict packets in real time
def capture_and_predict(interface):
    def process_packet(packet):
        prediction = predict_packet(packet)
        if prediction is not None:
            print(f"Prediction for packet: {prediction}")
    
    # Capture packets and predict in real time
    scapy.sniff(iface=interface, prn=process_packet, store=False)

# Example usage
if __name__ == "__main__":
    interface = '\\Device\\NPF_Loopback'  # Replace with your actual interface
    capture_and_predict(interface)
