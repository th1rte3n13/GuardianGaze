import scapy.all as scapy

def capture_packets(interface):
    packets = scapy.sniff(iface=interface, count=10)  # Capture 10 packets
    for packet in packets:
        print(packet.summary())  # Print a summary of each packet

if __name__ == "__main__":
    interface = '\\Device\\NPF_Loopback'  # Replace with correct interface
    capture_packets(interface)