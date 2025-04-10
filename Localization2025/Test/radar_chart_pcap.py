import numpy as np
import matplotlib.pyplot as plt
from scapy.all import rdpcap
from collections import defaultdict
from scapy.all import Dot11
import matplotlib.cm as cm

file_name = 'captured_packets_20_03_2025.pcap'

# RSSI to distance formula (not used directly for this plot)
def rssi_to_distance(rssi, rssi_0=-50, n=3):
    """
    Convert RSSI to approximate distance using the formula.
    rssi_0 is the reference RSSI value at 1 meter (default -50 dBm)
    n is the path loss exponent (default 3)
    """
    return 10 ** ((rssi_0 - rssi) / (10 * n))

# Function to extract RSSI and MAC address for each packet
def extract_rssi_and_mac(packet):
    rssi = packet.dBm_AntSignal if hasattr(packet, "dBm_AntSignal") else -100  # Default RSSI if not present
    mac = packet.addr2  # MAC address of the device sending the packet
    return mac, rssi

# Function to process the pcap and extract MAC addresses and their corresponding RSSI values
def process_pcap(file_name):
    packets = rdpcap(file_name)
    device_data = defaultdict(list)

    for packet in packets:
        if packet.haslayer(Dot11):
            mac, rssi = extract_rssi_and_mac(packet)
            device_data[mac].append(rssi)

    return device_data

# Function to create a scatter plot showing MAC addresses and their RSSI values
def plot_rssi_scatter(data):
    plt.figure(figsize=(10, 6))

    # Create a color map with distinct colors for each MAC address
    color_map = cm.get_cmap("tab20")  # Choose a colormap
    mac_to_color = {}  # Dictionary to map each MAC address to a unique color
    color_index = 0  # Counter to assign a unique color to each MAC address

    # Lists for plotting
    all_macs = []
    all_rssi_values = []
    all_colors = []

    # Loop through all devices (MAC addresses) and their RSSI values
    for device_mac, rssi_values in data.items():
        color = color_map(color_index / len(data))  # Normalize the color index
        mac_rssi_values = np.array(rssi_values)

        # Add the MAC address to the list and associate it with the color
        all_macs.extend([device_mac] * len(mac_rssi_values))
        all_rssi_values.extend(mac_rssi_values)
        all_colors.extend([color] * len(mac_rssi_values))

        mac_to_color[device_mac] = color  # Map MAC to its color
        color_index += 1

    # Scatter plot: x = MAC address (as index), y = RSSI value, color = MAC address color
    plt.scatter(all_macs, all_rssi_values, c=all_colors, alpha=0.7, edgecolors='w', s=100)

    # Labeling
    plt.title('RSSI Values of Devices (MAC Addresses) Over Time')
    plt.xlabel('Device MAC Address')
    plt.ylabel('RSSI Value')

    # Rotate x-axis labels to show the MAC addresses (optional)
    plt.xticks(rotation=90)

    # Add grid for better readability
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)

    # Display legend with MAC addresses mapped to colors
    handles, labels = plt.gca().get_legend_handles_labels()
    plt.legend(handles, labels, title="MAC Addresses", bbox_to_anchor=(1.2, 1.05))

    # Show the plot with tight layout to avoid clipping
    plt.tight_layout()
    plt.show()

# Main function to execute
def main():
    device_data = process_pcap(file_name)
    plot_rssi_scatter(device_data)

if __name__ == "__main__":
    main()
