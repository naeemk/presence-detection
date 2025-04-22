import json
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

def plot_groups_rssi(feature_data, mac_data):
    """
    Plots the average RSSI for each MAC address in each group.
    Each point will show the MAC address and its corresponding average RSSI.
    
    Args:
        feature_data (dict): The output of groupbyFeature, containing groups of MACs and their probe entries.
        mac_data (dict): The data containing RSSI values for each MAC address.
    """
    
    group_ids = list(feature_data.keys())  # Group IDs (e.g., 1, 2, 3, ...)
    
    # Iterate over each group in feature_data
    plt.figure(figsize=(12, 8))
    
    for group_id in group_ids:
        group_entries = feature_data[group_id]['entries']
        
        # For each MAC in the group, calculate the average RSSI
        for mac in feature_data[group_id]['macs']:
            if mac in mac_data:
                # Gather RSSI values for the MAC address in this group
                mac_rssis = [entry['RSSI'] for entry in group_entries if entry['MAC'] == mac]
                if mac_rssis:
                    avg_rssi = np.mean(mac_rssis)  # Calculate the average RSSI for the MAC
                    
                    # Plot the MAC with its average RSSI
                    plt.scatter(group_id, avg_rssi, label=mac, alpha=0.7)
                    plt.text(group_id, avg_rssi, mac, fontsize=9, ha='right', va='bottom')

    # Labels and title
    plt.xlabel('Group Number')
    plt.ylabel('Average RSSI')
    plt.title('Average RSSI for Each MAC in Each Group')

    # Add a grid for better readability
    plt.grid(True)

    # Display the plot
    plt.show()

# Example usage (assuming you have mac_data and feature_data already populated)
# mac_data = groupbyMAC(probe_data)  # Obtain MAC data from probe data
# feature_data = groupbyFeature(ssid_data)  # Obtain grouped data based on SSID and features
# plot_groups_rssi(feature_data, mac_data)
