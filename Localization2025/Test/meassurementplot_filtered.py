import json
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
import datetime
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from kalman_filter import KalmanFilter

# Index selection variable - change this to select different data points
selected_index = 0

def load_rssi_data(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []
    except json.JSONDecodeError:
        print(f"Invalid JSON format in file: {file_path}")
        return []


def create_boxplot(rssi_data, selected_index=None):
    distance_data = defaultdict(list)
    filtered_distance_data = defaultdict(list)

    for entry in rssi_data:
        distance = entry.get("distance")
        rssi_values = entry.get("rssi_values", [])

        if distance is not None and rssi_values:
            distance_data[distance].extend(rssi_values)

            # Apply Kalman filter to RSSI values
            filtered_values = KalmanFilter(rssi_values)
            filtered_distance_data[distance].extend(filtered_values)

    if not distance_data:
        print("No valid RSSI data found in the file.")
        return None

    distances = sorted(distance_data.keys())
    plot_data = []
    labels = []

    for dist in distances:
        plot_data.append(distance_data[dist])
        plot_data.append(filtered_distance_data[dist])
        labels.append(f'{dist}m')
        labels.append(f'{dist}m (F)')

    fig, ax = plt.subplots(figsize=(14, 7))
    box = ax.boxplot(plot_data, patch_artist=True, labels=labels)

    colors = ['#3498db', '#2ecc71'] * len(distances)
    for patch, color in zip(box['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    ax.set_xlabel('Distance (meters)', fontsize=12)
    ax.set_ylabel('RSSI Value (dBm)', fontsize=12)
    ax.set_title('RSSI Values vs Distance | Original vs Filtered', fontsize=14, fontweight='bold')
    ax.grid(True, linestyle='--', alpha=0.7)

    plt.tight_layout()
    return fig, distance_data


file_path = "data/RSSI_DistanceMeasurements.json"
rssi_data = load_rssi_data(file_path)

if rssi_data:
    fig, _ = create_boxplot(rssi_data, selected_index)
    plt.show()
else:
    print("No data to plot.")
