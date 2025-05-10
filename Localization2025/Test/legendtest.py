import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import random
import time

# Simulated device data: (device_index, device_name, first_timestamp, latest_timestamp, rssi, distance)
device_data = [
    (1, 'Device 1', 100, 200, -73.4, 12.3),
    (1, 'Device 1', 100, 210, -72.1, 13.1),  # Latest
    (2, 'Device 2', 100, 150, -65.0, 5.2),
    (2, 'Device 2', 100, 180, -64.0, 6.1),   # Latest
    (3, 'Device 3', 100, 300, -80.0, 34.2),  # Only one
]

# Assume current time for fading alpha
current_time = 220
min_alpha = 0.2
max_alpha = 1.0
fade_time = 150  # seconds

# Get latest entries per device
device_latest_data = {}
for entry in device_data:
    device_index, device_name, _, latest_timestamp, *_ = entry
    if device_name not in device_latest_data or latest_timestamp > device_latest_data[device_name][3]:
        device_latest_data[device_name] = entry

# Start plotting
plt.figure(figsize=(8, 6))
plt.title("Device Distance Visualization")
plt.xlabel("Device Nr.")
plt.ylabel("Distance (m)")

legend_entries = []

for entry in device_data:
    device_index, device_name, first_timestamp, latest_timestamp, rssi, distance = entry
    if device_latest_data[device_name] == entry:
        color = (1, 0, 0, 1)  # Solid red
        plt.scatter(device_index, distance, color=color)
        plt.text(device_index, distance + 0.2, device_name, fontsize=8)

        legend_entries.append(Line2D([0], [0], marker='o', color='w',
                                     label=f"{device_name} / {rssi:.2f}dBm / {distance:.2f}m",
                                     markerfacecolor=color[:3], markersize=6))
    else:
        age = current_time - first_timestamp
        alpha = max(min_alpha, max_alpha - (age / fade_time) * (max_alpha - min_alpha))
        faded_color = (1, 0, 0, alpha)
        plt.scatter(device_index, distance, color=faded_color)

# Add legend to the right
plt.legend(handles=legend_entries, loc='center left', bbox_to_anchor=(1, 0.5), fontsize=8)
plt.tight_layout()
plt.show()
