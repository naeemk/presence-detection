import json
import time
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from distance_measurement import calculate_distance

# Load config
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()
max_distance = config["plot"]["max_distance"]
max_alpha = config["plot"]["max_alpha"]
min_alpha = config["plot"]["min_alpha"]
fade_time = config["plot"]["fade_time"]

# Globals
history_log = []
device_indices = {}
device_counter = 1


def visualize_plot(data):
    global history_log, device_indices, device_counter
    current_time = time.time()

    device_latest = {}

    # Update history log and assign persistent indices
    for device in data:
        device_name = device["Device_Name"]
        first_ts = device["First_Timestamp"]
        last_ts = device["Last_Timestamp"]
        rssi = device["Average_RSSI"]
        distance = calculate_distance(rssi)

        # Assign index once34
        if device_name not in device_indices:
            device_indices[device_name] = device_counter
            device_counter += 1
        device_index = device_indices[device_name]

        entry = (device_index, device_name, first_ts, last_ts, rssi, distance)

        # Only add to history if it's a new (device, timestamp) combination
        if not any(e[1] == device_name and e[2] == first_ts and e[3] == last_ts for e in history_log):
            history_log.append(entry)

        # Track latest entry for this device
        if device_name not in device_latest or last_ts > device_latest[device_name][3]:
            device_latest[device_name] = entry

    # Sort by timestamp for fading
    history_log.sort(key=lambda x: x[2])

    # Plot
    plt.clf()
    plt.gca().legend_ = None
    legend_entries = {}
    
    for entry in history_log:
        device_index, device_name, first_ts, last_ts, rssi, distance = entry
        is_latest = device_latest.get(device_name) == entry

        if is_latest:
            color = (1, 0, 0, 1)  # Opaque red
            plt.scatter(device_index, distance, color=color)
            plt.text(device_index, distance + 0.2, f"{device_name}", fontsize=8)

            # Only add legend once per device
            if device_name not in legend_entries:
                legend_entries[device_name] = Line2D([0], [0], marker='o', color='w',
                                                     label=f"{device_name} / {rssi:.2f}dBm / {distance:.2f}m",
                                                     markerfacecolor=color[:3], markersize=6)
        else:
            age = current_time - first_ts
            alpha = max(min_alpha, max_alpha - (age / fade_time) * (max_alpha - min_alpha))
            alpha = min(max_alpha, max(alpha, min_alpha))
            color = (1, 0, 0, alpha)
            plt.scatter(device_index, distance, color=color)
    
    # Sort legend entries by device index
    sorted_legend_handles = [
        legend_entries[device_name]
        for device_name in sorted(legend_entries, key=lambda name: device_indices[name])
    ]   

    # Finalize plot
    plt.ylim(0, max_distance)
    plt.xlabel("Device Nr.")
    plt.ylabel("Distance (m)")
    plt.title("Device Distance Visualization")

    plt.legend(handles=sorted_legend_handles, loc='center left', bbox_to_anchor=(1, 0.5), fontsize=8)
    plt.xticks(range(1, device_counter))

    plt.tight_layout()
    plt.pause(0.5)
    plt.show()
