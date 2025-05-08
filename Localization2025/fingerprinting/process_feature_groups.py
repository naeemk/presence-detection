import json
import time
from collections import defaultdict
from kalman_filter import KalmanFilter

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()

time_window = config["general"]["time_window"]  # Time window in seconds

def process_feature_groups(feature_data):
    devices = []
    device_counter = 1
    current_time = time.time()

    for group in feature_data.values():
        macs = set(group.get("macs", []))
        ssids = set()
        rssis = []
        timestamps = []
        features_set = set()

        entries = group.get("entries", [])
        if not entries:
            continue

        for entry in entries:
            timestamp = entry.get("Timestamp")
            if timestamp is None or abs(timestamp - current_time) > time_window:
                continue

            ssids.add(entry.get("SSID", ""))
            rssi = entry.get("RSSI")
            if rssi is not None:
                rssis.append(rssi)

            timestamps.append(timestamp)

            features = entry.get("Features", [])
            features_set.update(features)


        if not rssis or not timestamps:
            continue  # Skip this group if missing required data
        
        # Check if any value in rssis is above 0
        if any(rssi > 0 for rssi in rssis):
            rssis = [0]

        # Apply Kalman filter to RSSI values
        rssis_filtered = KalmanFilter(rssis)

        # Calculate the average filtered RSSI
        average_rssi = sum(rssis_filtered) / len(rssis_filtered)

        # Prepare device data
        device = {
            "Device_Name": f"Device {device_counter}",
            "MACs": list(macs),
            "SSIDs": list(ssids),
            "Probe Request Count": len(entries),
            "RSSIs": rssis,
            "Filtered_RSSIs": rssis_filtered,
            "Average_RSSI": average_rssi,
            "First_Timestamp": min(timestamps),
            "Last_Timestamp": max(timestamps),
            "Features": sorted(features_set)  # Sort features for consistency
        }

        devices.append(device)
        device_counter += 1

    # Save the processed devices data to a JSON file
    with open("data/devices.json", "w") as json_file:
        json.dump(devices, json_file, indent=4)

    return devices