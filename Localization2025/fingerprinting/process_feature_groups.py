import json
import time
from collections import defaultdict

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()

time_window = config["general"]["time_window"]  # Time window in seconds

def process_feature_groups(feature_data):
    devices = []
    device_counter = 1
    time_window = 60  # in seconds

    for group in feature_data.values():
        macs = set(group.get("macs", []))
        ssids = set()
        rssis = []
        timestamps = []
        features = []

        entries = group.get("entries", [])
        if not entries:
            continue

        # Use the first timestamp as the reference point
        reference_ts = entries[0].get("Timestamp")
        if reference_ts is None:
            continue

        for entry in entries:
            timestamp = entry.get("Timestamp")
            if timestamp is None or abs(timestamp - reference_ts) > time_window:
                continue  # Skip entries outside the time window

            ssids.add(entry.get("SSID", ""))
            rssi = entry.get("RSSI")
            feature_str = entry.get("Features", "")

            if rssi is not None:
                rssis.append(rssi)
            timestamps.append(timestamp)
            if feature_str:
                features.extend([f.strip() for f in feature_str.split(",")])

        if not rssis or not timestamps:
            continue  # Skip this group if missing required data

        #weights = [1 / (current_time - ts + 1) for ts in timestamps]
        #weighted_sum = sum(rssi * weight for rssi, weight in zip(rssi_values, weights))
        #total_weight = sum(weights)
        #average_rssi = round(weighted_sum / total_weight, 1)
        average_rssi = sum(rssis) / len(rssis)

        device = {
            "Device_Name": f"Device {device_counter}",
            "MACs": list(macs),
            "SSIDs": list(ssids),
            "Average_RSSI": average_rssi,
            "First_Timestamp": min(timestamps),
            "Last_Timestamp": max(timestamps),
            "Features": ", ".join(sorted(set(filter(None, features))))
        }

        devices.append(device)
        device_counter += 1
    
    with open("data/devices.json", "w") as json_file:
        json.dump(devices, json_file, indent=4)
    return devices
