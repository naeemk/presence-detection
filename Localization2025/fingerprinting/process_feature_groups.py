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
    current_time = time.time()
    devices = []

    for idx, (group_key, probes) in enumerate(feature_data.items(), start=1):
        macs = set()
        ssids = set()
        rssi_values = []
        timestamps = []
        features = set()

        for probe in probes:
            ts = probe.get("Timestamp", 0)
            if current_time - time_window <= ts <= current_time:
                macs.add(probe.get("Source", ""))
                ssids.add(probe.get("SSID", "<Unknown SSID>"))
                rssi = probe.get("RSSI")
                if rssi is not None:
                    rssi_values.append(rssi)
                timestamps.append(ts)
                features.add(probe.get("Features", ""))

        if not rssi_values or not timestamps:
            continue
        
        weights = [1 / (current_time - ts + 1) for ts in timestamps]
        weighted_sum = sum(rssi * weight for rssi, weight in zip(rssi_values, weights))
        total_weight = sum(weights)
        average_rssi = round(weighted_sum / total_weight, 1)


        #average_rssi = round(sum(rssi_values) / len(rssi_values), 1)

        device = {
            "Device_Name": f"Device {idx}",
            "MACs": list(macs),
            "SSIDs": list(ssids),
            "Average_RSSI": average_rssi,
            "First_Timestamp": min(timestamps),
            "Last_Timestamp": max(timestamps),
            "Features": ", ".join(sorted(set(filter(None, features))))
        }
        devices.append(device)

    return devices
