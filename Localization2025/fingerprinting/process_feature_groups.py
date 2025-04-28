import json
import time
from collections import defaultdict
from kalman_filter import KalmanFilter  # <-- import Kalman filter

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
        features = set()

        entries = group.get("entries", [])
        if not entries:
            continue

        reference_ts = entries[0].get("Timestamp")
        if reference_ts is None:
            continue

        kf = KalmanFilter()  # <-- instantiate a Kalman Filter per device group

        for entry in entries:
            timestamp = entry.get("Timestamp")
            if timestamp is None or abs(timestamp - reference_ts) > time_window:
                continue

            ssids.add(entry.get("SSID", ""))
            rssi = entry.get("RSSI")
            feature_list = entry.get("Features", [])

            if rssi is not None:
                filtered_rssi = kf.filter(rssi)  # <-- apply Kalman filter here
                rssis.append(filtered_rssi)
            timestamps.append(timestamp)

            if feature_list:
                features.update(f.strip() for f in feature_list if f.strip())

        if not rssis or not timestamps:
            continue

        average_rssi = sum(rssis) / len(rssis)

        device = {
            "Device_Name": f"Device {device_counter}",
            "MACs": list(macs),
            "SSIDs": list(ssids),
            "Average_RSSI": average_rssi,
            "First_Timestamp": min(timestamps),
            "Last_Timestamp": max(timestamps),
            "Features": ", ".join(sorted(features))
        }

        devices.append(device)
        device_counter += 1

    with open("data/devices.json", "w") as json_file:
        json.dump(devices, json_file, indent=4)

    return devices
