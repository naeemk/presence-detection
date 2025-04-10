import json
import time

from collections import defaultdict

def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)
config = load_config()

TIME_WINDOW = config["general"]["time_window"]

def cluster_data(data):
    clustered_results = []
    device_clusters = {}
    current_time = time.time()  # Get the current time in seconds

    # Sort data by Device_Name
    data.sort(key=lambda x: x["Device_Name"])

    for entry in data:
        device_name = entry["Device_Name"]
        timestamp = entry["Timestamp"]
        
        # Check if the timestamp is within the time window (current_time - timestamp <= TIME_WINDOW)
        if current_time - timestamp > TIME_WINDOW:
            continue

        # Initialize the device cluster if it doesn't exist
        if device_name not in device_clusters:
            device_clusters[device_name] = {
                "Device_Name": device_name,
                "MAC": [],
                "SSID": [],
                "RSSI": [],
                "First_Timestamp": timestamp,
                "Last_Timestamp": timestamp,
                "Features": entry["Features"]
            }

        # Add the MAC address if it doesn't already exist in the list
        if entry["MAC"] not in device_clusters[device_name]["MAC"]:
            device_clusters[device_name]["MAC"].append(entry["MAC"])

        # Add the SSID if it doesn't already exist in the list
        if entry["SSID"] not in device_clusters[device_name]["SSID"]:
            device_clusters[device_name]["SSID"].append(entry["SSID"])

        # Update the timestamps
        device_clusters[device_name]["Last_Timestamp"] = max(device_clusters[device_name]["Last_Timestamp"], timestamp)

    # Calculate the average RSSI for each device and build the final clustered result
    for device_name, cluster in device_clusters.items():
        # Calculate the average RSSI from the collected data
        avg_rssi = sum([entry["RSSI"] for entry in data if entry["Device_Name"] == device_name and current_time - entry["Timestamp"] <= TIME_WINDOW]) / \
                   len([entry["RSSI"] for entry in data if entry["Device_Name"] == device_name and current_time - entry["Timestamp"] <= TIME_WINDOW])

        clustered_results.append({
            "Device_Name": cluster["Device_Name"],
            "MAC": cluster["MAC"],
            "SSID": cluster["SSID"],
            "Average_RSSI": avg_rssi,
            "First_Timestamp": cluster["First_Timestamp"],
            "Last_Timestamp": cluster["Last_Timestamp"],
            "Features": cluster["Features"]
        })

    # Output the clustered results to a JSON file
    with open("probe_request_results_clustered.json", "w") as outfile:
        json.dump(clustered_results, outfile, indent=4)

    return clustered_results