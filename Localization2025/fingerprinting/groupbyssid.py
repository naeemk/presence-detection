import json
import time
from collections import defaultdict

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()
TIME_LIMIT = 1

# Accessing values from the config
#required_matches_config = config["fingerprint"]["required_matches"]
#time_window = config["fingerprint"]["time_window"]  # Time window in seconds


def groupbySSID(mac_data):
    ssid_data = defaultdict(list)
    for entry in mac_data:
        ssid = entry["SSID"]
        if ssid:
            ssid_data[ssid].append(entry)
    print("=============================================")
    for ssid, entries in ssid_data.items():
        print(f"SSID Address: {ssid}, Entries: {entries}")
    print("=============================================")
    return ssid_data
        