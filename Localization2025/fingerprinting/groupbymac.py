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


def groupbyMAC(probe_data):
    mac_data = defaultdict(list)
    for entry in probe_data:
        mac = entry["MAC"]
        if mac:
            mac_data[mac].append(entry)
    print("=============================================")
    print(mac_data)
    for mac, entries in mac_data.items():
        print(f"MAC Address: {mac}, Entries: {entries}")
    print("=============================================")
    return mac_data