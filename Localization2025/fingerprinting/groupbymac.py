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
            
    with open("data/mac_data.json", "w") as json_file:
        json.dump(mac_data, json_file, indent=4)

    return mac_data