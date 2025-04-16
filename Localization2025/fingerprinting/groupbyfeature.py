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


def groupbyFeature(ssid_data):
    feature_data = defaultdict(list)
    for entry in ssid_data:
        feature = entry["feature"]
        if feature:
            feature_data[feature].append(entry)
    print("=============================================")
    for ssid, entries in ssid_data.items():
        print(f"SSID Address: {ssid}, Entries: {entries}")
    print("=============================================")
    return ssid_data
        


    



    return feature_data