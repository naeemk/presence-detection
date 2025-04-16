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
required_matches_config = config["device_signature"]["required_matches"]
time_window = config["device_signature"]["time_window"]  # Time window in seconds

previous_list = []

def sortbyMAC(probe_data):
    mac_data = defaultdict(list)
    for entry in probe_data:
        mac = entry["MAC"]
        if mac:
            mac_data[mac].append(entry)
    print("=============================================")
    for mac, entries in mac_data.items():
        print(f"MAC Address: {mac}, Entries: {entries}")
    print("=============================================")
    return mac_data

def sortbySSID(mac_data):
    ssid_data = defaultdict(list)
    
    return ssid_data

def sortbyFeature(ssid_data):
    feature_data = defaultdict(list)
    
    return feature_data


def fingerprint(probe_data):
    
    mac_data = sortbyMAC(probe_data)

    ssidsorted = sortbySSID(mac_data)

    featuresorted = sortbyFeature(ssidsorted)
    



    # Create a list to store the new data
    new_list = []

    

    previous_list = new_list
    return new_list

