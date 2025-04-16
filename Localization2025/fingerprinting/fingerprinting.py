import json
import time
from collections import defaultdict
from .groupbymac import groupbyMAC
from .groupbyssid import groupbySSID
from .groupbyfeature import groupbyFeature

# Load configuration
def load_config(filename="./config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()

# Accessing values from the config
required_matches_config = config["fingerprint"]["required_matches"]
time_window = config["fingerprint"]["time_window"]  # Time window in seconds

previous_list = []

def fingerprint(probe_data):
    
    mac_data = groupbyMAC(probe_data)

    ssid_data = groupbySSID(mac_data)

    feature_data = groupbyFeature(ssid_data)
    
    print(time_window)

    # Create a list to store the new data
    new_list = []

    

    previous_list = new_list
    return new_list

