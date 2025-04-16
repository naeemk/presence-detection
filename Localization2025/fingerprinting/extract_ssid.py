import json
import time
from collections import defaultdict

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()
TIME_LIMIT = 1

def extract_ssid(mac_data):
    ssid_set = []
    
    for mac, entries in mac_data.items():
        extract_ssid
        for entry in entries:
            ssid = entry["SSID"]
            if ssid:
                ssid_set.add(ssid)
        extract_ssid[mac] = list(ssid_set)

    return extract_ssid

