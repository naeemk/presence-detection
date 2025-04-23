import json
import time
from collections import defaultdict

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()
TIME_LIMIT = 1

def extract_ssid(sequence_data):
    grouped_ssid = {}
    for mac, entries in sequence_data.items():
        ssid_set = set()

        for entry in entries:
            ssid = entry["SSID"]
            if ssid:
                ssid_set.add(ssid)
        grouped_ssid[mac] = list(ssid_set)

    return grouped_ssid

