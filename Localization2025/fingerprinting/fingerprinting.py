import json
import time
from collections import defaultdict, Counter
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
threshold_ratio = config["fingerprint"]["threshold_ratio"]  # Threshold ratio for common SSIDs
ssid_threshold = config["fingerprint"]["ssid_threshold"]  # Threshold for SSID similarity

previous_list = []

def get_common_ssids(probe_data, threshold_ratio):
    """
    Given a list of probe_data (each item is a dict containing 'ssid'), 
    return a set of SSIDs that appear too frequently based on the threshold ratio.

    :param probe_data: List[Dict], each containing at least an 'ssid' key
    :param threshold_ratio: float, e.g. 0.5 means SSIDs appearing in over 50% of the data are considered 'too common'
    :return: Set of SSIDs to weigh less or ignore
    """
    ssid_counts = Counter()

    for entry in probe_data:
        ssid = entry.get('SSID')
        if ssid:
            ssid_counts[ssid] += 1

    total_entries = len(probe_data)
    too_common_ssids = {ssid for ssid, count in ssid_counts.items() 
                        if count / total_entries >= threshold_ratio}

    return too_common_ssids

def fingerprint(probe_data):
    common_ssids = get_common_ssids(probe_data, threshold_ratio)
    print("Common SSIDs (to ignore):")
    print(common_ssids)  # Output: {"<Hidden >", "eduroam"}


    mac_data = groupbyMAC(probe_data)

    ssid_data = groupbySSID(mac_data, ssid_threshold)

    feature_data = groupbyFeature(ssid_data)
    


    print(time_window)

    # Create a list to store the new data
    new_list = []

    

    previous_list = new_list
    return new_list

