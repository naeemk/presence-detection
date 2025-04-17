import json
import time
from collections import defaultdict, Counter
from .groupbymac import groupbyMAC
from .groupbyssid import groupbySSID
from .groupbyfeature import groupbyFeature
from .match_and_sort_clusters import match_and_sort_fuzzy


# Load configuration
def load_config(filename="./config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()

# Accessing values from the config
time_window = config["fingerprint"]["time_window"]  # Time window in seconds
threshold_ratio = config["fingerprint"]["threshold_ratio"]  # Threshold ratio for common SSIDs
ssid_threshold = config["fingerprint"]["ssid_threshold"]  # Threshold for SSID similarity

previous_list = []

oldtestdata = [
    {
        "device_name": "Device 1",
        "macs": ["6e:b9:d7:2e:c3:d1", "3a:d6:e5:18:d1:66"],
        "ssids": ["mahabad", "<Hidden SSID>"],
        "avg_rssi": -71.0,
        "first_seen": 1744822668.7486384,
        "last_seen": 1744822668.7493975,
        "features": "Supported Rates: 1.0 Mbps, 2.0 Mbps, 5.5 Mbps, 11.0 Mbps, Extended Supported Rates: 6.0 Mbps, 9.0 Mbps, 12.0 Mbps, 18.0 Mbps, 24.0 Mbps, 36.0 Mbps, 48.0 Mbps, 54.0 Mbps"
    },
    {
        "device_name": "Device 2",
        "macs": ["6e:b9:d7:2e:c3:d2", "3a:d6:e5:18:d1:67"],
        "ssids": ["Airport Wifi", "<Hidden SSID>"],
        "avg_rssi": -50.0,
        "first_seen": 1744822669.7486384,
        "last_seen": 1744822671.7493975,
        "features": "Supported Rates: 1.0 Mbps, 2.0 Mbps, 5.5 Mbps, 11.0 Mbps, Extended Supported Rates: 6.0 Mbps, 9.0 Mbps, 12.0 Mbps, 18.0 Mbps, 24.0 Mbps, 36.0 Mbps, 48.0 Mbps, 54.0 Mbps"
    }
]

testdata = [
    {
        "device_name": "Device 2",
        "macs": ["6e:b9:d7:2e:c3:d1", "3a:d6:e5:18:d1:66"],
        "ssids": ["mahabad", "<Hidden SSID>"],
        "avg_rssi": -71.0,
        "first_seen": 1744822668.7486384,
        "last_seen": 1744822668.7493975,
        "features": "Supported Rates: 1.0 Mbps, 2.0 Mbps, 5.5 Mbps, 11.0 Mbps, Extended Supported Rates: 6.0 Mbps, 9.0 Mbps, 12.0 Mbps, 18.0 Mbps, 24.0 Mbps, 36.0 Mbps, 48.0 Mbps, 54.0 Mbps"
    },
    {
        "device_name": "Device 1",
        "macs": ["6e:b9:d7:2e:c3:d2", "3a:d6:e5:18:d1:67"],
        "ssids": ["Airport Wifi", "<Hidden SSID>"],
        "avg_rssi": -50.0,
        "first_seen": 1744822669.7486384,
        "last_seen": 1744822671.7493975,
        "features": "Supported Rates: 1.0 Mbps, 2.0 Mbps, 5.5 Mbps, 11.0 Mbps, Extended Supported Rates: 6.0 Mbps, 9.0 Mbps, 12.0 Mbps, 18.0 Mbps, 24.0 Mbps, 36.0 Mbps, 48.0 Mbps, 54.0 Mbps"
    }
]


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
    common_ssids = {ssid for ssid, count in ssid_counts.items() 
                        if count / total_entries >= threshold_ratio}

    return common_ssids

def fingerprint(probe_data):
    common_ssids = get_common_ssids(probe_data, threshold_ratio)
    print("Common SSIDs (to ignore):")
    print(common_ssids)  # Output: {"<Hidden >", "eduroam"}


    mac_data = groupbyMAC(probe_data)

    ssid_data = groupbySSID(mac_data, ssid_threshold, common_ssids)

    feature_data = groupbyFeature(ssid_data)
    
    print("=======================1======================")
    #print(previous_list)
    print("=============================================")

    print("===================2==========================")
    #print(feature_data)
    print("=============================================")

    #new_list = match_and_sort_fuzzy(oldtestdata, testdata)  

    print("====================3=========================")
    #print(new_list)
    print("=============================================")
    #previous_list = new_list

    return None

