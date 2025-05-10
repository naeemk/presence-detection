import json
import time
from collections import defaultdict, Counter
from .groupbymac import groupbyMAC
from .groupbyssid import groupbySSID
from .groupbyfeature import groupbyFeature
from .match_and_sort_clusters import match_and_sort_fuzzy
from .process_feature_groups import process_feature_groups


# Load configuration
def load_config(filename="./config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()

# Accessing values from the config
ssid_common_threshold = config["fingerprint"]["ssid_common_threshold"]  # Threshold ratio for common SSIDs
group_ssid_match_threshold = config["fingerprint"]["group_ssid_match_threshold"]  # Threshold for SSID similarity

previous_dict = defaultdict(list)

oldtestdata = [
    {
        "Device_Name": "Device 1",
        "MACs": ["6e:b9:d7:2e:c3:d1", "3a:d6:e5:18:d1:66"],
        "SSIDs": ["mahabad", "<Hidden SSID>"],
        "Average_RSSI": -71.0,
        "First_Timestamp": 1744822668.7486384,
        "Last_Timestamp": 1744822668.7493975,
        "Features": "Supported Rates: 1.0 Mbps, 2.0 Mbps, 5.5 Mbps, 11.0 Mbps, Extended Supported Rates: 6.0 Mbps, 9.0 Mbps, 12.0 Mbps, 18.0 Mbps, 24.0 Mbps, 36.0 Mbps, 48.0 Mbps, 54.0 Mbps"
    },
    {
        "Device_Name": "Device 2",
        "MACs": ["6e:b9:d7:2e:c3:d2", "3a:d6:e5:18:d1:67"],
        "SSIDs": ["Airport Wifi", "<Hidden SSID>"],
        "Average_RSSI": -50.0,
        "First_Timestamp": 1744822669.7486384,
        "Last_Timestamp": 1744822671.7493975,
        "Features": "Supported Rates: 1.0 Mbps, 2.0 Mbps, 5.5 Mbps, 11.0 Mbps, Extended Supported Rates: 6.0 Mbps, 9.0 Mbps, 12.0 Mbps, 18.0 Mbps, 24.0 Mbps, 36.0 Mbps, 48.0 Mbps, 54.0 Mbps"
    },
    {
        "Device_Name": "Device 3",
        "MACs": ["6e:b9:d7:2e:c3:d3", "3a:d6:e5:18:d1:68"],
        "SSIDs": ["Hotel Wifi", "<Hidden SSID>"],
        "Average_RSSI": -40.0,
        "First_Timestamp": 1744822670.7486384,
        "Last_Timestamp": 1744822672.7493975,
        "Features": "Supported Rates: 1.0 Mbps, 2.0 Mbps, 5.5 Mbps, 11.0 Mbps, Extended Supported Rates: 6.0 Mbps, 9.0 Mbps, 12.0 Mbps, 18.0 Mbps, 24.0 Mbps, 36.0 Mbps, 48.0 Mbps, 54.0 Mbps"
    }
]

testdata = [
    {
        "Device_Name": "Device 1",
        "MACs": ["6e:b9:d7:2e:c3:d1", "3a:d6:e5:18:d1:66"],
        "SSIDs": ["mahabad", "<Hidden SSID>"],
        "Average_RSSI": -70.0,
        "First_Timestamp": 1744822668.7486384,
        "Last_Timestamp": 1744822668.7493975,
        "Features": "Supported Rates: 1.0 Mbps, 2.0 Mbps, 5.5 Mbps, 11.0 Mbps, Extended Supported Rates: 6.0 Mbps, 9.0 Mbps, 12.0 Mbps, 18.0 Mbps, 24.0 Mbps, 36.0 Mbps, 48.0 Mbps, 54.0 Mbps"
    },
    {
        "Device_Name": "Device 2",
        "MACs": ["6e:b9:d7:2e:c3:d3", "3a:d6:e5:18:d1:68"],
        "SSIDs": ["Hotel Wifi", "<Hidden SSID>", "Test SSID"],
        "Average_RSSI": -43.0,
        "First_Timestamp": 1744822670.7486384,
        "Last_Timestamp": 1744822672.7493975,
        "Features": "Supported Rates: 1.0 Mbps, 2.0 Mbps, 5.5 Mbps, 11.0 Mbps, Extended Supported Rates: 6.0 Mbps, 9.0 Mbps, 12.0 Mbps, 18.0 Mbps, 24.0 Mbps, 36.0 Mbps, 48.0 Mbps, 54.0 Mbps"
    },
    {
        "Device_Name": "Device 3",
        "MACs": ["6e:b9:d7:2e:c3:d2", "3a:d6:e5:18:d1:67"],
        "SSIDs": ["Airport Wifi", "<Hidden SSID>"],
        "Average_RSSI": -55.0,
        "First_Timestamp": 1744822669.7486384,
        "Last_Timestamp": 1744822671.7493975,
        "Features": "Supported Rates: 1.0 Mbps, 2.0 Mbps, 5.5 Mbps, 11.0 Mbps, Extended Supported Rates: 6.0 Mbps, 9.0 Mbps, 12.0 Mbps, 18.0 Mbps, 24.0 Mbps, 36.0 Mbps, 48.0 Mbps, 54.0 Mbps"
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

    total_entries = len(probe_data)

    if total_entries <= 15:
        return set()

    for entry in probe_data:
        ssid = entry.get('SSID')
        if ssid:
            ssid_counts[ssid] += 1

    common_ssids = {ssid for ssid, count in ssid_counts.items() 
                        if count / total_entries >= threshold_ratio}

    return common_ssids

def fingerprint(probe_data):
    common_ssids = get_common_ssids(probe_data, ssid_common_threshold)
    print("Common SSIDs (to ignore):")
    print(common_ssids)  # Output: {"<Hidden >", "eduroam"})

    mac_data = groupbyMAC(probe_data)

    ssid_data = groupbySSID(mac_data, group_ssid_match_threshold, common_ssids)

    feature_data = groupbyFeature(ssid_data)
   
    finaldevicegroup = process_feature_groups(feature_data)

    print("===================1==========================")
    print(finaldevicegroup)
    print("=============================================")

    #new_list = match_and_sort_fuzzy(previous_dict, finaldevicegroup)  

    #print("====================4=========================")
    #print(new_list)
    #print("=============================================")
    #previous_dict = new_list

    return finaldevicegroup