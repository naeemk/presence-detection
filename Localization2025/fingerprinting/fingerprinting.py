import json
import time
from collections import defaultdict, Counter
from .groupbymac import groupbyMAC
from .groupbyssid import groupbySSID
from .groupbyfeature import groupbyFeature
from .match_and_sort_clusters import match_and_sort_fuzzy
from .process_feature_groups import process_feature_groups
import os


# Load configuration
def load_config(filename="./config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()

# Accessing values from the config
ssid_common_threshold = config["fingerprint"]["ssid_common_threshold"]  # Threshold ratio for common SSIDs
group_ssid_match_threshold = config["fingerprint"]["group_ssid_match_threshold"]  # Threshold for SSID similarity

previous_dict = defaultdict(list)

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

def fingerprint(probe_data, start_time):
    common_ssids = get_common_ssids(probe_data, ssid_common_threshold)
    print("Common SSIDs (to ignore):")
    print(common_ssids)  # Output: {"<Hidden >", "eduroam"})

    mac_data = groupbyMAC(probe_data)

    ssid_data = groupbySSID(mac_data, group_ssid_match_threshold, common_ssids)

    feature_data = groupbyFeature(ssid_data)
    
    last_save_time = start_time
    current_time = time.time()
    elapsed_time = current_time - last_save_time

    if elapsed_time >= 60:
        # Update the last save time to the current time
        last_save_time = current_time
        
        # Collect data to save
        data_to_save = {
            "ssid_data_length": len(ssid_data),
            "feature_data_length": len(feature_data),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_time))
        }

        output_file = "data/MergedGroupsPerMin.json"
        if os.path.exists(output_file):
            with open(output_file, "r") as file:
                existing_data = json.load(file)
        else:
            existing_data = []

        existing_data.append(data_to_save)

        with open(output_file, "w") as file:
            json.dump(existing_data, file, indent=4)

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