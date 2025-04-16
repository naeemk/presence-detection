import json
import time
from collections import defaultdict
from .extract_ssid import extract_ssid
# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()
TIME_LIMIT = 1
ssid_threshold = 0.8

# Accessing values from the config
#required_matches_config = config["fingerprint"]["required_matches"]
#time_window = config["fingerprint"]["time_window"]  # Time window in seconds

def groupbyssid(grouped_ssid, ssid_threshold):

    # Build initial groups: one per MAC
    grouped_macs = {mac: {mac} for mac in grouped_ssid}

    changed = True
    while changed:
        changed = False
        mac_list = list(grouped_macs.keys())
        n = len(mac_list)

        for i in range(n):
            mac1 = mac_list[i]
            ssids1 = set(grouped_ssid.get(mac1, []))
            for j in range(i + 1, n):
                mac2 = mac_list[j]
                ssids2 = set(grouped_ssid.get(mac2, []))

                # Skip if already in the same group
                if grouped_macs[mac1] == grouped_macs[mac2]:
                    continue

                # Check if they have enough SSIDs in common
                shared_ssids = ssids1.intersection(ssids2)
                if len(shared_ssids) >= ssid_threshold:
                    # Merge their groups
                    merged_group = grouped_macs[mac1].union(grouped_macs[mac2])
                    for mac in merged_group:
                        grouped_macs[mac] = merged_group
                    changed = True

    # Remove duplicates: convert group sets into a set of frozensets (for uniqueness)
    unique_groups = {}
    for group in grouped_macs.values():
        unique_groups[frozenset(group)] = group

    # Return a clean list of MAC groups
    final_groups = [list(group) for group in unique_groups.values()]
    print("======= Final MAC Groups Based on SSID Similarity =======")
    for i, group in enumerate(final_groups, 1):
        print(f"Group {i}: {group}")
    print("=========================================================")
    return final_groups
