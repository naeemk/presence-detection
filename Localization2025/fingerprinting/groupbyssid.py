import json
import time
from collections import defaultdict
from .extract_ssid import extract_ssid
# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()


# Accessing values from the config
#required_matches_config = config["fingerprint"]["required_matches"]
#time_window = config["fingerprint"]["time_window"]  # Time window in seconds

def groupbySSID(mac_data, ssid_threshold, common_ssids):
    print("=============================================")
    print("DEBUG")
    print("==============================================")
    grouped_ssid = extract_ssid(mac_data)

    # Filter out common SSIDs from each MAC’s SSID list
    for mac in grouped_ssid:
        grouped_ssid[mac] = [ssid for ssid in grouped_ssid[mac] if ssid not in common_ssids]

    print("Filtered SSID data (common removed):")
    print(grouped_ssid)

    # Build initial groups: one per MAC
    grouped_macs = {mac: {mac} for mac in grouped_ssid}
    print(grouped_macs)

    changed = True
    while changed:
        changed = False
        mac_list = list(grouped_macs.keys())
        n = len(mac_list)
        print(n)
        print("DEBUG 1")
        for i in range(n):
            print(i)
            mac1 = mac_list[i]
            ssids1 = set(grouped_ssid.get(mac1, []))
            print("DEBUG 2")
            for j in range(i + 1, n):
                print(j)
                mac2 = mac_list[j]
                ssids2 = set(grouped_ssid.get(mac2, []))
                print("DEBUG 3")
                # Skip if already in the same group
                if grouped_macs[mac1] == grouped_macs[mac2]:
                    print("DEBUG 3.1")
                    continue

                # Check if they have enough SSIDs in common
                shared_ssids = ssids1.intersection(ssids2)
                if len(shared_ssids) >= ssid_threshold:
                    print("DEBUG 4")
                    # Merge their groups
                    merged_group = grouped_macs[mac1].union(grouped_macs[mac2])
                    for mac in merged_group:
                        grouped_macs[mac] = merged_group
                    changed = True

    # Remove duplicates: convert group sets into a set of frozensets (for uniqueness)
    unique_groups = {}
    for group in grouped_macs.values():
        unique_groups[frozenset(group)] = group

    # Format the result with full probe entries
    ssid_data = defaultdict(list)
    for idx, group in enumerate(unique_groups.values(), start=1):
        group_entries = []
        for mac in group:
            group_entries.extend(mac_data.get(mac, []))

        ssid_data[idx] = {
            "macs": list(group),
            "entries": group_entries
        }

    # Optional: print the grouped info
    print("======= Final MAC Groups Based on SSID Similarity =======")
    for group_id, group_data in ssid_data.items():
        print(f"Group {group_id}: MACs = {group_data['macs']}, Entries = {len(group_data['entries'])} records")
        for entry in group_data['entries']:
            print(f"  SSIDs: {entry.get('SSID', [])}")
        for entry in group_data['entries']:
            print(f"  Features: {entry.get('Features', [])}") 
    print("=========================================================")
    return ssid_data
