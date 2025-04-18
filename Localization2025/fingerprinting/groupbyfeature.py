import json
import time
from collections import defaultdict

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()
TIME_LIMIT = 1

def normalize_features(feature_string):
    # Normalize features string for comparison (strip, lowercase, remove spacing issues)
    return feature_string.strip().lower().replace(" ", "")

def are_features_similar(f1, f2, threshold=0.95):
    # Simple string similarity comparison — tweak as needed
    from difflib import SequenceMatcher
    return SequenceMatcher(None, f1, f2).ratio() >= threshold

def groupbyFeature(ssid_data):
    feature_data = {}
    current_group_id = 1

    print("======= Grouping Devices Based on Feature Similarity =======")

    for ssid_group_id, group_info in ssid_data.items():
        entries = group_info["entries"]
        
        assigned = [False] * len(entries)
        ssid_count = {}  # Track the SSID count for each MAC
        
        # Count the number of unique SSIDs for each MAC
        for entry in entries:
            mac = entry['MAC']
            ssids = entry.get("SSID", [])
            ssid_count[mac] = len(set(ssids))  # Store the number of unique SSIDs for each MAC

        for i in range(len(entries)):
            if assigned[i]:
                continue

            base_entry = entries[i]
            base_feat = normalize_features(base_entry.get("Features", ""))
            base_mac = base_entry["MAC"]
            
            subgroup = [base_entry]
            assigned[i] = True
            subgroup_macs = {base_mac}
            ssid_pool = {base_entry.get("SSID", "")}  # Track SSID pool for base device

            # Now compare it to the other entries
            for j in range(i + 1, len(entries)):
                if assigned[j]:
                    continue

                compare_entry = entries[j]
                compare_feat = normalize_features(compare_entry.get("Features", ""))
                
                # If the features are similar, add the entry to the subgroup
                if are_features_similar(base_feat, compare_feat):
                    # Always keep track of unique SSIDs and features
                    subgroup.append(compare_entry)
                    subgroup_macs.add(compare_entry["MAC"])
                    ssid_pool.update(compare_entry.get("SSID", []))
                    assigned[j] = True

            # If the number of unique SSIDs in the pool is 3 or more, keep this group intact
            if len(ssid_pool) >= 3:
                feature_data[current_group_id] = {
                    "ssid_group": ssid_group_id,
                    "entries": subgroup,
                    "macs": list(subgroup_macs),
                    "ssid_count": len(ssid_pool)
                }
                current_group_id += 1
            else:
                # For groups with fewer than 3 unique SSIDs, still merge if feature similarity is strong
                feature_data[current_group_id] = {
                    "ssid_group": ssid_group_id,
                    "entries": subgroup,
                    "macs": list(subgroup_macs),
                    "ssid_count": len(ssid_pool)
                }
                current_group_id += 1

    # Optional debug print
    print("======= Final Device Groups Based on Feature Similarity =======")
    for group_id, group_info in feature_data.items():
        print(f"Group {group_id} (from SSID group {group_info['ssid_group']}): {len(group_info['entries'])} entries")
        print(f"  SSID Count: {group_info['ssid_count']}")
        
        # Print all the MACs, SSIDs, and Features for each entry in this group
        for entry in group_info["entries"]:
            print(f"  MAC: {entry['MAC']}")
            print(f"    SSIDs: {entry.get('SSID', [])}")
            print(f"    Features: {entry.get('Features', [])}")
        
    print("===============================================================")

    return feature_data
