import json
from collections import defaultdict
from difflib import SequenceMatcher

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()
TIME_LIMIT = 1

def normalize_features(feature_string):
    return feature_string.strip().lower().replace(" ", "")

def average_feature_similarity(candidate_feat, feature_pool):
    if not feature_pool:
        return 0.0
    scores = [
        SequenceMatcher(None, candidate_feat, pool_feat).ratio()
        for pool_feat in feature_pool
    ]
    return sum(scores) / len(scores)

def groupbyFeature(ssid_data, similarity_threshold=0.8):
    feature_data = {}
    current_group_id = 1

    print("======= Grouping Devices by Comparing Feature Pools =======")

    for ssid_group_id, group_info in ssid_data.items():
        entries = group_info["entries"]
        groups = []

        for entry in entries:
            mac = entry['MAC']
            feat = normalize_features(entry.get("Features", ""))
            ssids = entry.get("SSID", [])
            matched = False

            for group in groups:
                avg_sim = average_feature_similarity(feat, group["feature_pool"])
                if avg_sim >= similarity_threshold:
                    group["entries"].append(entry)
                    group["macs"].add(mac)
                    group["feature_pool"].append(feat)
                    if isinstance(ssids, list):
                        group["ssid_pool"].update(ssids)
                    else:
                        group["ssid_pool"].add(ssids)
                    matched = True
                    break

            if not matched:
                # Create a new group
                groups.append({
                    "ssid_group": ssid_group_id,
                    "entries": [entry],
                    "macs": {mac},
                    "feature_pool": [feat],
                    "ssid_pool": set(ssids) if isinstance(ssids, list) else {ssids}
                })

        # Convert group structure into final output
        for group in groups:
            feature_data[current_group_id] = {
                "ssid_group": group["ssid_group"],
                "entries": group["entries"],
                "macs": list(group["macs"]),
                "ssid_count": len(group["ssid_pool"])
            }
            current_group_id += 1

    # Debug output
    print("======= Final Device Groups Based on Feature Pool Similarity =======")
    for group_id, group_info in feature_data.items():
        print(f"Group {group_id} (from SSID group {group_info['ssid_group']}): {len(group_info['entries'])} entries")
        print(f"  SSID Count: {group_info['ssid_count']}")
        for entry in group_info["entries"]:
            print(f"  MAC: {entry['MAC']}")
            print(f"    SSIDs: {entry.get('SSID', [])}")
            print(f"    Features: {entry.get('Features', [])}")
    print("=====================================================================")

    return feature_data
