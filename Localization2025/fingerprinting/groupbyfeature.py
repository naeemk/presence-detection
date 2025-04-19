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
    return sum(
        SequenceMatcher(None, candidate_feat, pool_feat).ratio()
        for pool_feat in feature_pool
    ) / len(feature_pool)

def groupbyFeature(ssid_data, similarity_threshold=0.5):
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
            matched_group = None

            for group in groups:
                sim = average_feature_similarity(feat, group["feature_pool"])
                if sim >= similarity_threshold:
                    matched_group = group
                    break

            if matched_group:
                matched_group["entries"].append(entry)
                matched_group["macs"].add(mac)
                matched_group["feature_pool"].append(feat)
                if isinstance(ssids, list):
                    matched_group["ssid_pool"].update(ssids)
                else:
                    matched_group["ssid_pool"].add(ssids)
            else:
                groups.append({
                    "ssid_group": ssid_group_id,
                    "entries": [entry],
                    "macs": {mac},
                    "feature_pool": [feat],
                    "ssid_pool": set(ssids) if isinstance(ssids, list) else {ssids}
                })

        # Convert internal group structure into final output format
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
