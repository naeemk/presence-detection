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

    for ssid_group_id, group_info in ssid_data.items():
        entries = group_info["entries"]
        
        assigned = [False] * len(entries)

        for i in range(len(entries)):
            if assigned[i]:
                continue

            base_entry = entries[i]
            base_feat = normalize_features(base_entry.get("Features", ""))

            subgroup = [base_entry]
            assigned[i] = True

            for j in range(i + 1, len(entries)):
                if assigned[j]:
                    continue

                compare_feat = normalize_features(entries[j].get("Features", ""))
                if are_features_similar(base_feat, compare_feat):
                    subgroup.append(entries[j])
                    assigned[j] = True

            feature_data[current_group_id] = {
                "ssid_group": ssid_group_id,
                "entries": subgroup
            }
            current_group_id += 1

    # Optional debug print
    print("======= Final Device Groups Based on Feature Similarity =======")
    for group_id, group_info in feature_data.items():
        print(f"Group {group_id} (from SSID group {group_info['ssid_group']}): {len(group_info['entries'])} entries")
        for entry in group_info["entries"]:
            print(f"  MAC: {entry['MAC']}, Features: {entry['Features']}")
    print("===============================================================")

    return feature_data
