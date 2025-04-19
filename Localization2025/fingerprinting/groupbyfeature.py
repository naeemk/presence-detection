import json
from collections import defaultdict
from difflib import SequenceMatcher

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()
TIME_LIMIT = 1

def groupbyFeature(ssid_data, feature_threshold=0.8):
    """
    Further groups SSID-based MAC groups based on similarity in Features (dict keys).

    Args:
        ssid_data (dict): Output from groupbySSID.
        feature_threshold (int): Minimum number of shared feature keys to merge groups.

    Returns:
        dict: Final grouped data based on feature similarity.
    """
    # Step 1: Extract set of feature keys per group
    group_features = {}
    for group_id, group_info in ssid_data.items():
        print("Test 1")
        feature_keys = set()
        for entry in group_info["entries"]:
            entry_features = entry.get("Features", {})
            feature_keys.update(entry_features.keys())
        group_features[group_id] = feature_keys

    # Step 2: Initialize each group ID as its own cluster
    group_map = {gid: {gid} for gid in ssid_data}

    changed = True
    while changed:
        print("Test 2")
        changed = False
        group_ids = list(group_map.keys())

        for i in range(len(group_ids)):
            gid1 = group_ids[i]
            f1 = group_features.get(gid1, set())

            for j in range(i + 1, len(group_ids)):
                gid2 = group_ids[j]
                f2 = group_features.get(gid2, set())

                # Skip if already in same group
                if group_map[gid1] == group_map[gid2]:
                    continue

                shared_keys = f1 & f2
                if len(shared_keys) >= feature_threshold:
                    # Merge group clusters
                    merged = group_map[gid1] | group_map[gid2]
                    for gid in merged:
                        group_map[gid] = merged
                    changed = True

    # Step 3: De-duplicate merged groupings
    unique_groups = {}
    for group in group_map.values():
        print("Test 3")
        unique_groups[frozenset(group)] = group

    # Step 4: Build final merged output
    feature_data = defaultdict(dict)
    for idx, group_ids in enumerate(unique_groups.values(), start=1):
        print("Test 4")
        merged_macs = []
        merged_entries = []
        for gid in group_ids:
            merged_macs.extend(ssid_data[gid]["macs"])
            merged_entries.extend(ssid_data[gid]["entries"])

        feature_data[idx] = {
            "macs": merged_macs,
            "entries": merged_entries
        }

    # Final printout
    print("======= Final MAC Groups Based on Feature Similarity =======")
    for group_id, group_data in feature_data.items():
        print(f"\nGroup {group_id}:")
        print(f"  MACs: {group_data['macs']}")
        print(f"  Total Entries: {len(group_data['entries'])}")
        for entry in group_data['entries']:
            print(f"    SSID: {entry.get('SSID', '')}")
            print(f"    Features: {entry.get('Features', {})}")
        print("-----------------------------------------------------------")

    return feature_data