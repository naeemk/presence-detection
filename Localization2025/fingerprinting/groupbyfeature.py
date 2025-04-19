import json
from collections import defaultdict

# Optional: load config if needed
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

# Helper: Extract feature tokens from feature string
def parse_feature_string(feature_str):
    if not feature_str:
        return set()

    # Split by comma, strip whitespace, remove duplicates
    parts = [p.strip() for p in feature_str.split(",") if p.strip()]
    return set(parts)

# Main function: Group by feature similarity between groups
def groupbyFeature(ssid_data, feature_threshold=0.8):
    """
    Further groups SSID-based MAC groups based on similarity in Features (parsed strings).
    
    Args:
        ssid_data (dict): Output from groupbySSID.
        feature_threshold (int): Minimum number of shared feature tokens to merge groups.

    Returns:
        dict: Final grouped data based on feature similarity.
    """
    # Step 1: Build a feature set for each group
    group_features = {}
    for group_id, group_info in ssid_data.items():
        feature_set = set()
        for entry in group_info["entries"]:
            feature_str = entry.get("Features", "")
            feature_tokens = parse_feature_string(feature_str)
            feature_set.update(feature_tokens)
        group_features[group_id] = feature_set


    # Step 2: Initialize each group as its own cluster
    group_map = {gid: {gid} for gid in ssid_data}

    changed = True
    while changed:
        changed = False
        group_ids = list(group_map.keys())

        for i in range(len(group_ids)):
            gid1 = group_ids[i]
            features1 = group_features.get(gid1, set())

            for j in range(i + 1, len(group_ids)):
                gid2 = group_ids[j]
                features2 = group_features.get(gid2, set())

                # Skip if already in the same group
                if group_map[gid1] == group_map[gid2]:
                    continue

                shared = features1 & features2
                if len(shared) >= feature_threshold:
                    # Merge groups
                    merged = group_map[gid1] | group_map[gid2]
                    for gid in merged:
                        group_map[gid] = merged
                    changed = True

    # Step 3: Remove duplicates
    unique_groups = {}
    for group in group_map.values():
        unique_groups[frozenset(group)] = group

    # Step 4: Format final output
    feature_data = defaultdict(dict)
    for idx, group_ids in enumerate(unique_groups.values(), start=1):
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
        print(f"  Group {group_id}:")
        print(f"  MACs: {group_data['macs']}")
        print(f"  Total Entries: {len(group_data['entries'])}")
        for entry in group_data["entries"]:
            print(f"    SSID: {entry.get('SSID', '')}")
            print(f"    Features: {entry.get('Features', '')}")
        print("------------------------------------------------------------")

    return feature_data
