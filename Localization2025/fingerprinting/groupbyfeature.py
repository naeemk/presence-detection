import json
from collections import defaultdict

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()
TIME_LIMIT = 1


def groupbyFeature(ssid_data, similarity_threshold=0.8):
    """
    Further groups SSID-based MAC groups based on similarity in Features.
    Args:
        ssid_data (dict): Output from groupbySSID.
        similarity_threshold (float): Jaccard similarity threshold (0 to 1).
    Returns:
        dict: Final grouped data based on feature similarity.
    """
    # Step 1: Parse and collect full feature sets per group

    group_features = {}
    for group_id, group_info in ssid_data.items():
        all_features = set()  # Will hold features for this group
        for entry in group_info["entries"]:
            # Assuming 'Features' is a key in each entry and it's a list of features
            all_features.update(entry.get("Features", []))
        group_features[group_id] = all_features


    # Step 2: Create group clusters
    group_map = {gid: {gid} for gid in ssid_data}
    changed = True

    while changed:
        changed = False
        group_ids = list(group_map.keys())

        for i in range(len(group_ids)):
            gid1 = group_ids[i]
            f1 = group_features.get(gid1, set())

            for j in range(i + 1, len(group_ids)):
                gid2 = group_ids[j]
                f2 = group_features.get(gid2, set())

                if group_map[gid1] == group_map[gid2]:
                    continue

                union = f1 | f2
                if not union:
                    continue  # avoid division by zero

                similarity = len(f1 & f2) / len(union)

                if similarity >= similarity_threshold:
                    print(f"\n🔗 Merging Group {gid1} & {gid2}")
                    print(f"  Shared Features ({len(f1 & f2)}): {f1 & f2}")
                    print(f"  Jaccard Similarity: {similarity:.2f}")
                    print(f"  Group {gid1} Features: {f1}")
                    print(f"  Group {gid2} Features: {f2}")

                    merged = group_map[gid1] | group_map[gid2]
                    for gid in merged:
                        group_map[gid] = merged
                    changed = True

    # Step 3: Deduplicate merged clusters
    unique_groups = {}
    for group in group_map.values():
        unique_groups[frozenset(group)] = group

    # Step 4: Build merged output
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

    # Step 5: Print final groups
    print("======= Final MAC Groups Based on Feature Similarity =======")
    for group_id, group_data in feature_data.items():
        print(f" Group {group_id}:")
        print(f"  MACs: {group_data['macs']}")
        print(f"  Total Entries: {len(group_data['entries'])}")
                # ➕ New section: Collect unique SSIDs
        unique_ssids = sorted(set(entry.get("SSID", "<Unknown SSID>") for entry in group_data["entries"]))
        print(f"  Unique SSIDs in Group: {unique_ssids}")
        for entry in group_data['entries']:
            print(f"    SSID: {entry.get('SSID', '')}")
            print(f"    Features: {entry.get('Features', '')}")
        print("-----------------------------------------------------------")

    return feature_data
