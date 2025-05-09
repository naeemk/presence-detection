import json
from collections import defaultdict

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()
TIME_LIMIT = 1

# Define feature weights 🔥
FEATURE_WEIGHTS = {
    "Supported Rates": config["feature_weight"]["supported_rates"],
    "Extended Supported Rates": config["feature_weight"]["extended_supported_rates"],
    "ERP Information": config["feature_weight"]["erp_information"],
    "HT Capabilities": config["feature_weight"]["ht_capabilities"],
    "Extended Capabilities": config["feature_weight"]["extended_capabilities"],
    "VHT Capabilities": config["feature_weight"]["vht_capabilities"],
    "Vendor Specific": config["feature_weight"]["vendor_specific"],
}

def weighted_jaccard(set1, set2, feature_weights):
    weighted_intersection = sum(feature_weights.get(f.split(":")[0], 1) for f in set1 & set2)
    weighted_union = sum(feature_weights.get(f.split(":")[0], 1) for f in set1 | set2)
    if weighted_union == 0:
        return 0
    return weighted_intersection / weighted_union

def groupbyFeature(ssid_data, similarity_threshold=0.8):
    group_features = {}
    
    # Step 1: Collect features per group
    for group_id, group_info in ssid_data.items():
        all_features = set()
        for entry in group_info["entries"]:
            features = entry.get("Features", [])
            all_features.update(features)
        group_features[group_id] = all_features

    # Step 2: Group by weighted Jaccard similarity
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

                similarity = weighted_jaccard(f1, f2, FEATURE_WEIGHTS)

                if similarity >= similarity_threshold:
                    merged = group_map[gid1] | group_map[gid2]
                    for gid in merged:
                        group_map[gid] = merged
                    changed = True

    # Step 3: Merge single-entry MACs with exact feature match
    single_groups = {gid for gid, info in ssid_data.items() if len(info["entries"]) == 1}
    merged_single_groups = set()

    for gid_single in single_groups:
        if gid_single in merged_single_groups:
            continue

        f_single = group_features.get(gid_single, set())

        for gid_other, f_other in group_features.items():
            if gid_single == gid_other or gid_other in single_groups:
                continue

            if f_single == f_other:
                merged = group_map[gid_single] | group_map[gid_other]
                for gid in merged:
                    group_map[gid] = merged
                merged_single_groups.add(gid_single)
                print(f"\n🔍 Exact Match: Merging single-entry group {gid_single} into group {gid_other}")
                break

    # Step 4: Deduplicate merged clusters
    unique_groups = {}
    for group in group_map.values():
        unique_groups[frozenset(group)] = group

    # Step 5: Build merged output
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

    # Step 6: Logging
    print("\n======= Final MAC Groups Based on Weighted Feature Similarity =======")
    for group_id, group_data in feature_data.items():
        print(f" Group {group_id}:")
        print(f"  MACs: {', '.join(group_data['macs'])}")
        print(f"  Total Entries: {len(group_data['entries'])}")

        ssids = set(entry.get("SSID", "") for entry in group_data['entries'])
        print(f"  Unique SSIDs: {', '.join(sorted(ssids))}")
        print("  Entries:")
        for entry in group_data['entries']:
            print(f"    MAC: {entry.get('MAC', '')}")
            print(f"    SSID: {entry.get('SSID', '')}")
            print(f"    RSSI: {entry.get('RSSI', '')}")
            print(f"    Timestamp: {entry.get('Timestamp', '')}")
            print(f"    Features: {entry.get('Features', '')}")
            print("    -------------------")
        print("-----------------------------------------------------------")

    # Step 7: Save output
    with open("data/feature_data.json", "w") as json_file:
        json.dump(feature_data, json_file, indent=4)

    return feature_data
