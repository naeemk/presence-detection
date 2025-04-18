def analyze_feature_changes(ssid_data, feature_data):
    from collections import defaultdict

    # Create mappings from MAC to SSID group and feature group
    mac_to_ssid_group = {}
    mac_to_feature_group = defaultdict(list)

    for ssid_group_id, group in ssid_data.items():
        for mac in group["macs"]:
            mac_to_ssid_group[mac] = ssid_group_id

    for feature_group_id, group in feature_data.items():
        for mac in group["macs"]:
            mac_to_feature_group[mac].append(feature_group_id)

    # Track splits and merges
    ssid_groupings = defaultdict(set)
    for mac, ssid_group in mac_to_ssid_group.items():
        ssid_groupings[ssid_group].add(mac)

    feature_groupings = defaultdict(set)
    for mac, feature_groups in mac_to_feature_group.items():
        for fg in feature_groups:
            feature_groupings[fg].add(mac)

    print("============= Analysis of Feature-Based Merges/Splits =============")
    # Check for splits: MACs that were in the same SSID group but now in different feature groups
    for ssid_id, macs in ssid_groupings.items():
        feature_groups_seen = defaultdict(set)
        for mac in macs:
            for fg in mac_to_feature_group[mac]:
                feature_groups_seen[fg].add(mac)

        if len(feature_groups_seen) > 1:
            macs_by_group = {fg: list(mg) for fg, mg in feature_groups_seen.items()}
            print(f"[Split] Devices from SSID group {ssid_id} were split into multiple feature groups:")
            for fg, macs_in_group in macs_by_group.items():
                print(f"   Feature Group {fg}: {macs_in_group}")

    # Check for merges: MACs from different SSID groups that ended up in the same feature group
    for fg_id, macs in feature_groupings.items():
        ssid_groups = set(mac_to_ssid_group[mac] for mac in macs)
        if len(ssid_groups) > 1:
            print(f"[Merge] Devices from different SSID groups merged into Feature Group {fg_id}:")
            for mac in macs:
                print(f"   MAC: {mac}, originally from SSID group {mac_to_ssid_group[mac]}")
    print("===================================================================")
