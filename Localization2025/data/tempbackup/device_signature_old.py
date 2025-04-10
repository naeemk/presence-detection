import json

def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)
config = load_config()

# Accessing values from the config
required_matches_config = config["device_signature"]["required_matches"]

device_signatures = {}
device_counter = 1

def get_device_name(device_signature):
    """
    Assigns or retrieves the device name based on the device signature.
    A device is considered the same if 3 or more attributes (SSID, MAC, HT, EXT, or Vendor) match.
    If all three features (HT, EXT, and Vendor) are missing, it counts as 1 match.
    """
    global device_counter
    
    # Extract SSID, MAC, and Features
    ssid, mac, features = device_signature

    # Determine if SSID is hidden (empty or None ssid implies hidden)
    is_hidden_ssid = ssid == "<Hidden SSID>"

    # Extract and count specific features
    device_features = features.split(", ") if features else []  # Split only if features exist
    
    # Initialize counts for each feature type
    ht_count = sum(1 for f in device_features if f.startswith("HT:"))
    ext_count = sum(1 for f in device_features if f.startswith("Ext:"))
    vendor_oui_count = sum(1 for f in device_features if f.startswith("Vendor OUI:"))  # Separate Vendor OUI count
    vendor_info_count = sum(1 for f in device_features if f.startswith("Vendor Info:"))  # Separate Vendor Info count
    supported_rates_count = sum(1 for f in device_features if f.startswith("Supported Rates:"))
    rsn_count = sum(1 for f in device_features if f.startswith("RSN:"))


    # Check if all feature types are missing
    all_features_missing = (ht_count == 0 and ext_count == 0 and vendor_oui_count == 0 and vendor_info_count == 0 and
                            supported_rates_count == 0 and rsn_count == 0)

    #print(f"New Device Signature: {device_signature}")
    #print(f"HT Count: {ht_count}, EXT Count: {ext_count}, Vendor OUI Count: {vendor_oui_count}, Vendor Info Count: {vendor_info_count}")
    #print(f"Supported Rates Count: {supported_rates_count}, RSN Count: {rsn_count}")
    #print(f"All Features Missing: {all_features_missing}")

    # Set initial threshold based on whether the SSID is hidden or not
    required_matches = required_matches_config if not is_hidden_ssid else required_matches_config - 1

    # Adjust threshold down based on missing features
    missing_features = 0
    if ht_count == 0:
        missing_features += 1
    if ext_count == 0:
        missing_features += 1
    if vendor_oui_count == 0:
        missing_features += 1
    if vendor_info_count == 0:
        missing_features += 1
    if supported_rates_count == 0:
        missing_features += 1
    if rsn_count == 0:
        missing_features += 1

    # Reduce the required matches by the number of missing features
    required_matches = max(1, required_matches - missing_features)  # Ensure minimum of 1 match

    #print(f"Required Matches (after adjusting for missing features): {required_matches}")

    # Compare against existing device signatures
    for existing_signature, existing_device_name in device_signatures.items():
        existing_ssid, existing_mac, existing_features = existing_signature

        # Check for MAC address match first, and return immediately if they match
        if mac == existing_mac:
            #print(f"MAC Match Found: {mac} == {existing_mac}, considering as same device.")
            return existing_device_name

        # Extract and count features for the existing device
        existing_feature_list = existing_features.split(", ") if existing_features else []
        existing_ht_count = sum(1 for f in existing_feature_list if f.startswith("HT:"))
        existing_ext_count = sum(1 for f in existing_feature_list if f.startswith("Ext:"))
        existing_vendor_oui_count = sum(1 for f in existing_feature_list if f.startswith("Vendor OUI:"))
        existing_vendor_info_count = sum(1 for f in existing_feature_list if f.startswith("Vendor Info:"))
        existing_supported_rates_count = sum(1 for f in existing_feature_list if f.startswith("Supported Rates:"))
        existing_rsn_count = sum(1 for f in existing_feature_list if f.startswith("RSN:"))

        # Initialize match_count
        match_count = 0

        #print(f"Comparing with Existing Device: {existing_device_name}")
        #print(f"Existing SSID: {existing_ssid}, Existing MAC: {existing_mac}")
        #print(f"Existing HT Count: {existing_ht_count}, EXT Count: {existing_ext_count}, Vendor OUI Count: {existing_vendor_oui_count}, Vendor Info Count: {existing_vendor_info_count}")
        #print(f"Existing Supported Rates Count: {existing_supported_rates_count}")

        # Check SSID and Features (HT, EXT, Vendor OUI, Vendor Info, Supported Rates, RSN, WMM) for matching
        if ssid and ssid == existing_ssid:
            match_count += 1
            print("SSID Match")
        if ht_count > 0 and ht_count == existing_ht_count:
            match_count += 1
            print("HT Match")
        if ext_count > 0 and ext_count == existing_ext_count:
            match_count += 1
            print("EXT Match")
        if vendor_oui_count > 0 and vendor_oui_count == existing_vendor_oui_count:
            match_count += 1
            print("Vendor OUI Match")
        if vendor_info_count > 0 and vendor_info_count == existing_vendor_info_count:
            match_count += 1
            print("Vendor Info Match")
        if supported_rates_count > 0 and supported_rates_count == existing_supported_rates_count:
            match_count += 1
            print("Supported Rates Match")
        if rsn_count > 0 and rsn_count == existing_rsn_count:
            match_count += 1
            print("RSN Match")
        # If all HT, EXT, Vendor, Supported Rates, RSN, and WMM features are missing, count as 1 match
        if all_features_missing:
            match_count += 1
            print("All Features Missing, Adding 1 Match")

        print(f"Total Match Count: {match_count}")

        # If the match count meets the threshold, return the existing device name
        if match_count >= required_matches:
            print(f"Matched with {existing_device_name}")
            return existing_device_name

    # No match found, assign a new device name
    device_name = f"Device {device_counter}"
    device_signatures[device_signature] = device_name
    device_counter += 1

    print(f"New Device Assigned: {device_name}")
    return device_name