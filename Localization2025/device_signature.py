import json
import time
from collections import defaultdict

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()

# Accessing values from the config
required_matches_config = config["device_signature"]["required_matches"]
time_window = config["device_signature"]["time_window"]  # Time window in seconds

device_signatures = {}  # Existing devices
device_counter = 1  # To assign new device IDs
temp_devices = defaultdict(list)  # Temporary devices in Batch 1
semi_devices = defaultdict(list)  # Devices in Batch 2
device_time_stamps = {}  # Time of last capture for each device

# SSID matching threshold (70% similarity)
SSID_MATCH_THRESHOLD = 0.7
MIN_SSID_MATCH_COUNT = 3  # Minimum SSID matches to consider a device a match
MIN_FEATURE_MATCH_COUNT = 2  # Minimum number of required feature matches

# Helper functions
def calculate_ssid_match_percentage(ssids_a, ssids_b):
    """ Calculate the percentage of SSIDs that match between two sets of SSIDs. """
    common_ssids = set(ssids_a).intersection(set(ssids_b))
    match_percentage = len(common_ssids) / len(set(ssids_a)) if ssids_a else 0
    print(f"Calculating SSID match: {ssids_a} vs {ssids_b} -> {len(common_ssids)} common, match percentage = {match_percentage}")
    return match_percentage

def device_age(mac):
    """ Return the time difference between the current time and the last seen time of the device. """
    age = time.time() - device_time_stamps.get(mac, 0)
    print(f"Device {mac} age: {age} seconds")
    return age

def calculate_required_matches(features_list, min_required=MIN_FEATURE_MATCH_COUNT):
    """
    Calculate the required number of feature matches based on the total features in a device signature.
    If the device has fewer features, apply the minimum required threshold.
    
    :param features_list: List of features of the current device.
    :param min_required: Minimum required features for matching.
    :return: The number of required matches.
    """
    total_features = len(features_list)
    required_matches = max(min_required, total_features // 2)  # Ensure at least half of the features need to match
    print(f"Required matches for {total_features} features: {required_matches}")
    return required_matches

def get_device_name(device_signature, ssid_match_priority=True):
    global device_counter

    ssid, mac, features = device_signature
    device_time_stamps[mac] = time.time()  # Update last seen time for the device
    print(f"Processing device signature: {device_signature} (MAC: {mac})")

    # Handle Temporary Devices in Batch 1 - Continuously add data to the same MAC address list
    if mac not in temp_devices:
        temp_devices[mac] = []  # Initialize an empty list for this MAC address
        print(f"Initialized new entry for MAC: {mac} in temp_devices")
    
    # Add the current device signature to the temporary list (Batch 1)
    temp_devices[mac].append((ssid, features))
    print(f"Added device with SSID: {ssid} to temp_devices for MAC: {mac}. Total SSIDs: {len(temp_devices[mac])}")

    # Print the number of SSIDs in the temp_devices list for the current MAC
    print(f"MAC: {mac} - Temp SSIDs: {len(temp_devices[mac])}")

    # Process Batch 2 (semi-stored devices) after a specific time window
    if device_age(mac) > time_window:
        # Move to Batch 2 after the time window expires
        if mac not in semi_devices:
            semi_devices[mac] = []  # Initialize if not already present in semi_devices
            print(f"Initialized new entry for MAC: {mac} in semi_devices")

        # Add the accumulated device signatures from Batch 1 to Batch 2
        semi_devices[mac].extend(temp_devices[mac])
        print(f"Moved {len(temp_devices[mac])} SSID entries from temp_devices to semi_devices for MAC: {mac}")
        
        # Clear temporary list in Batch 1 for this MAC address
        temp_devices[mac] = []
        print(f"Cleared temp_devices for MAC: {mac} after moving to semi_devices.")

        # Print the number of SSIDs in the semi_devices list for the current MAC
        print(f"MAC: {mac} - Semi SSIDs: {len(semi_devices[mac])}")

        # Now, proceed with the semi-device comparison
        for stored_device in semi_devices[mac]:
            stored_ssids = [d[0] for d in stored_device]  # Extract all SSIDs for comparison
            temp_ssids = [d[0] for d in temp_devices[mac]]

            ssid_match_percentage = calculate_ssid_match_percentage(stored_ssids, temp_ssids)
            common_ssids = set(stored_ssids).intersection(set(temp_ssids))
            
            if len(common_ssids) >= MIN_SSID_MATCH_COUNT:
                print(f"Found sufficient SSID matches: {len(common_ssids)} >= {MIN_SSID_MATCH_COUNT}")
                return stored_device[0][1]  # Return the first device name

        # Improved fallback: check SSID match first, then features if SSID match is low
        for existing_signature, existing_device_name in device_signatures.items():
            existing_ssid, existing_mac, existing_features = existing_signature

            if mac == existing_mac:
                # Calculate dynamic required matches based on current device's features
                required_matches_dynamic = calculate_required_matches(features.split(", "))
                
                # Prioritize SSID match, then check features if needed
                existing_features = existing_features.split(", ")
                match_count = sum(1 for f in existing_features if f in features.split(", "))
                print(f"Comparing features for MAC: {mac} -> Match count: {match_count}, required: {required_matches_dynamic}")
                
                if match_count >= required_matches_dynamic:
                    print(f"Features match successful for MAC: {mac}. Device name: {existing_device_name}")
                    return existing_device_name

    # After SSID match check, fallback to batch comparison by checking features
    # Check against existing devices (Batch 3)
    for existing_signature, existing_device_name in device_signatures.items():
        existing_ssid, existing_mac, existing_features = existing_signature

        ssid_match_percentage = calculate_ssid_match_percentage([ssid], [existing_ssid])
        print(f"SSID match percentage for {ssid} vs {existing_ssid}: {ssid_match_percentage}")

        if ssid_match_percentage >= SSID_MATCH_THRESHOLD:
            print(f"SSID match threshold met for MAC: {mac}. Returning device name: {existing_device_name}")
            return existing_device_name

        # Extract and count features for the existing device
        existing_feature_list = existing_features.split(", ") if existing_features else []
        existing_match_count = sum(1 for f in existing_feature_list if f in features.split(", "))
        print(f"Existing feature match count for MAC {mac}: {existing_match_count} / {len(existing_feature_list)}")

        if existing_match_count >= required_matches_dynamic:
            print(f"Feature match threshold met for MAC: {mac}. Returning device name: {existing_device_name}")
            return existing_device_name

    # No match found, assign a new device name
    device_name = f"Device {device_counter}"
    device_signatures[device_signature] = device_name
    device_counter += 1
    print(f"No match found. Assigning new device name: {device_name}")

    return device_name
