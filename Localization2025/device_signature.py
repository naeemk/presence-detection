import json
import time
from collections import defaultdict

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()
TIME_LIMIT = 1

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
    if not features_list:  # If no features are provided
        return 0
    
    total_features = len(features_list)
    required_matches = max(min_required, total_features // 2)  # Ensure at least half of the features need to match
    print(f"Required matches for {total_features} features: {required_matches}")
    return required_matches

def get_device_name(device_signature, ssid_match_priority=True):
    global device_counter

    ssid, mac, features = device_signature
    device_time_stamps[mac] = time.time()  # Update last seen time

    # Ensure features is a list
    if isinstance(features, str):
        features = [f.strip() for f in features.split(",")]

    print(f"Processing device: MAC={mac}, SSID={ssid}, Features={features}")

    # Batch 1: collect all SSIDs/features for the same MAC
    temp_devices[mac].append((ssid, features))
    print(f"[Batch 1] Added SSID to temp_devices[{mac}]. Total collected: {len(temp_devices[mac])}")

    if device_age(mac) >= TIME_LIMIT:
        print(f"[Batch 2] Time window expired for {mac}. Moving data to semi_devices.")
        semi_devices[mac].extend(temp_devices[mac])
        temp_devices[mac] = []  # clear temp list

    # Extract collected SSIDs and features from semi_devices
    collected_ssids = [entry[0] for entry in semi_devices[mac]]
    collected_features = []
    for entry in semi_devices[mac]:
        collected_features.extend(entry[1])
    collected_features = list(set(collected_features))  # remove duplicates

    print(f"[Batch 2] Total SSIDs: {len(collected_ssids)}, Total unique features: {len(collected_features)}")

    # Batch 3: compare against known devices
    for existing_signature, device_name in device_signatures.items():
        existing_ssid, _, existing_features = existing_signature

        # SSID match
        ssid_match = calculate_ssid_match_percentage(collected_ssids, [existing_ssid]) >= SSID_MATCH_THRESHOLD
        # Feature match
        if isinstance(existing_features, str):
            existing_features = [f.strip() for f in existing_features.split(",")]
        feature_match_count = sum(1 for f in existing_features if f in collected_features)
        required_feature_matches = calculate_required_matches(existing_features)

        print(f"[Batch 3] Comparing with {device_name}: SSID match={ssid_match}, Feature matches={feature_match_count}/{required_feature_matches}")

        if ssid_match or feature_match_count >= required_feature_matches:
            print(f"[Match] MAC {mac} matches {device_name}")
            return device_name

    # No match found — assign new device name
    device_name = f"Device {device_counter}"
    device_counter += 1

    # Use latest known data as the representative signature
    representative_ssid = collected_ssids[0] if collected_ssids else "<Unknown>"
    representative_features = ", ".join(collected_features)
    device_signatures[(representative_ssid, mac, representative_features)] = device_name

    print(f"[New Device] No match found. Assigning new name: {device_name}")
    return device_name
