import json
import math

def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)
config = load_config()

# Accessing values from the config
rssi_1_meter = config["distance_calculation"]["rssi_1_meter"]
path_loss_exponent = config["distance_calculation"]["path_loss_exponent"]
shadowing_effect = config["distance_calculation"]["shadowing_effect"]
reference_distance = config["distance_calculation"]["reference_distance"]
environmental_correction_constant= config["distance_calculation"]["environmental_correction_constant"]

# Function to calculate distance from RSSI free model
def calculate_distance(rssi):
    """
    Estimate the distance to a device using RSSI.

    :param rssi: Received Signal Strength Indicator (RSSI) in dBm.
    :param A: RSSI at 1 meter distance (default is -50 dBm).
    :param n: Path loss exponent (default is 2 for free-space, but can vary).
    :return: Estimated distance in meters.
    """
    return 10 ** ((rssi_1_meter - rssi) / (10 * path_loss_exponent))

#free loss path model
def calculate_distance_beacon_to_device(rssi):
    """
    Calculate the distance to a device based on RSSI using the Path Loss model.

    :param rssi: Received Signal Strength Indicator (RSSI) in dBm.
    :param A: RSSI at reference distance (typically 1 meter, default is -50 dBm).
    :param n: Path loss exponent (default is 3 for tunnels).
    :param X: Shadowing effect (default is 0).
    :param d0: Reference distance (default is 1 meter).
    :param C: Environmental correction constant (default is 0).
    :return: Estimated distance in meters.
    """
    # Rearranged formula to calculate distance
    distance = reference_distance * 10 ** ((rssi_1_meter - rssi - shadowing_effect + environmental_correction_constant) / (10 * path_loss_exponent))
    return distance

# Function to measure the distance to a fingerprinted device
def measure_distance_to_device(data, device_name):
    """
    Measure the distance to a fingerprinted device using its Average RSSI.

    :param data: List of dictionaries containing fingerprinted device data.
    :param device_name: The Device_Name of the known device.
    :return: Estimated distance to the device.
    """
    # Search for the device by Device_Name
    device_entry = next((entry for entry in data if entry["Device_Name"] == device_name), None)

    if device_entry:
        average_rssi = device_entry["Average_RSSI"]
        print(f"Average RSSI of {device_name}: {average_rssi} dBm")

        # Calculate the estimated distance
        distance = calculate_distance(average_rssi)
        print(f"Estimated distance to {device_name}: {distance:.2f} meters")
        return distance
    else:
        print(f"Device '{device_name}' not found in the data.")
        return None

