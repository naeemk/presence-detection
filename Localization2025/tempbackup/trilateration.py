from distance_measurement import calculate_distance_beacon_to_device
import numpy as np
import math
import json
from concurrent.futures import ThreadPoolExecutor

beacon_positions = [(x1, y1), (x2, y2), (x3, y3)]  # Example fixed positions of beacons

# Function to check if points are collinear
def are_collinear(p1, p2, p3):
    # Unpack points
    x1, y1 = p1
    x2, y2 = p2
    x3, y3 = p3
    
    # Calculate the area of the triangle formed by the three points
    area = abs(x1*(y2 - y3) + x2*(y3 - y1) + x3*(y1 - y2)) / 2
    return area == 0

def trilateration(beacon_positions, rssi_values, A=-50, n=3):
    """
    Estimate receiver's position using trilateration with RSSI-based distances.

    :param beacon_positions: List of (x, y) coordinates of three transmitters.
    :param rssi_values: List of RSSI values from the three transmitters.
    :param A: RSSI at 1 meter (default -50 dBm).
    :param n: Path loss exponent (default 3).
    :return: Estimated (x, y) position of the receiver.
    """
    # Convert RSSI values to distances
    distances = [calculate_distance_beacon_to_device(rssi, A, n) for rssi in rssi_values]

    # Extract beacon positions
    (x1, y1), (x2, y2), (x3, y3) = beacon_positions
    r1, r2, r3 = distances

    # Trilateration calculations (solving a system of equations)
    A = 2 * (x2 - x1)
    B = 2 * (y2 - y1)
    D = 2 * (x3 - x1)
    E = 2 * (y3 - y1)

    C = r1**2 - r2**2 - x1**2 - y1**2 + x2**2 + y2**2
    F = r1**2 - r3**2 - x1**2 - y1**2 + x3**2 + y3**2

    # Solve for x and y using linear algebra
    xy_matrix = np.array([[A, B], [D, E]])
    pos_vector = np.array([C, F])
    
    try:
        estimated_position = np.linalg.solve(xy_matrix, pos_vector)
        return estimated_position[0], estimated_position[1]
    except np.linalg.LinAlgError:
        return None  # No solution due to collinear beacons
    
def process_multiple_devices(beacon_positions, rssi_data_for_devices):
    """
    Process RSSI data for multiple devices concurrently.
    
    :param beacon_positions: List of beacon positions (fixed).
    :param rssi_data_for_devices: Dictionary where key is device ID and value is list of RSSI values.
    :return: Dictionary of estimated positions for each device.
    """
    device_positions = {}

    with ThreadPoolExecutor() as executor:
        # Use parallel execution to calculate positions for multiple devices
        futures = {device_id: executor.submit(trilateration, beacon_positions, rssi) 
                   for device_id, rssi in rssi_data_for_devices.items()}

        for device_id, future in futures.items():
            position = future.result()
            if position:
                device_positions[device_id] = position
            else:
                device_positions[device_id] = "Invalid position (collinear beacons)"

    return device_positions
    