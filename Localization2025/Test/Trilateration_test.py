import matplotlib.pyplot as plt
import numpy as np
import random

# Define three fixed beacon positions (simulated)
beacon_positions = [(0, 0), (5, 0), (2, 5)]  # Example coordinates in meters
# Simulate RSSI values from multiple health personnel (simulated as devices in different positions)
personnel_positions = [(-2, -2), (3, 3), (4, -4)]  # Simulated positions for 3 personnel
# Simulate the 4th person in need (position to be found)
person_in_need_position = (1, 1)  # Simulated position of the person in need

def calculate_distance_from_rssi(rssi, A=-50, n=3, d0=1):
    """
    Convert RSSI to estimated distance using the Path Loss Model.
    """
    distance = d0 * 10 ** ((A - rssi) / (10 * n))
    return distance

def generate_fake_rssi(device_position, beacon_position, A=-50, n=3):
    """
    Simulate an RSSI reading for a device at a given position.
    """
    true_distance = np.sqrt((device_position[0] - beacon_position[0])**2 +
                            (device_position[1] - beacon_position[1])**2)
    # Convert true distance to RSSI
    rssi = A - 10 * n * np.log10(true_distance)
    # Add some random noise to simulate real-world conditions
    return round(rssi + random.uniform(-2, 2), 2)

def trilateration(beacon_positions, rssi_values, A=-50, n=3):
    """
    Estimate receiver's position using trilateration with RSSI-based distances.
    """
    # Convert RSSI values to distances
    distances = [calculate_distance_from_rssi(rssi, A, n) for rssi in rssi_values]

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
        return estimated_position[0], estimated_position[1], distances
    except np.linalg.LinAlgError:
        return None  # No solution due to collinear beacons

# Simulate RSSI readings for each personnel and the person in need
personnel_rssi = []
for position in personnel_positions:
    rssi_values = [generate_fake_rssi(position, beacon) for beacon in beacon_positions]
    personnel_rssi.append(rssi_values)

# Run trilateration for each personnel to estimate their positions
for i, rssi_values in enumerate(personnel_rssi):
    print(f"\nEstimating position for Personnel {i+1} at position {personnel_positions[i]}:")

    result = trilateration(beacon_positions, rssi_values)
    
    if result:
        estimated_x, estimated_y, estimated_distances = result
        print("Simulated RSSI Readings")
        for j, (beacon, rssi, distance) in enumerate(zip(beacon_positions, rssi_values, estimated_distances)):
            print(f"Beacon {j+1} at {beacon}: RSSI = {rssi} dBm -> Estimated Distance = {round(distance, 2)} meters")

        print("Position Results")
        print(f"Estimated Position: ({round(estimated_x, 2)}, {round(estimated_y, 2)})")
    else:
        print("Trilateration failed (beacons might be collinear).")

# Simulate RSSI readings for the person in need
rssi_values_for_person_in_need = [generate_fake_rssi(person_in_need_position, beacon) for beacon in beacon_positions]

# Run trilateration to estimate the position of the person in need
print("\nEstimating position for the Person in Need at position", person_in_need_position)

result_for_person_in_need = trilateration(beacon_positions, rssi_values_for_person_in_need)

if result_for_person_in_need:
    estimated_x_in_need, estimated_y_in_need, estimated_distances_in_need = result_for_person_in_need
    print("Simulated RSSI Readings for the Person in Need")
    for j, (beacon, rssi, distance) in enumerate(zip(beacon_positions, rssi_values_for_person_in_need, estimated_distances_in_need)):
        print(f"Beacon {j+1} at {beacon}: RSSI = {rssi} dBm -> Estimated Distance = {round(distance, 2)} meters")

    print("Position Results for the Person in Need")
    print(f"Estimated Position: ({round(estimated_x_in_need, 2)}, {round(estimated_y_in_need, 2)})")
else:
    print("Trilateration failed for the Person in Need (beacons might be collinear).")

# Radar plot setup
fig, ax = plt.subplots(subplot_kw={'projection': 'polar'})

# Set up radar (polar) coordinates
radar_radius = max(max(beacon_positions[0]), max(beacon_positions[1]), max(beacon_positions[2])) + 2
ax.set_ylim(0, radar_radius)

# Plot beacons on radar
for beacon in beacon_positions:
    angle = np.arctan2(beacon[1], beacon[0])
    distance = np.sqrt(beacon[0]**2 + beacon[1]**2)
    ax.plot(angle, distance, 'bo', markersize=10)  # Beacon in blue

# Plot the estimated device positions for all personnel
for i, personnel_position in enumerate(personnel_positions):
    rssi_values = personnel_rssi[i]
    result = trilateration(beacon_positions, rssi_values)
    if result:
        estimated_x, estimated_y, _ = result
        estimated_angle = np.arctan2(estimated_y, estimated_x)
        estimated_distance = np.sqrt(estimated_x**2 + estimated_y**2)
        ax.plot(estimated_angle, estimated_distance, 'ro', markersize=12, label=f'Personnel {i+1} Estimated')

# Plot the estimated position for the person in need
if result_for_person_in_need:
    estimated_angle_in_need = np.arctan2(estimated_y_in_need, estimated_x_in_need)
    estimated_distance_in_need = np.sqrt(estimated_x_in_need**2 + estimated_y_in_need**2)
    ax.plot(estimated_angle_in_need, estimated_distance_in_need, 'go', markersize=12, label='Person in Need (Estimated)')

ax.set_title("Personnel and Person in Need Positions on Radar", va='bottom')
ax.legend(loc='upper right')

plt.show()
