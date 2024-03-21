import math

def geographic_to_cartesian(ref_lat, ref_lon, lat1, lon1, lat2, lon2):
    # Radius of the Earth in meters
    R = 6371000.0

    # Convert reference point latitude and longitude from degrees to radians
    ref_lat_rad = math.radians(ref_lat)
    ref_lon_rad = math.radians(ref_lon)

    # Convert provided coordinates to XY based on the reference point
    def lonlat_to_xy(lat, lon):
        lat_rad = math.radians(lat)
        lon_rad = math.radians(lon)
        x = R * (lon_rad - ref_lon_rad) * math.cos(ref_lat_rad)
        y = R * (lat_rad - ref_lat_rad)
        return x, y

    # Convert the provided coordinates to XY
    ref_x, ref_y = lonlat_to_xy(ref_lat, ref_lon)
    x1, y1 = lonlat_to_xy(lat1, lon1)
    x2, y2 = lonlat_to_xy(lat2, lon2)

    # Calculate differences in x and y axes
    diff1_x = x1 - ref_x
    diff1_y = y1 - ref_y
    diff2_x = x2 - ref_x
    diff2_y = y2 - ref_y

    return {
        'coordinate_1': {'x_difference_meters': diff1_x, 'y_difference_meters': diff1_y},
        'coordinate_2': {'x_difference_meters': diff2_x, 'y_difference_meters': diff2_y}
    }

# Example usage:
'''
ref_lat, ref_lon = 58.853494167352515, 5.673532230205838
lat1, lon1 = 58.85345457204034, 5.6811875142702855
lat2, lon2 = 60.68706059465622, 7.572221870645819

differences = geographic_to_cartesian(ref_lat, ref_lon, lat1, lon1, lat2, lon2)
print("Differences for coordinate 1:")
print("X Difference:", differences['coordinate_1']['x_difference_meters'], "meters")
print("Y Difference:", differences['coordinate_1']['y_difference_meters'], "meters")
print("\nDifferences for coordinate 2:")
print("X Difference:", differences['coordinate_2']['x_difference_meters'], "meters")
print("Y Difference:", differences['coordinate_2']['y_difference_meters'], "meters")
print(differences)
'''