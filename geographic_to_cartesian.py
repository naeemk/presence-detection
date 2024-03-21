import math

def geographic_to_cartesian(ref_lon, ref_lat, lon1, lat1, lon2, lat2):
    # Radius of the Earth in meters
    R = 6371000.0

    # Convert reference point latitude and longitude from degrees to radians
    ref_lon_rad = math.radians(ref_lon)
    ref_lat_rad = math.radians(ref_lat)

    # Convert provided coordinates to XY based on the reference point
    def lonlat_to_xy(lon, lat):
        lon_rad = math.radians(lon)
        lat_rad = math.radians(lat)
        x = R * (lon_rad - ref_lon_rad) * math.cos(ref_lat_rad)
        y = R * (lat_rad - ref_lat_rad)
        return x, y

    # Convert the provided coordinates to XY
    ref_x, ref_y = lonlat_to_xy(ref_lon, ref_lat)
    x1, y1 = lonlat_to_xy(lon1, lat1)
    x2, y2 = lonlat_to_xy(lon2, lat2)

    # Calculate differences in x and y axes
    diff_x1 = x1 - ref_x
    diff_y1 = y1 - ref_y
    diff_x2 = x2 - ref_x
    diff_y2 = y2 - ref_y

    return (diff_x1, diff_y1), (diff_x2, diff_y2)

# Example usage:
'''
ref_lon, ref_lat = 5.677191738694266, 58.843097521369714
lon1, lat1 = 5.678947997678502, 58.843103409011356 
lon2, lat2 = 5.677172772614523, 58.843656842858145

diff1, diff2 = geographic_to_cartesian(ref_lon, ref_lat, lon1, lat1, lon2, lat2)
print("Difference in X axis for coordinate 1:", diff1[0], "meters")
print("Difference in Y axis for coordinate 1:", diff1[1], "meters")
print("Difference in X axis for coordinate 2:", diff2[0], "meters")
print("Difference in Y axis for coordinate 2:", diff2[1], "meters")
'''