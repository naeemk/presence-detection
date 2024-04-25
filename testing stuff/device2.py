import time

class Device:
    def __init__(self, fingerprint, coordinates):
        self.fingerprint = fingerprint
        self.last_modified = time.time()
        if isinstance(coordinates, tuple) and len(coordinates) == 2 and all(isinstance(coord, (int, float)) for coord in coordinates):
            self.coordinates = coordinates
        elif isinstance(coordinates, (int, float)):
            self.coordinates = coordinates
        else:
            raise ValueError("Coordinates must be a number or a tuple of two numbers.")

    def update(self, new_coordinates):
        self.last_modified = time.time()
        if isinstance(new_coordinates, tuple) and len(new_coordinates) == 2 and all(isinstance(coord, (int, float)) for coord in new_coordinates):
            self.coordinates = new_coordinates
        elif isinstance(new_coordinates, (int, float)):
            self.coordinates = new_coordinates
        else:
            raise ValueError("Coordinates must be a number or a tuple of two numbers.")

# Example usage:
device1 = Device("fingerprint1", (10, 20))
print(device1.coordinates)  # Output: (10, 20)

device1.update(30)
print(device1.coordinates)  # Output: 30
