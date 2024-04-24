import time

class ModifiedObject:
    def __init__(self, radius):
        self.last_modified = time.time()
        self.radius = radius

    def update_last_modified(self):
        self.last_modified = time.time()

    def check_last_modified(self):
        current_time = time.time()
        time_difference = current_time - self.last_modified
        return time_difference

# Example usage
obj = ModifiedObject()
time.sleep(2)  # Simulating some time passing
print("Time since last modified:", obj.check_last_modified())
obj.update_last_modified()
time.sleep(3)  # Simulating some time passing
print("Time since last modification:", obj.check_last_modified(), "seconds")
