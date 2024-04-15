from functions.utils.rssi_to_distance import rssi_to_distance
from objects.device import Device
from objects.proberequest import ProbeRequest
import time

def update_solo(probelist, devices, lock):
    counter = 0
    max_distance = 5
    while True:
        time.sleep(0.5)
        with lock:
            while counter < len(probelist):
                distance = rssi_to_distance(probelist[counter].rssi)
                print(f"[update_solo] Calculated rssi: {probelist[counter].rssi} to distance: {distance}")
                if distance > max_distance:
                    counter+=1
                    continue
                new_device = Device(probelist[counter].fingerprint, distance)
                should_append = True
                counter2 = 0
                for device in devices:
                    if device.fingerprint == new_device.fingerprint:
                        print(f"[update_solo] Found device with similar fingerprint at index {counter2}")
                        print(f"[update_solo] Updating distance from {device.coordinates} to {new_device.coordinates}")
                        device.coordinates == new_device.coordinates
                        should_append = False
                    counter += 1

                if should_append:
                    print(f"[update_solo] Did not recognize fingerprint, appending device to list")
                    devices.append(new_device)
                counter += 1
                print("[update_solo] Coordinates of each device")
                for device in devices:
                    print(device.coordinates)