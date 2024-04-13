from functions.utils.rssi_to_distance import rssi_to_distance
from objects.device import Device
from objects.proberequest import ProbeRequest
import time

def update_solo(probelist, devices, lock):
    counter = 0
    while True:
        time.sleep(0.5)
        with lock:
            print("update solo has lock")
            print(f"checking {counter} < {len(probelist)}")
            while counter < len(probelist):
                print("starting update solo")
                distance = rssi_to_distance(probelist[counter].rssi)
                new_device = Device(probelist[counter].fingerprint, distance)
                should_append = True

                for device in devices:
                    if device.fingerprint == new_device.fingerprint:
                        device.coordinates == new_device.coordinates
                        should_append = False

                if should_append:
                    devices.append(new_device)
                counter += 1
                print("devices: ", devices)