from utils.rssi_to_distance import rssi_to_distance
from objects.device import Device
from objects.proberequest import ProbeRequest
import time

def update_solo(probelist, devices, lock):
    counter = 0
    with lock:
        while counter < len(probelist):
            distance = rssi_to_distance(probelist[counter].rssi)
            new_device = Device(probelist[counter].fingerprint, distance)
            should_append = True

            for device in devices:
                if device.fingerprint == new_device.fingerprint:
                    device.coordinates == new_device.coordinates
                    should_append = False

            if should_append:
                devices.append(new_device)