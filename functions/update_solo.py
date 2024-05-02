from functions.utils.rssi_to_distance import rssi_to_distance
from objects.device import Device
from objects.proberequest import ProbeRequest
from functions.utils.write_to_file import write_to_csv
import time


def update_solo(probelist, devices, lock):
    should_filter = [False, 'Fingerprint here']
    counter = 0
    max_distance = 1000
    while True:
        time.sleep(0.5)
        with lock:
            while counter < len(probelist):
                distance = rssi_to_distance(probelist[counter].rssi)
                rssi = probelist[counter].rssi
                print(f"[update_solo] Calculated rssi: {probelist[counter].rssi} to distance: {distance}")
                if distance > max_distance:
                    counter+=1
                    continue
                new_device = Device(probelist[counter].fingerprint, distance)

                if should_filter[0]:
                    if len(devices) == 0:
                        if new_device.fingerprint == should_filter[1]:
                            devices.append(new_device)
                            write_to_csv('test.csv', 0, new_device.coordinates)
                    elif len(devices) == 1:
                        if new_device.fingerprint == should_filter[1]:
                            devices[0].update(new_device.coordinates)
                            write_to_csv('test.csv', 0, new_device.coordinates)
                    continue

                should_append = True
                counter2 = 0
                for index, device in enumerate(devices):
                    if device.fingerprint == new_device.fingerprint:



                        write_to_csv('test.csv', index, new_device.coordinates)
                        
                        
                        
                        print(f"[update_solo] Found device with similar fingerprint at index {counter2}")
                        print(f"[update_solo] Updating distance from {device.coordinates} to {new_device.coordinates}")
                        device.update(new_device.coordinates)
                        should_append = False
                    counter += 1
                    counter2 += 1

                if should_append:
                    print(f"[update_solo] Did not recognize fingerprint, appending device to list")
                    devices.append(new_device)



                    write_to_csv('test.csv', len(devices), new_device.coordinates)



                counter += 1
                print("[update_solo] Coordinates of each device")
                for device in devices:
                    print(device.coordinates)