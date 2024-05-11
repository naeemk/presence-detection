import sys

from functions.utils.has_different_sniffer_ips import has_different_sniffer_ips
from functions.utils.write_to_csv import write_to_csv
sys.path.append(".")
from functions.utils.find_last_probes import find_last_probes
from functions.utils.rssi_to_distance import rssi_to_distance
from functions.utils.trilaterate import trilaterate
from objects.device import Device
from objects.proberequest import ProbeRequest
import time

def update(probelist, all_received_probes, devices, lock):
    counter = 0
    max_distance = 1000
    print(f"\n[update]\tStarting update thread")
    while True:
        time.sleep(1)
        if len(all_received_probes) > 0:
            if has_different_sniffer_ips(all_received_probes):
                last_3_probes_by_fingerprint = find_last_probes(probelist, all_received_probes)
                for fingerprint, probes in last_3_probes_by_fingerprint.items():
                    sniffercoords_list = []
                    distance_list = []
                    for probe in probes:
                        sniffercoords_list.append(probe.sniffercords)
                        distance_list.append(probe.distance)
                    x1 = sniffercoords_list[0]['x']
                    y1 = sniffercoords_list[0]['y']
                    d1 = distance_list[0]

                    x2 = sniffercoords_list[1]['x']
                    y2 = sniffercoords_list[1]['y']
                    d2 = distance_list[1]

                    x3 = sniffercoords_list[2]['x']
                    y3 = sniffercoords_list[2]['y']
                    d3 = distance_list[2]
                    device_coordinates = trilaterate(x1, x2, x3, y1, y2, y3, d1, d2, d3)
                    coordinates_tuple = (device_coordinates['x'], device_coordinates['y'])
                    new_device = Device(fingerprint, coordinates_tuple)

                    should_append = True
                    with lock:
                        for index, device in enumerate(devices):
                            if device.fingerprint == new_device.fingerprint:
                                write_to_csv('test.csv', new_device.fingerprint, new_device.coordinates)
                                print(f"[update] Found device with similar fingerprint at index {index}")
                                print(f"[update Updating distance from {device.coordinates} to {new_device.coordinates}")
                                device.update(new_device.coordinates)
                                should_append = False
                            
                        if should_append:
                            print(f"[update] Did not recognize fingerprint, appending device to list")
                            devices.append(new_device)
                            write_to_csv('test.csv', new_device.fingerprint, new_device.coordinates)


        