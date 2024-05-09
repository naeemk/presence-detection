from functions.utils.rssi_to_distance import rssi_to_distance
from functions.utils.trilaterate import trilaterate
from functions.utils.write_to_file import write_to_csv
from objects.device import Device
from objects.proberequest import ProbeRequest
import time

def update(common_queue, devices, lock):
    counter = 0
    max_distance = 1000
    print(f"[update]\tStarting update thread")
    while True:
        time.sleep(0.5)

        
        while counter > len(common_queue):
            with lock:
                three_elements = common_queue[counter]
                print(f"[update]\tReceived common data")
                fingerprint = three_elements['element1'].fingerprint
                x1 = three_elements['element1'].sniffercords['x']
                y1 = three_elements['element1'].sniffercords['y']
                d1 = three_elements['element1'].distance

                x2 = three_elements['element2'].sniffercords['x']
                y2 = three_elements['element2'].sniffercords['y']
                d2 = three_elements['element2'].distance

                x3 = three_elements['element3'].sniffercords['x']
                y3 = three_elements['element3'].sniffercords['y']
                d3 = three_elements['element3'].distance
                
            device_coordinates = trilaterate(x1, x2, x3, y1, y2, y3, d1, d2, d3) # dict with keys "x" "y"
            print(f"[update]\tResult of trilateration: {device_coordinates}")
            coordinates_tuple = (device_coordinates['x'], device_coordinates['y'])
            new_device = Device(fingerprint, coordinates_tuple)


            should_append = True
            with lock:
                for index, device in enumerate(devices):
                    if device.fingerprint == new_device.fingerprint:



                        write_to_csv('test.csv', index, new_device.coordinates)
                        
                        
                        
                        print(f"[update] Found device with similar fingerprint at index {index}")
                        print(f"[update Updating distance from {device.coordinates} to {new_device.coordinates}")
                        device.update(new_device.coordinates)
                        should_append = False
                    

                if should_append:
                    print(f"[update] Did not recognize fingerprint, appending device to list")
                    devices.append(new_device)



                    write_to_csv('test.csv', len(devices), new_device.coordinates)



                
                print("[update] Coordinates of each device")
                for device in devices:
                    print(device.coordinates)






    #for each element in common queue
    # get its fingerprint, which should be the same on all 3
    # get its rssi's of all 3
    # get sniffercords of all 3
    # perform trilateration to calculate coords
    # create device object with fingerprint and coords that was just calculated
    # check devices whether to update or add new device


    