from functions.utils.rssi_to_distance import rssi_to_distance
from objects.device import Device
from objects.proberequest import ProbeRequest
import time

def update(common_queue, devices, lock):
    counter = 0
    max_distance = 5
    while True:
        time.sleep(0.5)
        with lock:
            three_elements = common_queue.get()
            
    #for each element in common queue
    # get it, 
    # get its fingerprint, which should be the same on all 3
    # get its rssi's of all 3
    # get sniffercords of all 3
    # perform trilateration to calculate coords
    # create device object with fingerprint and coords that was just calculated
    # check devices whether to update or add new device


    