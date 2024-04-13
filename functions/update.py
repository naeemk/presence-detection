from functions.utils.rssi_to_distance import rssi_to_distance
from objects.device import Device
from objects.proberequest import ProbeRequest
import time

def update(common_queue, devices, lock):
    pass
    #for each element in common queue
    # get it, 
    # get its fingerprint, which should be the same on all 3
    # get its rssi's of all 3
    # get sniffercords of all 3
    # perform trilateration to calculate coords
