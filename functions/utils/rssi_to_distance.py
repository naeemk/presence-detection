import random


def rssi_to_distance(rssi):
    if rssi != None:
        return abs(rssi)
    else:
        return random.randint(1,100)
        # return None