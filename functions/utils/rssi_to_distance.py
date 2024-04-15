import random


def rssi_to_distance(rssi):
    measured_power = 40
    n = 2
    distance = 10 ** ((-measured_power - rssi) / (10 * n))
    return distance

    



