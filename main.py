import threading
import queue
import time
import random
import subprocess
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt
from functions.configure_socket import configure_socket
from functions.threads.packet_sniffer_solo import packet_sniffer_solo
from functions.threads.receive_data import receive_data
from functions.threads import radar
from functions.threads.packet_sniffer import packet_sniffer
from functions.threads.sync_probes import sync_probes
from functions.threads.update import update
from functions.threads.update_solo import update_solo
from functions.utils.delete_csv_files import delete_csv_files
from objects.proberequest import ProbeRequest
from objects.device import Device
from functions import configure_adhoc_network, setup_interface
from functions.threads import radar



def main_run():
    while True: 
        try:
            to_run = int(input("How many threads to run (1-5): "))
            if 1 <= to_run <= 5:
                break  # Exit the loop if the number is valid
            else:
                print("Number must be between 1 and 5.")
        except ValueError:
            print("Please enter a valid integer.")

    while True:
        run_radar = input("Do you want to run the radar? (y/n): ").lower()
        if run_radar == 'y':
            break
        elif run_radar == 'n':
            while True:
                coordinates = input("Please enter sniffer coordinates (in the format: a b): ")
                # Split the input string into two numbers
                nums = coordinates.split()
                if len(nums) != 2:
                    print("Invalid input. Please enter two numbers separated by a space.")
                    continue
                try:
                    x, y = map(int, nums)
                    print("Coordinates entered:", (x, y))
                    break
                except ValueError:
                    print("Invalid input. Please enter valid integers for coordinates.")
            break
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

    
    while True:
        try:
            measured_power = float(input("Please enter the measured power (e.g. 40)"))
            if not 10 <= measured_power <= 120:
                print("Bad value")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid number for measured power.")

    while True:
        try:
            n = int(input("Please enter a number for n (e.g. 2): "))
            if not 1 <= n <= 4:
                print("n must be between 1 and 4.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer for n.")

    mon_interface = input("Please enter the network interface for monitor mode: (e.g. wlan1mon) ")
       


    delete_csv_files("probelist.csv", "broadcasted_probes.csv", "all_received_probes.csv")

    probelist = []
    all_received_probes = []
    common_probes = []
    devices = []
    sniffercords = [None]
    if run_radar == "y":
        sniffercords_ready = threading.Event()
    else:
        sniffercords_ready = None
        sniffercords[0] = {'x': x, 'y': y}
    lock = threading.Lock()

    interface = "wlan1"
    monitor_interface = setup_interface.setup_interface(interface, mon_interface)
    

    
    my_ip = configure_adhoc_network.configure_adhoc_network()
    print(f"[startup]\tMy ip is: {my_ip}")
    sock = configure_socket(my_ip)

    network_ips = [f"10.192.200.{i}" for i in range(1, 255) if f"10.192.200.{i}" != my_ip]


    sniff_thread = threading.Thread(target=packet_sniffer,
                                     args=(monitor_interface, probelist, sniffercords, lock, sniffercords_ready, measured_power, n, sock, network_ips, my_ip), daemon=False)
    
    
    
    
    
    receive_probes_thread = threading.Thread(target=receive_data,
                                     args=(sock, all_received_probes), daemon=False)
    


    update_thread = threading.Thread(target=update,
                                    args=(probelist, all_received_probes, devices, lock), daemon=False)
    if to_run > 0:   
        sniff_thread.start()
    if to_run > 1:
        #print(f"[main]\tStarting broadcast thread with args: sock={sock}, network_ips={network_ips}, probelist={probelist}, ")
        #broadcast_probes_thread.start()
        pass
    if to_run > 2:
        print(f"[main]\tStarting receive_probes_thread with args: sock={sock}, all_received_probes={all_received_probes}")
        receive_probes_thread.start()
    if to_run > 3:
        #print(f"[main]\tStarting sync_probes_thread with args: probelist={probelist}, all_received_probes={all_received_probes}, common_queue={common_probes}, lock={lock}")
        #sync_probes_thread.start()
        pass
    if to_run > 4:
        print(f"[main]\tStarting update_thread with args: common_probes={common_probes}, devices={devices}, lock={lock}")
        update_thread.start()
    if run_radar == "y":    
        print(f"[main]\tStarting radar  with args: devices={devices}, sniffercords={sniffercords}, sniffercords_ready={sniffercords_ready}, ")
        radar.radar_main(devices, sniffercords, sniffercords_ready, False)


def main_run_solo():
    delete_csv_files("test.csv")
    probelist = []
    devices = []
    sniffercords = [None]
    interface = input("Please enter the network interface to put into monitor mode with airmon: (e.g. wlan0, wlan1) ")
    mon_interface = input("Please enter the network interface for monitor mode: (e.g. wlan1mon) ")

    while True:
        try:
            measured_power = float(input("Please enter the measured power (e.g. 40)"))
            if not 10 <= measured_power <= 120:
                print("Bad value")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid number for measured power.")

    while True:
        try:
            n = int(input("Please enter a number for n (e.g. 2): "))
            if not 1 <= n <= 4:
                print("n must be between 1 and 4.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer for n.")

    while True:
        run_radar = input("Do you want to run the radar? (y/n): ").lower()
        if run_radar == 'y':
            break
        elif run_radar == 'n':
            while True:
                coordinates = input("Please enter sniffer coordinates (in the format: a b): ")
                # Split the input string into two numbers
                nums = coordinates.split()
                if len(nums) != 2:
                    print("Invalid input. Please enter two numbers separated by a space.")
                    continue
                try:
                    x, y = map(int, nums)
                    print("Coordinates entered:", (x, y))
                    break
                except ValueError:
                    print("Invalid input. Please enter valid integers for coordinates.")
            break
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

    if run_radar == "y":
        sniffercords_ready = threading.Event()
    else:
        sniffercords_ready = None
        sniffercords[0] = {'x': x, 'y': y}

    lock = threading.Lock()
    monitor_interface = setup_interface.setup_interface(interface, mon_interface)
    
    sniff_thread = threading.Thread(target=packet_sniffer_solo,
                                     args=(monitor_interface, probelist, sniffercords, lock, sniffercords_ready, measured_power, n), daemon=False)
    update_solo_thread = threading.Thread(target=update_solo,
                                    args=(probelist, devices, lock), daemon=False)
    
    sniff_thread.start()
    update_solo_thread.start()
    if run_radar == "y":
        radar.radar_main(devices, sniffercords, sniffercords_ready, True)

if __name__ == "__main__":

    print("[Main] Starting program")

    run_solo = input("Do you want to run solo? (y/n): ").lower()
    if run_solo == 'y':
        main_run_solo()
    else:
        main_run()
    


















