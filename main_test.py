import threading
import queue
import time
import random
import subprocess
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt
from functions.configure_socket import configure_socket
from functions.update_solo import update_solo
from functions.update import update
from functions.communication import send_data, receive_data
from functions.sync_probes import sync_probes
from objects.proberequest import ProbeRequest
from objects.device import Device
from functions import configure_adhoc_network, extract_vendor_specific, process_packet, setup_interface, radar, packet_sniffer, process_burst
from functions import radar



def run():
    while True:
        try:
            to_run = int(input("Please enter a number between 1 and 5: "))
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
            break
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

    
    mon_interface = input("Please enter the network interface for monitor mode: ")
       


    probelist = []
    all_received_probes = []
    common_queue = queue.Queue()
    devices = []
    sniffercords = [None]
    if run_radar == "y":
        sniffercords_ready = threading.Event()
    else:
        sniffercords_ready = None
    lock = threading.Lock()

    interface = "wlan1"
    monitor_interface = setup_interface.setup_interface(interface, mon_interface)
    

    
    my_ip = configure_adhoc_network.configure_adhoc_network()

    sock = configure_socket(my_ip)

    network_ips = [f"10.192.200.{i}" for i in range(1, 255) if f"10.192.200.{i}" != my_ip]


    sniff_thread = threading.Thread(target=packet_sniffer.packet_sniffer,
                                     args=(monitor_interface, probelist, sniffercords, lock, sniffercords_ready), daemon=True)
    
    
    broadcast_probes_thread = threading.Thread(target=send_data,
                                     args=(sock, network_ips, probelist), daemon=True)
    
    
    receive_probes_thread = threading.Thread(target=receive_data,
                                     args=(sock, all_received_probes), daemon=True)
    
    sync_probes_thread = threading.Thread(target=sync_probes,
                                     args=(probelist, all_received_probes, common_queue, lock), daemon=True)

    update_thread = threading.Thread(target=update,
                                    args=(common_queue, devices, lock), daemon=True)
    if to_run > 0:   
        sniff_thread.start()
    if to_run > 1:
        print(f"[main]\tStarting broadcast thread with args: sock={sock}, network_ips={network_ips}, probelist={probelist}, ")
        broadcast_probes_thread.start()
    if to_run > 2:
        print(f"[main]\tStarting receive_probes_thread with args: sock={sock}, all_received_probes={all_received_probes}")
        receive_probes_thread.start()
    if to_run > 3:
        print(f"[main]\tStarting sync_probes_thread with args: probelist={probelist}, all_received_probes={all_received_probes}, 
              common_queue={common_queue}, lock={lock}")
        sync_probes_thread.start()
    if to_run > 4:
        print(f"[main]\tStarting update_thread with args: common_queue={common_queue}, devices={devices}, 
              lock={lock}")
        update_thread.start()
    if run_radar == "y":    
        print(f"[main]\tStarting radar  with args: devices={devices}, sniffercords={sniffercords}, sniffercords_ready={sniffercords_ready}, ")
        radar.radar_main(devices, sniffercords, sniffercords_ready)


if __name__ == "__main__":

    print("[Main] Starting program")
    print("[Main] Starting program")
    print("[Main] Starting program")

    run()
    


















