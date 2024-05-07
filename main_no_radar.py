import threading
import queue
import time
import random
import subprocess
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt
from functions.configure_socket import configure_socket
from functions.threads import radar
from functions.update_solo import update_solo
from functions.update import update
from functions.communication import send_data, receive_data
from functions.sync_probes import sync_probes
from objects.proberequest import ProbeRequest
from objects.device import Device
from functions import configure_adhoc_network, extract_vendor_specific, process_packet, setup_interface, packet_sniffer, process_burst
from functions.threads import radar



def run():
    probelist = []
    all_received_probes = []
    common_queue = queue.Queue()
    devices = []
    sniffercords = [None]
    sniffercords_ready = threading.Event()
    lock = threading.Lock()

    interface = "wlan1"
    monitor_interface = setup_interface.setup_interface(interface)

    
    my_ip = configure_adhoc_network.configure_adhoc_network()

    sock = configure_socket(my_ip)

    network_ips = [f"10.192.200.{i}" for i in range(1, 255) if f"10.192.200.{i}" != my_ip]


    sniff_thread = threading.Thread(target=packet_sniffer.packet_sniffer,
                                     args=(monitor_interface, probelist, sniffercords, lock, None), daemon=True)
    
    broadcast_probes_thread = threading.Thread(target=send_data,
                                     args=(sock, network_ips, probelist), daemon=True)
    
    receive_probes_thread = threading.Thread(target=receive_data,
                                     args=(sock, all_received_probes), daemon=True)
    
    sync_probes_thread = threading.Thread(target=sync_probes,
                                     args=(probelist, all_received_probes, common_queue, lock), daemon=True)

    update_thread = threading.Thread(target=update,
                                    args=(common_queue, devices, lock), daemon=True)
    
    sniff_thread.start()
    broadcast_probes_thread.start()
    receive_probes_thread.start()
    sync_probes_thread.start()
    update_thread.start()
    


if __name__ == "__main__":

    print("[Main] Starting program")
    print("[Main] Starting program")
    print("[Main] Starting program")

    run()
    


















