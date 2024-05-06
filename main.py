import threading
import queue
import time
import random
import subprocess
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt
from functions.update_solo import update_solo
from functions.update import update
from functions.communication import create_udp_socket, broadcast_probes, receive_probes
from functions.sync_probes import sync_probes
from objects.proberequest import ProbeRequest
from objects.device import Device
from functions import extract_vendor_specific, process_packet, setup_interface, radar, packet_sniffer, process_burst, configure_adhoc
from functions import radar



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

    
    ssid = 'AdHocNetwork'  
    channel = 1  

    
    configure_adhoc.configure_adhoc_network(interface, ssid, channel)

    interface_ip = "0.0.0.0"
    listen_port = "12345"

    udp_socket = create_udp_socket(interface_ip, listen_port)

    sniff_thread = threading.Thread(target=packet_sniffer.packet_sniffer,
                                     args=(monitor_interface, probelist, sniffercords, lock, sniffercords_ready), daemon=True)
    
    broadcast_probes_thread = threading.Thread(target=broadcast_probes,
                                     args=(probelist, udp_socket), daemon=True)
    
    receive_probes_thread = threading.Thread(target=broadcast_probes,
                                     args=(probelist, udp_socket), daemon=True)
    
    sync_probes_thread = threading.Thread(target=sync_probes,
                                     args=(probelist, all_received_probes, common_queue), daemon=True)

    update_thread = threading.Thread(target=update,
                                    args=(all_received_probes, udp_socket), daemon=True)
    
    sniff_thread.start()
    broadcast_probes.start()
    receive_probes_thread.start()
    sync_probes_thread.start()
    update_thread.start()
    radar.radar_main(devices, sniffercords, sniffercords_ready)


if __name__ == "__main__":

    print("[Main] Starting program")
    print("[Main] Starting program")
    print("[Main] Starting program")

    run()
    


















