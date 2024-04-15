import threading
import queue
import time
import random
import subprocess
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt
from functions.update_solo import update_solo
from objects.proberequest import ProbeRequest
from objects.device import Device
from functions import extract_vendor_specific, process_packet, setup_interface, radar, packet_sniffer, process_burst
from functions import radarmerged

def run_solo():
    probelist = []
    local_queue = []
    devices = []
    sniffercords = [None]
    sniffercords_ready = threading.Event()
    interface = "wlan0"
    lock = threading.Lock()
    monitor_interface = setup_interface.setup_interface(interface)
    
    sniff_thread = threading.Thread(target=packet_sniffer.packet_sniffer, args=(monitor_interface, probelist, sniffercords, lock, sniffercords_ready))
    update_solo_thread = threading.Thread(target=update_solo,
                                    args=(probelist, devices, lock))
    
    sniff_thread.start()
    update_solo_thread.start()
    radarmerged.radar_main(devices, sniffercords, sniffercords_ready)

def run():
    unfiltered_probes = []
    local_queue = []
    socket_probe_requests = []
    lock = threading.Lock() 
    interface = "wlan0"
    monitor_interface = setup_interface.setup_interface(interface)

    sniff_thread = threading.Thread(target=packet_sniffer.packet_sniffer, args=(monitor_interface, unfiltered_probes, lock))
    process_burst_thread = threading.Thread(target=process_burst.process_burst, args=(unfiltered_probes, local_queue, lock))

    sniff_thread.start()
    process_burst_thread.start()


if __name__ == "__main__":
    print("[Main] Starting program")
    print("[Main] Starting program")
    print("[Main] Starting program")
    run_solo()
    


    """
    # Simulating a probe request packet
    from scapy.all import Dot11, RadioTap

    # Craft a simulated probe request packet
    packet = RadioTap() / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2="11:22:33:44:55:66") / Dot11ProbeReq()
    packet = RadioTap() / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2="11:22:33:44:55:66") / Dot11ProbeReq()

    # Call the process_packet function with the simulated packet
    probelist = []
    localqueue = []
    lock = threading.Lock()  # Assuming you're using threading
    process_packet.process_packet(packet, probelist, lock)
    process_packet.process_packet(packet, probelist, lock)
    process_burst.process_burst(probelist, localqueue, lock)
    print(probelist, localqueue)
    """















