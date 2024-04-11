import threading
import queue
import time
import random
import subprocess
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt
from objects.proberequest import ProbeRequest
from objects.device import Device
from functions import extract_vendor_specific, process_packet, setup_interface, radar, packet_sniffer, process_burst


if __name__ == "__main__":
    unfiltered_probes = []
    local_queue = []
    socket_probe_requests = []
    lock = threading.Lock() 

    setup_interface.setup_interface()

    sniff_thread = threading.Thread(target=packet_sniffer.packet_sniffer, args=(monitor_interface, unfiltered_probes, lock))
    process_burst_thread = threading.Thread(target=process_burst.process_burst, args=(unfiltered_probes, local_queue, lock))

    sniff_thread.start()
    process_burst_thread.start()
    















