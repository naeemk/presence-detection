import threading
import time
from scapy.all import Dot11ProbeReq, RadioTap, Dot11, Dot11Elt
from random import randint
from functions import radarmerged
from functions.update_solo import update_solo

import sys
import os
import random

# Add the path to folder B to the Python path
current_path = os.path.dirname(os.path.abspath(__file__))  # Get the absolute path of the current file
folder_b_path = os.path.abspath(os.path.join(current_path, '..', ''))  # Get the absolute path of folder B
sys.path.append(folder_b_path)  # Add folder B to the Python path
print(folder_b_path)

# Now you can import module c from folder C
from objects.proberequest import ProbeRequest


# Define process_packet function
def process_packet(packet, probelist, sniffercords, lock):
    if packet.haslayer(Dot11ProbeReq):
        print("\nProbe Request Detected:")
        # Extract the MAC address of the device
        mac_address = packet.addr2
        print(f"MAC: {mac_address}")

        # Extract and print RSSI value
        if packet.haslayer(RadioTap):
            rssi = packet[RadioTap].dBm_AntSignal
            print(f"RSSI: {rssi} dBm")
        else:
            rssi = 0
            print("RSSI: Not available")

        # Extract sequence number
        sequence_number = packet[Dot11].SC >> 4
        print(f"Sequence Number: {sequence_number}")

        # Create fingerprint
        fingerprint = ""
        ie_Ids = [1, 10, 45, 50, 191, 221, 127, 3, 35]
        for el in ie_Ids:
            ie = packet.getlayer(Dot11Elt, ID=el)
            if ie:
                fingerprint += ie.info.hex()


        print(f"[process_packet] sniffercords: {sniffercords}")

        # Create probe object and append to list
        with lock:
            print()
            print("process packet acquiring lock")
            print()
            probelist.append(ProbeRequest(mac_address, rssi, fingerprint, sequence_number, sniffercords))
            print("finished processing and appending to probelist")
            mac_addresses = [probe.macaddress for probe in probelist]
            print("probelist so far:", mac_addresses)
            print()





# Define function to generate random packets
def generate_random_packets(process_func, probelist, sniffercords, lock):
    sniffercords_ready.wait()
    while not stop_threads:
        mac_addresses = [
            "00:11:22:33:44:55",
            "aa:bb:cc:dd:ee:ff",
            "12:34:56:78:90:ab",
            "de:ad:be:ef:12:34"
        ]
        # Generate random packet data
        random_mac_address = f"00:11:22:{randint(0, 255)}:{randint(0, 255)}:{randint(0, 255)}"
        random_rssi = randint(-100, 0)  # Random RSSI value between -100 and 0 dBm

        # Create a Dot11ProbeReq packet
        packet = RadioTap(dBm_AntSignal=random_rssi) / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                                                    addr2=random.choice(mac_addresses)) / Dot11ProbeReq()

        # Add the RadioTap layer and set the dBm_AntSignal field

        # Process the packet using the provided function
        print("processing new packet", packet[RadioTap].dBm_AntSignal)
        print("Packet:", packet)

        process_func(packet, probelist, sniffercords, lock)

        # Sleep for a random interval before generating the next packet
        time.sleep(randint(1, 5))

def thread_function():
    global stop_threads
    try:
        while not stop_threads:
            # Print probelist every 10 iterations
            # Perform other tasks if needed
            # For testing, we are just sleeping here
            time.sleep(0.2)
    except KeyboardInterrupt:
        # If Ctrl+C is pressed, stop the threads
        stop_threads = True
        print("Threads stopped.")
        packet_thread.join()


if __name__ == "__main__":
    # Create lists to store probe requests and sniffercords
    probelist = []
    sniffercords = [None]
    localqueue = []
    devices = []
    stop_threads = False
    # Create a lock to ensure thread-safe access to the probelist
    lock = threading.Lock()
    sniffercords_ready = threading.Event()


    

    # Start the packet generation thread
    packet_thread = threading.Thread(target=generate_random_packets,
                                    args=(process_packet, probelist, sniffercords, lock))
    packet_thread.start()

    thread1 = threading.Thread(target=thread_function, daemon=True)
    thread1.start()

    update_solo_thread = threading.Thread(target=update_solo,
                                    args=(probelist, devices, lock))
    update_solo_thread.start()
    print("main block")
    radarmerged.radar_main(devices, sniffercords, sniffercords_ready)



