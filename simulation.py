import threading
import time
from scapy.all import Dot11ProbeReq, RadioTap, Dot11, Dot11Elt
from random import randint

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
def process_packet(packet, probelist, geocords, lock):
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

        # Create probe object and append to list
        with lock:
            print()
            print("process packet acquiring lock")
            print()
            probelist.append(ProbeRequest(mac_address, rssi, fingerprint, sequence_number, geocords))
            print("finished processing and appending to probelist")
            mac_addresses = [probe.macaddress for probe in probelist]
            print("probelist so far:", mac_addresses)
            print()


def process_burst(probelist, localqueue, lock):
    counter = 0
    while not stop_threads:
        time.sleep(2)
        with lock:
            print()
            print("probe burst acquiring lock")
            
            
            print()
            
            if len(probelist) >= 2:
                while counter +1 < len(probelist):
                    if counter + 1 < len(probelist) and probelist[counter].macaddress != probelist[counter + 1].macaddress:
                        print("Found the element followed by a different MAC address")
                        element_to_push = probelist[counter]
                        localqueue.append(element_to_push)

                        # print so far
                        print("localqueue so far:")
                        for j, probe in enumerate(localqueue, 1):
                            print(f"Probe {j}:")
                            print(f"  MAC Address: {probe.macaddress}")
                            print(f"  RSSI: {probe.rssi}")
                            print(f"  Fingerprint: {probe.fingerprint}")
                            print(f"  Sequence number: {probe.sequencenumber}")

                        # Move counter to the next element
                        counter += 1
                    else:
                        # Increment the counter
                        print("did not go into the if")
                        print("length of probelist: ", len(probelist))
                        print("counter is ", counter)
                        print("element mac + next mac")
                        print(probelist[counter].macaddress, probelist[counter+1].macaddress)
                        counter += 1
            else:
                # If probelist doesn't have enough elements, wait for more data
                time.sleep(1)


# Define function to generate random packets
def generate_random_packets(process_func, probelist, geocords, lock):
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
        packet = RadioTap() / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                                    addr2=random.choice(mac_addresses)) / Dot11ProbeReq()

        # Add the RadioTap layer and set the dBm_AntSignal field

        # Process the packet using the provided function
        print("processing new packet")
        process_func(packet, probelist, geocords, lock)

        # Sleep for a random interval before generating the next packet
        time.sleep(randint(1, 5))


# Create lists to store probe requests and geocords
probelist = []
geocords = []
localqueue = []

# Create a lock to ensure thread-safe access to the probelist
lock = threading.Lock()

# Variable to control threads
stop_threads = False

# Start the packet generation thread
packet_thread = threading.Thread(target=generate_random_packets,
                                 args=(process_packet, probelist, geocords, lock))
process_burst_thread = threading.Thread(target=process_burst, args=(probelist, localqueue, lock))
packet_thread.start()
process_burst_thread.start()

try:

    while not stop_threads:
        # Print probelist every 10 iterations
        # Perform other tasks if needed
        # For testing, we are just sleeping here
        time.sleep(1)
except KeyboardInterrupt:
    # If Ctrl+C is pressed, stop the threads
    stop_threads = True
    print("Threads stopped.")
    packet_thread.join()
    process_burst_thread.join()