import threading
import socket
import json
import time
import random
import sys

sys.path.append('../localization')

from functions.configure_adhoc_network import configure_adhoc_network
from functions.configure_socket import configure_socket


# Define ProbeRequest class
class ProbeRequest:
    def __init__(self, macaddress, distance, fingerprint, sequencenumber, sniffercords):
        self.macaddress = macaddress
        self.distance = distance
        self.fingerprint = fingerprint
        self.sequencenumber = sequencenumber
        self.sniffercords = sniffercords



# Function to periodically populate probelist with random elements
def populate_probelist(probelist):
    while True:
        # Generate random sample data
        probe = ProbeRequest(
            macaddress=":".join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)]),  # Random MAC address
            distance=random.uniform(0, 100),  # Random distance
            fingerprint="".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=8)),  # Random fingerprint
            sequencenumber=random.randint(1, 1000),  # Random sequence number
            sniffercords=(random.uniform(-180, 180), random.uniform(-90, 90))  # Random sniffer coordinates
        )
        # Add the random probe to the probelist
        probelist.append(probe)
        time.sleep(1)  # Wait for 1 second before adding another sample



# Function to send data
def send_data(sock, network_ips, probelist):
    print(f"[send_data]\tExecuting send_data thread")
    counter = 0  
    while True:
        print(f"[send_data]\tchecking if probelist: {len(probelist)} >= 1")
        if len(probelist) >= 1:
            print(f"[send_data]\tchecking if counter: {counter} < probelist: {len(probelist)}")
            while counter < len(probelist):
                probe_request_json = json.dumps({
                    "macaddress": probelist[counter].macaddress,
                    "distance": probelist[counter].distance,
                    "fingerprint": probelist[counter].fingerprint,
                    "sequencenumber": probelist[counter].sequencenumber,
                    "sniffercords": probelist[counter].sniffercords
                })
                probe_request_bytes = probe_request_json.encode()
                for ip in network_ips:
                    sock.sendto(probe_request_bytes, (ip, 12345))
                print(f"[send_data]\tSent this probe request {probe_request_json}")
                counter+=1
                
        time.sleep(0.1)



def receive_data(sock, all_received_probes):
    print(f"[receive_data]\tExecuting receive_data thread")
    while True:

        data, addr = sock.recvfrom(1024)
        print(f"[receive_data]\treceived data")
        data_str = data.decode()

        # Parse JSON data and create ProbeRequest objects
        try:
            decoded_data = json.loads(data_str)
            for item in decoded_data:
                probe = ProbeRequest(
                    item.get("macaddress"),
                    item.get("distance"),
                    item.get("fingerprint"),
                    item.get("sequencenumber"),
                    item.get("sniffercords")
                )
                all_received_probes.append(probe)
        except json.JSONDecodeError as e:
            print("Error decoding JSON:", e)
            continue
        
        print(f"[receive_probes]\tReceived This Probe)")
        print(f"\n \tMac: {probe.macaddress}\tSN: {probe.sequencenumber}\tSniffercords: {probe.sniffercords}")
           
        # print("All Probe Requests Received:", all_received_probes)  # Print all received ProbeRequest objects

# Main function
def main():
    # Initialize variables
    probelist = []
    all_received_probes = []
    
    my_ip = configure_adhoc_network()
    print(f"[Startup]\tmy ip: {my_ip}")

    sock = configure_socket(my_ip)

    network_ips = [f"10.192.200.{i}" for i in range(1, 255) if f"10.192.200.{i}" != my_ip]

    # Create a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Start threads for populating probelist, sending data, and receiving data
    populate_thread = threading.Thread(target=populate_probelist, args=(probelist,))
    send_thread = threading.Thread(target=send_data, args=(sock, network_ips, probelist))
    receive_thread = threading.Thread(target=receive_data, args=(sock, all_received_probes))

    populate_thread.start()
    send_thread.start()
    receive_thread.start()

    # Join threads to the main thread
    populate_thread.join()
    send_thread.join()
    receive_thread.join()

if __name__ == "__main__":
    main()
