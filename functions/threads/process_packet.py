import json
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt
import sys

from functions.utils.write_probe_to_csv import write_probe_to_csv
sys.path.append('.')
from functions.utils.rssi_to_distance import rssi_to_distance
from objects.proberequest import ProbeRequest

# processes packets, creates proberequest objects of all received probes and populates list
# which is then filtered by process_burst
def process_packet(packet, probelist, sniffercords, measured_power, n, socket, network_ips, lock):
    if packet.haslayer(Dot11ProbeReq):
        print(f"\n[process_packet] Captured probe", end="\n")

        # Extract the MAC address of the device
        mac_address = packet.addr2
        #print(f"MAC: {mac_address}", end=" ")


	    # Extract and print RSSI value
        if packet.haslayer(RadioTap):
            rssi = packet[RadioTap].dBm_AntSignal
            #print(f"RSSI: {rssi} dBm", end=" ")
        else:
            rssi = 0
            print("RSSI: Not available", end=" ")
            
        # Extract sequence number
        sequence_number = packet[Dot11].SC >> 4 
        #print(f"Sequence Number: {sequence_number}", end=" ") 


        #  Create fingerprint
        fingerprint= ""
        ie_Ids = [1, 10, 45, 50, 191, 221, 127, 3, 35]
        for el in ie_Ids:
            ie = packet.getlayer(Dot11Elt, ID=el)
            if ie:
                fingerprint += ie.info.hex()



        #print(f"Fingerprint: {fingerprint}")

        # Create probe object and append to list
        probe = ProbeRequest(mac_address, rssi_to_distance(rssi, measured_power, n), fingerprint, sequence_number, sniffercords[0])
        with lock:
            probelist.append(probelist)
            write_probe_to_csv("probelist.csv", probe)
        print(f"Probelist length: {len(probelist)}")
        print()

        probe_request_json = json.dumps({
            "macaddress": probe.macaddress,
            "distance": probe.distance,
            "fingerprint": probe.fingerprint,
            "sequencenumber": probe.sequencenumber,
            "sniffercords": probe.sniffercords
        })
        probe_request_bytes = probe_request_json.encode()
        for ip in network_ips:
            socket.sendto(probe_request_bytes, (ip, 12345))
        print(f"[send_data]\Broadcasted this probe request Mac: {probe.macaddress} SN: {probe.sequencenumber}")
        write_probe_to_csv("broadcasted_probes.csv", probe)
        counter+=1
        print(f"length of broadcasted probes: {len(counter)}")