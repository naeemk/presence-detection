from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt

from functions.utils.rssi_to_distance import rssi_to_distance
from objects.proberequest import ProbeRequest

# processes packets, creates proberequest objects of all received probes and populates list
# which is then filtered by process_burst
def process_packet(packet, probelist, sniffercords, measured_power, n, lock):
    print(f"[process_packet]\tReceived packet: Executing process_packet with arguments packet = {packet} probelist(length)={len(probelist)}, sniffercords={sniffercords}, lock={lock}")
    if packet.haslayer(Dot11ProbeReq):
        print(f"\n[process_packet]\tPacket is a probe request")

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


        #  Create fingerprint
        fingerprint= ""
        ie_Ids = [1, 10, 45, 50, 191, 221, 127, 3, 35]
        for el in ie_Ids:
            ie = packet.getlayer(Dot11Elt, ID=el)
            if ie:
                fingerprint += ie.info.hex()



        print(f"Fingerprint: {fingerprint}")

        # Create probe object and append to list
        with lock:
            print(f"Adding probe to probelist:")
            probelist.append(ProbeRequest(mac_address, rssi_to_distance(rssi, measured_power, n), fingerprint, sequence_number, sniffercords[0]))
        print(f"Probelist length: {len(probelist)}")
        print()