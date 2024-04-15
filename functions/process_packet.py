from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt

from objects.proberequest import ProbeRequest

# processes packets, creates proberequest objects of all received probes and populates list
# which is then filtered by process_burst
def process_packet(packet, probelist, sniffercords, lock):
    if packet.haslayer(Dot11ProbeReq):
        print("\n[process_packet] Probe Request Detected:")

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
            probelist.append(ProbeRequest(mac_address, rssi, fingerprint, sequence_number, sniffercords))
