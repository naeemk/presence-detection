
import subprocess
from scapy.all import sniff
from functions import process_packet

def setup_interface(interface):
    global monitor_interface
    # Commands to set up the interface for monitoring
    subprocess.call(["sudo", "ifconfig", interface, "down"])
    subprocess.call(["sudo", "airmon-ng", "start", interface])
    # Adjust for your environment - some systems rename the interface to wlan0mon
    monitor_interface = "wlan1mon" if interface == "wlan1" else interface
    subprocess.call(["sudo", "ifconfig", monitor_interface, "up"])
    print(f"{monitor_interface} set to monitor mode and brought up.")
    
    return monitor_interface



def process_packet(packet):
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



interface = "wlan1"
monitor_interface = setup_interface(interface)
sniff(iface=monitor_interface, prn=lambda packet: process_packet(packet), store=False, lfilter=lambda x: x.type == 0 and x.subtype == 4)


