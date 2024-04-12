from scapy.all import sniff
from functions import process_packet

def packet_sniffer(interface, probelist, lock):
        sniff(iface=interface, prn=lambda packet: process_packet(packet, probelist, lock), store=False, lfilter=lambda x: x.type == 0 and x.subtype == 4)
