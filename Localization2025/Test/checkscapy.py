from scapy.all import *
sniff(iface="wlan0", count=10, prn=lambda x: x.summary())