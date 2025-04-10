from scapy.all import *

def parse_80211(pkt):
    if pkt.haslayer(Dot11):
        print("=== 802.11 Frame ===")
        pkt.show()

        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while isinstance(elt, Dot11Elt):
                print(f"[Elt] ID: {elt.ID}, Len: {elt.len}, Info: {elt.info}")
                elt = elt.payload

sniff(iface="wlan0", prn=parse_80211, filter="type mgt subtype probe-req", timeout=3)

