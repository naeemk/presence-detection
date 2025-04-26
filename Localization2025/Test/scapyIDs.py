from scapy.all import Dot11, Dot11Elt, sniff


def handle_packet(pkt):
    if pkt.haslayer(Dot11):
        dot11 = pkt.getlayer(Dot11)
        if dot11.type == 0 and dot11.subtype == 4:  # Management frame, Probe Request
            print(f"\n[+] Probe Request from {dot11.addr2}")

            # Parse all Dot11Elt layers
            elt = pkt.getlayer(Dot11Elt)
            while elt is not None and isinstance(elt, Dot11Elt):
                print(f"    ID: {elt.ID} | Length: {elt.len} | Info: {elt.info}")
                elt = elt.payload.getlayer(Dot11Elt)

print("Sniffing Probe Requests... (Press Ctrl+C to stop)")
sniff(iface="wlan0", prn=handle_packet, store=0)
