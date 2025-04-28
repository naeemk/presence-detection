from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt

def parse_rates(info):
    rates = []
    for rate_byte in info:
        rate = (rate_byte & 0x7F) / 2  # remove 'basic rate' flag and divide by 2
        rates.append(f"{rate} Mbps")
    return rates

def handle_packet(pkt):
    if pkt.haslayer(Dot11):
        dot11 = pkt.getlayer(Dot11)
        if dot11.type == 0 and dot11.subtype == 4:  # Management frame, Probe Request
            
            mac = dot11.addr2  # Source MAC (even if randomized)
            ssid = dot11.info.decode(errors="ignore") if dot11.info else "<Hidden SSID>"
            
            # Filter only for "HUAWEI-5G-9Ysz" or hidden SSID
            if ssid != "HUAWEI-5G-9Ysz" and mac !="ce:0a:dd:5c:9e:f7":
               return  # Ignore packets that don't match the filter


            print(f"\n[+] Probe Request from {dot11.addr2}")

            # Parse all Dot11Elt layers
            elt = pkt.getlayer(Dot11Elt)
            while elt is not None and isinstance(elt, Dot11Elt):
                if elt.ID == 0:
                    ssid = elt.info.decode(errors="ignore")
                    if not ssid:
                        print(f"    ID: {elt.ID} | SSID: <hidden> (broadcast)")
                    else:
                        print(f"    ID: {elt.ID} | SSID: {ssid}")
                elif elt.ID == 1:
                    print(f"    ID: {elt.ID} | Supported Rates: {parse_rates(elt.info)}")
                elif elt.ID == 45:
                    print(f"    ID: {elt.ID} | HT Capabilities: {elt.info.hex()}")
                elif elt.ID == 50:
                    print(f"    ID: {elt.ID} | Extended Supported Rates: {parse_rates(elt.info)}")
                elif elt.ID == 127:
                    print(f"    ID: {elt.ID} | Extended Capabilities: {elt.info.hex()}")
                elif elt.ID == 221:
                    print(f"    ID: {elt.ID} | Vendor: {elt.info.hex()}")
                elif elt.ID == 3:
                    if len(elt.info) >= 1:
                        channel = elt.info[0]
                        print(f"    ID: {elt.ID} | DS Parameter Set: Channel {channel}")
                    else:
                        print(f"    ID: {elt.ID} | DS Parameter Set: [Malformed: no channel info]")
                else:
                    # For all others (including HT Capabilities, Extended Capabilities, etc.)
                    print(f"    ID: {elt.ID} | Length: {elt.len} | Raw Info: {elt.info.hex()}")

                elt = elt.payload.getlayer(Dot11Elt)

print("Sniffing Probe Requests... (Press Ctrl+C to stop)")
sniff(iface="wlan0", prn=handle_packet, store=0)
