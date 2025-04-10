from scapy.all import sniff, Dot11

seen_macs = set()  # Store MAC addresses we've already printed

def is_not_randomized(mac):
    """Check if the 7th bit (bit index 1) is 0 in the first byte of the MAC."""
    first_byte = int(mac.split(":")[0], 16)
    return (first_byte & 0b00000010) == 0

def process_packet(pkt):
    if pkt.haslayer(Dot11):
        # Check for probe request: type=0 (Mgmt), subtype=4 (Probe Request)
        if pkt.type == 0 and pkt.subtype == 4:
            mac = pkt.addr2
            ssid = pkt.info.decode(errors="ignore") if pkt.info else "Hidden SSID"
            if mac and is_not_randomized(mac) and mac not in seen_macs:
                seen_macs.add(mac)
                print(f"Non-randomized Probe Request MAC: {mac} | SSID: {ssid}")

# Start sniffing (change iface to your monitor mode interface like "wlan0mon")
sniff(prn=process_packet, store=0, iface="wlan0", monitor=True)
