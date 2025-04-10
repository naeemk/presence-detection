import asyncio
import json
import time

from scapy.all import Dot11, Dot11Elt, Dot11ProbeReq, sniff, wrpcap
from scapy.all import getmacbyip
from netaddr import EUI, AddrFormatError, NotRegisteredError

def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)
config = load_config()

interface = config["general"]["interface"]
duration = config["general"]["duration_of_sniffing"]

def get_vendor_name(oui_bytes: bytes) -> str:
    if len(oui_bytes) != 3:
        raise ValueError("OUI must be exactly 3 bytes")

    # Pad the OUI to a full 48-bit MAC address
    padded_mac = oui_bytes + b'\x00\x00\x00'
    
    # Convert to MAC address string
    mac_str = '-'.join(f'{b:02X}' for b in padded_mac)

    try:
        # Create EUI object
        mac = EUI(mac_str)

        # Try to retrieve the vendor name
        return mac.oui.registration().org
    except (AddrFormatError, TypeError, KeyError, AttributeError, NotRegisteredError):
        return "Unknown Vendor"

    
# Global list to store captured probe data
probe_data = []
unsorted_probe_data = []

def handle_probe_request(packet):
    if packet.haslayer(Dot11ProbeReq):

        #wrpcap("captured_packets.pcap", [packet], append=True)

        mac = packet.addr2  # Source MAC (even if randomized)
        ssid = packet.info.decode(errors="ignore") if packet.info else "<Hidden SSID>"
        
        # Filter only for "HUAWEI-5G-9Ysz" or hidden SSID
        #if ssid != "HUAWEI-5G-9Ysz" and mac !="de:0f:c5:13:d9:ec":
         #   return  # Ignore packets that don't match the filter

        rssi = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else None
        #print(f"Raw RSSI: {rssi}, Adjusted RSSI: {rssi - 256 if rssi > 0 else rssi}")
        timestamp = time.time()
        
        # DEBUG INFO
        #print(packet.summary())  # Basic packet info
        #print("split")
        #print(packet.show())     # Full packet structure
        
        
        # Extract Wi-Fi Capabilities (HT, Extended, Vendor)
        wifi_features = []
        if packet.haslayer(Dot11Elt):
            try:
                elt = packet.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 1:  # Supported Rates
                        rates = [f"{(b & 0x7F) / 2} Mbps" for b in elt.info]
                        wifi_features.append(f"Supported Rates: {', '.join(rates)}")
                    elif elt.ID == 221:
                        if len(elt.info) >= 3:
                            vendor_oui = elt.info[:3]
                            vendor_oui_str = ':'.join(f'{b:02X}' for b in vendor_oui)
                            vendor_name = get_vendor_name(vendor_oui)
                            vendor_info = elt.info[3:]
                            wifi_features.append(f"Vendor: {vendor_oui_str} ({vendor_name})")
                            wifi_features.append(f"Vendor Info: {vendor_info.hex()}")
                        else:
                            wifi_features.append("Vendor Element Malformed")
                    elif elt.ID == 42:
                        wifi_features.append(f"HT Capabilities: {elt.info.hex()}")
                    elif elt.ID == 50:  # Extended Supported Rates
                        rates = [f"{(b & 0x7F) / 2} Mbps" for b in elt.info]
                        wifi_features.append(f"Extended Supported Rates: {', '.join(rates)}")
                    elif elt.ID == 48:
                        try:
                            version = int.from_bytes(elt.info[0:2], byteorder='little')
                            wifi_features.append(f"RSN Version: {version}")
                            # You can go further and parse cipher suites, AKM etc if needed
                        except:
                            wifi_features.append(f"RSN: Malformed ({elt.info.hex()})")

                    # Move to the next Dot11Elt layer
                    elt = elt.payload.getlayer(Dot11Elt)


            except Exception as e:
                print(f"[!] Error parsing Dot11Elt: {e}")
                wifi_features.append("Null")
                
        # Store the fingerprint
        probe_data.append({
            "MAC": mac,
            "SSID": ssid,
            "RSSI": rssi,
            "Timestamp": timestamp,
            "Features": ", ".join(wifi_features)
        })
        
        # Print captured details
        #print(f"\n[+] Probe Request from {mac}")
        #print(f"    - SSID: {ssid}")
        #print(f"    - RSSI: {rssi} dBm")
        #print(f"    - Features: {wifi_features}")

async def start_sniffing(interface):
    while True:
        print("[*] Listening for Wi-Fi probe requests...")
        sniff(iface=interface, prn=handle_probe_request, store=0, filter="type mgt subtype probe-req", timeout=duration)
        await asyncio.sleep(2)
