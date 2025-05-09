import asyncio
import json
import time

from scapy.all import Dot11, Dot11Elt, Dot11ProbeReq, sniff, wrpcap, rdpcap

from netaddr import EUI, AddrFormatError, NotRegisteredError

def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)
config = load_config()

interface = config["general"]["interface"]
duration = config["general"]["duration_of_sniffing"]
pcap_file = config["jsonfiles"]["pcap_file"]

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

        #wrpcap("data/captured_packets.pcap", [packet], append=True)

        mac = packet.addr2  # Source MAC (even if randomized)
        ssid = packet.info.decode(errors="ignore") if packet.info else "<Hidden SSID>"
        
        seq_num = (packet[Dot11].SC >> 4)  # Extract sequence number from SC field
        
        # Filter only for "HUAWEI-5G-9Ysz" or hidden SSID
        #if ssid != "HUAWEI-5G-9Ysz" and mac !="ce:0a:dd:5c:9e:f7":
        #    return  # Ignore packets that don't match the filter

        #if mac !="e2:89:8b:a7:eb:24":
        #    return

        rssi = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else None
        
        timestamp = time.time()
        
        myvendor_oui = b'\x8C\xFD\xF0'  # Qualcomm Vendor


        # Extract Wi-Fi Capabilities (Supported Rates, ERPHT, Extended, Vendor)
        wifi_features = []
        if packet.haslayer(Dot11Elt):
            try:
                elt = packet.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 1:  # Supported Rates
                        wifi_features.append(f"Supported Rates: {elt.info.hex()}")
                    elif elt.ID == 45:  # HT Capabilities
                        wifi_features.append(f"HT Capabilities: {elt.info.hex()}")
                    elif elt.ID == 50:  # Extended Supported Rates
                        wifi_features.append(f"Extended Supported Rates: {elt.info.hex()}")
                    elif elt.ID == 127:  # Extended Capabilities
                        wifi_features.append(f"Extended Capabilities: {elt.info.hex()}")
                    elif elt.ID == 191:  # VHT Capabilities
                        wifi_features.append(f"VHT Capabilities: {elt.info.hex()}")
                    elif elt.ID == 221:  # Vendor Specific
                        if len(elt.info) >= 3:
                            vendor_oui = elt.info[:3]
                            vendor_oui_str = ':'.join(f'{b:02X}' for b in vendor_oui)
                            vendor_name = get_vendor_name(vendor_oui)
                            vendor_info = elt.info[3:]
                            wifi_features.append(f"Vendor: {vendor_oui_str} ({vendor_name}) Vendor Info: {vendor_info.hex()}")
                        else:
                            wifi_features.append("Vendor Element Malformed")

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
            "Features": wifi_features
        })
         # Save the processed devices data to a JSON file
        with open("data/probe_data.json", "w") as json_file:
            json.dump(probe_data, json_file, indent=4)


async def start_sniffing(interface):
    while True:
        print("[*] Listening for Wi-Fi probe requests...")
        sniff(iface=interface, prn=handle_probe_request, store=0, filter="type mgt subtype probe-req", timeout=duration)
        await asyncio.sleep(2)
