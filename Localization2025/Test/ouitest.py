from netaddr import EUI, AddrFormatError, NotRegisteredError

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

# Example usage:
print(get_vendor_name(b'\x00\x50\xf2'))  # MICROSOFT CORP.
print(get_vendor_name(b'\xbb\xbb\xbb'))  # Unknown Vendor
