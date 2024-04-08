def extract_vendor_specific(elements):
    while isinstance(elements, Dot11Elt):
        if elements.ID == 221 and elements.info.startswith(b'\x00\x50\xF2\x04'):  # Check for WPS UUID
            # Parse the UUID from the WPS element
            wps_info = elements.info[4:]  # Skip the OUI and type
            # Look for UUID-E attribute in WPS data (type 0x1048)
            pos = wps_info.find(b'\x10\x48')
            if pos != -1:
                # Assuming the next two bytes after the type indicate the length
                length = int.from_bytes(wps_info[pos+2:pos+4], byteorder='big')
                uuid_e = wps_info[pos+4:pos+4+length]
                print(f"WPS UUID-E: {uuid_e.hex()}")
            break  # UUID found, no need to check further elements
        elements = elements.payload