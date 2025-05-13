from scapy.all import *
import time
import statistics
import json
from datetime import datetime


# Change this to the MAC addresses you're interested in (list of MAC addresses)
TARGET_MAC_PREFIXES = ["ce:0a:dd:5c:9e:f7", "48:74:6e:de:c7:5c"]
OUTPUT_FILE_JSON = "data/RSSI_DistanceMeasurements.json"

# Function to capture RSSI values from probe requests
def capture_rssi(interface, duration, target_prefixes):
    rssi_values = {mac: [] for mac in target_prefixes}
    start_time = time.time()

    def handle_probe_request(packet):
        nonlocal start_time
        elapsed_time = time.time() - start_time
        remaining_time = duration - elapsed_time

        if packet.haslayer(Dot11ProbeReq) and packet.haslayer(RadioTap):
            mac = packet.addr2
            ssid = packet.info.decode(errors="ignore") if packet.info else "<Hidden SSID>"

            # Filter only for specific MAC addresses
            if mac not in target_prefixes:
                return

            rssi = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else None
            if rssi is not None:
                rssi_values[mac].append(rssi)
                if remaining_time <= 20:
                    print(f"Less than 20 seconds until next measurement ({int(remaining_time)} seconds left)")
                print(f"Captured RSSI: {rssi} dBm from {mac}")

    sniff(iface=interface, prn=handle_probe_request, timeout=duration)
    return rssi_values


# Function to save RSSI measurements to a file
def save_results(distance, rssi_values):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data_entry = {"timestamp": current_time, "distance": distance, "devices": {}}

    for mac, values in rssi_values.items():
        avg_rssi = statistics.mean(values) if values else "No data captured"
        data_entry["devices"][mac] = {"rssi_values": values, "average_rssi": avg_rssi}

    try:
        with open(OUTPUT_FILE_JSON, "r") as json_file:
            data = json.load(json_file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []

    data.append(data_entry)

    with open(OUTPUT_FILE_JSON, "w") as json_file:
        json.dump(data, json_file, indent=4)

# Main function to run captures at different distances
def main():
    interface = "wlan0"  # Change this to your monitoring interface
    duration = 120  # Capture duration for each distance in seconds
    distances = [30, 40, 50]  # Distances in meters
    delay = 30  # Delay between captures in seconds

    for distance in distances:
        time.sleep(delay)  # Short delay before next capture

        print(f"Starting capture for {distance} meter(s)...")
        rssi_values = capture_rssi(interface, duration, TARGET_MAC_PREFIXES)
        save_results(distance, rssi_values)
        print(f"Finished capture for {distance} meter(s). Data saved.")


if __name__ == "__main__":
    main()
