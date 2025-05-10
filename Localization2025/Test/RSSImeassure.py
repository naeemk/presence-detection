from scapy.all import *
import time
import statistics
from datetime import datetime


# Change this to the MAC prefix you're interested in (first 3 bytes of MAC address)
TARGET_MAC_PREFIX = "ce:0a:dd:5c:9e:f7"
OUTPUT_FILE = "RSSI_DistanceMeasurements.txt"
OUTPUT_FILE_JSON = "data/RSSI_DistanceMeasurements.json"

# Function to capture RSSI values from probe requests
def capture_rssi(interface, duration, target_prefix):
    rssi_values = []
    
    def handle_probe_request(packet):
        if packet.haslayer(Dot11ProbeReq) and packet.haslayer(RadioTap):
            mac = packet.addr2
            ssid = packet.info.decode(errors="ignore") if packet.info else "<Hidden SSID>"

            # Filter only for "HUAWEI-5G-9Ysz" or MAC
            if ssid !="HUAWEI-5G-9Ysz" and mac != target_prefix:
                return  # Ignore packets that don't match the filter


            rssi = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else None
            if rssi is not None:
                rssi_values.append(rssi)
                if duration < 20:
                    print("Less than 20 seconds until next measurement")
                print(f"Captured RSSI: {rssi} dBm from {mac}")
    
    sniff(iface=interface, prn=handle_probe_request, timeout=duration)
    return rssi_values

# Function to save RSSI measurements to a file
def save_results(distance, rssi_values):
    if rssi_values:
        avg_rssi = statistics.mean(rssi_values)
    else:
        avg_rssi = "No data captured"
    
    with open(OUTPUT_FILE, "a") as f:
        f.write(f"Distance: {distance} meters\n")
        f.write(f"RSSI values: {rssi_values}\n")
        f.write(f"Average RSSI: {avg_rssi}\n\n")

    # Append the current time and date to the file in a readable format
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Save results to JSON file
    data_entry = {
        "distance": distance,
        "rssi_values": rssi_values,
        "average_rssi": avg_rssi,
        "timestamp": current_time
    }

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
    distances = [0, 1, 4, 7, 10, 13, 16, 19, 21, 24, 27, 30, 33, 36, 39, 42, 45, 48, 51]  # Distances in meters
    delay = 15  # Delay between captures in seconds
    
    for distance in distances:
        print("-----------------------------------------------")
        print("-----------------------------------------------")
        print(f"Starting capture for {distance} meter(s)...")
        print("-----------------------------------------------")
        print("-----------------------------------------------")
        rssi_values = capture_rssi(interface, duration, TARGET_MAC_PREFIX)
        save_results(distance, rssi_values)
        print("--------------------!!!------------------------")
        print("--------------------!!!------------------------")
        print(f"Finished capture for {distance} meter(s). Data saved.")
        print("--------------------!!!------------------------")
        print("--------------------!!!------------------------")
        time.sleep(delay)  # Short delay before next capture
    
if __name__ == "__main__":
    main()
