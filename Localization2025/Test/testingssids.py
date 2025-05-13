from scapy.all import sniff, Dot11
import time

# Predefined list of common SSIDs
COMMON_SSIDS = {"eduroam"}

# Sets to store unique SSIDs and counters for each category
hidden_count = 0
common_count = 0
other_ssids = set()
other_count = 0

# Counter for total probe requests
total_requests = 0

def process_probe_request(packet):
    global total_requests, hidden_count, common_count, other_count
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 4:  # Probe request frame
        ssid = packet.info.decode(errors='ignore')
        total_requests += 1

        if not ssid:  # Hidden SSID
            hidden_count += 1
        elif ssid in COMMON_SSIDS:  # Common SSID
            common_count += 1
        else:  # Other SSID
            other_ssids.add(ssid)
            other_count += 1

        display_statistics()


def display_statistics():
    if total_requests == 0:
        return

    elapsed_time = time.time() - start_time
    minutes = int(elapsed_time // 60)
    seconds = int(elapsed_time % 60)
    print(f"Elapsed Time: {minutes} minutes {seconds} seconds")

    hidden_percent = (hidden_count / total_requests) * 100
    common_percent = (common_count / total_requests) * 100
    other_percent = (other_count / total_requests) * 100

    print("\nStatistics:")
    print(f"Total probe requests: {total_requests}")
    print(f"Hidden SSIDs: {hidden_count} ({hidden_percent:.2f}%)")
    print(f"Common SSIDs (Eduroam): {common_count} ({common_percent:.2f}%)")
    print(f"Other unique SSIDs: {len(other_ssids)} ({other_percent:.2f}%)")


print("Starting to capture probe requests...")
start_time = time.time()
sniff(iface="wlan0", prn=process_probe_request, store=0)
# 