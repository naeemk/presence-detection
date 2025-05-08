import json
import statistics

def analyze_mac_probes(mac_address, data):
    probes = data.get(mac_address, [])
    if not probes:
        print(f"No data found for MAC {mac_address}")
        return

    # Sort probes by timestamp, in case it's not already sorted
    probes.sort(key=lambda x: x["Timestamp"])

    bursts = []
    current_burst = []
    last_sequence = None

    for probe in probes:
        sequence = probe["Sequence Number"]
        if last_sequence is None or abs(sequence - last_sequence) <= 3:
            current_burst.append(probe)
        else:
            bursts.append(current_burst)
            current_burst = [probe]
        last_sequence = sequence

    if current_burst:
        bursts.append(current_burst)

    # Now collect statistics
    burst_lengths = [len(burst) for burst in bursts]
    burst_start_times = [burst[0]["Timestamp"] for burst in bursts]

    # Calculate time differences between bursts
    burst_intervals = [
        burst_start_times[i+1] - burst_start_times[i]
        for i in range(len(burst_start_times) - 1)
    ]

    # Print the results
    print(f"Results for MAC {mac_address} :")
    print(f"  Probe Requests per Burst:")
    print(f"    Min: {min(burst_lengths)}")
    print(f"    Max: {max(burst_lengths)}")
    print(f"    Median: {statistics.median(burst_lengths)}")
    if burst_intervals:
        print(f"  Seconds Between Bursts:")
        print(f"    Min: {min(burst_intervals):.2f} sec")
        print(f"    Max: {max(burst_intervals):.2f} sec")
        print(f"    Median: {statistics.median(burst_intervals):.2f} sec")
    else:
        print("  Not enough bursts to calculate intervals.")

# Example usage
if __name__ == "__main__":
    with open("./data/mac_data.json", "r") as f:
        mac_data = json.load(f)

    mac_to_analyze = "de:0f:c5:13:d9:ec"
    analyze_mac_probes(mac_to_analyze, mac_data)
