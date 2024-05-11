import queue
import threading
import time

def sync_probes(list1, list2, common_probes, lock):

    def find_last_probes(list1, list2):
        # Merge list1 and list2
        merged_list = list1 + list2

        # Dictionary to store the last probe request index for each fingerprint and IP combination
        last_probes = {}

        # Find the last probe request index for each fingerprint and IP combination
        for index, probe in enumerate(merged_list):
            key = (probe.fingerprint, probe.sniffer_ip)
            last_probes[key] = index

        # Dictionary to store the final result
        result = {}

        # Find unique IPs present in list1 and list2
        unique_ips = set()
        for probe in merged_list:
            unique_ips.add(probe.sniffer_ip)

        # Find probes with different IPs for each fingerprint
        for fingerprint, _ in last_probes:
            probe_requests = [merged_list[last_probes[(fingerprint, ip)]] for ip in unique_ips if (fingerprint, ip) in last_probes]
            if len(probe_requests) == len(unique_ips):
                result[fingerprint] = probe_requests

        return result

    synced_probes_keys = []
    while True:
        time.sleep(0.2)
        with lock:
            for item1 in list1[:]:
                # Generate a key to check for corresponding elements based on mac and sn
                key = (item1.macaddress, item1.sequencenumber)

                # Find corresponding elements in list2
                corresponding_elements = [item2 for item2 in list2 if (item2.macaddress, item2.sequencenumber) == key]

                # If there are at least two corresponding elements in list2
                if len(corresponding_elements) >= 2 and key not in synced_probes_keys:
                    # Add the elements to the queue
                    synced_probes_keys.append(key)
                    common_data = {'element1': item1, 'element2': corresponding_elements[0], 'element3': corresponding_elements[1]}
                    print(f"[sync_probes]\tFound common probe.", end="")
                    common_probes.append(common_data)
                    print(f"Length of common_probes: {len(common_probes)}")


