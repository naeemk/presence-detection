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