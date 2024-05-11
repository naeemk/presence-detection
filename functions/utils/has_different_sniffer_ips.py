def has_different_sniffer_ips(probe_requests):
    sniffer_ips = set()
    for probe_request in probe_requests:
        sniffer_ip = probe_request.sniffer_ip
        sniffer_ips.add(sniffer_ip)
    return len(sniffer_ips) > 1