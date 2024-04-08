def sniff_probes():
    sniff(iface=monitor_interface, prn=process_packet, store=False, lfilter=lambda x: x.type == 0 and x.subtype == 4)