from collections import defaultdict

SEQUENCE_THRESHOLD = 10
TIME_WINDOW = 5  # seconds


def groupbysequence(mac_data):
    """
    Takes mac_data from groupbyMAC and groups entries for each MAC into bursts
    based on sequence number similarity and timestamp proximity.
    
    Returns:
        Dict[str, List[List[Dict]]] where key is MAC, and value is a list of bursts (list of entries).
    """
    sequence_data = defaultdict(list)

    for mac, entries in mac_data.items():
        sorted_entries = sorted(entries, key=lambda x: x["Timestamp"])
        current_burst = []

        for entry in sorted_entries:
            seq = entry.get("Seq")
            ts = entry.get("Timestamp")

            if not current_burst:
                current_burst.append(entry)
                continue

            last_seq = current_burst[-1].get("Seq")
            last_ts = current_burst[-1].get("Timestamp")

            if (
                last_seq is not None and seq is not None and
                abs(seq - last_seq) <= SEQUENCE_THRESHOLD and
                abs(ts - last_ts) <= TIME_WINDOW
            ):
                current_burst.append(entry)
            else:
                sequence_data[mac].append(current_burst)
                current_burst = [entry]

        if current_burst:
            sequence_data[mac].append(current_burst)

    return sequence_data
