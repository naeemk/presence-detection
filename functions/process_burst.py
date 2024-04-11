import time


# this function aims to filter the list of all received probe requests 
# so there are no duplicate mac addresses, to counter bursting nature of probes
def process_burst(probelist, localqueue, lock):
    counter = 0  
    while True:
        with lock:
            if len(probelist) >= 2:
                i = counter  
                while i < len(probelist):
                    if (i + 1 < len(probelist) and probelist[i].macaddress != probelist[i + 1].macaddress) or (i + 1 == len(probelist)):
                        # Found the element followed by a different MAC address
                        element_to_push = probelist[i]
                        localqueue.append(element_to_push)

                        #print so far
                        print("localqueue so far:")
                        for i, probe in enumerate(localqueue, 1):
                            print(f"Probe {i}:")
                            print(f"  MAC Address: {probe.macaddress}")
                            print(f"  RSSI: {probe.rssi}")
                            print(f"  Fingerprint: {probe.fingerprint}")
                            print(f"  Sequence number: {probe.sequencenumber}")

                        counter = i + 1  
                        break  
                    else:
                        i += 1
            else:
                # If probelist doesn't have enough elements, wait for more data
                time.sleep(1)
