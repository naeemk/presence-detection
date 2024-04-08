def process_burst(probelist, localqueue, lock):
    with lock:
        for i in range(len(probelist) - 1):
            if probelist[i].mac != probelist[i + 1].mac:
                # Found the element followed by a different MAC address
                element_to_push = probelist[i]
                # Remove all previous elements from the list, including the one to return
                del probelist[:i + 1]
                localqueue.append(element_to_push)
    
        # If no such element is found, return None
        return None