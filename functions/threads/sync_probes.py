import queue
import threading
import time

def sync_probes(list1, list2, common_queue, lock):
    while True:
        time.sleep(0.2)
        with lock:
            for item1 in list1[:]:
                # Generate a key to check for corresponding elements based on mac and sn
                key = (item1.macaddress, item1.sequencenumber)

                # Find corresponding elements in list2
                corresponding_elements = [item2 for item2 in list2 if (item2.macaddress, item2.sequencenumber) == key]

                # If there are at least two corresponding elements in list2
                if len(corresponding_elements) >= 2:
                    # Remove the corresponding elements from list2
                    for item2 in corresponding_elements:
                        list2.remove(item2)

                    # Remove the corresponding element from list1
                    list1.remove(item1)

                    # Add the elements to the queue
                    common_data = {'element1': item1, 'element2': corresponding_elements[0], 'element3': corresponding_elements[1]}
                    print(f"[sync_probes]\tFound common data: {common_data}")
                    common_queue.put(common_data)


