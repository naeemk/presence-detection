import time

def process_burst(probelist, localqueue, lock):
    counter = 0  # Initialize counter variable
    while True:
        with lock:
            if len(probelist) >= 2:
                i = counter  # Start from the counter value
                while i < len(probelist) - 1:
                    if i + 1 < len(probelist) and probelist[i].macaddress != probelist[i + 1].macaddress:
                        # Found the element followed by a different MAC address
                        element_to_push = probelist[i]
                        localqueue.append(element_to_push)
                        counter = i + 1  # Update counter to next position
                        break  # Exit the loop after processing one burst
                    else:
                        i += 1
                if not i < len(probelist) - 1:
                    break
            else:
                # If probelist doesn't have enough elements, wait for more data
                time.sleep(1)
