import queue

def find_and_remove_corresponding_elements(list1, list2, common_queue):
    for item1 in list1:
        # Generate a key to check for corresponding elements based on mac and sn
        key = (item1['mac'], item1['sn'])
        
        # Find corresponding elements in list2
        corresponding_elements = [item2 for item2 in list2 if (item2['mac'], item2['sn']) == key]
        
        # If there are at least two corresponding elements in list2
        if len(corresponding_elements) >= 2:
            # Remove the corresponding elements from list2
            for item2 in corresponding_elements:
                list2.remove(item2)
            
            # Remove the corresponding element from list1
            list1.remove(item1)
            
            # Add the elements to the queue
            common_data = {'element1': item1, 'element2': corresponding_elements[0], 'element3': corresponding_elements[1]}
            common_queue.put(common_data)

# Example usage:
if __name__ == "__main__":
    # Sample lists
    list1 = [
        {'mac': 1, 'sn': 100, 'id': 1, 'distance': 10},
        {'mac': 2, 'sn': 200, 'id': 2, 'distance': 20},
        {'mac': 3, 'sn': 300, 'id': 3, 'distance': 30}
    ]

    list2 = [
        {'mac': 1, 'sn': 100, 'id': 4, 'distance': 40},
        {'mac': 2, 'sn': 200, 'id': 5, 'distance': 50},
        {'mac': 2, 'sn': 200, 'id': 6, 'distance': 60},
        {'mac': 4, 'sn': 400, 'id': 7, 'distance': 70},
        {'mac': 3, 'sn': 300, 'id': 5, 'distance': 50},
        {'mac': 3, 'sn': 300, 'id': 6, 'distance': 10},
    ]
    
    # Queue for common data
    common_data_queue = queue.Queue()
    
    # Call the function
    # ran multiple times, manually, but should be ran in a loop with an interval for real time implementation
    find_and_remove_corresponding_elements(list1, list2, common_data_queue)
    find_and_remove_corresponding_elements(list1, list2, common_data_queue)
    find_and_remove_corresponding_elements(list1, list2, common_data_queue)
    find_and_remove_corresponding_elements(list1, list2, common_data_queue)
    find_and_remove_corresponding_elements(list1, list2, common_data_queue)
    
    # Print the modified lists and elements in the queue
    print("Modified List 1:", list1)
    print("Modified List 2:", list2)
    print("Elements in the Queue:")
    while not common_data_queue.empty():
        print(common_data_queue.get())
