def write_probe_to_csv(filename, probe):
    import csv
    import os
    
    # Define the field names for the CSV file
    fieldnames = ['macaddress', 'distance', 'fingerprint', 'sequencenumber', 'sniffercords']
    
    # Check if the file exists
    file_exists = os.path.exists(filename)

    # Open the CSV file in append mode
    with open(filename, 'a', newline='') as csvfile:
        # Create a CSV writer object
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write the header row only if the file doesn't exist
        if not file_exists:
            writer.writeheader()

        # Write the ProbeRequest object to the CSV file
        writer.writerow({
            'macaddress': probe.macaddress,
            'distance': probe.distance,
            'fingerprint': probe.fingerprint,
            'sequencenumber': probe.sequencenumber,
            'sniffercords': probe.sniffercords
        })
