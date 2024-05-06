class ProbeRequest:
    def __init__(self, macaddress, distance, fingerprint, sequencenumber, sniffercords):
        self.macaddress = macaddress
        self.distance = distance
        self.fingerprint = fingerprint
        self.sequencenumber = sequencenumber
        self.sniffercords = sniffercords