class ProbeRequest:
    def __init__(self, macaddress, rssi, fingerprint, sequencenumber, sniffercords):
        self.macaddress = macaddress
        self.rssi = rssi
        self.fingerprint = fingerprint
        self.sequencenumber = sequencenumber
        self.sniffercords = sniffercords